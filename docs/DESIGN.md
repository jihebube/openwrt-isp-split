# 设计与原理

## 设计目标

- 在不修改 mwan3 核心逻辑的前提下，为 mwan3-nft 提供「按目标运营商选线」能力
- 数据维护、规则接入、更新全部自动化，且更新过程不影响已建立连接
- 任何操作可预演、可回滚；卸载后配置完全还原

非目标：不做代理、不做应用层（DPI）识别、不处理 IPv6（见 README 路线图）。

## 数据管线

```
ispip.clang.cn/<运营商>.txt
   |  cidr2range.awk       CIDR -> [起始, 结束] 整数区间
   |  sort + merge.awk     区间合并
   |  exclude.awk          按优先级做区间差集（互斥化）
   |  range2cidr.awk       区间 -> 最小 CIDR 集合
   v
/etc/isp-split/data/<运营商>.txt  ->  mwan3 的 loadfile
```

### 为什么需要互斥化

上游数据中各运营商的网段存在大量重叠（如 chinatelecom 与 unicom_cnc 之间 494 处）。若直接将各列表写入各自集合，同一 IP 的归属就取决于规则顺序，成为隐性行为。管线按 `ISP_TABLE` 的声明顺序做区间差集：14276 条输入合并为 13417 条，每个 IP 只可能命中一个集合。

| 运营商 | 原始条目 | 互斥化后 |
|---|---:|---:|
| chinatelecom | 1790 | 1790 |
| unicom_cnc | 1368 | 1001 |
| cmcc | 319 | 166 |
| othernet | 2071 | 1914 |
| hk | 7367 | 7245 |

### 为什么用零填充整数排序

busybox 的 `sort -n` 对超出 2^31 的数值不保证数值序（实测 `3232235520` 会排在 `134744064` 之前）。将地址区间端点补零至 10 位后，字典序与数值序等价，在所有平台行为一致。

## 规则接线

mwan3 严格按配置文件顺序渲染 `mwan3_rules` 链，而 `uci add` 只能追加到末尾——追加的规则必然落在 `default_rule` 之后而永远无法命中。因此采用文本级拼接（`rules-splice.awk`），将规则插入到第一个含 `dest_port` 的规则之前，并做两项防护：

1. 插入后运行 `uci show mwan3` 冒烟检查，解析失败则放弃写入（保留备份）
2. `stage` 子命令可将规则以 `enabled=0` 写入——mwan3 不渲染它们，确认健康后再 `enable`

## 运行时路径

```
包 -> mwan3_prerouting(mangle+1)
   -> mwan3_rules: ip daddr @isp_tel && mark&0x3f00==0 -> jump mwan3_policy_wan_only
   -> mwan3 策略链: mark set 0x500，ct mark set 0x500
   -> ip rule (fwmark 0x500) -> 路由表 -> wan1
```

- 掩码判断 `mark & 0x3f00 == 0` 意为「尚未标记」。OpenClash 的 `0x162` 在该掩码下非零，代理流量天然被跳过
- mwan3 将标记存入 conntrack（`ct mark set`）并在子链入口以 `mark & 0x3f00 == 0` 作前置条件，因此已建立连接的后续包不会再次进入规则链——实测每个连接只有首包触发集合查找
- 集合为 interval + auto-merge 的红黑树实现，2300 个元素占内核内存约 344 kB（约 150 B/元素）

## 与代理（OpenClash / sing-box）共存

| 组件 | 挂载点 | 标记 |
|---|---|---|
| OpenClash | prerouting mangle（-150） | `0x162` |
| mwan3 / 本工具 | prerouting mangle+1（-149） | `0x3F00` 掩码 |

代理流量在更早的优先级完成 TPROXY 标记与策略路由，mwan3 判断标记已存在而直接跳过。因此本工具只影响直连流量，代理出口由代理自身决定。

DNS 层：代理通常通过 dnsmasq 的通配转发（`server=/#/127.0.0.1#7874`）接管解析。dnsmasq 按最长域名后缀匹配且与顺序无关，本工具生成的 `server=/域名/IP` 更具体而优先生效——列入分流的域名会绕过代理 DNS 直接解析并走对应线路。需要走代理的域名不应加入 `DOMAIN_SPLIT`（fake-ip 模式下这些域名将获得真实地址而不经代理）。

## 更新的原子性

`apply` 通过单次 `nft -f` 事务（`flush set` + `add element`）完成全部集合替换。nft 批处理是原子的：任何一条元素非法则整批拒绝，因此不会出现「部分集合更新、部分保持旧数据」的中间态。写入前的 `check` 子命令用 `nft -c` 干跑校验，失败时附带数据文件逐行定位（`badcidr.awk`）。

## 性能

在 OpenWrt 25.12.6 (x86_64) 上的实测数据：

| 项目 | 数值 |
|---|---|
| 全量 13417 条 CIDR（10 集合）加载 | 约 800 ms，合并为 10278 个内核元素 |
| 4 个启用集合（2300 元素）内核内存 | 344 kB |
| 每连接开销 | 首包一次集合查找 + 一次策略跳转；稳态为零 |
| 每日 `refresh` | 后台一次，期间新连接可能排队数百微秒 |

无 TPROXY、无用户态转发、无新增 conntrack 条目，开销与 mwan3 自身规则同一量级。

## 与商业方案（iKuai）的对比

iKuai 分流效果更准的核心原因不在选路算法，而在于两点：

1. **多线路 DNS**：每条 WAN 配置各自的 DNS，DNS 查询随线路发出，CDN 主动返回该运营商的节点。官方文档明确「域名分流必须配合多线路 DNS」。CDN 按「来访 DNS 的运营商与位置」调度，事后按 IP 纠正无法弥补解析阶段的选择错误
2. **DPI 应用识别**：3200+ 特征库按应用而非 IP/端口分流，规避同一应用 CDN 分布在多运营商的问题

本工具已补齐第一点（`isp-split dns`，见 [CONFIGURATION.md](CONFIGURATION.md)），DPI 在 nftables 架构下不可行（无法解析 L7，TLS SNI 偏移不固定），不列入目标。

粘滞粒度：iKuai 支持源 IP+目的 IP(+端口) 粘滞，mwan3 的 sticky 仅按源 IP；如需更细粒度可用 mwan3 的 `config rule` 组合自行补充。

## 数据来源与准确性

- 运营商网段来自 [ispip.clang.cn](https://ispip.clang.cn)，其数据基于 APNIC 与公开 BGP/WHOIS 记录，每日更新
- 该数据解决绝大多数场景；个别骨干节点或代播段可能归类偏差，可通过 `DOMAIN_SPLIT` 做域名级覆盖，或向数据源反馈
