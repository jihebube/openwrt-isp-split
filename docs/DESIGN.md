# 设计与原理

## 设计目标

- 在不修改 mwan3 核心逻辑的前提下，为 mwan3-nft 提供「按目标运营商选线」能力
- 数据维护、规则接入、更新全部自动化，且更新过程不影响已建立连接
- 任何操作可预演、可回滚；卸载会还原 mwan3/dnsmasq 改动（配置与数据文件默认保留）

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

上游数据中各运营商的网段存在大量重叠（如 chinatelecom 与 unicom_cnc 之间有数百处）。若直接将各列表写入各自集合，同一 IP 的归属就取决于规则顺序，成为隐性行为。管线按 `ISP_TABLE` 的声明顺序做区间差集：约 1.4 万条输入合并后约 1.3 万条，每个 IP 只可能命中一个集合。

下表为某次运行的示例数据，具体数值随数据源每日变化，以实际运行为准：

| 运营商 | 原始条目（约） | 互斥化后（约） |
|---|---:|---:|
| chinatelecom | 1800 | 1800 |
| unicom_cnc | 1400 | 1000 |
| cmcc | 320 | 170 |
| othernet | 2100 | 1900 |
| hk | 7400 | 7200 |

### 为什么用零填充整数排序

busybox 的 `sort -n` 对超出 2^31 的数值不保证数值序（实测 `3232235520` 会排在 `134744064` 之前）。将地址区间端点补零至 10 位后，字典序与数值序等价，在所有平台行为一致。

## 规则接线

mwan3 严格按配置文件顺序渲染 `mwan3_rules` 链，而 `uci add` 只能追加到末尾——追加的规则必然落在 `default_rule` 之后而永远无法命中。因此采用文本级拼接（`rules-splice.awk`）：按 `ISP_ANCHOR`（默认正则 `dest_port|src_port|default_rule|https|internet`，可配置）定位第一个匹配的非本工具 rule，把规则块插到它之前；锚点缺失时直接报错退出，不会静默追加到链尾。为避免写坏配置：

1. 只按精确标记 `option isp_split '1'` 识别并替换本工具的规则块，不误删用户规则
2. 把新配置复制到临时目录后以 UCI 解析校验，失败则放弃写入（保留备份）
3. 校验通过后再原子覆盖 `/etc/config/mwan3`
4. `stage` 子命令可将规则以 `enabled=0` 写入——mwan3 不渲染它们，确认健康后再 `enable`

## 运行时路径

```
包 -> mwan3_prerouting(mangle+1)
   -> mwan3_rules: ip daddr @isp_tel && mark&0x3f00==0 -> jump mwan3_policy_wan_only
   -> mwan3 策略链: mark set 0x500，ct mark set 0x500
   -> ip rule (fwmark 0x500) -> 路由表 -> wan1
```

- 掩码判断 `mark & 0x3f00 == 0` 意为「尚未标记」。OpenClash 的 `0x162` 在该掩码下非零，代理流量天然被跳过
- mwan3 将标记存入 conntrack（`ct mark set`）并在子链入口以 `mark & 0x3f00 == 0` 作前置条件，因此已建立连接的后续包不会再次进入规则链——实测每个连接只有首包触发集合查找
- 集合为 interval + auto-merge 的红黑树实现，典型 4 个启用集合约 2300 个元素占内核内存约 344 kB（约 150 B/元素，x86_64 实测示例）

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

在 OpenWrt 25.12.6 (x86_64) 上的实测示例（数据随每日源变化，以实际运行为准）：

| 项目 | 数值 |
|---|---|
| 全量约 1.3 万条 CIDR（10 集合）加载 | 约 800 ms，合并为约 1 万个内核元素 |
| 典型 4 个启用集合（约 2300 元素）内核内存 | 约 344 kB |
| 每连接开销 | 首包一次集合查找 + 一次策略跳转；稳态为零 |
| 每日 `refresh` | 后台一次，期间新连接可能排队数百微秒 |

无 TPROXY、无用户态转发、无新增 conntrack 条目，开销与 mwan3 自身规则同一量级。

## 与商业方案（iKuai/爱快）的对比

一句话结论：**运营商分流与多线路 DNS 已追平；DPI 应用识别是唯一差距**（详见下表）。

| 能力 | iKuai（商业闭源） | 本项目 | 状态 |
|---|---|---|---|
| 运营商网段分流 | 内置 | ✅ 10 类运营商约 1.3 万网段，每日自动更新 | **已追平** |
| 多线路 DNS（CDN 正确调度） | ✅ | ✅ bind / mark 双模式，兼容代理接管 DNS 的部署 | **已追平** |
| 域名钉线 | ✅ | ✅ `DOMAIN_SPLIT`（策略级）+ 外部域名清单 | **已追平** |
| 设备/源地址钉线 | ✅ | ✅ 依赖 mwan3 原生 `config rule`（saddr → 策略） | **已追平**（组合 mwan3 即可） |
| 灰度上线 / 预演 / 回滚 | 部分 | ✅ plan / check / selftest 三级预检 + stage 灰度 + 备份回滚 | **本项目更强** |
| 开源 / 可审计 | ❌ | ✅ MIT，全 shell + awk，无黑盒 | **本项目更强** |
| 粘滞粒度 | 源 IP + 目的 IP(+端口) | 仅源 IP（mwan3 sticky 限制） | 差距（可组合规则近似） |
| DPI 应用识别选线 | ✅ 3200+ 特征库 | ❌ 明确非目标（见下） | **未追平（架构性）** |

关于 DPI：经调研（netifyd/nDPI、netqmon 等 eBPF 方案、OAF 移植），开源侧目前没有能把「识别结果」接入多 WAN 路由决策的现成方案——DPI 需要看到多个包才敢下结论（TLS SNI 要等 ClientHello），而策略路由必须在连接首包就打标，存在时序矛盾。替代思路：用 `DOMAIN_SPLIT` 把大流量应用的 CDN 域名钉到指定线路（CDN 域名即应用本体，比 DPI 识别更精准），配合 mwan3 按设备分线，可覆盖按应用调度的大部分实际收益。

iKuai 分流效果更准的核心原因不在选路算法，而在于两点：

1. **多线路 DNS**：每条 WAN 配置各自的 DNS，DNS 查询随线路发出，CDN 主动返回该运营商的节点。官方文档明确「域名分流必须配合多线路 DNS」。CDN 按「来访 DNS 的运营商与位置」调度，事后按 IP 纠正无法弥补解析阶段的选择错误
2. **DPI 应用识别**：3200+ 特征库按应用而非 IP/端口分流，规避同一应用 CDN 分布在多运营商的问题

本工具已补齐第一点（`isp-split dns`，见 [CONFIGURATION.md](CONFIGURATION.md)），DPI 在 nftables 架构下不可行（无法解析 L7，TLS SNI 偏移不固定），不列入目标。

粘滞粒度：iKuai 支持源 IP+目的 IP(+端口) 粘滞，mwan3 的 sticky 仅按源 IP；如需更细粒度可用 mwan3 的 `config rule` 组合自行补充。

## 数据来源与准确性

- 运营商网段来自 [ispip.clang.cn](https://ispip.clang.cn)，其数据基于 APNIC 与公开 BGP/WHOIS 记录，每日更新
- 该数据解决绝大多数场景；个别骨干节点或代播段可能归类偏差，可通过 `DOMAIN_SPLIT` 做域名级覆盖，或向数据源反馈
