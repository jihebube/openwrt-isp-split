# 配置详解

主配置文件为 `/etc/isp-split.conf`。所有改动需要对应的生效命令：

| 改动的配置段 | 生效命令 |
|---|---|
| `ISP_TABLE` | `isp-split wire && isp-split apply` |
| `DNS_TABLE` / `DOMAIN_SPLIT` / `DNS_MODE` | `isp-split dns` |
| 定时任务 | `isp-split install`（或 `scripts/install.sh --cron`） |

也可以在 LuCI「网络 → 运营商分流 → 配置」页完成同样的修改。

---

## ISP_TABLE：运营商 → 策略映射

```sh
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
cmcc:isp_cmcc:wanb_only:1
cernet:isp_cernet:wan_only:1
chinabtn:isp_tietong:wanb_only:0
gwbn:isp_gwbn:balanced:0
othernet:isp_other:wanb_only:0
hk:isp_hk:wanb_only:0
mo:isp_mo:wanb_only:0
tw:isp_tw:wanb_only:0
"
```

每行四段，冒号分隔：

| 字段 | 含义 | 取值 |
|---|---|---|
| 1 | 数据来源（`/etc/isp-split/data/<名称>.txt`） | ispip.clang.cn 的名称 |
| 2 | nftables 集合名 | `isp_` 前缀，任意 |
| 3 | mwan3 策略 | `wan_only` / `wanb_only` / `balanced`（必须在 mwan3 中已存在） |
| 4 | 启用 | `1` / `0` |

要点：

- **顺序即优先级**。上游数据存在重叠（如电信与联通之间有数百处），靠前的运营商先占用网段，因此每个 IP 只归属一个集合
- 第三列是 mwan3 的策略名，也可以用自定义策略
- 被完全覆盖的集合（如本例中 unicom_cnc 被 chinatelecom 抢走大量网段后）条目数会显著减少，属正常现象

### 未命中集合的流量

不在任何**已启用**集合内的流量（海外 IP、未启用的运营商、云厂商自有 AS 等）不会被本工具打标，交给 mwan3 处理：

- `default_rule_v4` **缺省即启用**（mwan3 对 rule 的 `enabled` 缺省=启用）→ 按默认策略分配（推荐）
- 显式禁用或删除该规则 → 走系统默认路由，不参与负载均衡

`isp-split status` 会检测后一种情况并给出提示。

---

## 多线路 DNS

只按目标 IP 纠正线路存在一个先天缺陷：如果 DNS 查询本身从 A 线路发出，CDN 会返回 A 线路的节点。多线路 DNS 让「查询从哪条线发出」与「业务走哪条线」一致，从源头获得正确的 CDN 调度。

```sh
# 每条线路对应的 DNS：<mwan3策略>:<DNS服务器>
DNS_TABLE="
wan_only:223.5.5.5
wanb_only:119.29.29.29
"

# 需要钉到线路的域名后缀：<域名后缀>:<策略>
DOMAIN_SPLIT="
bilivideo.com:wanb_only
bilibili.com:wanb_only
"

# 出线方式
DNS_MODE="bind"
```

执行 `isp-split dns` 后：

1. 先探测 dnsmasq **实际加载**的 conf-dir，再把 `isp-split.conf` 写进去：

   ```
   server=/bilivideo.com/119.29.29.29@pppoe-wan2
   ```

    `@` 后是 mwan3 成员接口的运行时设备名（如 `pppoe-wan2`），不是 UCI 接口名（`wan2`）；照写 UCI 接口名会得到 dnsmasq 的 unknown interface 错误。

   探测优先级：`/var/etc/dnsmasq.conf.*` 里的 `conf-dir=` 行（权威源）→
   运行中 dnsmasq 的 `--conf-dir=` 参数 → UCI
   `dhcp.@dnsmasq[0].confdir` → 默认 `/tmp/dnsmasq.d`。
   解析时容忍尾斜杠、空格分隔的多个目录，以及 `conf-dir=<dir>,*.conf`
   形式的扩展名过滤；多实例的配置会全部读取。

   探测到运行配置（典型场景：OpenClash 接管 DNS，UCI confdir 为空，
   实际目录是 `/tmp/dnsmasq.cfgXXXX.d`）时**不改写 UCI**，避免 OpenClash
   关闭后残留一个改变 dnsmasq 加载路径的配置。只有 UCI 本身就是权威源
   （无运行配置）时才沿用原来的 confdir 处理与状态记录逻辑。

2. 在 `inet mwan3 mwan3_output` 链顶部插入 DNS 出线规则（随 mwan3 重启丢失，`/etc/init.d/isp-split` 会在启动时自动重放）
3. 重启 dnsmasq；卸载时按同一套探测结果清理所有可能目录里的
   `isp-split.conf`。只有确实改过 UCI 时才有
   `dnsmasq.confdir.orig` 状态文件，没改过就不动 UCI（旧版本写入的
   `/etc/isp-split/dnsmasq.d` 仍会被自动摘除）

### DNS_MODE：bind 与 mark

| 模式 | 实现 | 适用 |
|---|---|---|
| `bind` | `server=/域名/IP@接口`（dnsmasq 的 SO_BINDTODEVICE） | 纯 dnsmasq 环境 |
| `mark` | `server=/域名/IP` + nft 对发往该 DNS 的 53 端口流量跳转到对应策略 | OpenClash 接管 DNS、或解析器非 dnsmasq |

`mark` 模式只依据目标 IP，不依赖 dnsmasq 的接口绑定特性，在有代理接管的环境里更稳定。

### 与代理的 DNS 共存

dnsmasq 按**最长域名后缀**匹配、与书写顺序无关。代理装进来的通配转发（`server=/#/127.0.0.1#7874`）不会覆盖本工具的特定域名规则——列入 `DOMAIN_SPLIT` 的域名会绕过代理 DNS 直接获得真实地址并走对应线路。因此：希望走代理的域名不要加入 `DOMAIN_SPLIT`。

### 外部域名清单

`/etc/isp-split/domains/<策略>.txt`，每行一个域名，兼容 [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 `server=/域名/1.2.3.4` 格式（仅提取域名，DNS 使用本线路配置值）。

---

## 其他配置项

| 变量 | 默认 | 说明 |
|---|---|---|
| `ISP_MIRROR` | `https://ispip.clang.cn` | 数据源 |
| `ISP_CRON` | `17 4 * * *` | 每日更新时间（cron 表达式） |
| `DNSDIR` | `/etc/isp-split/dnsmasq.d` | 旧版片段目录（仅用于迁移/清理，新版本不再写入） |
| `DOMAIN_LIST_DIR` | `/etc/isp-split/domains` | 外部域名清单目录 |
| `DNS_MODE` | `bind` | 多线路 DNS 出线方式 |
| `COUNT_FALLBACK` | `1` | 统计未命中集合的兜底流量（`status` 显示"兜底"行） |

---

## 关于 status 的流量口径

`isp-split status` 中的「命中包 / 流量」统计的是**连接首包**：每个连接只有
首包进入 mwan3 规则链（后续包由 conntrack 恢复标记，被 `mark==0` 前置条件
挡住），因此这两列反映的是连接建立开销，**不是业务吞吐**。

判断实际带宽分布要看接口计数：

```sh
cat /sys/class/net/pppoe-wan*/statistics/rx_bytes
```

## 定时更新

```sh
17 4 * * * /usr/sbin/isp-split refresh
```

`refresh` = `fetch` + `apply`：只更新数据，不重写 mwan3 配置。需要改变规则映射时才使用 `wire` / `sync`。

前提：cron 服务已启用（`/etc/init.d/cron enable && /etc/init.d/cron start`）。
