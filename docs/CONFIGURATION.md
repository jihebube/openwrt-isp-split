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
| 1 | 数据来源（`/etc/isp-split/data/<名称>.txt`） | 运营商源名（经 `ISP_SOURCE_FILES` 映射到各源的远端文件名） |
| 2 | nftables 集合名 | `isp_` 前缀，任意 |
| 3 | mwan3 策略 | `wan_only` / `wanb_only` / `balanced`（由 `isp-split init` 创建并绑定成员） |
| 4 | 启用 | `1` / `0` |

要点：

- **顺序即优先级**。上游数据存在重叠（如电信与联通之间有数百处），靠前的运营商先占用网段，因此每个 IP 只归属一个集合
- 第三列是 mwan3 的策略名，也可以用自定义策略
- 被完全覆盖的集合（如本例中 unicom_cnc 被 chinatelecom 抢走大量网段后）条目数会显著减少，属正常现象

### 首次安装：`isp-split init` 绑定线路

mwan3 的 **policy** 只是成员列表，真正决定走哪条线的是 **member**（接口 + metric/weight）。首次安装时 mwan3 里通常没有 `wan_only` / `wanb_only`，或策略存在但成员为空；这种状态下 `wire` 生成 `option use_policy '...'` 后，mwan3 会静默丢掉整条规则。因此 0.3.0 起：

- `wire` / `plan` 在动任何配置之前预检 `ISP_TABLE` 中**已启用行**引用的每个策略，缺失或空成员直接报错退出，并提示运行 `isp-split init`；`init` 同样只处理启用行（disabled 行不生成规则，也不去动它的策略）
- `verify` 增加「策略存在且有成员」检查行；`uninstall` 按 `isp_split=1` 标记删除 init 生成的 policy/member

用法：

```sh
# 交互：列出 mwan3 接口 → network 接口 → pppoe/静态设备，逐个策略选择
isp-split init

# 脚本/无人值守：可重复的 --bind + --assume-yes（未绑定的策略按顺序自动分配）
isp-split init --bind wan_only=wan1 --bind wanb_only=wan2 --assume-yes
```

生成的段形如：

```sh
config policy 'wan_only'
	list use_member 'isp_split_wan_only_m1'
	option isp_split '1'

config member 'isp_split_wan_only_m1'
	option interface 'wan1'
	option metric '1'
	option weight '1'
	option isp_split '1'
```

约束与幂等：

- 同名**带 `isp_split=1` 标记**的策略/成员段只更新接口，不会重复追加
- 同名但**没有标记**的策略段一律报错、不做改动（保护用户自建配置）；需要接管时请先在 mwan3 中删除或改名
- 从 `ISP_TABLE` 移除的策略，其带标记段会在下次 `init` / `wire` 时作为孤儿清理；仍被 mwan3 规则或其它策略引用的段会保留并告警
- `init` 结束后自动跑一次 `plan` 摘要

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
| `ISP_MIRROR` | `https://ispip.clang.cn` | **仅单源兼容模式**（`ISP_SOURCES` 为空）使用的基址；文件名为 `<源名>.txt` |
| `ISP_CRON` | `17 4 * * *` | 每日更新时间（只能是 5 段 cron 时间字段） |
| `DNSDIR` | `/etc/isp-split/dnsmasq.d` | 旧版片段目录（仅用于迁移/清理，新版本不再写入） |
| `DOMAIN_LIST_DIR` | `/etc/isp-split/domains` | 外部域名清单目录 |
| `DNS_MODE` | `bind` | 多线路 DNS 出线方式 |
| `COUNT_FALLBACK` | `1` | 统计未命中集合的兜底流量（`status` 显示"兜底"行）；口径是 `ct state new`，即只计每条连接的首包 |
| `COUNT_FALLBACK_SKIP_DNS` | `1` | 兜底计数排除 DNS（udp/tcp 任一侧端口 53，查询与响应都不计）；`0` 保持不排除 DNS 的旧行为 |
| `ISP_SOURCES` | yfgao 主源 + clang 校验源 | 多数据源声明，见下节；留空则完全退回 0.1.x 的单源行为 |
| `ISP_SOURCE_FILES` | yfgao/clang 四类映射 | 每源文件名映射（不同源的同一运营商文件名不同） |
| `ISP_VERIFY_ENABLE` | `1`（0.2.1 起） | 是否启用校验源；配置里显式写 `0` 可关闭 |
| `ISP_DIFF_MAX_JACCARD_DROP` | `90` | 与校验源的 Jaccard 低于此值就拒绝本次更新 |
| `ISP_DIFF_MAX_DELTA_PCT` | `3` | 单个运营商地址数的日变化上限（%，仅校验源启用时生效） |
| `ISP_SOURCE_MAX_FAIL_DAYS` | `3` | 校验源连续失败多少天后升级为"拒绝更新" |

### 兜底计数为什么默认排除 DNS

`COUNT_FALLBACK_SKIP_DNS` 默认 `1`：兜底计数器只统计**会出公网**的
未命中流量，UDP/TCP 任一侧端口为 53 的 DNS 查询与响应都不计入。

理由：DNS 查询/响应本身不是业务流量——LAN 设备到网关（例如
`192.168.50.1:53`）的查询在本地就被应答，到运营商 DNS 的查询也只是
解析开销。它们占兜底包数的比例通常很高（实测可到 90% 量级），
计进去只会稀释"未命中运营商集合的真实业务流量"这个口径，让覆盖率
看起来比实际差。

判断只看 **UDP/TCP 的源端口或目的端口是否为 53**，不写死网关地址：

- 出向查询：`dport == 53`（sport 为客户端随机高位端口）→ 排除；
- 入向响应：`sport == 53`（dport 为客户端随机高位端口）→ 排除。

只排除 `dport 53` 会漏掉从 WAN 回来的响应包（`sport=53`、`dport=高位`），
这正是 BUG-21 第一版只修了一半的原因。现在一条 TCP/UDP 规则同时带
`th dport != 53 th sport != 53`，任一侧 53 都不计数；ICMP 等非 TCP/UDP
流量仍由另一条规则照常计数。

> 补充（BUG-21 收尾的实测结论）：在健康的 mwan3 里，DNS **响应**其实
> 根本走不到这条计数规则——`mwan3_prerouting`（priority `mangle+1`，即
> `-149`）在 conntrack 的 DNAT/un-SNAT（`-100`）之前，WAN 回来的响应包
> 有三道各自独立、任一命中就提前离开的门：
>
> 1. `ct mark & 0x3f00 != 0` → 直接 vmap 到策略链（首包出向时已打标）；
> 2. `mwan3_ifaces_in` 按 `iifname` 给 WAN 入向包打 `0x500/0x600`；
> 3. `mwan3_connected`（响应此刻的目的地址还是路由器自己的 WAN 地址，
>    属于 connected 网段）或 `fib daddr type local return`。
>
> 所以 `th sport != 53` 是**防御性**的：它保证即使 mwan3 规则被改坏、
> 或某条 WAN 没被 mwan3 纳管，响应也不会污染兜底计数；它不是生产上
> 那个"+8 包/次查询"的原因。定量核对方法见 `docs/DIAGNOSIS.md`。

需要兼容旧统计口径（不排除 DNS）时在 `/etc/isp-split.conf` 写：

```sh
COUNT_FALLBACK_SKIP_DNS="0"
```

改完执行 `isp-split apply` 重建计数规则。规则形状会从单条变成两条
（非 TCP/UDP 一条、TCP/UDP 且两侧都非 53 一条，共用一个命名计数器），
所以升级后第一次 `apply` 会看到规则被重建，计数从旧值继续累加。

### 兜底计数的单位是"连接"，不是"包"

两条规则都带 `ct state new`：

```nft
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new \
     meta l4proto != tcp meta l4proto != udp counter name "isp_fallback"
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new \
     meta l4proto { tcp, udp } th dport != 53 th sport != 53 counter name "isp_fallback"
```

原因：`meta mark & 0x3f00 == 0` 只说明"这个包进来时还没打标"，并不保证
这条连接最终会被打标。如果 mwan3 的 `default_rule_v4` 被 `enabled=0`
关闭（`status` 会提示这种情况），未命中集合的流就不会有 conntrack 标记，
同一连接的每个包都会重新经过 `mwan3_rules`，兜底计数从"按连接"退化
成"按包"——一条 5 个包的 ICMP 流会记 +5 而不是 +1。加上 `ct state new`
之后，无论后续是否打标，每条连接只计首包，`status` 里的数字才能直接
当"未命中集合的新连接数"读。

升级后第一次 `apply` 会重建这两条规则（旧形状没有 `ct state new`），
计数从旧值继续累加。

---

<!-- lc:begin -->
## 线路体检（LINE_CHECK_*）

0.3.0 新增 `isp-split linecheck`：对每条启用的 WAN 依次做

1. **本机口 IP 分类**：公网 / CGNAT（`100.64.0.0/10`）/ 私网；
2. **出口 IP**：`curl --interface <l3_device>` 请求 `LINE_CHECK_ECHO_URLS`；
   WAN IP 本身是公网、出口却是另一个公网 IP 时标“多层 NAT/代理”；
3. **同运营商目标四段延迟**：域名清单 → DNS 解析 → 用 `@isp_*` 集合校验归属
   → `curl --resolve` 钉住已验证 IP，5 次尝试；显示 DNS / TCP / TLS / 首字节，
   评分用 TCP 建连中位数；
4. **归属地**：只发送出口公网 IP，百度优先、ip-api 兜底，24h 缓存；
5. **双 STUN**：`socat ...,so-bindtodevice=<l3_device>`，同一本地端口打两个
   不同 IP 的服务器，判五态 NAT；
6. **评分**：公开规则表 + 硬上限 + 完整明细 + 一句话建议。

```sh
isp-split linecheck                 # 人类可读
isp-split linecheck --json          # 给 LuCI / 脚本
isp-split linecheck --wan wan2      # 只体检指定接口（也接受 pppoe-wan1/br-lan 等设备名）
isp-split linecheck --force         # 绕过 60s 结果缓存，强制重测
```

### 配置项

| 变量 | 默认 | 说明 |
|---|---|---|
| `LINE_CHECK_ENABLE` | `1` | 总开关；`0` 时命令直接拒绝执行，LuCI 显示已关闭 |
| `LINE_CHECK_GEO` | `1` | 归属地隐私开关；`1` 允许把每条 WAN 的**出口公网 IP**发给第三方，`0` 只关闭归属地查询（出口 IP 回显、STUN、延迟探测照常外发） |
| `LINE_CHECK_GEO_PROVIDER` | `auto` | `auto`（百度优先，失败转 ip-api）/ `baidu` / `ip-api` / `off` |
| `LINE_CHECK_GEO_TTL` | `86400` | 同一出口 IP 的归属地缓存秒数（最小 60） |
| `LINE_CHECK_MIN_INTERVAL` | `60` | 结果缓存与手动触发最小间隔（15-3600 秒）；`--force` 可绕过 |
| `LINE_CHECK_TIMEOUT` | `3` | 单次探测超时（1-10 秒），curl 与 socat 共用 |
| `LINE_CHECK_BUDGET` | `20` | 单条 WAN 的探测预算；超出后跳过剩余 STUN/归属地并在明细里标注 |
| `LINE_CHECK_TARGETS` | 电信/联通/移动/教育网各 2 个域名 | 格式 `<运营商源名>:<域名1>,<域名2>`；源名必须与 `ISP_TABLE` 第一列一致。线路运营商由 WAN IP / 出口 IP 匹配 `@isp_*` 得出；两者都不在集合里时直接走跨网基线，不猜运营商 |
| `LINE_CHECK_BASELINE` | `www.baidu.com,www.qq.com` | 同网目标全部失败时的跨网基线；只判连通性，延迟项最高 15 分 |
| `LINE_CHECK_STUN_SERVERS` | miwifi / douyu / freeswitch / cloudflare（bilibili 可选） | `<域名或 IP>:<端口>`；运行时按厂商优先解析，同一本地端口探测，失败自动换下一个；公网 STUN 可达性会波动。清单为空或全部非法时该 WAN 的 NAT 判 `unknown`，不影响其它项 |
| `LINE_CHECK_ECHO_URLS` | `api.ipify.org,ipv4.icanhazip.com` | 出口 IP 回显服务，按顺序尝试；只接受 `http(s)://` + 常规 URL 字符（不接受查询串、curl 选项或 shell 元字符） |
| `LINE_CHECK_UA` | 浏览器 UA | 部分运营商站点对默认 curl UA 返回 412/418，必须带浏览器 UA；`conf set/check` 限制 512 字符并拒绝 CR/LF |

### 隐私声明

开启 `LINE_CHECK_GEO=1` 后，体检会把**每条 WAN 的出口公网 IP**发送给第三方
（默认百度，失败时 `ip-api.com`）查询归属地。

- 只发送出口 IP，**不发送**内网地址、设备名、MAC、流量内容；
- `ip-api` 使用 **HTTP**，传输不加密；介意时把 `LINE_CHECK_GEO_PROVIDER` 固定为 `baidu`；
- `LINE_CHECK_GEO=0` 时不发起任何归属地请求，卡片显示“归属地：未查询（隐私开关关闭）”；
- 关闭后仍可用本地 `@isp_*` 集合判断运营商大类（电信/联通/移动/教育网），不需要外发。

### NAT 五态（不是 NAT1-4）

| 观测 | 判定 | 含义 |
|---|---|---|
| WAN IP ∈ `100.64.0.0/10`，或 STUN 映射是私网/CGNAT | **CGNAT / 多层 NAT** | 端口映射不可用 |
| 两个探测点映射一致，且公网 WAN IP/本地端口与映射完全一致 | **公网** | 无 NAT，可直接映射 |
| 两个探测点映射一致，但 IP 或端口经过转换 | **锥形 NAT（未细分）** | 端口映射可能可用 |
| 两个探测点映射不同 | **对称 / 多出口 NAT** | P2P、端口映射成功率低 |
| 两个探测点都超时/坏包 | **未知** | UDP 3478 可能被阻断；不判死 |

只在两个不同厂商的服务器结果一致时给 `high` 置信度；只有一个探测点成功给
`medium`。公网 STUN 基本不支持 `CHANGE-REQUEST`，因此**不做** Full Cone /
Restricted / Port-Restricted 细分。

### 评分与硬上限

| 维度 | 分值 | 规则 |
|---|---:|---|
| 出口类型 | 30 | 公网 30；锥形 20；对称 8；CGNAT 0；未知 10 |
| 延迟 | 30 | 同网 TCP 建连中位数：≤20ms 30；≤40 26；≤70 20；≤110 12；≤160 5；>160/超时 0 |
| 稳定性 | 25 | 抖动 ≤5/≤15/≤30ms → 15/10/5；丢包 0/≤20/≤50% → 10/6/2（可叠加，上限 25） |
| 可用性 | 15 | DNS+TCP+TLS 且 HTTP<500 → 15；4xx → 12；5xx/TLS 失败 → 8；TCP/DNS 失败 → 0 |

硬上限：WAN down → 0/D；CGNAT 或对称 NAT → 69/C；丢包 >20% → 69/C；
同网目标 >160ms 或全超时 → 69/C；只有跨网基线时延迟项最高 15。
档位：A ≥85，B 70-84，C 50-69，D <50。

### 缓存与并发

结果按“本次 WAN 集合”缓存到 `/etc/isp-split/state/linecheck/`：

| 文件 | 作用 |
|---|---|
| `meta` | `生成时间 间隔 geo socat WAN…`（epoch 秒，UTC，与本地时区无关） |
| `last.json` | 最后一次完整结果，**LuCI 只读这一个文件** |
| `wan-<接口>.json` / `.txt` | 单条 WAN 的机器/人类可读结果 |
| `errors.json` | 整体性错误（如没有启用的 WAN） |

`LINE_CHECK_MIN_INTERVAL` 秒内重复执行直接读缓存返回（`"cached":true`，`age`
为缓存年龄），不探测、不访问网络，耗时 <1s；`--force` 绕过。`--wan` 只体检并
缓存指定线路，之后的全量调用会重新体检其余线路。

缓存有效的充要条件是 `meta` + `last.json` + 每条被请求 WAN 的 json/txt 都在；
缺一个就按未命中处理并清理，不会出现“有目录但永远不命中”。探测过程写在
`state/linecheck.tmp.<pid>`，退出时由 trap 删除，下次启动还会扫掉 pid 已死的
残留（`linecheck.tmp.*` 不应长期存在）。

#### `--background`（LuCI 用）

```sh
isp-split linecheck --background           # 立刻返回，探测在后台跑
```

真实探测可能 20-60s，而 rpcd 的 exec 硬超时是 30s，所以页面**不能**同步调用
`linecheck --json`。`--background` 只做“要不要起、能不能起”，返回单行 JSON：

| 返回 | 含义 |
|---|---|
| `{"started":true,"pid":N}` | 已在后台开始 |
| `{"started":true,"finished":true}` | 1 秒内就跑完了（夹具/极快线路） |
| `{"started":false,"running":true,"pid":N,"elapsed":S}` | 已有一次在跑，本次不重复探测 |
| `{"started":false,"cached":true,"generated":N,"age":S}` | 缓存仍新鲜，没必要重测 |
| `{"started":false,"error":"…"}` | 起不来（见 `state/linecheck.log`） |

去重靠锁目录 `state/linecheck.lock`（`mkdir` 原子）；子进程用 `setsid` 脱离
rpcd 会话，探测结束后原子替换缓存目录。前台 `linecheck` 也会抢同一把锁：
已有体检在跑时，有新鲜缓存就返回缓存，否则输出 `"running":true` 并以退出码
4 结束（不给脚本返回半截数据）。

### socat 缺失

`socat` 是 `isp-split` 的包依赖（`DEPENDS+=+socat`）。若固件被裁剪或手动删除：
体检仍可完成公网/CGNAT/私网、出口 IP、延迟、归属地与评分，NAT 项显示
“未知（socat 未安装）”，并在建议里提示安装（`opkg install socat` / `apk add socat`）。

---

<!-- lc:end -->

## 多数据源（v0.2.1 默认双源）

0.2.1 默认启用 **主源 + 校验源**（FIX12 方案 c）：
`gaoyifan/china-operator-ip` 出数据，`ispip.clang.cn` 只跑日 diff。
默认模板长这样：

```sh
ISP_SOURCES="
yfgao:primary:https://china-operator-ip.yfgao.com
clang:verify:https://ispip.clang.cn
"
ISP_SOURCE_FILES="
yfgao:chinatelecom=chinanet,unicom_cnc=unicom,cmcc=cmcc,cernet=cernet
clang:chinatelecom=chinatelecom,unicom_cnc=unicom_cnc,cmcc=cmcc,cernet=cernet
"
ISP_VERIFY_ENABLE=1
```

### 升级兼容：已有配置不会被覆盖

`/etc/isp-split.conf` 是 conffile，opkg/apk 升级会保留用户已有内容。
因此：

- 已有部署如果已经显式声明了 `ISP_SOURCES`（例如 `clang:primary` +
  `yfgao:verify` + `ISP_VERIFY_ENABLE=0`），升级后**完全按原声明执行**，
  不会被悄悄切换主源或打开校验；
- 想采用 0.2.1 默认双源，手动改这三项即可（或对照新模板合并）；
- 只有**新安装**会拿到上面的默认模板；
- 脚本里的 `ISP_VERIFY_ENABLE` 默认值改为 `1`，但配置里显式写 `0` 时仍然以用户值为准。

### ISP_SOURCES：源声明

格式：每行一条 `<名字>:<角色>:<镜像基址>`。

| 角色 | 含义 | 是否参与合成 |
|---|---|---|
| `primary` | 出数据的主源，**必须且只能有一个** | 是 |
| `verify` | 只用来跑日 diff 的校验源 | 否 |
| `audit` | 低频审计源（同样只跑 diff） | 否 |

- 基址必须是 `https://host[:port][/path]`，不能带查询串；确需明文 HTTP 时
  显式设 `ISP_SPLIT_ALLOW_HTTP=1`（不建议）。
- **留空 `ISP_SOURCES` = 单源兼容模式**：仍按 `ISP_MIRROR/<源名>.txt` 拉取，
  行为与 0.1.x 完全一致，老配置升级不需要改任何东西。

### ISP_SOURCE_FILES：文件名映射

不同源对同一个运营商的叫法不一样：clang 上叫 `chinatelecom.txt`，
yfgao 上叫 `chinanet.txt`。这里**以显式声明为准**：

```
<源名>:<ISP_TABLE 里的源名>=<该源上的文件名>,<源名2>...
```

- 值写不带 `.txt` 的名字（`chinatelecom=chinanet`）；写全名（`foo.dat`）时原样使用。
- **某源只要声明了任意一条映射，映射里没列出的运营商默认不下载、不参与 diff**。
  若该运营商在 `ISP_TABLE` 里已启用，主源会按历史命名 `<源名>.txt` 再试一次
  （仅为兼容 0.2.0 老配置），文件不存在时 `fetch` 会明确报错而不是静默少一个集合。
- 完全没声明映射的老配置（`ISP_SOURCES` 为空、`ISP_SOURCE_FILES` 为空）才走
  `<源名>.txt` 兼容路径。
- **校验源/审计源**只认上面的映射；没列出的运营商不会去下载，也不会参与 diff。
- 默认主源 yfgao 只有 `chinanet/unicom/cmcc/cernet` 四类，没有
  `chinabtn/gwbn/othernet/hk/mo/tw`；`ISP_TABLE` 里后六类默认保持关闭。
  要启用它们，需要换成提供这些文件的源，或自行补映射。

### 降级与冻结策略

| 情形 | 行为 | 退出码 | 数据 |
|---|---|---|---|
| 主源正常、校验源正常、Jaccard ≥ 阈值 | 正常更新，Jaccard/时间写入 `state/` | 0 | 更新 |
| 主源正常、校验源**失败 1-2 天** | **降级**：继续用主源更新；`status`/日志标「降级 n/3 天」 | 0 | 更新 |
| 校验源**连续失败 ≥ `ISP_SOURCE_MAX_FAIL_DAYS`（默认 3）** | 升级为拒绝更新：不允许长期无校验运行 | **3** | 保留旧数据 |
| 校验源下载成功但**没有可比对的运营商** | 拒绝更新（映射错误/源改版），提示检查 `ISP_SOURCE_FILES` | **3** | 保留旧数据 |
| 分歧 Jaccard < 90% | 拒绝更新 + `quarantine/<日期>/` 留档差异段 | **3** | 保留旧数据 |
| 单运营商日变化 > 3%（仅校验启用时） | 拒绝更新 | **3** | 保留旧数据 |
| **主源**下载失败 | **立即冻结**（不自动换源，换源=换口径） | 1 | 保留旧数据 |
| 两源都失败 | 冻结；`status` 显示数据 N 天未更新 | 1 | 保留旧数据 |

放行：确认数据无误后用 `ISP_SPLIT_FORCE_FETCH=1 isp-split fetch`（同时放行 Jaccard、
日变化、无可比对项与连续失败几道闸门）。

### 阈值参数

| 参数 | 默认 | 正常范围 | 拒绝阈值 | 说明 |
|---|---|---|---|---|
| `ISP_DIFF_MAX_JACCARD_DROP` | 90 | 95.7%–96.9% | < 90% | 两源每运营商 Jaccard |
| `ISP_DIFF_MAX_DELTA_PCT` | 3 | < 1% | > 3%（告警） | 主源单运营商地址数日变化 |
| `ISP_SOURCE_MAX_FAIL_DAYS` | 3 | — | ≥ 3 天 | 校验源连续失败升级为拒绝 |

阈值不是拍脑袋：93%/90% 是在实测正常值 95.7–96.9 与口径切错时 64.6–87.9 之间取的中间带。

### 目录与状态

| 路径 | 内容 |
|---|---|
| `$BASE/raw/<源名>/` | 每个源最近一次成功拉取的原始文件（diff 的比较基准） |
| `$BASE/state/sources.tsv` | 每源 `名字 角色 最后成功 连续失败 Jaccard 备注` |
| `$BASE/state/last-diff` | 最近一次 diff 的最小 Jaccard 与时间 |
| `$BASE/quarantine/<YYYYMMDD>/` | 被拒绝那次的差异段：`<源>.<运营商>.only-primary.txt` / `.only-verify.txt` / `summary.tsv` |

`sources.tsv` 会做**残留清理**：`fetch` / `status` / `health` 入口只保留当前
`ISP_SOURCES` 声明过的源（`ISP_SOURCES` 为空时只保留兼容模式的 `ispip`）。
单源时代留下的旧行（如 `ispip`）不会继续出现在 `status` 里；清理是幂等的，
没有残留时不会重写文件。

### 相关命令

```sh
isp-split diff          # 用存档重算主源 vs 校验源的分歧（不联网；超阈值返回 3）
isp-split diff --no-save  # 同上，但不写 quarantine
isp-split health        # 源健康度 + 双线状态（--json 给 LuCI 用）
isp-split status        # 集合统计 + 数据源健康度区块
```

LuCI 配置页的「数据源」区块只读展示每源角色/状态/最近 Jaccard，不开放编辑：
数据源地址是 root 路径的下载入口，避免把非法 URL 写进配置。修改请直接编辑
`ISP_SOURCES` / `ISP_SOURCE_FILES`。

### 许可红线（重要）

| 源 | 许可 | 能否随固件/ipk 分发 |
|---|---|---|
| `gaoyifan/china-operator-ip` | **MIT** | ✅ 可随固件/ipk 分发（本仓库默认主源） |
| `ispip.clang.cn` | **无许可证**，仅免责声明 | ❌ 只做运行时下载，仓库与包内**不含**任何 clang 数据 |

仓库和安装包只带**空的示例配置与文件映射**，所有运营商数据都是设备自己运行时下载的。
不要把自己抓下来的 `$BASE/data/*.txt` 打包分发——那属于源站数据的再分发。

### Jaccard 是什么、为什么用 90%

Jaccard = 两个集合交集地址数 / 并集地址数。实测（见 FIX12 设计文档）：

| 对比 | Jaccard |
|---|---|
| clang 默认变体 vs yfgao（同属主流口径） | 95.7%–96.9% |
| clang 默认 vs clang `_apnic` 变体（口径不同） | 64.6%–87.9% |

所以 90% 落在"正常波动"和"口径切错"之间：低于它就说明某一方的归属规则变了，
这时候**保留旧数据**比"生成一份可能错的集合"安全（分流错了会把几十 M 地址导到错误的线）。

### 下载与熔断（v0.1.5 安全加固）

`fetch` 对源数据有三道闸门，都是为了防"数据被污染 → 流量被导到错误出口"：

| 闸门 | 默认 | 说明 |
|---|---|---|
| 协议 | 只接受 `https://` | 明文 HTTP 会被中间人改写；确实需要时设环境变量 `ISP_SPLIT_ALLOW_HTTP=1` |
| 单文件体积 | 4 MiB | 正常数据 < 300 KB；可用 `ISP_SPLIT_MAX_RAW_BYTES` 调整 |
| 总量/增幅 | 25% IPv4 / 2 倍 | 单集合 50% 只是第一道；另外要求所有集合合计不超过 25%，且与上一份数据相比不翻倍 |

命中熔断时 `fetch` 会拒绝本次更新并保留现有数据，**不会**动线上集合。确认源站确实大改版（例如新增运营商）后可显式放行：

```sh
ISP_SPLIT_FORCE_FETCH=1 isp-split fetch
```

`$BASE/data/.sets` 记录上一次启用的运营商列表；表结构变化（启用/停用某个运营商）会跳过"增幅"比较，只保留绝对上限。

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
