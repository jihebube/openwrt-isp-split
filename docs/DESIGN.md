# 设计与原理

## 设计目标

- 在不修改 mwan3 核心逻辑的前提下，为 mwan3-nft 提供「按目标运营商选线」能力
- 数据维护、规则接入、更新全部自动化，且更新过程不影响已建立连接
- 任何操作可预演、可回滚；卸载会还原 mwan3/dnsmasq 改动（配置与数据文件默认保留）

非目标：不做代理、不做应用层（DPI）识别、不处理 IPv6（见 README 路线图）。

## 数据管线

```
yfgao/china-operator-ip（主源）
   |  ISP_SOURCE_FILES 映射成 <运营商>.raw
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

### 多源融合（0.2.1 默认双源）

```
ISP_SOURCES（源声明）            每源独立下载到 raw/<源名>/
  yfgao:primary   ──►  三道单源闸门（体积 / 行数 / badcidr）
  clang:verify    ──►  同上（默认 ISP_VERIFY_ENABLE=1）
        │
        ├─ 主源按 ISP_SOURCE_FILES 映射成 <运营商>.raw  ──►  build.sh（不变）
        │
        └─ 主源 vs 校验源：cidr2range + sort + 扫描线（ispdiff.awk）
              ├─ Jaccard ≥ 90% ──► 正常更新
              ├─ Jaccard < 90% ──► 拒绝更新 + quarantine/<日期>/ 差异段
              └─ 校验源失败 1-2 天降级；连续 ≥3 天拒绝更新
```

#### 融合策略：为什么是"主源 + 校验源"（方案 c），不是投票制

| | 方案 a：优先级差集 | 方案 b：投票制 | **方案 c：主源 + 校验源（采用）** |
|---|---|---|---|
| 做法 | 多源按优先级逐级 exclude | ≥2 源同归属才入集合 | 主源出数据；校验源只跑 diff |
| 能否发现单源口径漂移 | ❌ 静默采用第一个源 | ⚠️ 能发现分歧，但判不出谁对 | ✅ 阈值 + 人工看 diff，默认不更新 |
| 每日耗时 | 最低 | 高（2-3 源全量 + 投票） | 中（2 源约 175 KB + 扫描线） |
| 失败行为 | 静默换口径 | 大量进 quarantine / 集合缩水 | **保留旧数据**（fail-safe） |

关键实测（FIX12 §2.3，CIDR→整数区间精确求交，非抽样）：

| 对比 | 每运营商 Jaccard |
|---|---|
| clang 默认 vs yfgao（不同发布者、不同方法学） | 95.7%–96.9% |
| clang 默认 vs clang `_apnic`（同一发布者、不同方法学） | 64.6%–87.9% |

**同一发布者两个变体的分歧，大于两个不同发布者的分歧。** 这说明决定归属质量的是
**方法学**，不是源的数量。投票制（方案 b）的统计学前提是"多源独立、误差随机"，
而这里的误差是**系统性口径偏移**（例如移动整体高估到 59M）：投票会把票投给同一个
系统性错误，还让结果不可解释。

方案 c 的盲区是"两源同时错"（diff 一致 → 通过），只能靠第三方审计源（chnroutes2
月度体检）或商业库兜底。但它的失败行为可预测：**保留旧数据永远比生成一份可能错的
集合安全**——把 40M 地址导到错误的线的代价，远大于"今天没更新"。

默认主源选 yfgao 还有两个非技术原因：MIT 许可可随固件分发；clang 无许可证，只能
由设备运行时下载，因此只适合做校验源。详见 [CONFIGURATION.md](CONFIGURATION.md)
的「多数据源」一节。

0.2.0 只建骨架（主源仍是 clang，校验默认关闭）；0.2.1 把默认模板切成 yfgao 主源 +
clang 校验 + `ISP_VERIFY_ENABLE=1`。用户已有配置里显式声明的 `ISP_SOURCES` 不被覆盖，
所以老用户升级 0.2.0/0.1.x 时行为不变。

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

## 观测面：线路体检（0.3.0）

分流解决“包走哪条线”，线路体检回答“这条线本身怎么样”。它是**只读观测面**：
不写 mwan3 配置、不改 nft 规则、不装常驻进程；每次体检结束后除缓存和日志外
不留下任何状态。

### 探测路径：为什么必须绑设备

路由器自己发起的探测同样经过 `inet mwan3 mwan3_output`，目标 IP 若落在
`@isp_tel/@isp_uni` 等集合里，mwan3 会按策略打标，把探针带到另一条线：

- 只绑源 IP（如 `netcat -s`）不够：`ip route get ... from <src> mark 0x500`
  仍会选择策略表里的另一条设备；
- `curl --interface <l3_device>` 与 `socat ...,so-bindtodevice=<l3_device>`
  通过 `SO_BINDTODEVICE` 把 `oif` 带进路由查找，设备绑定优先于 mark。

因此：

| 探测 | 绑定方式 |
|---|---|
| 出口 IP | `curl --interface <l3_device>` |
| 四段延迟 | `curl --interface <l3_device> --resolve <域名>:443:<已校验 IP>` |
| UDP STUN | `socat -T <n> - UDP4:<ip>:<port>,bind=:<同一本地端口>,so-bindtodevice=<l3_device>` |
| DNS | 系统 resolver；不承诺按线解析，解析后用 `@isp_*` 校验归属 |

`l3_device` 取 `ifstatus <接口> | jsonfilter -e '@.l3_device'`，PPPoE 下是
`pppoe-wan1` 而不是底层 VLAN；这与 `dns` 子命令的 `policy_device()` 同源。

### 目标从哪来：域名清单 + 集合校验

不从 `@isp_*` 的上万条 CIDR 里随机抽 IP：命中 443 的概率低、行为像端口扫描，
也无法保证是“该运营商的真实业务节点”。正确做法是：

1. `LINE_CHECK_TARGETS` 维护每家 2 个域名；
2. 运行时用系统 DNS 解析；
3. 对每个 IPv4 执行 `nft get element inet mwan3 <set> "{ IP }"`，命中才认为
   是“同运营商目标”；
4. `curl --resolve` 把连接钉到这个 IP，避免二次解析换节点；
5. 全部失败才用 `LINE_CHECK_BASELINE` 做跨网连通性基线，并标记
   `mode=baseline`、延迟项上限 15 分。

HTTP 用 `GET + Range: bytes=0-0` 和浏览器 UA：实测 `www.chinatelecom.com.cn`
对默认 curl UA 返回 412，换浏览器 UA 后 200；HEAD 在多个站点被 403/520。

### NAT：五态，不做 NAT1-4

RFC 3489 的完整分类需要 `CHANGE-REQUEST` / `OTHER-ADDRESS` 和至少 3 个
探测点；公网 STUN 服务器基本不配合（实测 bilibili 只回原地址，其余超时）。
所以 0.3.0 只承诺行为描述：

```
公网（可直接映射） / 锥形 NAT（未细分） / 对称或多出口 NAT / CGNAT（含多层 NAT） / 未知
```

判定逻辑（同一本地端口、两个不同 IP 的 Binding Response）：

| 观测 | 判定 |
|---|---|
| WAN IP ∈ `100.64.0.0/10` | CGNAT（优先于 STUN） |
| 任一映射是私网/CGNAT | 多层 NAT → CGNAT 档 |
| 两个映射 `IP:port` 完全相同且 WAN 公网、端口未转换 | 公网 |
| 两个映射完全相同（有转换） | 锥形 |
| 两个映射不同 | 对称/多出口 |
| 都超时或坏包 | 未知 |

解析器校验 magic cookie、transaction id、消息类型和属性边界；32/84 字节
响应与坏包 fixture 由 `tools/linecheck-fixtures.sh` 生成并进入 selftest。
UDP 3478 被阻断时只把 NAT 标“未知”，不影响延迟/归属地/评分其他项。

### 评分是可解释的，不是黑盒

总分 100 = 出口类型 30 + 延迟 30 + 稳定性 25 + 可用性 15。每条得分都带
`reason`，并列出硬上限（CGNAT/对称/丢包>20%/同网>160ms → 69 分上限）。
阈值是工程初值，只用于**同一路由器多条线横向比较**，不跨地区比较；后续可用
真实线路校准。JSON 里保留 `breakdown`、`caps` 和原始样本，LuCI 不允许只显示
一个总分。

### 隐私边界

归属地是唯一的第三方请求：只发送每条 WAN 的**出口公网 IP**，不发内网地址、
设备名、MAC 或流量内容。默认百度（HTTPS）优先、ip-api（HTTP）兜底，按
“IP + provider”缓存 24h。`LINE_CHECK_GEO=0` 时不发任何请求；关闭后仍可用
本地集合判断运营商大类。UI 与文档都显式写出“ip-api 使用 HTTP 不加密”。

### 缓存与预算

- 结果按 WAN 集合缓存到 `state/linecheck/`，`LINE_CHECK_MIN_INTERVAL` 内
  重复调用直接返回（`cached=true`、`age`），`--force` 绕过；
- 单条 WAN 有 `LINE_CHECK_BUDGET` 预算，超时后跳过剩余 STUN/归属地并标注，
  避免 rpcd/LuCI 超时；
- 目标失败早停（连续两次失败换下一个），正常路径通常 3-10 秒。

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
| 运营商网段分流 | 内置 | ✅ 默认 4 类主流运营商（可扩到 10 类），每日自动更新 | **已追平** |
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

- 默认主源：[gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)（MIT），
  按 BGP Route Views / AS_PATH 做 per-prefix 归属，每日更新
- 默认校验源：[ispip.clang.cn](https://ispip.clang.cn)（无许可证，仅运行时下载），
  默认变体基于 IPNetDB 等多源 BGP/WHOIS 整理，每日更新；只跑 diff，不参与合成
- 两源正常分歧 95.7%–96.9%，属于不同方法学的正常差异；低于 90% 视为口径漂移，
  拒绝更新并保留旧数据
- 个别骨干节点或代播段可能归类偏差，可通过 `DOMAIN_SPLIT` 做域名级覆盖，或向数据源反馈
