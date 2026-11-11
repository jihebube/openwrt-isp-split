# FEATURES-PROPOSAL — isp-split 功能扩展与优化提案

- 基线：`main @ 3acf1a1`（v0.4.1 已发布）
- 性质：**只分析，不改代码**；本文不包含任何实现改动，`tools/selftest.sh` 也未动
- 证据口径：
  - **【代码】**＝读本仓库源码/文档得出的结论，附函数或行号
  - **【本地复现】**＝在本机离线环境复现（临时 `ISP_SPLIT_BASE`，不碰生产/VM/GitHub）
  - **【文档】**＝仓库内或上游文档的明确写法
  - **【推断】**＝未在本机验证、需要真机确认的行为
- 离线基线：`sh tools/selftest.sh` → **356 通过 / 5 失败 / 10 跳过（73s，x86_64）**；5 项失败与 fix39 文档记录的“非 root 环境项”一致（第 7 节 conf-dir + 20.3d/e/f/g）

---

## 0. 一句话结论

**IP 分流主干已经成熟，继续加“分流算法”的边际收益很低；下一步最值钱的是把分流决策变得可查、可钉、可验证：先做“域名/端口钉线、explain 归因、真实吞吐”三个 P0，同时修掉 doctor C1 的每日 stale 误报和数据源健康度的三处口径错误。**

三个 P0：

| # | 提案 | 为什么是现在 |
|---|---|---|
| P0-1 | 域名/端口钉线 `pin` | 真实用户已经在手改 mwan3 钉 B 站 PCDN；`plan` 只检测 nftset 不启用，README 却已写“域名钉线已追平” |
| P0-2 | 单目标分流归因 `explain` | 现在只能看集合总命中，回答不了“这个域名/这条连接为什么走这条线” |
| P0-3 | 真实吞吐 `traffic` | `status` 的流量是建连首包口径，offload 下必然偏小；用户问“真实速率”时只能自己 `cat /sys/class/net` |

> P0 严格限定 3 个。B 清单里的最高优先级标为 **P1**，不占用 P0 名额；其中 B1（doctor C1 每日 stale 误报）建议作为 0.4.2 补丁先修，和功能发布解耦。

### 0.1 十个思考方向的落点

| 方向 | 本文落点 |
|---|---|
| 1. 域名级钉线 | **A1**（`pin`，含端口；与 DNS 分线的边界见 A1.5） |
| 2. 分流效果可视化 | **A3**（真实吞吐）+ **A2**（单目标归因；`flows` TopN 为 P2 扩展） |
| 3. 线路质量趋势 | **A4**（手动体检历史 + 会话时长，不做自动重拨） |
| 4. export 深化 | **A7**（smartdns / AdGuard / mihomo / sing-box 域名清单 + manifest） |
| 5. fake-ip 兜底 | **A5**（兼容矩阵 + 检测泛化 + `compat` 报告） |
| 6. IPv6 | **A8**（先披露，暂不破冰；完整 v6 为 P3） |
| 7. 移动线/CGNAT | **A4.3**（期望管理 + `linecheck` 的 v6 地址信息） |
| 8. 数据源韧性 | **A6**（新鲜度、失败天数、拒绝后的复查、`fetch --check/--offline`） |
| 9. LuCI 侧 | **A9**（跨提案的统一落点：不加新菜单、不扩 ACL） |
| 10. 顺手就能加 | **B**（逐命令毛刺 + 判据共享 + 性能） |

### 0.2 硬约束核对（逐条）

| 红线 | 本文的处理 |
|---|---|
| 不装任何定时/自动任务 | A1 的静态解析只在 `pin apply`/`wire` 时做；A4 历史只在用户手动体检时追加；A5/A8 只读；A6 的 `fetch --check/--offline` 都是手动命令。**没有新增 cron，也没有改现有 cron 的触发频率** |
| 不引入新依赖 | A1 的 dnsmasq nftset 是**可选能力**（有则用，无则静态兜底）；A2/A3/A4 只用 nft/awk/curl/ifstatus/sysfs；A7 只写文件；不引入 jq/python/ucode/新包 |
| 零新外部服务调用 | A1 的域名解析走用户已配置的 DNS（与现有 `dnstest`/`linecheck` 同一边界）；A2 加 `--no-resolve`；A3/A4/A7/A8 全本地；A5 只读本地配置；A6 只复用现有数据源 |
| 不让 doctor 再出新误报 | 不新增第 7 项检查；A2/A3/A4/A7 对 doctor 零影响；A1 只修 C1 的 `domain_split_configured` 配置判据（不加检查，否则 pin-only 配置会漏报）；A5 只加 C2 facts/advice、不改 verdict；A6/A8 放在 `health`/`status`，**不进 doctor** |
| 不做自动重拨 | A4 只做“可观测”，明确不写重拨钩子；重拨仍是用户手动决定 |
| 不做 DPI / 每域名字节统计 | 见 §0.3“明确不提案” |

### 0.3 明确不提案（避免“为了做而做”）

| 想法 | 结论 | 理由 |
|---|---|---|
| PPPoE 定时自动重拨 | **不做** | 用户已否决两次；A4 只把“会话时长 + 质量趋势”摆出来，让用户自己决定 |
| 每域名/每集合的字节级流量统计 | **不做** | nft set 元素级计数器要为 1.3 万条元素建计数对象，内存/刷新成本高；conntrack acct + 反查域名又受 offload 和隐私约束。A3 用接口计数、A2 用单目标归因，已经能回答 90% 的问题 |
| 自动切换数据源 | **不做** | 换源＝换口径；现有“主源失败冻结、校验源连续失败拒绝更新”是正确设计，A6 只补可观测性和手动恢复入口 |
| DPI 应用识别 | **不做** | 既有 `DPI-ANALYSIS.md` 已论证架构性不可行；A1 的域名/端口钉线是更精准的替代 |
| IPv6 全量分流 | **暂不做**（P3） | 数据源虽有 v6，但现有 awk 管线是 32 位区间运算；v6 需要 128 位十六进制运算、独立表/规则/测试，属于 L 级改动。A8 先做披露 |
| 自动改道 + 自动 flush conntrack | **不做** | 断流代价必须显式 opt-in；本项目没有常驻进程 |

---

## A. 功能提案

### A.0 提案总表

| # | 提案 | 解决谁的问题（真实场景） | CLI 形态 | LuCI 形态 | 成本 | 主要风险 | 优先级 |
|---|---|---|---|---|---|---|---|
| A1 | 域名/端口钉线 `pin` | 双宽带用户把 B 站 PCDN（`mcdn:8082`/`edge:4483`）钉到电信；现在只能手改 mwan3，`wire` 一跑就被重写 | `pin list/check/add/del`，`wire`/`dns` 消费配置 | 配置页新增“钉线”区块，保存前预检 | M（静态/端口 MVP）/ L（nftset 动态 + CRUD） | 规则顺序、mwan3 15 字符名、dnsmasq nftset 能力、静态 IP 漂移、与 fake-ip 冲突 | **P0** |
| A2 | 单目标归因 `explain` | 用户问“这个域名为什么走联通/为什么没命中”，现在只能看集合总数或跑开发机上的 `verify-domains.sh` | `explain <domain 或 ip> [--json] [--via <policy>] [--no-resolve]`；P2 加 `flows --top` | 状态页搜索框 + 结果卡 | S（explain）/ M（flows） | 只读；域名解析会出网（可关）；`nft get element` 对 interval 集合的行为需真机复核 | **P0**（flows P2） |
| A3 | 真实吞吐 `traffic` | 用户问“这条线现在跑多少”，`status` 只有首包计数；offload 下数字偏小；现在提示硬编码 `pppoe-wan*` | `traffic [--json] [--watch]`；`status --traffic` | 状态页每条线加速率/总量，标注接口计数口径 | S/M | 接口计数包含该线全部流量（不只分流命中）；设备名映射 | **P0** |
| A4 | 体检历史/趋势 + CGNAT 预期 | 联通 PPPoE 约 10 天劣化，重拨恢复；现在 `last.json` 每次覆盖，看不到曲线；移动 CGNAT 用户不知道“端口映射不可用”是正常的 | `linecheck --history [--json] [--wan]` | 体检页 sparkline + 会话时长；概览显示最近评分 | M | 手动体检才写历史（不是定时）；历史含出口 IP（沿用现有 state ACL） | P1 |
| A5 | fake-ip 兼容报告 + 检测泛化 | 恩山 fake-ip 用户：IP 分流确实失效，但“直连域名/域名分流”仍可能工作；现在只认 OpenClash，且 README 写成“全都不生效” | `compat [--json]`；`doctor` C2 facts 增补 | 状态页横幅 + 向导第 0 步 | S/M | 检测误报（配置文件 grep）；必须按产品给不同建议 | P1 |
| A6 | 数据源新鲜度与韧性 | 主源冻结/校验源拒绝更新时，用户只看到“数据更新时间”很旧，不知道为什么；`fail_days` 实际是“失败次数”；拒绝后 `diff` 复查不到被拒数据 | `health --json` 增字段；`fetch --check` / `fetch --offline`；`diff --from` | 状态页“数据已 N 天未更新”徽标 | M | state 格式兼容；`fetch --check` 会耗流量；不自动换源 | P1 |
| A7 | export 深化 | SmartDNS / AdGuard Home / mihomo 域名 rule-provider 用户要手抄 `DOMAIN_SPLIT`；现在 `export` 只有 IP CIDR | `export domains <fmt> <dir>`；`export manifest`；`export fakeip-filter` | 配置页“导出”按钮（可选） | M | 各产品语法版本差异；只写用户指定目录 | P2 |
| A8 | IPv6：先披露，暂不破冰 | 用户以为“装了分流就全管”，实际 v6 默认路由绕过 v4 集合；双栈 CGNAT 用户又需要 v6 做公网入口 | `health --json` 增 `ipv6`；`status` 提示；`linecheck` 增 v6 地址 | 状态页一行“IPv6 未分流”说明 | S（披露）/ L（完整 v6） | 完整 v6 的 128 位运算、表/规则/测试；**不加 doctor 第 7 项** | P2（完整 v6 P3） |

> 表里“成本”S≈0.5–1 天、M≈2–4 天、L≈1 周以上（含 selftest/文档）；是相对量级，不是承诺工期。

---

### A1. 域名/端口钉线 `pin`（P0，M/L）

#### A1.1 解决什么问题

真实场景（用户已手工做过）：

- B 站 PCDN 走 `mcdn.bilivideo.cn:8082` 与 `edge*.bilivideo.com:4483`，IP 归属在移动段，但实测电信 12–22 MB/s、联通 0.04–1 MB/s。按运营商集合分流会把它送到联通，必须**按域名+端口钉到电信**。
- 现在只能手改 `/etc/config/mwan3` 加一条规则；下一次 `isp-split wire` 会按 `isp_split=1` 标记重写规则块，手改规则要么被覆盖，要么留在锚点之后永远不命中。
- `DOMAIN_SPLIT` 只改变**DNS 查询从哪条线出去**，让 CDN 返回本运营商节点；它不能覆盖“这个域名解析出来的 IP 在另一个运营商集合里”的情况，也不能表达“只对 8082 端口钉线”。
- `plan` 已经检测 dnsmasq nftset 能力，但明确写“本版本只检测，不启用钉线”（`files/usr/sbin/isp-split` 第 3574 行）；而 README 的对比表把“域名 / 设备钉线”写成 ✅，DESIGN.md 更直接写“域名钉线 ✅ 已追平”。这是一个**能力与文档口径的真空**。

#### A1.2 方案概要

**配置格式**（沿用现有“冒号分隔、空白分隔多行”的风格）：

```sh
# <域名|any>:<端口|any>:<策略>
# any 表示不限制；一行一个组合，避免端口列表的解析歧义
DOMAIN_PIN="
mcdn.bilivideo.cn:8082:wan_only
mcdn.bilivideo.cn:4483:wan_only
bilivideo.com:any:wan_only
"
```

不建议用 `*` 作通配（入口 `_table_no_glob` 会拒绝 `*`，这是有意的防 glob 注入设计）；用 `any` 这个保留字。

**CLI**：

```sh
isp-split pin list                     # 读配置，列出 domain/port/policy/解析状态
isp-split pin check [--json]          # 只读预检：解析 A 记录、查集合归属、查冲突、查 nftset 能力
isp-split pin add <domain|any> <port|any> <policy>
isp-split pin del <domain|any> <port|any> <policy>
```

`pin add/del` 只改 `DOMAIN_PIN`（复用 `_conf_write` 的双向校验），**不自动 wire/apply**；保存后提示下一步：

```sh
isp-split pin check && isp-split wire && isp-split dns
```

**数据面（两条路径，按能力自动选）**：

| 路径 | 前置条件 | 做法 | 优点/缺点 |
|---|---|---|---|
| **动态：dnsmasq nftset** | `dnsmasq --version` 的 Compile time options 含 `nftset`（`plan` 已有检测） | 在 dnsmasq 片段写 `nftset=/mcdn.bilivideo.cn/4#inet#mwan3#pin_wan_only`；集合 `pin_wan_only` 由 mwan3 ipset 段创建；规则按 `ipset + dest_port` 匹配 | 域名换 IP 自动跟进；依赖 dnsmasq-full，且 fake-ip 下会把假 IP 写进集合（必须禁用） |
| **静态：解析快照** | 没有 nftset，或用户显式选择 | `pin check/apply` 时用 `nslookup`（可指定该线 DNS）解析 A 记录，写 `pin-<policy>.txt` 作为 mwan3 `loadfile`；规则同上 | 无新依赖；CDN 换 IP 后会漂移，需要用户再跑一次 `pin apply`；不挂定时任务 |

**端口-only 模式**：`domain=any` 时只按 `dest_port` 建规则，不解析域名；这正好覆盖“B 站 PCDN 端口钉线”的最短路径，也是 MVP 的第一阶段。

**规则接线**：

- 集合名/规则名必须 ≤15 字符（mwan3 限制）。`pin_wan_only` = 12 字符可用；自定义长策略名用 `pin_<slug>` 的 slug 截断/哈希，并在 `pin check` 里显示映射。
- pin 规则写进现有 `WORK/rules.txt` 块，**排在运营商规则之前**；`rules-splice.awk` 仍按 `option isp_split '1'` 整块替换，因此 idempotent，不会留下手改残片。
- 集合用 `config ipset 'ipset_pin_wan_only'`，`family=ipv4`、`counters=1`、`isp_split=1`；动态路径的 `loadfile` 指向空的 `pin-<policy>.txt`（或省略，需按 mwan3 版本验证），静态路径指向解析快照。
- 端口规则每个 `(domain,port,policy)` 一条，避免依赖 mwan3 对多端口 list 的渲染顺序；规则名 `pin<序号>_<slug>` 保证唯一且 ≤15。

**LuCI**：配置页新增“钉线”区块（表格：域名 / 端口 / 策略 / 删除），保存前跑 `pin check --json`：

- 显示每个域名解析到的 IP、命中哪个集合、是否与 ISP 规则冲突；
- 显示 `nftset` 可用 / 将使用静态快照 / fake-ip 下不可用；
- 保存只写配置，随后提示“重写规则并生效”（二次确认，沿用现有危险确认风格）。

#### A1.3 实现成本

- **M（MVP）**：端口-only + 静态解析 + 配置/预检 + 规则注入 + LuCI 表格；约 2–4 天。
- **L（完整）**：dnsmasq nftset 动态路径 + `pin add/del` 双向校验 + 冲突诊断 + selftest 用例；约 1 周。
- 建议先做 MVP，把动态 nftset 作为同一提案的第二阶段，避免一次性改太多 doctor 相关面。

#### A1.4 风险与对现有分流的干扰面

| 风险 | 说明 | 缓解 |
|---|---|---|
| 规则顺序 | pin 必须在 ISP 集合规则之前，否则永远不命中 | pin 规则写在同一个 `rules.txt` 块顶部；`verify` 增加“pin 规则在 @isp_* 之前”的检查 |
| mwan3 名称限制 | 集合/规则名 >15 字符会被 mwan3 静默丢弃 | `pin check` 先校验；`pin_<slug>` 截断/哈希 |
| 空集合 | 静态解析失败或域名无 A 记录时集合为空 | 规则匹配空集合＝不命中，不影响其他分流；`pin check` 明确告警，不写空规则或写但标注 |
| dnsmasq 能力 | 基础版 dnsmasq 是 `no-nftset`，写 `nftset=` 会让 `dnsmasq --test` 失败，可能拖垮整份片段 | 只在检测到 nftset 时生成；生成前 `dnsmasq --test`；否则静态兜底 |
| fake-ip | fake-ip 下 nftset 写入 198.18.x，pin 规则永远不会命中真实目标；静态解析也会拿到假 IP | `pin check` 检测 fake-ip 并拒绝动态路径；A5 的 `compat` 明确告知“fake-ip 下 pin 不可用” |
| 静态 IP 漂移 | CDN 换 IP 后旧快照失效 | 文档写明“静态快照需手动 `pin apply`”；不挂定时任务；`pin check` 对比当前解析与快照，提示差异 |
| 覆盖既有归属 | pin 的 IP 可能同时属于另一个运营商集合 | 这是**有意覆盖**；`pin check` 显示“将覆盖 @isp_uni 的 N 个地址”，让用户确认 |
| 代理流量 | OpenClash 已打标的流量不会经过 `mark & 0x3f00 == 0` 的 pin 规则 | 正确行为：pin 只管直连；文档写明“代理流量仍由代理决定” |
| doctor | 新对象都在 `inet mwan3` 表内，C3/C5 按 fix38 的归属规则整表排除；C1 的 `domain_split_configured` 目前只看 `DOMAIN_SPLIT`/`$DOMAINDIR`，**pin-only 配置会被误判“不需要片段”** | 同步把 `DOMAIN_PIN` 纳入 C1 的“域名分流已配置”判据；新增 selftest：pin-only + 片段缺失 → conflict，而不是 `DNS_FRAGMENT_NOT_NEEDED` |

#### A1.5 与 DNS 分线的边界（必须写进文档）

| 需求 | 用 `DOMAIN_SPLIT` | 用 `DOMAIN_PIN` |
|---|---|---|
| 让 CDN 返回本运营商节点 | ✅ 首选：改 DNS 出线，CDN 自己选对 | ❌ 不改变解析路径 |
| 域名解析出的 IP 在“错的”运营商集合里 | ⚠️ 只能碰运气（DNS 可能仍返回该 IP） | ✅ 强制覆盖 |
| 只对某个端口钉线（PCDN 8082/4483） | ❌ 表达不了端口 | ✅ `port` 字段 |
| fake-ip 模式 | ⚠️ 列入的域名会拿真实地址，可能绕过代理 | ❌ 动态路径不可用；静态也不可靠 |
| 需要跟随 CDN 换 IP | ✅ DNS 每次查 | ✅ nftset 动态；⚠️ 静态快照会漂移 |

一句话：**DOMAIN_SPLIT 管“怎么解析”，DOMAIN_PIN 管“解析完走哪条线”；能靠 DNS 调度解决的先别 pin，pin 是覆盖手段，不是默认手段。**

---

### A2. 单目标分流归因 `explain`（P0；`flows` P2）

#### A2.1 解决什么问题

- 用户问“`www.bilibili.com` 为什么走联通/为什么没命中电信”，现在只能：
  - 看 `status` 的集合总命中（不知道单个域名）；
  - 跑仓库里的 `tools/verify-domains.sh`（开发工具，未随包发货，依赖 conntrack，且要手工构造目标）；
  - 或者 `nft list set` + 肉眼查 1.3 万条。
- 配了 `DOMAIN_SPLIT` / 即将配 `DOMAIN_PIN` 后，用户更需要一个“输入域名/IP，告诉我命中哪个集合、走哪条线、为什么”的入口。
- 这也是 fake-ip、移动 CGNAT、pin 冲突诊断的共同基础设施。

#### A2.2 方案概要

**CLI**：

```sh
isp-split explain <domain|ip> [--json] [--via <policy>] [--no-resolve]
```

输出（文本示例）：

```text
输入: mcdn.bilivideo.cn
解析: 1.2.3.4, 5.6.7.8（via wan_only / 223.5.5.5）
命中: @isp_cmcc（移动） -> 策略 wanb_only -> 成员 pppoe-wan2（在线）
覆盖: pin 规则 pin1_wan_only 将先于 @isp_cmcc 命中（端口 8082）
兜底: 若未命中，default_rule_v4 -> balanced
提示: 该 IP 同时出现在 @isp_tel（电信）的区间里；当前按 ISP_TABLE 顺序归移动
```

**实现要点**：

- IP 归属判断复用 `linecheck` 已经验证过的 `nft get element inet mwan3 <set> "{ <ip> }"` 路径（`files/usr/sbin/isp-split:_lc_ip_isp`）；对 interval 集合的行为已有生产使用，但提案要求 selftest 增加 `explain` 的 interval 用例，避免只靠推断。
- 同时检查**启用和禁用**集合：命中禁用集合时显示“在 @isp_hk 中，但该行 enabled=0，不会分流”。
- 域名解析：
  - 默认系统 resolver；
  - `--via <policy>` 用该策略的 `DNS_TABLE` DNS + 该线设备（复用 `_lc_dns_for_dev`/`_lc_dns_ms` 的思路）；
  - `--no-resolve` 只接受 IP，完全不出网。
- 规则优先级：解析 `mwan3_rules` 链，给出“pin 规则 / @isp_* / catch-all”的先后；如果 pin 规则端口不匹配，明确说“pin 不命中，继续看 @isp_*”。
- 兜底：读 `default_rule_v4` 的 `enabled` 与 `use_policy`，显示“未命中时走哪条线”；没有兜底规则时显示“走系统默认路由”。
- `--json` 输出固定 schema（建议 `schema:1`），字段含 `input`、`resolved[]`、`matches[]`、`pin[]`、`fallback`、`notes[]`。
- **P2 扩展 `flows`**：
  - `flows [--top 20] [--seconds 5] [--json]` 读 `/proc/net/nf_conntrack`，按目的 IP 聚合，映射集合/线路；
  - 只有 `nf_conntrack_acct=1` 时才有字节数，否则只给连接数；
  - 不做反向 DNS（会引入外部查询且不可靠），只显示 IP + 集合 + 线路；
  - 明确标注“offload 下 conntrack 也看不到已卸载流”，不把它当流量统计。

**LuCI**：状态页顶部搜索框（输入域名/IP），结果卡显示“命中集合 / 策略 / 线路 / 兜底 / pin 覆盖 / 提示”；只读，不加新菜单。

#### A2.3 成本与风险

- 成本：**S**（explain 主体 1–2 天）；**M**（flows + LuCI 卡片 + selftest）。
- 风险：
  - 只读，不碰 nft 规则；`nft get element` 是查询，不会改集合。
  - 域名解析会出网（DNS），但这是用户主动输入；`--no-resolve` 可完全本地。
  - 规则顺序解析可能与 mwan3 实际渲染有版本差异；以 `nft list chain` 的实际文本为准，不猜配置。
  - **doctor 影响：无**（不新增检查，不改变现有 verdict）。

---

### A3. 真实吞吐 `traffic`（P0，S/M）

#### A3.1 解决什么问题

- `status` 的“流量”列是 `ct state new` 的建连首包计数；offload 下后续包不走 `mwan3_rules`，所以它**永远不是真实吞吐**。文档已经写明，但用户还是每天问“为什么状态页只有几百 KB”。
- 现在 `status` 的提示硬编码：

  ```text
  业务吞吐请看接口计数: cat /sys/class/net/pppoe-wan*/statistics/rx_bytes
  ```

  对 DHCP/静态 WAN、改名后的 PPPoE、多 WAN 用户都不对。
- LuCI 状态页没有“这条线现在跑多少”的卡片；`linecheck` 只测延迟/NAT，不测吞吐。

#### A3.2 方案概要

**核心 helper**（建议放公共库，见 B17）：

```sh
# mwan3 interface -> l3_device / up / ipv4
_wan_devices() { ... ifstatus ... }
```

**CLI**：

```sh
isp-split traffic [--json] [--interval 1] [--watch]
isp-split status --traffic        # 文本状态页追加一段，不改变默认输出
```

输出：

```text
线路            设备            状态    接收速率    发送速率    累计接收    累计发送
wan1 (电信)     pppoe-wan1      up      12.4 MB/s   1.1 MB/s    1.2 TiB     80.3 GiB
wan2 (联通)     pppoe-wan2      up      3.2 MB/s    240 KB/s    400 GiB     12.1 GiB
```

- 数据源：`/sys/class/net/<dev>/statistics/{rx,tx}_bytes`、`operstate`、`speed`（可选）。
- 速率：两次采样（默认间隔 1s）或 LuCI 端用两次 `--json` 的累计值算差；**不写状态、不起后台进程**。
- `--json` 字段：`generated`、`lines[{iface,label,dev,state,rx_bytes,tx_bytes,rx_rate,tx_rate,speed}]`。
- LuCI：状态页在“双线健康”卡里加一行“实时吞吐”，每 10 秒随现有轮询刷新；标注“接口计数，不受 offload 影响；包含该线全部流量”。

#### A3.3 成本与风险

- 成本：**S/M**（纯 sysfs + ifstatus；无 nft）。
- 风险：
  - 接口计数包含该线**全部**流量（代理、LAN 其它设备、系统更新），不是“isp-split 命中的流量”；必须在 UI/文档写清楚，避免用户拿它和集合计数对账。
  - `l3_device` 映射失败时显示 `—`，不猜设备名。
  - **doctor 影响：无**；C4 的 offload 结论不变，反而可以用 traffic 的接口计数作为“真实口径”的参考。

---

### A4. 线路体检历史/趋势 + CGNAT 预期（P1，M）

#### A4.1 解决什么问题

- 联通 PPPoE 会话约 10 天后劣化，重拨即满速。用户明确否决定时自动重拨，但“劣化可观测化”仍然有价值：让用户看到“这条线的评分/延迟/抖动在最近 7 天怎么变”，自己决定何时重拨。
- 现在 `linecheck` 只保留 `state/linecheck/last.json`，每次覆盖；`--json` 有 `generated`，但没有历史。
- 移动线用户 CGNAT 占比高：`linecheck` 已经给 CGNAT 并封顶 69 分，但建议文案只讲“申请公网 IP 或 IPv6/内网穿透”，没有把“移动 CGNAT 是常态、不是线路坏”讲清楚。

#### A4.2 方案概要

**历史文件**：

- 路径：`state/linecheck/history.tsv`（与 `last.json` 同目录，权限 600）。
- 追加时机：**只在用户手动/后台体检真正完成并发布缓存后**追加；命中缓存不追加；不挂 cron。
- 字段（一行一条 WAN）：

  ```text
  generated  wan  score  grade  nat  tcp_ms  jitter  loss  avail  exit_ip  wan_uptime
  ```

- 保留：最近 2000 行或 180 天（先到者为准），写入时用临时文件 + rename 裁剪；不无限增长。
- `linecheck` JSON 增加 `wan_uptime`（来自 `ifstatus <iface>` 的 `uptime`，拿不到为 `null`），让“会话时长”与评分同屏。

**CLI**：

```sh
isp-split linecheck --history [--json] [--wan <iface>]
```

输出最近 N 条（默认 30）；`--json` 给 LuCI。

**LuCI**：体检页每条 WAN 卡下方加一个极简 sparkline（最近 30 个评分点，纯内联 SVG/CSS，不引入图表库），旁边显示“会话已持续 X 天”；不新增菜单。

**A4.3 移动/CGNAT 期望管理**：

- `_lc_advice` 在 `nat=cgnat` 且 `LC_ISP=cmcc` 时追加一句：
  “移动 CGNAT 是常见接入方式：端口映射/外网访问不可用，但日常下载/上行不受影响；需要公网入口请用 IPv6 或内网穿透。”
- 概览页线路卡显示 `移动（CGNAT）` 标签，不把 CGNAT 当故障红色。
- `linecheck` JSON 增加 `ipv6_address`/`ipv6_prefix`（来自 `ifstatus` 的 `ipv6-address`/`ipv6-prefix-assignment`，只读；不做 v6 连通性探测），让 CGNAT 用户看到“v6 是否可用”的线索。这与 A8 的披露共用字段。

#### A4.4 成本与风险

- 成本：**M**（历史写入/裁剪、JSON、LuCI sparkline、文案）。
- 风险：
  - 写 flash：每次手动体检一行/每 WAN，量很小；但必须限长，避免用户频繁点按钮把 overlay 写满。
  - 历史含出口公网 IP；现有 ACL 的 `read` 已覆盖整个 `state/` 树，不扩大权限；文档写明。
  - 不自动重拨；不根据历史自动改配置；不新增定时任务。
  - **doctor 影响：无**（历史不参与 doctor；C2/C4 不看这个文件）。

---

### A5. fake-ip 兼容报告与检测泛化（P1，S/M）

#### A5.1 解决什么问题

- 恩山反馈里 fake-ip 用户是真实群体：OpenClash / Passwall / sing-box / mihomo 都可能开 fake-ip。
- 现有判断：
  - `_openclash_fakeip` 只认 OpenClash 的 `uci openclash.config.en_mode`；
  - `_openclash_fakeip_warn` 文案写“IP 分流与多线路 DNS 均不会生效”，过于绝对；
  - `doctor` C2 把 fake-ip 判 `conflict`，但 advice 只说“关 auto-route / 切 redir-host”，没有告诉用户“如果只想让国内域名直连，可以只维护 DOMAIN_SPLIT/域名清单”。
- 实际情况（既有 `COMPAT-DNS-PROXY.md` 的结论）：
  - fake-ip 下**按目标 IP 的运营商集合**确实不命中；
  - 但列入 `DOMAIN_SPLIT` 的域名会拿到真实地址（绕过代理 DNS），这些域名的直连流量仍可被 IP 集合分流；
  - Passwall 的 direct 域名、mihomo 的 `fake-ip-filter` 也会把真实 IP 放出来。
  - 所以正确说法是“**IP 分流对 fake-ip 域名失效；域名分流/放行清单仍可工作**”，而不是“全都不生效”。

#### A5.2 方案概要

**检测泛化**（替换 `_openclash_fakeip`，保留函数名兼容或加 wrapper）：

| 证据 | 读法 | 强弱 |
|---|---|---|
| 假 IP 段 | 生成的配置/规则里出现 `198.18.` 或 `2001:2::`（OpenClash/Passwall/mihomo 默认 `/16`，不要只匹配 `/15`） | 强 |
| OpenClash | `openclash.config.enable=1` 且 `en_mode` 归一化后以 `fakeip` 开头 | 强 |
| Passwall | `passwall.@global[0].remote_fakedns=1`，或节点 `passwall.<node>.fakedns=1` | 强 |
| sing-box | `/etc/sing-box/config.json` 里 `dns.servers[].type == "fakeip"` | 强 |
| mihomo | `dns.enhanced-mode: fake-ip`（配 `fake-ip-range`） | 强 |
| 进程 | `ps w` 出现 mihomo/clash/sing-box/xray | 弱，仅作 hint，不单独定罪 |

输出统一为 `FAKEIP_PRODUCT` / `FAKEIP_RANGE` / `FAKEIP_EVIDENCE` / `FAKEIP_CONFIDENCE`；告警按产品分支给建议。

**CLI `compat`（只读）**：

```sh
isp-split compat [--json]
```

输出：

```json
{
  "proxy": {"product":"openclash","mode":"fake-ip","confidence":"high"},
  "ip_split": {"effective": false, "reason":"fake-ip 目的地址不在运营商集合"},
  "domain_split": {"configured": true, "domains": 2, "fragment_loaded": true},
  "pin": {"configured": false, "dynamic_available": false},
  "advice": ["若要 IP 分流：切 redir-host", "若只想国内域名直连：维护 DOMAIN_SPLIT/域名清单，并确认这些域名绕过 fake-ip"]
}
```

**doctor C2**：

- 不改变 `conflict` 判定（fake-ip 确实让 IP 分流失效）；
- 只在 `facts.fakeip` 增加 `product`、`range`、`confidence`、`domain_split_configured`、`pin_configured`、`ip_split_effective=false`、`domain_split_effective`；
- advice 按产品分支；如果 `domain_split_configured=true`，明确写“这些域名仍可工作，但其余域名不走运营商分流”。

**LuCI**：状态页横幅在 fake-ip 时显示“IP 分流不生效 / 域名分流 N 条仍可工作 / 建议”，并提供“查看兼容矩阵”链接（文档）；向导第 0 步复用 `compat --json`，不新增菜单。

#### A5.3 成本与风险

- 成本：**S/M**（检测函数 + compat + 文案 + LuCI 横幅）。
- 风险：
  - 配置文件 grep 可能把注释/示例里的 `198.18.` 当成 fake-ip；必须优先用产品配置键和生成配置的结构化特征，grep 只作弱证据。
  - 泛化检测会让更多用户看到 C2 conflict（真实阳性，但可能被感知为“新误报”）；advice 必须按产品给可执行路径，并说明“域名分流仍可工作”。
  - **doctor 影响：只加 facts/advice，不改 verdict/计数**；不新增第 7 项检查。
  - 零新外部服务：只读本地配置，不发 DNS/HTTP。

---

### A6. 数据源新鲜度与韧性（P1，M）

#### A6.1 现状与问题

现有失败语义是安全的：

- 主源失败 → 冻结旧数据，`die`；
- 校验源失败 1–2 次 → 降级只用主源；
- 校验源连续失败 ≥ `ISP_SOURCE_MAX_FAIL_DAYS`（默认 3）→ 拒绝更新；
- 分歧超阈值 → 拒绝更新并留档 `quarantine/<日期>/`。

但“安全”不等于“可诊断”：

1. `fail_days` 实际是**失败次数**（`_state_fail_plus` 每次失败 +1，没有日期），手动重试 3 次就会触发“连续 3 天”的拒绝。
2. `health --json` 的 `jaccard` 只接受纯数字，`96.12` 被当成非法 → `null`；LuCI 数据源表永远显示 `—`。`diff.min_jaccard` 同样。**【本地复现】** 见附录 D.1。
3. 分歧超阈值被拒绝后，`sources.tsv` 的 `fail=0`、`note=分歧超阈值`，但 `health`/`_sources_report` 只看 `fail`，于是两个源都显示“正常”，用户不知道为什么数据没更新。
4. `_archive_source` 的注释写“即使当天拒绝更新，也能事后 `isp-split diff` 复查”，但拒绝发生在 archive 之前（`exit 3`），`cmd_diff` 只读 `$RAW_ARCHIVE`，所以**复查的是上一次成功的数据，不是被拒的那份**。
5. `status`/LuCI 只显示“数据更新时间”，没有“已 N 天未更新”的显式告警；主源冻结 10 天后，页面仍可能看起来正常。

#### A6.2 方案概要

**health/status 字段**：

```json
"data": {
  "stamp": 1730000000,
  "updated": "2026-...",
  "age_days": 4,
  "stale": true,
  "last_attempt": 1730300000,
  "last_applied": 1730000000,
  "stale_after_days": 3
},
"sources": [
  {"name":"clang","fail_days":2,"last_fail_day":"2026-...","last_error":"...","jaccard":96.12,"status":"degraded"}
]
```

- 修正 jaccard 解析：允许 `^[0-9]+([.][0-9]+)?$`（或直接按 `awk` 数值校验），`last-diff` 同理。
- `fail_days` 改为真正的“连续失败天数”：state 增加 `last_fail_day`（YYYYMMDD 或 epoch day），同一天多次失败只 +1；成功清零。
- 状态判定增加“拒绝更新”：`note` 含“分歧超阈值”或 `jaccard < 阈值` 时，`status` 显示 `rejected`，不要显示“正常”。
- `data.stale`：`age_days > ISP_DATA_STALE_DAYS`（默认 3，范围 1–30）；只影响 status/LuCI 徽标，**不进 doctor**。
- `sources[].last_error`：`_fetch_source` 把失败原因（HTTP code/URL/校验失败）截断后写入 state，供 `health` 显示；不要只留“主源下载失败”。

**手动恢复入口**：

```sh
isp-split fetch --check     # 下载 + 单源闸门 + 合成 + diff，但不 commit DATA/state；退出码同 fetch
isp-split fetch --offline   # 从 $RAW_ARCHIVE 重新合成（不联网），用于改 ISP_TABLE 后没网/源全挂
isp-split diff --from quarantine/<日期>   # 复查被拒的那份 raw（需要在拒绝时留档）
```

- 拒绝时把 `raw.new` 归档到 `quarantine/<日期>/raw/<源名>/`（体积约为 175 KB/源，可接受）；`diff --from` 读它。
- `fetch --check` 仍持有 op lock，但不替换 DATA、不写 sources 状态（避免“检查一次就把失败天数加一”）。
- `fetch --offline` 写 DATA（和 fetch 一样做备份/原子替换），但明确打印“未联网，数据来自 X 时间的存档”。

**LuCI**：状态页“数据时间”卡增加 `已 N 天未更新` 橙色徽标（`stale` 时），点击展开“最后成功/最后尝试/最后错误/如何手动重试”；不新增菜单。

#### A6.3 成本与风险

- 成本：**M**（state 兼容、两个 fetch 模式、quarantine 归档、JSON/UI）。
- 风险：
  - state 文件新增列要兼容旧行（`NF>=6` 逻辑已有；新列可追加，旧行缺列按默认值）。
  - `fetch --check` 会消耗一次下载流量；默认不跑，只在用户显式调用时。
  - `fetch --offline` 仍写 DATA，必须持锁 + 备份 + 原子替换，复用现有事务。
  - 不自动换源；不自动重试；不新增定时任务。
  - **doctor 影响：无**；所有新鲜度判定留在 `health`/`status`，避免给 doctor 增加第 7 项和新的误报面。

---

### A7. export 深化（P2，M）

#### A7.1 解决什么问题

- 现在 `export mihomo|singbox|text <dir>` 只导出**运营商 IP CIDR**；SmartDNS / AdGuard Home 用户要手抄 `DOMAIN_SPLIT`；mihomo 的 domain rule-provider、sing-box 的 `domain_suffix` rule_set 也没有出口。
- 0.2.2 提案里的 F-1（`export domains`）没有落地；本次把它和“fake-ip 放行清单”合并成一个完整出口。
- 代理侧用户（OpenClash redir-host / sing-box / mihomo）需要“同一份策略在两边一致”，而不是两边各配一套。

#### A7.2 方案概要

```sh
isp-split export domains <smartdns|agh|mihomo|singbox|text> <dir>
isp-split export manifest <dir>          # 现有 IP 导出 + 元数据
isp-split export fakeip-filter <dir>     # 给 mihomo/sing-box 的放行清单
```

输入 = `DOMAIN_SPLIT` + `$DOMAINDIR/<策略>.txt`（复用 `cmd_dns` 的解析逻辑，含 `server=/domain/1.2.3.4` 兼容格式）；按策略归组。

| 格式 | 产物 | 备注 |
|---|---|---|
| `smartdns` | `isp-<policy>.txt` + `smartdns-isp-split.conf` 片段（`domain-set` + `nameserver /domain-set:.../<dns>`） | 文件头写生成时间、策略、smartdns 版本要求；不直接改用户配置 |
| `agh` | `isp-<policy>.txt` + `agh-upstreams.txt`（`[/d1/d2/]<dns>`） | 对齐 AdGuard Home `upstream_dns_file` |
| `mihomo` | `isp-<policy>.yaml`（`payload: - '+.domain'`） | 必须带 `+.` 才是“域+子域” |
| `singbox` | `isp-<policy>.json`（`{"version":1,"rules":[{"domain_suffix":[...]}]}`） | 与现有 `ip_cidr` 导出分开文件，避免混用 |
| `text` | 纯域名列表 | 给 mosdns/其它工具 |

`manifest`：JSON 记录 `generated`、`data.stamp`、每个集合的条目数、源角色、导出格式版本；不引入 checksum 依赖（可选 `cksum`，不强制）。

`fakeip-filter`：输出 `DOMAIN_SPLIT` + 外部清单的域名列表，供 mihomo `fake-ip-filter` / sing-box 放行；与 A5 的 `compat` 建议联动。

**LuCI**：配置页底部“导出”区块（格式下拉 + 目录输入 + 生成按钮），目录安全校验复用 `cmd_export` 的黑名单/真实路径检查；也可以先只做 CLI，LuCI 后置。

#### A7.3 成本与风险

- 成本：**M**（格式适配 + 文档 + selftest）。
- 风险：
  - SmartDNS/AGH 语法随版本变化；文件头写明“适用于哪个版本/语法”，并只导出到用户目录，不自动写入第三方配置。
  - 导出的是用户自己的域名策略，可能含敏感域名；沿用现有目录权限/路径守卫。
  - **doctor 影响：无**（纯输出，不碰 nft/mwan3）。

---

### A8. IPv6：先披露，暂不破冰（P2；完整 v6 P3）

#### A8.1 解决什么问题

- 当前所有集合/规则都是 `family ipv4`；IPv6 默认路由不经过本工具，用户可能以为“分流已全覆盖”。
- 双栈 CGNAT 用户（移动常见）反而依赖 v6 做公网入口；他们需要知道“v6 没有被分流”，而不是以为工具坏了。
- 完整 v6 不是小改动：现有 `cidr2range/merge/exclude/range2cidr` 用 double 做 32 位区间运算；v6 的 128 位需要十六进制字符串运算/比较，属于 L 级，且要独立表、规则、测试、数据源映射。

#### A8.2 方案概要

**Phase 0（P2，S）——只披露，不接线**：

- `health --json` 增加：

  ```json
  "ipv6": {
    "present": true,
    "default_dev": "pppoe-wan1",
    "mwan3_v6_ifaces": ["wan1"],
    "split": false,
    "note": "IPv6 不经过本工具分流"
  }
  ```

- `status` 文本/JSON 在检测到 v6 默认路由时加一行说明；LuCI 状态页加一行“IPv6 未分流（本版本只做 IPv4）”，不红色、不阻断。
- `linecheck` 增 `ipv6_address`/`ipv6_prefix`（A4 已提），让 CGNAT 用户看到 v6 线索；不做 v6 连通性探测（避免新外部服务）。
- 文档“已知限制”写清楚：v6 流量走系统默认路由；需要 v6 分流请等完整支持，或自行用 mwan3 v6 规则。

**Phase 1（P3，L）——完整 v6**：

1. 只读 v6 数据管线 + selftest（不接线）：验证 128 位区间互斥化、`::/0`、`/128`、边界合并；
2. 独立 `ISP6_TABLE` / `family` 维度；集合 `isp_tel6` 等；mwan3 `family=ipv6` 规则；
3. v6 兜底计数（`meta nfproto ipv6`）；
4. DNS AAAA 与 A 同路径；fake-ip v6 单独评估；
5. LuCI 分 family tab / 健康度。

**为什么不做第 7 项 doctor 检查**：v6 未分流是“已知限制”，不是“环境冲突”；给它一个 doctor verdict 会让所有双栈用户看到红/黄条，属于典型的新误报面。放在 `health`/`status` 的信息位即可。

#### A8.3 成本与风险

- Phase 0：**S**；Phase 1：**L**。
- 风险：完整 v6 改动面大、数据源/方法学需重新验证；在 v4 分流稳定之前不建议动。Phase 0 无风险。

---

### A9. LuCI 落点（跨提案，不单独计一个提案）

方向 9 不新增菜单，避免“设置项比功能多”。建议：

| 页面 | 增加什么 | 来源 |
|---|---|---|
| 状态（overview） | 每条线实时吞吐；数据“已 N 天未更新”徽标；`explain` 搜索框；fake-ip 兼容横幅；最近体检评分/趋势入口 | A3/A6/A2/A5/A4 |
| 配置（config） | “钉线”区块（域名/端口/策略）；`pin check` 预检结果；导出区块（可选） | A1/A7 |
| 线路体检（linecheck） | 评分 sparkline + 会话时长；v6 地址/前缀；CGNAT 期望文案 | A4/A8 |
| 引导（wizard） | 第 0 步复用 `compat --json`；fake-ip 时给出“切 redir-host / 只维护域名清单”两条路径 | A5 |

约束：

- 不新增 menu.d 节点；现有四个页面足够。
- 不扩大 ACL：新命令都走 `/usr/sbin/isp-split` 的现有 `write` exec 面；历史文件在 `state/` 下，现有 `read` 已覆盖；pin 配置写入走 CLI 的 `_conf_write`，不新增 LuCI 直接写配置文件的权限。
- linecheck 页面继续保持 `load()` 零 exec（只读缓存），趋势图只读 `history.tsv`，不触发探测。
- 所有新增文本仍走 `E()` 文本节点，不引入 `innerHTML`（沿用 A-15 的 XSS 约束）。

---

## B. 优化清单（现有功能怎么改更好）

> B 清单不设 P0；最高为 P1。P0 名额留给 A1/A2/A3。

### B.1 判据与误报

#### B1（P1）doctor C1 的 `DNS_FRAGMENT_STALE` 每天必报一次假警

**位置**：`files/usr/lib/isp-split/doctor.sh:doc_check_dns53`（约 1188–1190、1222 行）

**证据【代码】**：

```sh
if [ -f "$_l_frag" ] && [ -f "${DATA:-/nonexistent}/.stamp" ]; then
    _l_stamp=$(stat -c %Y "${DATA}/.stamp" 2>/dev/null || printf '0')
    [ "${_l_fmtime:-0}" -lt "${_l_stamp:-0}" ] 2>/dev/null && _l_stale=1
fi
...
_doc_find "DNS_FRAGMENT_STALE" warn "片段比最新数据旧（sh -x：数据已更新但片段没重写）" ...
```

**为什么是假警**：

- 现有 cron 是 `17 4 * * * isp-split refresh`；`refresh = fetch + apply`，**不跑 `dns`**。
- 每天的 `fetch` 会更新 `$DATA/.stamp`，但 `isp-split.conf` 片段的内容只依赖 `DOMAIN_SPLIT`/`DOMAIN_TABLE`/线路状态，**不依赖 IP 数据**。
- 因此只要配了 `DOMAIN_SPLIT`，每天 04:17 之后 doctor C1 必然 `warn`，建议用户“跑一次 isp-split dns”——这会让 dnsmasq 每天重启一次，且没有任何实际收益。

**修法**：

- 片段“新鲜度”应对**输入**比较，而不是对 IP 数据 `.stamp`：
  - 方案 a（推荐）：`cmd_dns` 在片段里写一行 `# inputs: <DOMAIN_SPLIT/DNS_TABLE 的 hash 或 mtime>`，doctor 比较这行；
  - 方案 b：比较片段 mtime 与 `DOMAIN_SPLIT`/`DNS_TABLE` 的配置 mtime（但配置文件改其它键也会变，较粗）；
  - 方案 c：删掉 stale 判据，只保留“片段存在 + 已被加载”两个事实。
- 不建议用“让 refresh 顺带跑 dns”来消警：那会把“数据更新”和“DNS 片段重写 + dnsmasq 重启”耦合，违背现有 refresh 的“不 reload mwan3”设计。

**doctor 影响**：修掉一个每日误报；不新增检查。

#### B2（P2）`_doc_fakeip` 用整文件 grep `198.18.`，可能把注释/示例当 fake-ip

**位置**：`doctor.sh:_doc_fakeip`（约 1005 行）

**证据【代码】**：对 `/etc/config/openclash`、`/etc/mihomo/config.yaml`、`/etc/sing-box/config.json` 等直接 `grep -q '198\.18\.'`，命中即 `DOC_FIP_DETECTED=1`。如果用户配置里只是注释/示例/`fake-ip-filter` 提到 198.18，但 fake-ip 未启用，会误判 C2 conflict。

**修法**：A5 的 `_fakeip_detect` 统一按“产品配置键/生成配置结构 > 假 IP 段 > 进程”的证据顺序；grep 只作弱证据，且必须排除注释行（`^[[:space:]]*#`）和 `fake-ip-filter` 语义。doctor C2 的 verdict 不变，只改事实来源。

#### B3（P3）doctor C2 的 TUN owner 不区分设备

**位置**：`doctor.sh:doc_check_tun` 循环里调用 `_doc_tun_owner` 无参数；`_doc_tun_owner`（约 973 行）扫描整个 `DOC_P2_MAP`，返回所有持有 `/dev/net/tun` 的进程。

**影响**：多 TUN 设备（如同时有 Meta 和另一个 tun）时，每个 `tun_devices[].owner` 都显示全部 owner，用户无法判断谁占着哪个设备。

**修法**：`_doc_tun_owner <dev>` 用 `DOC_P2_MAP` 里与 `/dev/net/tun` 的 fd 关联 + 设备 ifindex/name 做匹配；拿不到就返回 `unknown`，不要把所有 owner 塞给每个设备。

---

### B.2 数据源状态与 JSON

#### B4（P1）`health --json` 把小数 Jaccard 判成非法 → 永远 `null`

**位置**：`files/usr/sbin/isp-split:cmd_health_json`（约 3781–3782 行）

**证据【代码 + 本地复现】**：

```sh
_jac=$(_state_get "$_s_name" jaccard)
case "${_jac:-}" in '' | *[!0-9]*) _jac_json=null ;; *) _jac_json=$_jac ;; esac
```

`ispdiff.awk` 输出的是 `printf "%.2f"`（例如 `96.12`），包含小数点，命中 `*[!0-9]*` → `null`。用临时 `ISP_SPLIT_BASE` 复现（附录 D.1）：`sources.tsv` 写 `96.12`，`health --json` 输出 `"jaccard":null`。`diff.min_jaccard` 读取 `last-diff` 时同样只接受纯数字，也会 `null`。

**影响**：LuCI 数据源表的 Jaccard 列永远显示 `—`；用户看不到 95%+ 的正常值，也看不到 80% 的异常值。

**修法**：用 `awk` 或 case 允许一位小数点：

```sh
case "${_jac:-}" in
''|*[!0-9.]*|*.*.*) _jac_json=null ;;
*) _jac_json=$_jac ;;
esac
```

更稳妥：`awk -v j="$_jac" 'BEGIN{exit !(j ~ /^[0-9]+([.][0-9]+)?$/)}'`。`last-diff` 同改。

#### B5（P1）“连续失败 3 天”实际是“失败 3 次”

**位置**：`_state_fail_plus`（约 584–590 行）；`_cmd_fetch_body` 每次源失败调用；`_sources_report` 文案“连续 N 天”。

**证据【代码】**：`_state_fail_plus` 只做 `prev+1`，state 里没有 `last_fail_day`。用户手动跑 3 次 `fetch`（校验源仍挂）就会达到 `ISP_SOURCE_MAX_FAIL_DAYS=3`，下一次直接拒绝更新——不是“连续 3 天”，而是“连续 3 次”。

**影响**：手动重试会把降级提前升级成拒绝更新；用户以为“今天才第一次失败”。

**修法**：state 增加 `last_fail_day`（YYYYMMDD 或 epoch day）。同一天重复失败不增加 `fail_days`，只更新 `last_error`；跨天才 +1；成功清零。UI 文案保持“连续失败天数”，并显示 `last_fail_day`。

#### B6（P1）分歧被拒后，两个源仍显示“正常”

**位置**：`_sources_report`（约 955–965 行）、`cmd_health_json`（约 3783–3790 行）；`_run_diff` 拒绝时 `_state_put` 写 `fail=0`、`note=分歧超阈值`。

**证据【代码 + 本地复现】**：`sources.tsv` 里 `clang` 行 `fail=0`、`jaccard=80.00`、`note=分歧超阈值`；`health --json` 输出 `"status":"ok"`、`"jaccard":null`（B4）。`_sources_report` 只看 `fail>0`，也显示“正常”。

**影响**：fetch 明确拒绝了更新，但状态页/健康度显示“正常”，用户不知道数据为什么停在旧日期。

**修法**：状态判定加入 `note`/`jaccard`：
- `note` 含“分歧超阈值” → `status=rejected`；
- `jaccard < ISP_DIFF_MAX_JACCARD_DROP` → `status=rejected`（或 `warn`）；
- `fail_days >= max` → `rejected`；
- 文本/JSON 都显示“上次更新被拒绝”的原因和建议（`fetch` 手动重试 / 看 quarantine）。

#### B7（P1）`diff` 复查不到“被拒的那份数据”

**位置**：`_archive_source` 注释（约 769–770 行）vs `cmd_diff`（约 1438–1452 行）；拒绝路径 `exit 3`（约 1249 行）发生在 `_archive_source` 之前。

**证据【代码】**：`fetch` 在 diff 拒绝时直接 `exit 3`，`raw.new` 不会归档；`cmd_diff` 只读 `$RAW_ARCHIVE`，那里还是上一次成功的数据。注释“即使当天拒绝更新，也能事后 diff 复查”不成立。

**影响**：用户看到拒绝提示“差异段已留档”，但事后 `isp-split diff` 得到的是“两个源一致”的旧结果，容易误判“已经恢复”。

**修法**：
- 拒绝时把 `WORK/raw.new` 归档到 `quarantine/<日期>/raw/<源名>/`（quarantine 已有目录，体积可控）；
- `cmd_diff` 加 `--from <dir>`（或自动检测最近的 quarantine/raw），对那份数据重算；
- 如果不想加归档，至少改注释/文档，不要把“可复查”写成现有能力。

---

### B.3 命令行为与文案

#### B8（P1）`dns` 删除最后一条规则后不重启 dnsmasq，旧 `server=` 仍生效

**位置**：`_cmd_dns_body` 的 `_n=0` 分支（约 4946–4958 行）；只有 `_n>0` 分支才 `"$DNSMASQ_SERVICE" restart`（约 4975 行）。

**证据【代码】**：dnsmasq 在启动时读 `conf-dir`，删除文件不会自动卸载已加载的 `server=` 规则。用户清空 `DOMAIN_SPLIT` 后跑 `isp-split dns`：
- 片段被 `rm -f`；
- nft DNS 旁路被 `_dns_bypass` 清掉；
- 但 dnsmasq 仍按旧片段把那些域名发给旧线路 DNS，直到重启/重启路由器。

`teardown.sh` 卸载路径也只删片段、不重启 dnsmasq（`cmd_runtime` 只 reload mwan3），同类问题。

**修法**：记录“本次删除过片段”标志；在 `_n=0` 且确实删了 `$_out` 时重启 dnsmasq（或 `SIGHUP`，若该版本支持）；teardown 删除片段后同样重启。注意：如果 `_n=0` 是因为线路未就绪而**保留**旧片段，则不要重启。

**风险**：重启 dnsmasq 会有短暂 DNS 中断；只在“确实改变了片段”时做，和现在 `_n>0` 的行为一致。

#### B9（P1）`verify` 的兜底计数检查会漏报，也不检查形状

**位置**：`cmd_verify`（约 3446–3451 行）

**证据【代码】**：

```sh
if [ "${COUNT_FALLBACK:-1}" = "1" ] &&
   [ "$(nft list chain inet mwan3 mwan3_rules 2>/dev/null | grep -c "counter name")" -eq 0 ]; then
    echo "⚠ 兜底计数规则缺失"
fi
```

- `grep -c "counter name"` 统计的是**任意命名计数器**；只要链里有别的 `counter name`（用户探针、mwan3 自带计数器等），`isp_fallback` 缺失也不会提示。
- 即使 `isp_fallback` 存在，旧形状（没有 `ct state new`、只排 dport 53）也不会提示；`status` 用 `_fallback_rule_ok` 检查形状，`verify` 没有复用。

**修法**：`verify` 直接调用 `_fallback_rule_ok "$(_mwan3_rules_body | grep 'counter name "isp_fallback"')"`，与 `status` 同一判据；把“缺失/形状不符”分开报。

**同类**：`_dns_chain_ok` 只 `grep -qE 'dport 53 ... (return|jump ...)'`，DNS_TABLE 有 2 条时只看到 1 条也会说“有”。建议用 `_dns_rule_count` 与期望条数（每行 udp/tcp 各一条）比较。

#### B10（P1）`dnstest` 测的不是“这条线的 DNS”

**位置**：`cmd_dnstest`（约 1469–1505 行）

**证据【代码】**：`_dev=$(policy_device "$_pol")` 只用于打印（1497 行）；实际 `nslookup www.example.com "$_dns"` 没有绑定设备，也没有用 `--interface`/`--dns-servers`。它证明的是“这个 DNS IP 从当前路由可达”，不是“这条线的 DNS 路径可用”。

**影响**：用户以为在测线路 DNS；如果 DNS 从另一条线出去，结果可能“可用”但线路是错的；失败时文案把“DNS 无响应”和“nslookup 不可用”混在一起。

**修法**：
- 复用 `linecheck` 的按线 DNS 思路（`_lc_dns_for_dev` + `curl --dns-servers` 或 `nslookup @server`），至少输出 `scope=local|wan` 与 `device`；
- 文案拆开：`nslookup 缺失` / `DNS 超时` / `DNS 返回非 A` / `线路未就绪`；
- `--json` 增加 `ms`/`scope`/`server`，让 LuCI“测线”按钮显示真实口径。

#### B11（P1）`status` 每个集合 3 次 `nft list set`，10 秒轮询放大成 12 次进程

**位置**：`_status_one`（约 3676–3697 行）和 `cmd_status_json` 的 `_sj`（约 3722–3748 行）；`count_set_elements` 自身又一次 `nft list set`（约 321 行）。

**证据【代码】**：每个集合：
1. `nft list set ... >/dev/null` 判存在；
2. `nft list set ...` 取 counters；
3. `count_set_elements` 再 `nft list set ...` 数元素。

4 个启用集合 = 12 次 `nft` 进程；LuCI 每 10 秒轮询一次，即每分钟 72 次。路由器上 `nft` 进程启动/规则表解析是主要成本。

**修法**：
- 一次 `nft list set`，从同一份文本里同时解析 `exists`、`elements`、`packets/bytes`；
- 抽一个 `_status_fields <set>` 返回 TSV，`_status_one`/`_sj` 共用；`count_set_elements` 保留给 selftest/verify，但 status 不再调用；
- 预期把每集合 3 次降到 1 次，4 集合 12→4。

**风险**：解析逻辑要兼容 `elements = { ... }` 多行、counter 行；现有 `count_set_elements` 的注释已经踩过 busybox awk 的 `{}` 坑，重构时要保留同样的 `index()` 写法。

#### B12（P2）`status` 的说明文案有两处不随配置变化

**位置**：`cmd_status`（约 3941–3943 行）

**证据【代码】**：

```sh
echo "    DNS（udp/tcp 任一侧 53）不计入兜底，见 COUNT_FALLBACK_SKIP_DNS。"
echo "    业务吞吐请看接口计数: cat /sys/class/net/pppoe-wan*/statistics/rx_bytes"
```

- 当 `COUNT_FALLBACK_SKIP_DNS=0` 时，第一句是错的（DNS 会计入）；
- 第二句硬编码 `pppoe-wan*`，DHCP/静态 WAN 或改名后的设备不适用。

**修法**：按配置分支输出；设备列表用 `_wan_devices` 动态生成（A3），或直接改为“运行 `isp-split traffic` 查看真实吞吐”。

#### B13（P2）`health`/`status --json` 没有错误信封，只读命令会 `die`

**位置**：`cmd_status`（3911 `need_nft`）、`_sources_report`（945 `_source_check_all`）、`cmd_health_json`（3767 `_source_check_all`）。

**证据【代码】**：`status --json` 在 nft 表不存在时 `die`；`health --json` 在 `ISP_SOURCES` 配置非法时 `die`。LuCI 的 `readJson` 会拿到空 stdout，只能显示“退出码 N”，无法区分“mwan3 没跑”和“配置写错”。

**修法**：`status/health --json` 加 `schema` 与 `errors[]`；只读命令对可恢复错误降级（如 `{"schema":1,"errors":["MWAN3_NOT_RUNNING"],"sets":[]}`），仍以非 0 退出码表达严重性。不要改变 `doctor` 的“never die”语义。

#### B14（P2）`dns` 每次重启 dnsmasq，即使片段内容没变

**位置**：`_cmd_dns_body` 末尾无条件 `"$DNSMASQ_SERVICE" restart`（约 4975 行）。

**影响**：用户重复跑 `dns`（或开机 init 已跑过）会无谓中断 DNS；在弱路由器上重启 dnsmasq 需要几秒。

**修法**：落位前 `cmp -s "$_out_tmp" "$_out"`；相同且 dnsmasq 正在运行则跳过 restart，只打印“片段未变化”。注意：如果 UCI confdir 刚迁移、或 dnsmasq 未运行，仍要重启。

#### B15（P2）`selftest` 的加载耗时只有 1 秒粒度

**位置**：`cmd_selftest`（约 1839–1844 行）

**证据【代码】**：

```sh
_t0=$(date +%s)
nft -f ...
_t1=$(date +%s)
echo "加载耗时 $((_t1 - _t0)) 秒"
```

典型全量约 800ms，会显示 `0 秒` 或 `1 秒`，无法用于“低配设备是否可行”的判断。

**修法**：复用 linecheck 的 `_lc_clock_ns` 思路（`date +%N` 不可用则 `/proc/uptime` 10ms 精度），输出 `xxx ms`；保留整数秒作为粗略值。

#### B16（P2）`build.sh` 每个运营商重复做一次 CIDR→区间解析

**位置**：`files/usr/lib/isp-split/build.sh:35–69`

**证据【代码】**：

- 第 43 行 `cidr2range.awk` 做合并；
- 第 66 行 `n_raw=$(awk -f cidr2range.awk "$src" | wc -l)` 又解析一遍，只为数原始行数。

**修法**：`n_raw=$(wc -l < "$src")`（若担心坏行，用 `grep -c` 或一次 `cidr2range` 的结果缓存）。**本地合成 13,000 条 CIDR 的整链耗时 0.54s（x86_64）**，路由器上收益更明显，但不是当前瓶颈；属于“顺手削”的优化。

---

### B.4 代码结构、判据共享与文档

#### B17（P2）判据共享现状：doctor/preflight 已经单一来源，linecheck 仍有自己的小生态

**已经做得好的（不要重写）**：

- `tools/router-preflight.sh` 只 source `doctor.sh` 的判据（fix34/F7 的教训），没有第二套 `render_config_ipsets`。
- doctor C3/C5 共用 `_doc_owner_of`/`_doc_wr_eval`（fix38/fix39），归属与求值只有一份。
- JSON 转义 `_doc_esc` 优先复用主脚本 `_lc_json_esc`。

**仍有漂移风险的**：

| 重复点 | 现状 | 建议 |
|---|---|---|
| IPv4 校验 | `_valid_ipv4`（CLI）vs `_lc_ip_valid`（linecheck） | 抽 `valid_ipv4` 到公共库；两者语义要一致（前导零、范围） |
| IP→集合 | `_lc_ip_isp`（linecheck）vs A2 的 explain | A2 直接复用/抽取，不要写第二套 `nft get element` 循环 |
| WAN 设备发现 | `_lc_wans`（linecheck）vs A3 的 traffic | 抽 `wan_devices`；linecheck 后续可切换，减少 `ifstatus` 重复调用 |
| 接口计数 | `_doc_dev_bytes`（doctor）vs A3 | 抽 `dev_bytes`；doctor 只读 `/sys`，CLI 也同一实现 |
| status 解析 | `_status_one` vs `_sj` | 抽 `status_fields`（B11） |
| 导出目录守卫 | `cmd_export` 里两张相同黑名单 | 抽 `_export_dir_ok`，避免两张表漏一项 |

**建议**：新增 `files/usr/lib/isp-split/common.sh`，只放**纯函数**（无全局副作用）：`json_esc`、`valid_ipv4`、`human_bytes`、`dev_bytes`、`wan_devices`、`set_contains_ip`；由 CLI 和 doctor source。打包、selftest、卸载清单要同步（这是成本，不是难点）。不要为了“整洁”重写整个 CLI；只抽新功能需要的部分，避免 doctor 回归。

#### B18（P3）集合名未拒绝 `mwan3_` 前缀

**位置**：`_valid_name`（约 5069 行）、`_row_check`（约 5098 行）

**证据【代码】**：`_valid_name` 只检查字符集和 ≤15，未拒绝 `mwan3_`；配置模板注释明确写“不能以 `mwan3_` 开头（mwan3 内部保留）”。用户写 `mwan3_foo` 会通过校验，可能与 mwan3 内部命名冲突。

**修法**：`_valid_name` 加 `case "$1" in mwan3_*) return 1 ;; esac`，错误文案指向配置模板。**这是 0.2.2 提案 B-10 的遗留项，仍未修。**

#### B19（P2）`export` 的 README 让用户“cron 里跑 fetch 再 export”，但安装器没有这条 cron

**位置**：`cmd_export` 的 mihomo README（约 5840 行）；`cmd_install`/`scripts/install.sh` 只装 `refresh`。

**影响**：用户按导出的 README 配了 cron 也不会自动 export；或者以为已经自动更新。

**修法**：README 改成“手动运行，或自行在 crontab 增加”；如果将来要自动，必须显式 `export` 选项，不默认加任务（遵守“不装定时任务”）。

#### B20（P1 文档，随 A1 解决）`plan` 说“只检测不启用钉线”，README 说“域名钉线已追平”

**位置**：`cmd_plan` 的 `_dnsmasq_nftset` 输出（约 3518 行）；README 对比表（约 367 行）。

**影响**：用户按 README 以为域名钉线可用，实际 `plan` 明确说没启用；两处口径矛盾。

**修法**：A1 落地前，把 README 改成“域名分流已支持；域名/端口钉线为规划中（当前仅检测 nftset 能力）”；A1 落地后再改回“已支持”，并补 `pin` 用法。这是纯文档修正，可随 0.4.2 先做。

#### B21（P3）`rollback` 只恢复 `.stamp`，不恢复 `.sets`

**位置**：`_cmd_rollback_body`（约 5937 行）

**证据【代码】**：回滚只 `cp "$_last/.stamp"`；`.sets` 仍是回滚前（较新）的启用清单。下一次 `fetch` 的“增幅熔断”用 `.sets` 判断“运营商表有没有变化”；回滚后如果清单不同，会跳过相对增幅比较。

**影响**：熔断的一道保险在回滚后失效一次；不会造成直接错误，但属于可修的口径缺口。

**修法**：快照里若有 `.sets` 一并恢复；没有则删除当前 `.sets`，让下次 fetch 重新建立基准。

#### B22（P2）`probe` 仍然只有文本、接口硬编码（0.2.2 F-2 遗留）

**位置**：`cmd_probe`（约 4022 行）；`PROBE_IFACES` 默认 `pppoe-wan1 pppoe-wan2`。

**影响**：LuCI 无法安全调用（同步 25s×32MiB 会超 rpcd exec 超时）；设备名不同就直接“失败”。

**修法**：`probe --json` + `--bytes/--time` 小样本 + 从 mwan3 策略推导接口（A3 的 `wan_devices` 可复用）；LuCI 按钮二次确认“会消耗流量”。这是 A3 的延伸，不单独占 P0。

#### B23（P3）默认 dnsmasq conf-dir 没有过 `_dns_dir_ok`

**位置**：`_dns_confdir_detect` 的 default 分支（约 4288–4292 行）→ `_dns_confdir_first`；`_dns_dir_ok` 只在 runtime/ps 分支使用。

**证据【代码】**：`/tmp/dnsmasq.d` 不存在时 root `mkdir -p` 创建，属主 root，安全；但若低权用户预先创建了同名目录（属主非 root），`cmd_dns` 仍会往里写片段。`_dns_dir_ok` 已经能判“属主非 root/组可写”，默认分支没有调用。

**影响**：本地低权用户可通过预创建目录影响 root 写入的 dnsmasq 片段（DNS 劫持面），属于加固项，不是远程漏洞。

**修法**：default 分支也过 `_dns_dir_ok`；不通过则拒绝写入并提示“目录不可信，请让 dnsmasq 自己创建/修复权限”。成本极低。

> 说明：B23 是安全加固，不是本次功能主线的阻塞项；列在这里是因为它和 A1 的 dnsmasq 片段写入同一路径，改 A1 时顺手做最省事。

---

## C. 推荐路线图

### C.1 分批

| 批次 | 内容 | 目标 | 验收 |
|---|---|---|---|
| **0.4.2 补丁（建议先发）** | B1（C1 stale 误报）、B4（jaccard JSON）、B5（失败天数）、B6（拒绝状态）、B8（dns 删除后重启）、B9（verify 兜底形状）、B10（dnstest 口径）、B11（status nft 次数）、B12（文案）、B20（README 口径） | 不改功能面，只修“数字不对/提示不对/每天假警” | jaccard 在 LuCI 可见；`COUNT_FALLBACK_SKIP_DNS=0` 文案正确；清空 DOMAIN_SPLIT 后旧规则不再生效；verify 能报出 isp_fallback 缺失；status 每集合 1 次 nft |
| **0.5.0 可查可钉** | A2 `explain`、A3 `traffic`、A1 `pin` MVP（端口-only + 静态解析）、A9 状态页/配置页落点 | 回答“为什么走这条线”和“这条线现在多少”；把 B 站 PCDN 钉线产品化 | `explain` 对域名/IP 给出集合/策略/线路/兜底；`traffic` 与 `/sys/class/net` 对账一致；pin 规则在 `wire` 后仍在 `@isp_*` 之前且幂等 |
| **0.6.0 可观测** | A4 体检历史/趋势、A5 fake-ip 兼容、A6 数据源新鲜度/韧性（含 B7） | 让“劣化/冻结/拒绝/fake-ip”从沉默变成可解释 | 历史只随手动体检增长；fake-ip 横幅按产品给建议；数据 stale 徽标出现；`fetch --check` 不写 DATA；拒绝后可复查 |
| **0.7.0 生态** | A7 export domains/manifest/fakeip-filter、A8 IPv6 披露、B22 probe JSON、B17 公共库（只抽需要的） | 把代理/DNS 侧和 IPv6 预期补齐 | smartdns/AGH/mihomo/sing-box 导出文件可被对应软件读取（真机验证）；IPv6 提示出现且不阻断 |
| **Backlog/P3** | 完整 IPv6、`flows` TopN、B18/B19/B21/B23 | 视真实需求 | 单独立项，不混入补丁版 |

### C.2 为什么这个顺序

1. **先修口径，再加功能**：B1/B4/B5/B6 会让用户对现有页面的数字失去信任；不修就加功能，等于在错数字上叠新卡片。
2. **先做 explain，再做 pin**：pin 的调试依赖 explain（“pin 到底有没有先命中”）；explain 是只读、低风险，可以先落地。
3. **traffic 和 pin 互不依赖**：可以并行；但 pin 的 LuCI 预检需要 traffic 之外的“解析/集合”信息，工作量在配置页。
4. **历史/fake-ip/数据源放在 0.6**：它们都是“观测/预期”层，不改选路；等 0.5 的 explain/traffic 稳定后再做，回归面小。
5. **IPv6 只披露**：完整 v6 是 L 级，且会动数据管线核心；在 v4 还没被 explain/traffic 完全观测之前不动。

### C.3 每个 P0 的最小验收（建议写进未来 selftest，本次不改）

| 提案 | 验收点 |
|---|---|
| A1 pin | `pin check` 能解析域名并列出命中集合；`wire` 两次结果一致（幂等）；pin 规则在 `@isp_*` 之前；`nftset` 不支持时自动静态兜底；fake-ip 下拒绝动态路径；pin-only 配置下 doctor C1 不再误判“不需要片段” |
| A2 explain | 域名→多 A 记录→每 IP 集合/策略/线路；未命中时给兜底；`--no-resolve` 不出网；`--json` 可被 `json.load` 解析；interval 集合命中正确 |
| A3 traffic | `rx_bytes/tx_bytes` 与 `/sys/class/net/<dev>/statistics/` 逐字节一致；设备缺失显示 `null` 不猜；`--json` 纯 JSON；LuCI 10 秒轮询不增加 nft 调用 |

### C.4 不建议放进路线图的

- 自动重拨、自动切源、自动 flush conntrack；
- 任何新的 cron/systemd/timer/hotplug 常驻钩子；
- DPI、TLS SNI、eBPF 识别；
- 每域名/每元素字节计数；
- 为了“看起来完整”而新增第 7/8 项 doctor 检查。

---

## D. 附录：证据与复现

### D.1 `health --json` 的 Jaccard 小数 bug（本地复现）

用临时 `ISP_SPLIT_BASE`/`ISP_SPLIT_CONF`，不碰生产：

```sh
T=$(mktemp -d)
cat > "$T/conf" <<'EOF'
ISP_SOURCES="yfgao:primary:https://example.invalid
clang:verify:https://example.invalid"
ISP_SOURCE_FILES=""
ISP_TABLE="chinatelecom:isp_tel:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
ISP_VERIFY_ENABLE=1
EOF
mkdir -p "$T/base/state"
printf 'yfgao\tprimary\t1700000000\t0\t\tok\nclang\tverify\t1700000000\t0\t96.12\tok\n' \
  > "$T/base/state/sources.tsv"
ISP_SPLIT_CONF="$T/conf" ISP_SPLIT_BASE="$T/base" \
  sh files/usr/sbin/isp-split health --json
```

实际输出（节选）：

```json
{"sources":[
 {"name":"yfgao","jaccard":null,"status":"ok"},
 {"name":"clang","jaccard":null,"status":"ok"}
],"diff":{"min_jaccard":null}}
```

期望：`"jaccard":96.12`。同一份 `sources.tsv` 里把 `96.12` 换成 `80.00`、`note` 写成“分歧超阈值”，`status` 仍然是 `ok`（B6）。

### D.2 doctor C1 stale 的路径

```text
cron 04:17 -> isp-split refresh
  -> cmd_fetch: 更新 $DATA/.stamp
  -> cmd_apply: 只重放 nft DNS 旁路，不写 dnsmasq 片段
doctor C1:
  frag mtime < $DATA/.stamp -> DNS_FRAGMENT_STALE warn
```

片段内容只依赖 `DOMAIN_SPLIT`/`DNS_TABLE`/线路状态，和 IP 数据无关；因此这是“用错误的代理指标判新鲜度”，不是真的过期。

### D.3 离线基线

```text
$ sh tools/selftest.sh
通过 356 项，失败 5 项，跳过 10 项
real 1m13.211s
```

5 项失败均为非 root 环境的 conf-dir/dnsmasq 片段权限项，与 fix39 文档记录一致；本次分析未改任何断言。

### D.4 合成 13k CIDR 的构建耗时

```text
13,000 条 CIDR / 4 个运营商
build.sh 整链（含互斥化）: 0.54s（x86_64，临时目录）
```

用于判断 B16 的收益量级；路由器 CPU 更慢，但 fetch 的主要成本仍是下载，构建不是瓶颈。

### D.5 关键代码位置索引

| 主题 | 位置 |
|---|---|
| `status` 每集合 3 次 nft | `files/usr/sbin/isp-split:_status_one`（3676）、`cmd_status_json:_sj`（3722）、`count_set_elements`（321） |
| Jaccard JSON | `cmd_health_json`（3781–3782） |
| 失败次数 | `_state_fail_plus`（584） |
| 拒绝状态 | `_sources_report`（955–965）、`cmd_health_json`（3783–3790） |
| diff 复查 | `_archive_source` 注释（769）、拒绝 `exit 3`（1249）、`cmd_diff`（1438） |
| dns 删除不重启 | `_cmd_dns_body`（4946–4958）vs `_n>0` restart（4975） |
| verify 兜底 | `cmd_verify`（3446–3451） |
| dnstest | `cmd_dnstest`（1469–1505） |
| C1 stale | `doctor.sh:doc_check_dns53`（1188–1190、1222） |
| fake-ip grep | `doctor.sh:_doc_fakeip`（1005） |
| TUN owner | `doctor.sh:_doc_tun_owner`（973） |
| selftest 计时 | `cmd_selftest`（1839–1844） |
| build 重复解析 | `build.sh`（43、66） |

---

## 结语

这份提案的核心不是“再加十个功能”，而是三句话：

1. **把不可见的决策变成可查询的**（explain、traffic、linecheck 历史）；
2. **把用户已经在手工做的覆盖变成产品能力**（pin，且明确它和 DNS 分线的边界）；
3. **把会误导人的数字/提示先修对**（doctor C1 stale、Jaccard null、失败天数、拒绝状态、dns 删除不生效）。

三者都遵守同一条底线：**不装新定时任务、不引新依赖、不新增外部服务、不扩大 doctor 的误报面**。
