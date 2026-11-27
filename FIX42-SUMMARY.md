# FIX42-SUMMARY — 0.5.0 第一批：IP_SPLIT 手动补段 + geo 反哺（PCDN 时代结构修复）

仓库：`openwrt-isp-split`，基线 `main @ c68d5d5`（v0.4.1 已发布），本次版本 **0.5.0**
（`PKG_RELEASE=1`）。**已提交、未 push、未 tag**，等 Hermes 验收后统一发。

生产环境全程未触碰：所有证据来自 Hermes 提供的实测记录与本仓库的离线夹具。

---

## 0. 一句话结论

PCDN 把"动态家宽 IP"变成了视频流量的常态，而"运营商段表 + 兜底 balanced"这套模型
对这类目标**结构上就是覆盖不到的**。这次把两件事做成产品能力：

1. **手动补段变成一次配置、永久生效**（`IP_SPLIT`，每次渲染集合时自动重新合并），
   干掉"手工 `nft add element` + 追加数据文件 → 04:17 定时 fetch 重建后丢光"的循环；
2. **把兜底缺口变成建议**（`isp-split suggest`，从 conntrack + 归属地存档反推该补哪些段），
   并且**绝不进 cron**——补段是人的决定，不是定时器的决定。

顺带修掉一个"看起来配了其实永远不生效"的规则顺序缺陷（端口钉线被集合规则前置拦截）。

| 交付 | 状态 | 落点 |
|---|---|---|
| **D1** IP_SPLIT 手动补段（fetch 后自动合并） | ✅ | `files/usr/sbin/isp-split`、`files/etc/isp-split.conf`、doctor C1、plan |
| **D2** `suggest` 兜底缺口建议（只读 + `--apply`） | ✅ | `files/usr/sbin/isp-split`（新子命令） |
| **D3** LuCI 落点（手动补段区块 + 兜底占比提示） | ✅ | `config.js`、`overview.js`、`isp-split.css` |
| **D4** 端口钉线规则顺序缺陷 | ✅ | `rules-splice.awk`、`ISP_PIN_PORTS`、`verify` 断言 |
| 版本 0.5.0（五处 + sync-feed + release body + 断言） | ✅ | `Makefile`×2、`ISP_VERSION`、`feed`×2、`release.yml`、`verify-release-version.sh` |

---

## 1. 生产证据 → 修复对照表

| # | 生产实锤（2026-11-15~27，Hermes 提供） | 结构性问题 | 本次修复 | 复现/断言 |
|---|---|---|---|---|
| 1 | B 站卡顿两次，根因都是**家宽 PCDN 节点不在运营商集合**：`101.22.79.76`（联通家宽段）、`110.250.151.x`（唐山联通家宽段）→ 落兜底 → balanced 40% 摇到电信 → 跨网卡顿 | 段表只收录"运营商汇总段"，动态家宽地址永远缺席 | D1：`IP_SPLIT` 把这批地址直接钉到 `wanb_only`，与段表无关 | selftest 35.1/35.3（合并 + 优先）；35.7（suggest 从 conntrack 里认出这类目标） |
| 2 | 手动止血流程：`nft add element` + 追加数据文件行 → **每日 04:17 `isp-split refresh` 重建集合后反复丢失** | 手动改动落在"会被整体替换"的产物上，没有合并层 | D1：渲染层是纯函数（段表数据 + 当前配置 → 合并产物），fetch/apply/wire/rollback 每次都重算；`loadfile` 指向合并产物，重启也在 | selftest 35.4（连跑两次 fetch 模拟每日重建）、35.5（只跑 apply 也生效）、35.5c（清空后清理产物） |
| 3 | 决定性线索：`linecheck` 的归属地存档**早已记录** `101.22.79.76 → 河北省唐山市 联通`，探测器现成但没有反哺机制 | 有数据、无出口 | D2：`suggest` 先吃这份缓存，未命中才外发；输出"建议 + 证据 + 连接数" | selftest 35.7（缓存命中、无外发）、35.8（阈值）、35.10（写入）、35.11（幂等） |
| 4 | `mwan3_rules` 里集合规则（行 3-6）在端口钉线（行 7 `tcp 4483/8082`）之前 → 端口规则对集合内目标**永远不生效**，"B 站回退 8082 那天这条规则就是摆设" | first-match 链上"更具体的端口规则"被"更宽的网段规则"前置拦截 | D4：`wire` 把命中 `ISP_PIN_PORTS`（默认 4483/8082）的用户规则**整块搬到集合规则之前**；`verify` 逐端口断言 | selftest 35.12（顺序）、35.13（幂等）、35.14（关闭时行为不变） |
| 5 | 视频平台全面 PCDN 化 → 段表+兜底模型覆盖率持续下降，需要"产品级补段/学习机制" | 缺闭环 | D1+D2+D3 形成闭环：**suggest 找缺口 → 写入 IP_SPLIT → 每次渲染自动合并 → 状态页提示兜底占比** | selftest 35.1~35.11；LuCI 改动经 `node --check` |

---

## 2. D1 — IP_SPLIT 手动补段

### 2.1 配置面

```sh
# /etc/isp-split.conf
IP_SPLIT="
101.22.0.0/16:wanb_only
110.250.0.0/16:wanb_only
"
# 可选：外部目录，$IP_LIST_DIR/<策略>.txt，每行一个 CIDR（# 注释）
IP_LIST_DIR=""
```

- 写法与 `DOMAIN_SPLIT` 一致（`<值>:<mwan3 策略>`，多行）；入口统一去 CRLF、整行去注释。
- 新增 `conf` 白名单键：`ip_split` / `ip_list_dir` / `isp_pin_ports`（`conf get` 会输出
  `ipsplit <CIDR> <策略>` 行供 LuCI 渲染）。
- 写入侧校验：CIDR 必须是严格 `a.b.c.d/0-32`；策略必须在 mwan3 中存在；
  `IP_LIST_DIR` 只允许空或绝对路径且不含 `..`；值里禁止 `$ \` " ' \ ; |`。

### 2.2 数据面（为什么这样设计）

```
$BASE/data/<源名>.txt            段表数据（纯净：手动段绝不写回这里）
$BASE/data/.ipsplit/<集合名>.txt  渲染产物 = 段表数据 − 其它策略的手动段 + 本策略的手动段
```

- **渲染是纯函数**：`_ipsplit_render <数据目录>` 每次都从"段表数据 + 当前配置"重算，
  所以重复执行幂等；删掉一条手动段后地址会自动回到原来的集合（不会"扣掉就回不来"）。
- **调用点覆盖所有链路**：`fetch`（替换 `$DATA` 之前渲染到 `data.new`，失败即中止）、
  `apply`、`check`、`selftest`、`wire`（写 ipset 段之前）、`export`（导出与线上一致）。
  `rollback` 走 `cmd_apply` → 自动重算；`refresh`/`sync` 由 fetch+apply 覆盖。
- **重启后仍在**：mwan3 `config ipset` 的 `loadfile` 指向合并产物（`_set_data_file`），
  不是纯净段表数据。`_apply_one`、`_wire_ipset_block`、`_wire_ipset` 全部走同一个 helper。
- **手动段优先**：渲染时从**其它**集合里扣掉手动段覆盖的地址。于是同一 IP 只存在于
  手动段指定的集合里，mwan3 的规则先后不影响归属（与 `build.sh` 的"优先级即占位顺序"同语义）。
- **冲突处理不做删减**：手动段与段表数据重叠时保留手动段本身（不裁剪 CIDR），
  只让其它集合让路；`auto-merge` 由集合标志负责，未开时手动段自然成为独立区间。
- **失败即中止**：渲染失败时 fetch 不替换数据、apply 不刷 nft（`die`），
  绝不允许"手动段静默消失"这种中间态。
- 策略没有启用的运营商行：只告警跳过该组（不允许让每日 fetch 因一行配置整夜不更新）；
  `plan` 里会明确标注"本次不会合并"。

### 2.3 与既有功能的联动

| 落点 | 行为 |
|---|---|
| `fetch` | `data.new` 里先渲染再原子替换；`.ipsplit/` 随数据目录一起进历史快照 |
| `apply` / `check` | 渲染后按合并结果生成 batch（`check` 与 `apply` 结果一致） |
| `wire` | ipset 段 `loadfile` 指向合并文件（重启/热重载都带手动段） |
| `export mihomo/singbox/text` | 导出合并后的集合（否则代理侧"明明补了却漏掉"） |
| `plan` | 新增「手动补段」段：逐条列 CIDR → 策略 → 集合；格式非法时给出计数 |
| `rollback` | 恢复快照后由 apply 重算（快照里的 `.ipsplit` 不参与，避免旧产物覆盖新配置） |
| doctor C1 | 新增 `ip_split_configured` / `ip_split_segments` 事实；有手动段时不再判"无需片段"，改判 `DNS_FRAGMENT_IP_SPLIT_ONLY`（**verdict 仍 ok**，见 §2.4） |

### 2.4 doctor C1 的"不判无需"是怎么落的（判断说明）

任务要求"有手动段时不判'无需'"，同时"doctor 不得新增误报"。这两条一起看，
字面实现（有手动段 + 无片段 → conflict）会**新增误报**：IP 分流本来就不依赖
dnsmasq 片段。因此实现为：

- 旧分支 `DNS_FRAGMENT_NOT_NEEDED`（ok，理由"没有配置域名分流"）只在
  **既没有域名清单、也没有手动段**时成立；
- 有手动段时走新分支 `DNS_FRAGMENT_IP_SPLIT_ONLY`（**仍 ok**），detail 明确写
  "只配置了 IP 分流（含手动补段）"，evidence 写出手动段条数。

即：结论从"什么都没配所以不需要"变成"看到你在做 IP 分流所以不需要"——
这正是"误判要感知 IP_SPLIT 存在"的实质，且 verdict 不回退成 conflict。
selftest 30.2b 断言该 code 与 `ip_split_configured=true`；30.2（无手动段）仍走旧 code，
fix38/39 的 C3 判定逻辑一行未动。

---

## 3. D2 — `isp-split suggest`（geo 反哺）

```
isp-split suggest [--apply [--assume-yes]] [--min-conns N] [--min-bytes N]
```

### 3.1 算法

1. **集合边界一次性导出**：每个启用集合 `nft list set` 一次，解析
   `elements = { a-b, c.d.e.0/24, x }` 三种形态 → 零填充区间 → merge。
   （不是"每个目标 IP 一次 `nft get element`"——13k 元素 × N 集合 × 上千连接会慢到不可用。）
2. **扫 conntrack**：`/proc/net/nf_conntrack`（可 `ISP_SPLIT_CONNTRACK` 覆盖，供离线自检）。
   每条记录取首个 `dst=`/`bytes=`，跳过非公网（0/8、10/8、100.64/10、127/8、169.254/16、
   172.16/12、192.168/16、224/4、240/4），命中任一启用集合的**排除**，其余按 `/24` 聚合。
   - 游标每条记录重置：conntrack 目的 IP 是乱序的，单调游标会把"其实命中集合"的目标误算成兜底
     （自检里就是这么抓到的，见 §7.3）。
3. **阈值**：`conns ≥ SUGGEST_MIN_CONNS`（默认 1000）**或** `bytes ≥ SUGGEST_MIN_BYTES`
   （默认 1 MiB）；CLI 可覆盖。
4. **归属地**：先查 `state/linecheck.geo.tsv` 缓存（该 `/24` 内任一 IP），未命中才外发；
   结果写回同一份缓存（`_lc_geo_cache_put`，4 列 TSV、清洗过 TAB/CR/LF）。
5. **聚合成建议**：同一 `/16` 内 ≥2 个同运营商 `/24` → 建议 `/16`（贴近生产手工补的形态），
   否则 `/24`；运营商 → `ISP_TABLE` 启用行 → 策略。运营商未启用时如实"跳过"并给下一步。
6. **输出**（`--apply` 前只读）：

```
兜底计数（nft counter isp_fallback）: 1272 首包 / 5.0MiB
conntrack 快照: /proc/net/nf_conntrack（N 条连接记录）
---- 建议 ----
建议: 110.250.0.0/16 → wanb_only（联通，证据: linecheck geo + 1272 连接兜底）
```

### 3.2 `--apply`

- 只改 `IP_SPLIT`（等价手工编辑 conf），走 `_conf_write`（写前校验 + 备份 +
  `sh -n` + 回读校验 + 原子 rename）；
- 写入前**展示完整的新 `IP_SPLIT`**；交互确认（tty）或 `--assume-yes`；
  非交互且没给 `--assume-yes` → 直接拒绝，**配置一个字节都不动**（selftest 35.9）；
- 已存在的网段跳过（幂等，35.11）；写入后提示 `isp-split apply`。

### 3.3 隐私与"不进 cron"

- 只发送**聚合后的目标 IP**（默认百度 HTTPS；`LINE_CHECK_GEO_PROVIDER` 可显式切 ip-api），
  不发送内网地址、设备名、MAC、流量内容；`LINE_CHECK_GEO=0` 时**完全不外发**，只用本地缓存；
- 每次运行打印一行隐私声明（外发条数 / 全部命中缓存 / 本版本不含归属地查询）；
- **没有进 cron、没有进 init、没有进 LuCI 自动轮询**——只能人手动跑或（将来）按钮触发。
  selftest 19b.13 继续断言 init/uci-defaults/cron 无体检联动，本次新增代码不含任何定时入口。

---

## 4. D3 — LuCI 落点

| 页面 | 改动 |
|---|---|
| 配置页（`config.js`） | 新增「手动补段」区块：CIDR 输入 + 策略下拉 + 删除（二次确认），标签写「fetch 后自动合并」，说明"与段表数据重叠时手动段优先"；`values()/validateAll()/listErrors()/preflight()/save()` 全部接入 `ip_split`（保存前预检同样走临时副本） |
| 状态页（`overview.js`） | 兜底卡的占比 = 兜底首包 ÷（所有集合首包 + 兜底首包）；**>30%** 时追加一行提示「兜底占比 N%，偏高：运行 isp-split suggest 查看缺口建议」（`title` 里给出首包明细）。**只提示，不自动跑** |
| 样式（`isp-split.css`） | 新增 `.isp-fb-hint`（一行小字、warn 色、不抢卡片数字） |

两处 JS 均通过 `node --check`（完整版 + `FEATURE_LINECHECK=0` 剥离版，见 selftest 19b.9/34.9 同款路径）。

---

## 5. D4 — 端口钉线规则顺序（选型说明）

**症状**：`mwan3_rules` first-match。集合规则（`ip daddr @isp_*`）排在用户的端口钉线规则
（`tcp dport 4483/8082`）之前，于是"集合内目标"永远先命中集合，端口规则对它们**从不生效**。

**两个候选**：

| 方案 | 成本 | 代价 |
|---|---|---|
| A. 端口规则引用时排除集合已覆盖段 | 高：要在渲染时对每条端口规则做"全集差集"，生成上百个 `ip daddr !=` 项，规则体积与可读性都崩 | 每次数据更新都要重算，且用户看不出规则在表达什么 |
| **B. 把端口钉线规则搬到集合规则之前**（**采用**） | 低：`rules-splice.awk` 里加一个"钉线块识别 + 提前输出" | 会改变被搬规则与其它用户规则的相对顺序（仅限声明端口） |

**实现要点**：

- 新配置 `ISP_PIN_PORTS`（默认 `"4483 8082"`，即生产实证的 B 站 PCDN 回退端口；空=关闭，
  回到 0.4.x 行为）；
- `rules-splice.awk` 新增 `is_pin()`：rule 块里 `option/list dest_port|src_port` 命中声明端口即算；
- **锚点搜索跳过钉线块**——否则第二次注入会把规则块插到钉线块之前，把刚修好的顺序翻回去（非幂等）；
- 锚点之后的钉线块被"延后输出"到插入点之前，其它用户规则顺序不动；卸载（insert 为空）时不搬；
- `verify` 新增「端口钉线顺序」段：逐端口打印所在行 vs 第一条集合规则行，✗ 时直接给修复命令。

为什么不是"把默认锚点改到 default_rule 之前"：那会把用户的 `dest_port 443` 之类**宽端口规则**
一起提到集合之前，等于让所有 HTTPS 绕开运营商分流——那是行为回归，不是修复。

---

## 6. 版本与发版

- **版本 0.5.0**：`Makefile` / `luci-app-isp-split/Makefile` / `ISP_VERSION` / 两个 `feed` 壳
  （`tools/sync-feed.sh` 同步并逐字节校验，输出"feed 壳已同步 (PKG_VERSION=0.5.0)"）。
- **release body**：标题 `## v0.5.0 手动补段 + geo 反哺`，安装段目录 `isp-split-0.5.0/`，
  正文按 D1/D2/D4/LuCI/doctor 分节，并写入升级迁移的两条手动段。
- **`verify-release-version.sh` 新增第 6 项断言**：release body 的 `## v$VER` 与
  `isp-split-$VER/scripts/install.sh` 必须与 `PKG_VERSION` 一致（手写 body 最容易漏改）。
  实测：`v0.5.0` 通过；`v0.4.1` 被拒（"错版发车"）。
- **未 push、未 tag**，等 Hermes 验收。

---

## 7. 验证

### 7.1 selftest（离线，无路由器、无网络）

```
通过 373 项，失败 5 项，跳过 10 项
```

- 基线（`c68d5d5`）为 356 通过 / 5 失败 / 10 跳过；本次 **+17** 条断言，失败项与跳过项**完全一致**；
- 5 项失败全是非 root 主机的既有环境用例（`conf-dir` 探测 1 项 + `20.3d~g` dnsmasq 片段 4 项），
  与本次改动无交集（FIX41-SUMMARY 同样标注过）。

### 7.2 新增断言（§35，全部离线）

| 断言 | 覆盖点 |
|---|---|
| 35.1 | fetch 后 `110.250/16` 进 `isp_uni`、`5.5.5/24` 进 `isp_tel` |
| 35.2 | 段表数据保持纯净（手动段不写回 `data/<源名>.txt`） |
| 35.3 | 手动段优先级：重叠地址从其它集合让出 |
| 35.4 | **连续两次 fetch（模拟每日 04:17 重建）后手动段仍幸存** ← 生产问题的回归断言 |
| 35.5 / 35.5b / 35.5c | 只跑 apply 也生效 / 删掉手动段后地址回到段表集合（可逆）/ 清空后清理产物 |
| 35.6 | 渲染入口统一（apply 与 wire 的 `loadfile` 都走 `_set_data_file`） |
| 35.7 / 35.8 | suggest 输出格式 + `/24→/16` 聚合 + 命中集合的目标被排除 / 阈值生效 |
| 35.9 / 35.10 / 35.11 | 非交互 `--apply` 被拒且配置未改动 / `--assume-yes` 写入 / 幂等 |
| 35.12 / 35.13 / 35.14 | 端口钉线在集合规则之前 / 搬迁幂等 / `ISP_PIN_PORTS` 为空时行为不变 |
| 30.2b | doctor C1：只有手动补段 → `ok / DNS_FRAGMENT_IP_SPLIT_ONLY`，`ip_split_configured=true` |

### 7.3 本机 mock（fetch 重建 + 幸存）

用假 `uclient-fetch` 把镜像映射到夹具，构造"电信 1.x/5.x，联通 110.250/16 + 2.x"的段表：

- 第一轮 fetch：`data/unicom_cnc.txt` 仍是 5 行原始数据（纯净），
  `data/.ipsplit/isp_uni.txt` = 原始 5 行 + `101.22.0.0/16` + `110.250.0.0/16`；
  手动段 `2.1.0.0/16:wan_only` 让 `2.1.0.0/16` 从 `isp_uni` 消失、出现在 `isp_tel`；
- 第二轮 fetch（模拟次日重建）：结果逐字节一致（幂等 + 幸存）；
- 把 `IP_SPLIT` 改成只剩 `110.250.0.0/16` 再 `apply`：`2.1.0.0/16` 自动回到 `isp_uni`。

调试过程中还抓到并修掉一个真问题：`conntrack` 目的 IP 乱序时，单调游标会漏判
"已命中集合"的目标（自检 35.7 因此先红后绿），修复见 `_sg_scan` 注释。

### 7.4 其他

- `sh -n`：主脚本、doctor、selftest、conf 模板全部通过；busybox ash 兼容（无 `[[`/`mapfile`/`jq`/`date %N`）。
- 剥离版（`FEATURE_LINECHECK=0`）：`strip-linecheck.sh` 零残留（`linecheck`/`LINE_CHECK`/`线路体检`
  一个都不出现）；剥离版 `suggest` 自动降级为"未查询（本版本不含归属地查询）"，不报错、不瞎猜。
- `verify-release-version.sh v0.5.0` 通过、`v0.4.1` 被拒。
- LuCI：`config.js` / `overview.js` 完整版与剥离版 `node --check` 通过。

---

## 8. 升级说明（0.4.1 → 0.5.0）

1. **升级包**（opkg/apk 会保留现有 `/etc/isp-split.conf`，新配置项默认值不写入老文件）：

   ```sh
   # 方式一：一键脚本（Release 页版本号换成 0.5.0）
   wget -O /tmp/isp.tgz https://github.com/jihebube/openwrt-isp-split/releases/download/v0.5.0/isp-split-0.5.0.tar.gz
   mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp
   sh /tmp/isp/isp-split-0.5.0/scripts/install.sh --all
   ```

2. **把生产当前手工加的两段搬进配置**（这是本次迁移的核心；搬完就可以删掉当时往
   数据文件里追加的行和手工 `nft add element`）：

   ```sh
   isp-split conf set ip_split "101.22.0.0/16:wanb_only|110.250.0.0/16:wanb_only"
   # 等价于手工编辑 /etc/isp-split.conf：
   # IP_SPLIT="
   # 101.22.0.0/16:wanb_only
   # 110.250.0.0/16:wanb_only
   # "
   ```

   也可以放到外部目录批量维护：`IP_LIST_DIR=/etc/isp-split/ips`，`ips/wanb_only.txt`
   每行一个 CIDR。策略名必须是 mwan3 里已存在的策略（`wanb_only` 满足）。

3. **让改动生效并确认**：

   ```sh
   isp-split apply          # 只刷集合；不需要重写 mwan3 配置
   isp-split verify         # 看「端口钉线顺序」段是否为 ✓
   isp-split doctor         # C1 应显示 ok / DNS_FRAGMENT_IP_SPLIT_ONLY
   ```

   `wire` 不需要重跑（除非想同时拿到 D4 的端口规则搬迁；重跑一次 `isp-split wire`
   就会把 4483/8082 的钉线规则提到集合规则之前）。

4. **可选：让系统自己找缺口**（人工决定何时跑、跑不跑）：

   ```sh
   isp-split suggest                 # 只读，看建议与证据
   isp-split suggest --apply         # 写进 IP_SPLIT（会展示 + 确认）
   ```

5. 回滚：`isp-split rollback`（数据）/ 卸载用 `isp-split uninstall`。
   手动段只在 `IP_SPLIT` 里，删掉对应行 + `apply` 即恢复原归属。

---

## 9. 已知限制 / 后续（不在本批）

1. `suggest` 的"未命中"判定依赖 nft 集合的**当前**成员；如果某天集合是空的（fetch 失败留旧数据
   除外），会把所有目标都算成兜底——已在输出里打印集合条数供核对，但没有硬门。
2. `/24 → /16` 的聚合是"同一 `/16` 内 ≥2 个同运营商 `/24`"，不做跨 `/16` 合并，
   也不做"按省/市"细分（归属地文本里的地市信息只作证据展示）。
3. conntrack 在 flow-offload 下看不到已卸载流（与 A2 的 `flows` 提案同一限制），
   `suggest` 的样本会偏小。
4. 手动段目前只支持 `<CIDR>:<策略>`；按"运营商源名"而非策略的写法（更贴近 ISP_TABLE）
   留待 A1（pin）落地时一起考虑。
5. LuCI 只做"提示 + 编辑"，没有做 suggest 的一键按钮（D2 允许，但按钮需要新增 rpcd 白名单
   与后台执行语义，留到下一批与 A1 的 pin 一起做）。
6. `IP_SPLIT` 的条目数没有上限校验（每条都要过一次 awk 管线，实际几十条量级无压力）。

---

## 10. 改动文件清单

```
files/etc/isp-split.conf                  IP_SPLIT / IP_LIST_DIR / ISP_PIN_PORTS + 注释里的生产案例
files/usr/sbin/isp-split                  手动补段渲染层、suggest 子命令、渲染入口统一、
                                          verify 端口顺序段、plan 手动补段段、conf 白名单与校验
files/usr/lib/isp-split/rules-splice.awk  端口钉线块识别 + 提前输出（pinports）
files/usr/lib/isp-split/doctor.sh         C1：ip_split_configured / ip_split_segments / 新 code
luci-app-isp-split/.../config.js          手动补段区块 + 保存/预检接线
luci-app-isp-split/.../overview.js        兜底占比 >30% 提示
luci-app-isp-split/.../isp-split.css      .isp-fb-hint
Makefile / luci-app-isp-split/Makefile    0.5.0
feed/op-packages/**                       sync-feed 同步（版本 0.5.0 + 逐字节一致）
.github/workflows/release.yml             release body -> v0.5.0（含升级迁移说明）
scripts/verify-release-version.sh         新增 release body 版本断言
docs/CONFIGURATION.md                     手动补段 / suggest / ISP_PIN_PORTS / 配置项表
README.md                                 功能清单、配置样例、与 iKuai 对比表
tools/selftest.sh                         §30.2b + §35（17 条断言）
```

---

## 11. 提交

单条提交，落在 `c68d5d5` 之上（`git log -1` 查看 hash 与完整信息），标题：

```
feat: 0.5.0 第一批——IP_SPLIT 手动补段 + suggest 反哺 + 端口钉线顺序（fix42）
```

24 个文件、+3325/−39。**未 push、未 tag**，等 Hermes 验收后统一发。
