# FIX38 — doctor C3 把 mwan3 自家链误判成第三方 DPI（误报修复）

仓库：`openwrt-isp-split`，基线 `1e14dd2`（v0.4.0），本修复版本 **0.4.1**。
生产现场（Kwrt 25.12 + mwan3-nft 3.6.12）由 Hermes 取证，本仓库未连接生产。

## 1. 现象

`isp-split doctor` 的检查三（位段占用）在生产判 `conflict`，finding 为
`CTMARK_COLLISION`，文案「有程序在写 ct mark 的位段（OAF 类 DPI）」，导到 LuCI
首启向导 Step0 硬门禁（`summary.conflict>0` 即 disabled「下一步」）。
但生产**没有 OAF**：无进程、无包、无 OAF nft 规则。

## 2. 误报机理（四个问题叠在一起）

1. **P4 全表扫描把 mwan3 自己的 ct mark 同步规则也当成"写者"。**
   mwan3-nft 3.6 为了跨 register 复制 mark，会为每个线路值生成
   `mwan3_or_ct_<mark>` 链，内容为：

   ```
   ct mark set ct mark & 0xffffc1ff | 0x00000100
   ```

   这正是 mwan3 的 wan1 线路值（0x100，掩码 0x3f00）。上游实现见
   `dl12345/mwan3` v3.6.12 `common.sh: mwan3_build_or_chains_nft()`。
   `iface_in_*` / `policy_*` / `dynamic` 链里的 `meta mark set ... | 0x100` 同理。

2. **归属判据把 family 和链名写死。**
   旧 `_doc_owner_of` 只认「`inet` + 表名 `mwan3` + 链名 `mwan3*`」：
   - 非 `inet` 的同名表（Kwrt 兼容层 / iptables-nft 残留会留 `ip mwan3`、`ip6 mwan3`）
     整表落 `legacy` → 被当成第三方；
   - `inet mwan3` 里不以 `mwan3` 开头的子链（`iface_in_*`、`policy_*`、`dynamic`、
     `mwan3_hook` 等）被归成 isp-split 或"外来链"。

3. **C3 对 `third_party|legacy` 的 ct 写者一律判 conflict，文案写死「OAF 类 DPI」。**
   只要写者被误归属，值 0x100 又恰好是 OAF 的默认 ct mark，就形成"证据确凿"的假象。

4. **P4 解析器还同时存在漏检，让扫描面既误报又漏报：**
   - `ct mark set` 的值起点写成 `index+13`（应为 `+12`）→ 简单形态
     `ct mark set 0x100` 被读成 `x100`，整条漏掉；
   - `meta mark set meta mark | 0x100` 的 `|` 形态没解析（旧代码只认 `& mask | value`
     和文本 `or`）→ OR 立即数写者漏掉。

**复现（旧 doctor，同一夹具）：**

```
V=conflict
C=CTMARK_COLLISION
detail=有程序在写 ct mark 的位段（OAF 类 DPI），改道语义会串
```

夹具只有 `table ip mwan3`（含 `mwan3_iface_in_wan1`、`mwan3_or_ct_0x100`）和
2001/2002/3001/3002 四条 mwan3 线路 rule，没有任何第三方规则。

## 3. 修复：排除清单（识别优先于值签名）

`_doc_owner_of` 改为"先看表、再看链、最后才看 family"，并成为 C3/C5 的唯一归属判据：

| 优先级 | 判据 | 归属 |
| --- | --- | --- |
| ① | 表名 `mwan3` / `mwan3_*` / `mwan3-*`（**任意 family**：inet/ip/ip6） | mwan3，**整张表连同全部子链**（`iface_in_*`、`iface_out_*`、`policy_*`、`dynamic`、`mwan3_hook`、`mwan3_or_*` 等） |
| ② | 表名 `isptest` / `isp_split*` / `isp-split*` | isp-split |
| ③ | 任意表里链名 `mwan3*` / `iface_in_*` / `iface_out_*` | mwan3（表名被改过的固件兜底） |
| ④ | comment 含 `isp-split` | isp-split |
| ⑤ | 非 `inet` 表 | legacy（iptables-nft 残留） |
| ⑥ | 其余 | third_party |

mmx_mask 位段本身的使用者：

- **nft 写者**：mwan3 表内的线路打标（`meta mark set meta mark & ~mmx | 0x100`）和
  ct mark 同步（`ct mark set ct mark & ~mmx | 0x100`）按①整表排除；
- **ip rule 读者**：`fwmark 0x100/0x200/…/0x3f00`（掩码 = mmx_mask）登记在
  `facts.line_mark_rules`，明确标注 `owner=mwan3`，不参与第三方判据；
- **红线**：`0x100`、`0x200`、`0x3f00` 这些值**永远不作为归属/排除依据**。
  否则"真第三方在非 mwan3 表里 `ct mark set 0x100`"会被一起放过——
  selftest 30.37 就是这个反证。产品名（OAF 等）只作 hint。

其他判据调整：

- `doc_mwan3_table` 不再写死 inet，inet 不存在时回退 ip/ip6（表存在即 mwan3 在跑）。
- C3 facts 新增 `writer_total`、`excluded_count`、`excluded{mwan3,isp_split}`、
  `excluded_writers[]`（含 reason）、`line_mark_rules`、`collision{hint,hint_confidence,hint_basis}`；
  `writers[]` 只列决策相关的第三方/legacy（最多 40 条），避免生产上 100+ 条
  `mwan3_or_*` 把真正的第三方挤出清单。
- `CTMARK_COLLISION` 只对「不在排除清单 + 写入位与 mmx_mask 重叠」的 ct 写者成立；
  detail 列出具体 `fam table chain(value)`，产品名 hint 分三档：
  - 表/链名匹配 → 「疑似 OAF（表名/链名匹配，置信度高）」；
  - 仅值 0x100 → 「疑似 OAF（…仅值签名，置信度低，**不作判据**）」；
  - 都没有 → 「产品未识别（不建议按名字臆断）」。
- C3 advice 不再无脑提 OAF，改为"改 mark 值 / 排到 mwan3 之后；产品名只是提示"。
- C5 外来链判定同步：mwan3 表内的 `iface_in_*` / `iface_out_*` / `policy_*` /
  `dynamic` / `mwan3_hook` 是自有链，不再报 `MWAN3_TABLE_FOREIGN_CHAIN`；
  清单改为第三方优先（40 条）+ 自家 10 条。
- P4 解析器修 `ct mark set` 偏移与 `|` OR 形态。

## 4. 断言清单（tools/selftest.sh）

| 编号 | 断言 | 覆盖点 |
| --- | --- | --- |
| 30.35 | 真实 mwan3 形态（`iface_in_wan1` + `mwan3_or_ct_0x100` + `or` 形态 + `policy_*`/`dynamic`；rule 2001/2002/3001/3002）→ `ok`，`excluded_count=5` | 本修复的主回归 |
| 30.36 | 同一组规则换成 `ip mwan3` 表 → `ok`，`excluded_count=5` | 旧实现整表落 legacy 的复现路径 |
| 30.37 | 真第三方（`inet evil`，`ct mark set 0x100`）→ `conflict/CTMARK_COLLISION`，`hint_confidence=low` | 不能因值撞车放过第三方 |
| 30.38 | 第三方 ct mark 在 `0x80000`（位段外）→ `ok/MARK_OUTSIDE` | 不按字段名定罪 |
| 30.39 | `inet mwan3` 里 `iface_in_*/iface_out_*/policy_*/dynamic/mwan3_hook` → C5 `ok`，无外来链告警 | C5 同源修复 |
| 31.9 | 端到端 `doctor --json`：真实夹具（inet+ip 双表 + 4 条 rule）→ C3 `ok`、无 `CTMARK_COLLISION`、rc=0、gate 无 `CHECK_CONFLICT` | 用户可见行为（除 C3 外不引入其他冲突） |
| 31.10 | 同一夹具 + `table inet evil` 的 `ct mark set 0x100` → `conflict`、rc=2、gate 带 `CHECK_CONFLICT`、hint 低置信度 | 对照面（真第三方仍报） |

原有 30.11–30.17（mwan3 自写 ok / 第三方重叠 conflict / 先手 warn / 位段外 ok /
表缺失 unknown / 自定义 mmx_mask）全部保留，语义未放宽。

## 5. 验证结果

### 5.1 selftest

`sh tools/selftest.sh`：

- 通过 **347** 项，失败 **5** 项，跳过 10 项。
- 5 项失败与 `HEAD`（未修改）逐条相同，全部是开发机环境项：
  第 7 节 conf-dir（需要 uid=0）+ 20.3d/e/f/g（需要 root/dnsmasq 片段权限）。
  在纯净 `HEAD` worktree 上跑同一套 selftest 也是同样 5 项，非本修复引入。
- 新增 30.35/30.36/30.37/30.38/30.39/31.9/31.10 全绿。

### 5.2 mock 环境对照（`isp-split doctor`，真实 CLI）

夹具 A：`table inet mwan3` + `table ip mwan3`，含
`meta mark set meta mark & 0xffffc1ff | 0x100`、
`ct mark set ct mark & 0xffffc1ff | 0x100`、`meta mark set meta mark | 0x100`；
ip rule：2001/2002（lookup 1/2）、3001/3002（unreachable）。

```
[3/6] 标记位段（mmx_mask）占用与读写一致性
  状态: ok  置信度: high
  · 标记位段只有 mwan3/isp-split 自己在用（6 条自家写者已按归属排除，第三方 0 条）
  建议: 标记位段只有 mwan3/isp-split 自己（或位段之外的第三方）在用，分流选路正常。

== 汇总: ok 5  warn 0  conflict 0  unknown 1（最差: unknown）
  wire/apply 门: 阻断（MWAN3_NOT_INSTALLED）
```

夹具 B：A + `table inet evil { chain prerouting { ct mark set 0x00000100 } }`：

```
[3/6] 标记位段（mmx_mask）占用与读写一致性
  状态: conflict  置信度: high
  · [CTMARK_COLLISION] 有第三方程序改写了 ct mark 中与 mmx_mask(0x3F00) 重叠的位：inet evil prerouting(0x00000100)；疑似 OAF（ct mark 0x100 与 mwan3 的 wan1 线路值撞值；仅值签名，置信度低，不作判据）
  建议: 检测到第三方程序改写了 mwan3 用的 ct mark 位段（mmx_mask）；分流可能选错线。先把它的 mark 值移到位段之外，或让它排在 mwan3 之后；产品名只是提示，别按名字下结论。

== 汇总: ok 3  warn 0  conflict 2  unknown 1（最差: conflict）
  wire/apply 门: 阻断（MWAN3_NOT_INSTALLED, CHECK_CONFLICT）
```

说明：`MWAN3_NOT_INSTALLED` 是 mock 跑在开发机上的主机前提（没有
`/lib/mwan3/mwan3.sh`），与 C3 无关；对照的关键差异是
**A 没有 `CHECK_CONFLICT`、B 有**。`unknown 1` 来自 C1（mock 里 :53 无监听）。
conflict 2 = C3 + 继承 C3 的 C5（既有设计，不重复出 finding）。

### 5.3 JSON 形状

两份 mock JSON 均用 Python `json.load` 解析通过；C3 facts 的新字段
（`excluded_count` / `excluded_writers` / `line_mark_rules` / `collision`）
在无冲突时为 `null`/空数组，不影响 UI（UI 只读 `host.mwan3.*`）。

## 6. 版本、文件与发布纪律

- 版本 **0.4.1**（五处一致，`PKG_RELEASE=1`）：
  `Makefile`、`luci-app-isp-split/Makefile`、`feed/op-packages/isp-split/Makefile`、
  `feed/op-packages/luci-app-isp-split/Makefile`、`files/usr/sbin/isp-split:ISP_VERSION`。
- `tools/sync-feed.sh` 已跑，feed 镜像与主源码逐字节一致（selftest 32.6）。
- release body 版本引用已改：标题 `## v0.4.1`、安装路径
  `isp-split-0.4.1/scripts/install.sh`，并补了本次 C3 语义说明。
- 改动文件：`files/usr/lib/isp-split/doctor.sh`（+feed 镜像）、`tools/selftest.sh`、
  `files/usr/sbin/isp-split`、四个 Makefile、`.github/workflows/release.yml`、
  本文件。
- 本次只 commit，**不 push、不 tag**；生产验证由 Hermes 统一做。
