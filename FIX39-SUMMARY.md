# FIX39 — doctor C3 掩码表达式求值（消除 OpenWrt 自带 mangle 表的保守误报）

仓库：`openwrt-isp-split`，基线 `ec8063f`（fix38，未发版），本修复版本 **0.4.1**（版本号不再进位，
与 fix38 同发）。生产现场由 Hermes 取证，本仓库未连接生产。

## 1. 现象（第一层修完后的第二层误报）

fix38 之后生产 doctor 的检查三（位段占用）**仍然**判 `conflict` /
`CTMARK_COLLISION`，但写者不再来自 mwan3 自家链，而是 OpenWrt 固件自带的 fwmark
同步机制（`nft -a list ruleset` 原文）：

```
table ip mangle {
	chain PREROUTING {
		type filter hook prerouting priority mangle; policy accept;
		ct mark & 0x00ff0000 != 0x00000000 meta mark set ct mark & 0x00ff0000
	}
	chain OUTPUT {
		type route hook output priority mangle; policy accept;
		ct state new meta mark & 0x00ff0000 != 0x00000000 ct mark set meta mark & 0x00ff0000
	}
}
table ip6 mangle { ... 同款 ... }
```

该机制用的位段是 `0x00ff0000`（bits 16–23），mwan3 的 `mmx_mask=0x3f00`（bits 8–13），
`0x00ff0000 & 0x00003f00 = 0`——**物理上不可能重叠**。doctor 却报了"有程序改写了
ct mark 的位段"，Step0 硬门禁继续阻断。

## 2. 误报机理

C3 的旧求值只有"字面值"一条路，遇到 `ct mark set <表达式>` 时用一个**错误的近似**：

```sh
# fix38 版（简化）
mask_clear) _w_cleared=$(( (~mask) & _M )) ;;   # 把"mask 之外被清零的位"当成"写了位段"
```

`ct mark set meta mark & 0x00ff0000` 于是被算成"清掉了 `~0x00ff0000 & 0x3f00 = 0x3f00`"
——正是 mwan3 的整段，必然 conflict。P4 解析器也没有"这行读的是哪个字段"的信息，
既分不出跨字段同步（`ct ← meta`）与同字段掩码（`ct ← ct`），也认不出读向
（`meta ← ct`）。

三个具体缺陷：

1. **判据用错了位**：nft 的 `x & mask` 语义是"只保留 mask 内的位"，规则**写进**
   目标字段的位就是 mask（有 `| orbits` 时是 `mask | orbits`）；mask 之外的位由来源
   字段当时的值决定，不是这条规则写入的值。拿 `~mask` 当"写入位"对任何掩码同步规则
   都会误报。
2. **没有来源维度**：`meta mark set ct mark & 0x00ff0000`（把 ct mark 搬回 packet
   mark）只是**读** ct mark，根本进不了 conntrack，却和 `ct mark set ...` 一样被计入。
3. **无法判定的形态没有区分**：`ct mark set meta mark`（无掩码=整值写）在旧解析里
   落 `form=other`、touched=0，被静默归到"位段之外"——**该保守的地方反而不保守**。

## 3. 修复：把"写了哪些位"变成确定的求值

### 3.1 解析层（`doc_p4_writers`）

TSV 增加第 10 列 `src`：RHS 首个操作数的来源（`meta` / `ct` / `lit` / `other`，
行首锚定，不会把 `meta mark & 0x… != 0x…` 的条件段误当来源）。

### 3.2 求值层（`_doc_wr_eval`，C3/C5 唯一实现）

| # | 规则形态（nft 原文） | 求值 | 判定 |
| --- | --- | --- | --- |
| ① | `ct mark set 0x100`（字面值） | 覆盖位 = 值 | `值 & mmx_mask` ≠ 0 → `CTMARK_COLLISION`（fix38 行为，保留） |
| ② | `ct mark set meta mark & 0x00ff0000`（跨字段掩码，可带 `\| orbits`） | 覆盖位 = `mask \| orbits` | `& mmx_mask == 0` → **不报**，findings 记 `MARK_FWMARK_DISJOINT`（info，含「无重叠（已验证）」） |
| ②′ | `ct mark set meta mark & 0x00003f00` | 覆盖位 = `0x3f00` | 有交集 → 仍 `conflict`（断言 b） |
| ③ | `ct mark set meta mark`（无掩码=整值写） | 不可判定（`known=0`） | 保守 `conflict`，文案点明"无法静态求值"（断言 c） |
| ④ | `ct mark set ct mark & 0xffffc1ff \| 0x100`（同字段清+置） | 写 = `orbits`，清 = `~mask`，**两半取并集** | 与 fix38 同口径（mwan3 自家按归属排除） |
| ⑤ | `meta mark set ct mark & 0x00ff0000`（读向） | 不写 ct mark | **不报**，findings 记 `MARK_READ_DIRECTION`（info） |
| ⑥ | `meta mark set meta mark & <mask> \| <orbits>`（packet mark 同款） | 同 ②/④ | 写进位段才算重叠（C3 只关心会进 ct mark 的 packet mark 位） |
| ⑦ | `ct mark set ct mark`（自赋值） | 一位不改 | 不报（no-op） |

判定只在"覆盖位 & mmx_mask"上做，**不再看 mask 之外被清零的位**。

### 3.3 判定依据必须可见

求出不重叠时，findings 追加一条 info（不改 verdict、不改计数、不进 summary）：

```
[MARK_FWMARK_DISJOINT] mangle OUTPUT 的 fwmark 同步使用 0x00ff0000 位段，与 mmx_mask(0x3F00) 无重叠（已验证）
[MARK_READ_DIRECTION] 有 2 条规则只读 ct mark、写 packet mark（读向，例如 mangle PREROUTING 的 ct mark & 0x00ff0000），不写 ct mark，不计入冲突
```

按 `表/链/位段` 去重（ip 与 ip6 的同款规则只出一条），最多 4 条。C3 facts 新增
`write_eval{rule,mmx_mask,writers[],disjoint_count,read_direction_count,unevaluable_count}`：
每条第三方写者一条 `{fam,table,chain,handle,field,form,src,expr,bits,known,kind,overlap}`，
用户可以直接看到"这条规则写了哪些位、为什么判不重叠"。

字面值形态（①）落在位段之外时本来就有自己的 `MARK_OUTSIDE`（ok）finding，不再重复
记 `MARK_FWMARK_DISJOINT`；后者专指"掩码表达式求值后不重叠"，文案里的位段是规则
自己用的那一段。

### 3.4 连带修：C5 不再为同一批 mangle 表报 legacy 残留

`table ip mangle` / `table ip6 mangle` 是 ip/ip6 family，归属仍是 `legacy`（fix38 的
"非 inet 表 = iptables-nft 残留"口径不变——iptables 时代的 DPI 也可能落在同名表里，
不能按表名放过）。但 C5 的 `LEGACY_MARK_WRITER` 现在**只在 legacy 写者真的写了位段内
的位**时告警；写入位段外的 legacy 写者降为 `MARK_WRITERS_OUTSIDE`（ok），说明里带
"经掩码表达式求值也不重叠"。否则 C3 修好了、C5 又冒一条 warn，用户会以为还有问题。

## 4. 与 fix38 的关系

- **fix38 管归属**：mwan3 自家表/链整表排除、值签名永不作为归属依据（`0x100` 不是
  "OAF 的证据"）。本单**不动**这套判据，30.35–30.38 全部原样通过。
- **fix39 管求值**：非自家写者的"写了哪些位"从"mask 之外的位也算"改成"覆盖位 =
  mask | orbits"，并补上读向/不可判定两条边界。
- 两者叠加后 C3 的三段式：**是谁写（归属）→ 写了哪些位（求值）→ 有没有先手 rule
  （顺序）**。任何一段缺失都会产生一层新的误报，这正是 fix38→fix39 的路径。
- 排除清单仍有意义：即使位段真重叠，mwan3 自己的写者也不该报（30.44 就是这个反证）。

**已知边界（有意为之，写在这里以免下一轮当成 bug）**：

- 跨字段同步规则在 mask 之外**会**把目标字段的其它位写成 0（`ct mark := packet_mark
  & 0x00ff0000` 等于把 ct mark 其它位清零）。生产上这条规则由 `ct state new` 限定、
  且 ct mark 在该点通常还是空值，实测不影响 mwan3；若将来有人在 `ct state established`
  上也挂同款规则，需要重新评估——这属于求值口径的语义边界，不是解析遗漏。
- 同字段掩码写（④）仍按"写 + 清"两半算，宁可保守：`ct mark set ct mark & 0xffff00ff`
  这类"只清不置"的规则照样能报。

## 5. 断言清单（tools/selftest.sh）

| 编号 | 断言 | 覆盖点 |
| --- | --- | --- |
| 30.40 | OpenWrt 自带 mangle 表（`ip`/`ip6` 的 OUTPUT 同步 + PREROUTING 读向）→ `ok`，findings 含 `MARK_FWMARK_DISJOINT` 且文案有「无重叠（已验证）」 | 断言 a（本修复主回归） |
| 30.41 | `ct mark set meta mark & 0x3f00`（掩码真压在位段上）→ `conflict / CTMARK_COLLISION` | 断言 b |
| 30.42 | `ct mark set meta mark`（无掩码整值写）→ 保守 `conflict`，文案含「无法静态求值」 | 断言 c |
| 30.43 | `ct mark set 0x100`（字面值落在位段）→ 仍 `conflict` | 断言 d（fix38 不回退） |
| 30.44 | `mwan3_iface_in_wan1` 同款线路打标 → 不报（`excluded_count=1`） | 断言 e（fix38 不回退） |
| 30.45 | `meta mark set ct mark & 0x00ff0000` 单条读向 → `ok` + `MARK_READ_DIRECTION` | 读向不计冲突 |
| 30.46 | C5：OpenWrt mangle 表（legacy family）写入位段外 → `ok / MARK_WRITERS_OUTSIDE`，`legacy_in_mask=0` | C5 连带修 |
| 31.11 | 端到端 `doctor --json`：mangle（ip+ip6）+ mwan3 → C3/C5 `ok`、`warn=0`、`conflict=0`、rc≠2、info 含「无重叠（已验证）」、门禁无 `CHECK_CONFLICT` | 用户可见行为 |
| 31.12 | 同一夹具 + `ct mark set meta mark & 0x00003f00` → `conflict`、detail 带完整表达式、rc=2、门禁阻断 | 对照面（真重叠仍报） |

原有 30.11–30.39（含 fix38 的 30.35–30.39）语义未放宽，全部通过；30.23（legacy
写者落在位段内）仍然 `warn`。

## 6. 验证结果

### 6.1 selftest

`sh tools/selftest.sh`：

- 通过 **356** 项，失败 **5** 项，跳过 10 项。
- 基线对照：在 `ec8063f` 的独立 worktree（`git worktree add /tmp/fix39-base ec8063f`）
  跑同一套 selftest，结果是**通过 347 / 失败 5 / 跳过 10**，失败项与本分支逐条相同：
  第 7 节 conf-dir（需 uid=0）+ 20.3d/20.3e/20.3f/20.3g（需 root/dnsmasq 片段权限）。
  即新增的 9 项断言全绿（347 + 9 = 356），失败面零变化。
- 新增 30.40–30.46（7 项）、31.11、31.12（2 项）全绿。

### 6.2 mock 对照（`isp-split doctor`，真实 CLI + stub nft/uci/ip）

夹具 A = 生产形态：`table ip mangle` + `table ip6 mangle`（OUTPUT 同步 +
PREROUTING 读向）+ `table inet mwan3`（iface_in 线路打标 + `mwan3_or_ct_0x100`），
ip rule `2005 fwmark 0x500/0x3f00 lookup 5`，`E2E_MASK=0x3F00`。

```
[3/6] 标记位段（mmx_mask）占用与读写一致性
  状态: ok  置信度: high
  · [MARK_OUTSIDE] 第三方 mark 写者共 4 个，全部落在 mmx_mask 之外
  · [MARK_FWMARK_DISJOINT] mangle OUTPUT 的 fwmark 同步使用 0x00ff0000 位段，与 mmx_mask(0x3F00) 无重叠（已验证）
  · [MARK_READ_DIRECTION] 有 2 条规则只读 ct mark、写 packet mark（读向，例如 mangle PREROUTING 的 ct mark & 0x00ff0000），不写 ct mark，不计入冲突
  建议: 标记位段只有 mwan3/isp-split 自己（或位段之外的第三方）在用，分流选路正常。

[5/6] 第三方 mark 写者清单与 mwan3 归属
  状态: ok  置信度: high
  · [MARK_WRITERS_OUTSIDE] 第三方/legacy 写者共 4 个，写入位均不在 mmx_mask 位段内（ip/ip6 表里的 4 条经掩码表达式求值也不重叠）

== 汇总: ok 5  warn 0  conflict 0  unknown 1（最差: unknown）
  结论: 没有发现会让分流静默失效的冲突
  wire/apply 门: 阻断（MWAN3_NOT_INSTALLED）
```

`MWAN3_NOT_INSTALLED` 是 mock 跑在开发机上的主机前提（没有 `/lib/mwan3/mwan3.sh`），
与 C3 无关；`unknown 1` 来自 C1（mock 里 :53 无监听）。**关键是 `conflict 0`、门禁没有
`CHECK_CONFLICT`。**

C3 facts 的判定留痕（`jq` 不可用，以下为 `python3 -m json.tool` 摘录）：

```
"write_eval": {
  "rule": "覆盖位 = mask | orbits（跨字段）；同字段按 mask 内写 + mask 外清；无掩码整值写不可判定",
  "mmx_mask": "0x3F00",
  "writers": [
    {"fam":"ip","table":"mangle","chain":"PREROUTING","field":"mark","form":"mask_clear","src":"ct",
     "expr":"ct mark & 0x00ff0000","bits":"0x0","known":true,"kind":"read_from_ct","overlap":false},
    {"fam":"ip","table":"mangle","chain":"OUTPUT","field":"ctmark","form":"mask_clear","src":"meta",
     "expr":"meta mark & 0x00ff0000","bits":"0xff0000","known":true,"kind":"mask_expr","overlap":false},
    {"fam":"ip6","table":"mangle","chain":"PREROUTING", ... "kind":"read_from_ct","overlap":false},
    {"fam":"ip6","table":"mangle","chain":"OUTPUT", ... "expr":"meta mark & 0x00ff0000","bits":"0xff0000","overlap":false}
  ],
  "disjoint_count": 1, "read_direction_count": 2, "unevaluable_count": 0
}
```

### 6.3 三形态对照（同一 mock，换成三种 ct 写者）

| 规则 | `write_eval.writers[0]` | C3 verdict | finding |
| --- | --- | --- | --- |
| `ct mark set meta mark & 0x00ff0000` | `kind=mask_expr, bits=0xff0000, overlap=false` | `ok` | `MARK_OUTSIDE` + `MARK_FWMARK_DISJOINT`（info） |
| `ct mark set meta mark & 0x00003f00` | `kind=mask_expr, bits=0x3f00, overlap=true` | `conflict` | `CTMARK_COLLISION`（detail：`inet evil prerouting(meta mark & 0x00003f00)`） |
| `ct mark set meta mark` | `kind=unevaluable, known=false, overlap=true` | `conflict` | `CTMARK_COLLISION`（detail 追加「其中 1 条 ct mark 写入形态无法静态求值…按保守口径计入」） |
| `ct mark set 0x00000100` | `kind=literal, bits=0x100, overlap=true` | `conflict` | `CTMARK_COLLISION`（hint 仍是低置信度的值签名） |

三份 JSON 均用 Python `json.load` 解析通过（单行、括号平衡、6 项齐）；
`info` verdict 只出现在 findings 里，`checks[].verdict` 仍是 `ok/warn/conflict/unknown`
四值，LuCI 首启向导只按 `checks[].status` 上色、findings 逐行显示 detail，不受影响。

## 7. 版本、文件与发布纪律

- 版本 **0.4.1**（版本号不再进位，与 fix38 同发）：`Makefile`、
  `luci-app-isp-split/Makefile`、`feed/op-packages/isp-split/Makefile`、
  `feed/op-packages/luci-app-isp-split/Makefile`、`files/usr/sbin/isp-split:ISP_VERSION`
  五处一致，本次未改动。
- 改动文件：`files/usr/lib/isp-split/doctor.sh`（+ `tools/sync-feed.sh` 同步的 feed
  镜像，selftest 32.6 逐字节一致）、`tools/selftest.sh`、本文件。
- busybox ash 纪律照旧：无 `[[` / `read -a` / `mapfile` / `local` / `date %N` / `jq`，
  `sh -n` 通过（selftest 32.8）。
- 本次只 commit，**不 push、不 tag**；生产验证由 Hermes 统一做。
