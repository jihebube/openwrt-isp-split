# FIX33B — audit v2 安全修复第二批

- **仓库/基线**：`openwrt-isp-split` @ `27bf8e3`（fix33A 已验收）
- **版本**：仍为 `0.3.1`（本轮不动版本号）
- **改动面**：A-09..A-14 六件低危 + F-23 正式修复 + F-24b 正式修复 + A-15 XSS 回归断言
- **VM**：`192.168.12.1`（root），旧树 `/root/hv33a`，本轮树 `/root/hv33b`
- **纪律**：未 push、未 tag、未操作 GitHub、未触碰生产 `192.168.10.1`；logos/UI 产物（fix32D）未改

## 0. 结果摘要

| 环境 | 基线 | 本轮 | 说明 |
|---|---|---|---|
| VM（root） | **260 / 0 / 4** | **281 / 0 / 4** | +21 项，全部通过；4 项为 root 环境也跳过的 nft/apk 用例 |
| 本机（非 root） | 253 / 5 / 6 | **274 / 5 / 6** | +21 项全部通过；5 项失败与基线同集合（4 项 dnsmasq 环境 + 1 项 uid=0 专属），非本轮回归 |

VM 新增用例原始输出（§26/§27 全部通过）：

```text
== 26. audit v2 安全修复第二批（A-09..A-14）
  ✓ A-09 export 的 README/数据文件走原子落位，预置 symlink 未被写穿
  ✓ A-09 输出目录真实路径为 /etc 时被拒（symlink 组件不能绕过黑名单）
  ✓ A-10 ISP_SPLIT_BASE=/etc（含 //、/etc//）isp-split uninstall 被入口守卫拒绝
  ✓ A-10 teardown validate_base 拒绝 /etc /usr /var / /tmp（含 //、/etc//）
  ✓ A-10 validate_base：默认放行 / 自定义需 --i-know-what-im-doing
  ✓ A-10 自定义 BASE：无 flag 被拒且零删除；带 flag 才按 BASE 删除（假 rm 记录）
  ✓ A-10 沙箱真实删除：DESTDIR 内数据目录与固定清单同时清空
  ✓ A-10 --list 的数据目录随 BASE 推导（base /etc/isp-split）
  ✓ A-11 SECURITY.md/README/ACL 说明覆盖 write=任意子命令与 E() 文本节点
  ✓ A-12 action 全部 40 位 SHA、contents:write 只在 release job、SDK 有 sha256 校验
  ✓ A-12 sha256sums 的 *文件名 解析路径命中
  ✓ A-13 auto 只走百度 HTTPS、响应限体积、缓存 TAB/换行被清洗且截断 200
  ✓ A-14 state=700 / linecheck=700 / last.json=600（umask 077 + 落位 chmod）
  ✓ A-14 install/init 安装时 chmod + 运行时 umask 077 双向落地
== 27. F-23 回显源国内化 / F-24b 按线测 DNS / A-15 XSS 回归
  ✓ F-23 默认源国内 HTTPS；逐 URL 记录 http_code/err/耗时；失败文案与“未出网”已拆分
  ✓ F-23 端到端 JSON 含 exit_probe（失败+成功两条），exit_ip/exit_ok 正常
  ✓ F-23 旧 conf 兼容：install.sh 保留用户已有配置，默认 ECHO 变更不覆盖
  ✓ F-24b 夹具 dns=0.4 -> 400ms；dns 缺失 -> null；0 不再作为哨兵
  ✓ F-24b 秒->毫秒转换：0.0004 -> "<1"，0.4 -> 400，空 -> null
  ✓ F-24b 按线 DNS：nslookup 使用该 WAN 的 DNS IP（scope=wan），fmtMs 支持 "<1ms"
  ✓ A-15 静态断言：三个 view 的 innerHTML 各仅 1 处且为静态 SVG，外网字段只经 E() 文本节点

通过 281 项，失败 0 项，跳过 4 项
```

---

## 1. A-09 export 的 README 写穿 symlink

**修复前 PoC（VM，旧树 `/root/hv33a`）**：预置 `out/README-mihomo.txt -> /tmp/a09old/victim`，再以 root 导出：

```text
rc=0
victim-head=mihomo / OpenClash 用法：
```

即旧实现的 `cat > "$_dir/README-mihomo.txt"` **写穿了符号链接**，受害者文件被 README 覆盖。

**修复**：

- README 与数据文件统一改为 `_tmp_next_to "$_dir"`（同目录 `mktemp`，`O_EXCL`）→ 写入 → `mv -f` 原子落位；`rename` 不跟随 symlink。
- 输出目录在 `mkdir -p` 后用 `pwd -P` 解析真实路径，对字面路径与真实路径各跑一次系统目录黑名单；新增 `/www`、`/usr/share/luci`、`/etc/profile.d`、`/etc/rc.local.d`。
- README 写入后检查临时文件非空，失败即清理并报错。

**修复后（VM，新树 `/root/hv33b`）**：

```text
  /tmp/a09vm/out/isp-chinatelecom.yaml      1 条
[isp-split] 已导出 1 个集合到 /tmp/a09vm/out（格式: mihomo）
rc=0
readme-victim=VICTIM-README
yaml-victim=VICTIM-YAML
mihomo / OpenClash 用法：
[isp-split] 错误: 拒绝导出到系统目录: /etc（/tmp/a09vm/link-to-etc）
```

**selftest**：`✓ A-09 export 的 README/数据文件走原子落位，预置 symlink 未被写穿`；`✓ A-09 输出目录真实路径为 /etc 时被拒`。

---

## 2. A-10 teardown 的 BASE 守卫（本轮事故重演防线）

**修复前 PoC（VM，旧树 teardown + 假 `rm` 只记录不删除）**：

```text
PATH=/tmp/a10old/bin:$PATH ISP_SPLIT_BASE=/etc sh /root/hv33a/.../teardown.sh files
rc=0
-f /usr/sbin/isp-split
-f /etc/init.d/isp-split
-rf /usr/lib/isp-split
-f /etc/isp-split.conf
...
-rf /etc
```

旧实现 `rc=0`，同时删除固定清单（真实安装文件）与 `rm -rf /etc`。

**修复**：

- `teardown.sh` 新增 `validate_base()`：拒绝空、`/`、相对路径、`..`、以及 `/` `/etc` `/usr` `/var` `/bin` `/sbin` `/lib` `/boot` `/dev` `/proc` `/sys` `/www` `/root` `/home` `/tmp` `/mnt` `/opt`；归一化尾部斜杠（含 `//`、`/etc//`）。
- 真实根只接受默认 `/etc/isp-split`；其它目录必须显式 `--i-know-what-im-doing`。
- `ISP_SPLIT_DESTDIR` 非空时，BASE 必须在 DESTDIR 子树内（沙箱不能逃逸到宿主）。
- 固定清单中的数据目录由 `dir etc/isp-split` 改为 `base $BASE`，随 BASE 推导；删除逻辑只剩一条。
- 主脚本入口同步拒绝系统目录，避免 uninstall 在守卫前往 `/etc/work` 写临时文件。

**修复后（VM）**：

```text
=== main BASE=/etc ===
ISP_SPLIT_BASE 指向系统目录，拒绝执行: '/etc'
rc=1
=== teardown BASE=/etc ===
ISP_SPLIT_BASE 指向系统目录，拒绝执行: '/etc'
rc=1
=== custom no flag ===
ISP_SPLIT_BASE 不是默认的 /etc/isp-split: '/tmp/a10vm/base'
  如确需操作该目录，请加 --i-know-what-im-doing；系统目录永远不会被接受。
rc=1 exists=yes
=== --list ===
base /etc/isp-split
```

同一命令对新 teardown + 假 `rm`：`rc=1`，假 `rm` 日志 **0 行**（未发生任何删除）。

**selftest 断言（VM 实测）**：

- `ISP_SPLIT_BASE=/etc isp-split uninstall`（含 `//`、`/etc//`）→ 被入口守卫拒绝；
- `validate_base` 对 `/etc /usr /var / /tmp // /etc//` 全部 rc=1；
- 自定义 BASE 无 flag → rc=1 且零删除；带 flag → 按 BASE 删除；
- `DESTDIR` 沙箱内真实删除数据目录 + 固定清单，宿主不受影响。

---

## 3. A-11 ACL 授权面文档

**修复前**：`docs/SECURITY.md` 不存在；ACL 描述只有一句 “Grant access”；README 无安全章节。

**修复**：

- 新增 `docs/SECURITY.md`，明确：
  - rpcd `file exec` **按路径**授权，`write` = 以 root 执行**任意** `isp-split` 子命令（wire/apply/conf set/uninstall）；默认只有 root 拥有，不要授给受限账号；
  - `read` = conf + 整个 `state/` 树（公网 IP/归属地/STUN）；
  - A-15 的 `E()` → `createTextNode` 断链结论与 `innerHTML` 维护红线；
  - export/uninstall 的写文件边界、CI 供应链、state/cache 权限。
- README 新增「安全模型与已知边界」章节并链接该文档。
- ACL `description` 增加显式警告：`write = execute ANY isp-split subcommand as root ...`。
- 可选“按子命令白名单 wrapper”本轮未实现；文档按 `write = 任意子命令` 如实记录。

**selftest**：`✓ A-11 SECURITY.md/README/ACL 说明覆盖 write=任意子命令与 E() 文本节点`。

---

## 4. A-12 CI / 供应链加固

**修复前**（`27bf8e3`）：

```text
permissions:
  contents: write          # workflow 级，所有 job 都有写权限
uses: actions/checkout@v4  # 可变 tag
actions/upload-artifact@v4 / download-artifact@v4 / softprops/action-gh-release@v2
scripts/build-apk.sh: 无 sha256sums（grep -c = 0）
```

**修复后**：

| action | 钉住的 commit SHA | 版本注释 |
|---|---|---|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | v4.3.0 |
| `softprops/action-gh-release` | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` | v2.6.2 |

- 顶层 `permissions: contents: read`；只有 `release` job 有 `contents: write`（实测 YAML 解析：top=read，release=write）。
- `build-apk.sh` 下载 SDK 前取 `$BASE/sha256sums`，按 `文件名` / `*文件名` 两种写法提取期望哈希；下载后 `sha256sum` 比对，清单缺失或不匹配 **硬失败**，不降级跳过。
- 上游实测清单（2026-10）：
  `1864152619092e781fa36a401960c8e9ae42d6a364c44ee5f0b197ca5f3c0fcc *openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst`

**selftest**：`✓ A-12 action 全部 40 位 SHA、contents:write 只在 release job、SDK 有 sha256 校验`；`✓ A-12 sha256sums 的 *文件名 解析路径命中`。

---

## 5. A-13 归属地链路：HTTPS / 体积 / TSV 清洗

**修复前**：

- `auto` 源序列 `_provs="baidu ip-api"`，百度失败自动转 **HTTP 明文** 的 ip-api。
- `curl -m 2` 无体积上限。
- `_lc_geo_cache_put` 原样 `printf` 外部文本。

**修复前缓存投毒 PoC（VM 旧树）**：文本 `X<TAB>Y<LF>Z` 写入后：

```text
old fields:
4
2
```

即一行被拆成两行（第二行只有 2 列），TSV 行列结构被破坏。

**修复**：

- `auto` 只走 `baidu`（HTTPS）；`ip-api` 降级为显式选项，文档标注明文风险。
- 百度请求加 `--proto '=https' --max-filesize 131072`；ip-api 也加 `--max-filesize`。
- `_lc_geo_cache_put` 写前 `tr '\t\r\n'` 清洗 + `tr -s ' '` + 去控制字符 + `cut -c1-200`；`_lc_geo_cache_get` 只接受 `NF >= 4` 的完整行。

**修复后（VM 新树）**：

```text
new fields:
4
X Y Z
```

单行、4 列、文本 `X Y Z`；第 3 列不再含分隔符。文件权限同时被 A-14 收紧为 600。

**selftest**：`✓ A-13 auto 只走百度 HTTPS、响应限体积、缓存 TAB/换行被清洗且截断 200`。

---

## 6. A-14 state/cache 权限

**修复前（VM 旧树跑夹具 linecheck）**：

```text
drwxr-xr-x  ... /tmp/oldf24-base/state
drwxr-xr-x  ... /tmp/oldf24-base/state/linecheck
-rw-r--r--  ... /tmp/oldf24-base/state/linecheck/last.json
```

**修复**：

- `cmd_linecheck` 入口 `umask 077`；`STATE_DIR` 每次 `chmod 700`。
- `_lc_publish` 落位后 `chmod 700` cache 目录，并对 cache 内每个文件 `chmod 600`（兼容升级前旧权限）。
- `linecheck.geo.tsv`、`linecheck.log` 写入后 `chmod 600`。
- `install.sh` 创建 `/etc/isp-split/state` 后 `chmod 700`，并纠正已有 state 文件为 600。
- `init.d/isp-split` 开机路径 `umask 077` + `chmod 700`；`uci-defaults` 同样收紧。

**修复后（VM 新树）**：

```text
drwx------  ... /tmp/a14vm/base/state
drwx------  ... /tmp/a14vm/base/state/linecheck
-rw-------  ... /tmp/a14vm/base/state/linecheck/last.json
```

**selftest**：`✓ A-14 state=700 / linecheck=700 / last.json=600（umask 077 + 落位 chmod）`；`✓ install/init 安装时 chmod + 运行时 umask 077 双向落地`。

---

## 7. F-23 回显源国内化 + exit_probe

### 7.1 默认源候选实测

本测试床的 VM 两条 WAN 是隔离 `veth/netns`（`10.99.x`），**没有上游 Internet**。为拿到“VM 上 curl 真实返回”的原始输出，本轮在宿主 `192.168.12.2` 起了一个只做 CONNECT 的临时代理，VM 用 `curl -x http://192.168.12.2:3128` 访问真实端点；表里同时给出宿主机直连结果。代理只用于本轮证据，不进入产品代码。

| 候选源 | 宿主直连（原始） | VM 经宿主代理（原始） | 结论 |
|---|---|---|---|
| `https://4.ipw.cn` | `curl: (6) Could not resolve host: 4.ipw.cn`，`http_code=000` | `CONNECT tunnel failed, response 502`，`http_code=000` | **不可达**（DNS 解析失败），不采用 |
| `https://ip.3322.net` | `http_code=200 time_total=0.118850 size=14`，body `27.191.88.227` | `http_code=200 time_total=0.160884 size=14`，body `27.191.88.227` | **采用**（裸 IP） |
| `https://myip.ipip.net` | `http_code=200 time_total=0.188872 size=68`，body `当前 IP：27.191.88.227  来自于：中国 河北 唐山  电信` | `http_code=200 time_total=0.256116 size=68`，同 body | **采用**（文本提取） |
| `https://ddns.oray.com/checkip` | `http_code=200 time_total=0.119460 size=34`，body `Current IP Address: 101.17.124.251` | `http_code=200 time_total=0.308593 size=33`，body `Current IP Address: 27.191.88.227` | **采用**（文本提取） |
| `https://api-ipv4.ip.sb` | `http_code=301`，body 为 nginx 301 页面，无 IP | `http_code=301`，同 | 不采用（不跟随 301 时取不到 IP） |
| `https://api.ipify.org` | `http_code=200`，body `45.95.212.173` | `http_code=200`，body `45.95.212.173` | 不采用（境外源，F-23 症状来源） |
| `https://ipv4.icanhazip.com` | `http_code=200`，body `45.95.212.173` | `http_code=200`，body `45.95.212.173` | 不采用（境外源） |

**定稿默认值**（脚本与 `files/etc/isp-split.conf` 同一串）：

```text
LC_DEFAULT_ECHO='https://ip.3322.net,https://myip.ipip.net,https://ddns.oray.com/checkip'
LINE_CHECK_ECHO_URLS="https://ip.3322.net,https://myip.ipip.net,https://ddns.oray.com/checkip"
```

旧默认 `https://api.ipify.org,https://ipv4.icanhazip.com` 已移除；旧 `/etc/isp-split.conf` 由 install.sh 的“已存在不覆盖”约定保留，用户显式配置不被改写。

### 7.2 文本提取与 exit_probe

- `_lc_extract_ip`：对响应文本/JSON/HTML 统一 `grep -oE` 抓 IPv4 候选，逐个过 `_lc_ip_valid`，取第一个合法值；只接受 HTTP 2xx/3xx 的 body。
- `_lc_exit_ip` 改为直接设置全局 `LC_EXIT_IP` / `LC_EXIT_PROBE`（不再用命令替换，避免丢明细）；逐 URL 记录 `url/http_code/err/ms/ok`。
- `_lc_wan_json` 新增 `exit_probe` 数组；`linecheck.js` 文案拆分：
  - `exit_ok=false` 且 `exit_probe` 非空 → “回显源不可达（建议更换 LINE_CHECK_ECHO_URLS）”；
  - `exit_probe` 为空 → 维持“未取到（可能未真正出网）”。

**VM 真实源（经代理）**：

```text
ip.3322.net:
"exit_ip":"27.191.88.227","exit_ok":true,"exit_probe":[{"url":"https://ip.3322.net","http_code":200,"err":"","ms":209,"ok":true}]

myip.ipip.net:
"exit_ip":"27.191.88.227","exit_ok":true,"exit_probe":[{"url":"https://myip.ipip.net","http_code":200,"err":"","ms":245,"ok":true}]

ddns.oray.com/checkip:
"exit_ip":"101.17.124.251","exit_ok":true,"exit_probe":[{"url":"https://ddns.oray.com/checkip","http_code":200,"err":"","ms":250,"ok":true}]

全部失败:
"exit_ip":null,"exit_ok":false,"exit_probe":[{"url":"https://bad.invalid/ip","http_code":0,"err":"curl: (7) CONNECT tunnel failed, response 502 ","ms":2,"ok":false}]
```

**修复前（VM 旧脚本，同一夹具）**：

```text
"exit_ip":null,"exit_ok":false
exit_probe 出现次数: 0
```

即旧 JSON 无法区分“源不可达”和“未出网”，页面只有一句“未取到（可能未真正出网）”。

**selftest**：F-23 三项全部通过（默认源/conf、端到端 exit_probe、旧 conf 兼容）。

---

## 8. F-24b 按线测 DNS + 0 哨兵移除

### 8.1 按线映射（VM 实测）

从 `DNS_TABLE` 的策略取 `policy_device`，与 WAN 的 l3_device 比对：

```text
wan1 -> server=[223.5.5.5] scope=[wan]
wan2 -> server=[119.29.29.29] scope=[wan]
br-lan -> server=[] scope=[local]
```

（VM 默认 `DNS_TABLE="wan_only:223.5.5.5 wanb_only:119.29.29.29"`；`policy_device wan_only -> wan1`、`wanb_only -> wan2`。）

### 8.2 0 → null / `<1`

**修复前（VM 旧脚本，`--wan br-lan`，同一 linecheck 夹具）**：

```text
"dns_ms":0
```

旧 `_lc_dns_ms` 用系统 resolver 的 `curl -w %{time_namelookup}`；VM 上原始值 `0.000000`，经 `_lc_ms` 四舍五入成 0，前端 `fmtMs(0)` 显示“—”。

**修复后（VM 新脚本，同一命令）**：

```text
"dns_ms":null,"dns_scope":"local","dns_server":null
```

即“未测/失败”输出 null，不再输出 0。

**可测到的路径**：

- 夹具 `ISP_SPLIT_LC_LAT="dns=0.4,..."` → `"dns_ms":400`；
- 夹具 `dns=0.0004` → `_lc_sec_to_dns_ms` 输出 `"<1"`；
- 夹具缺失 `dns=` → `null`；
- VM 用 `ISP_SPLIT_LC_DNS_IP=127.0.0.1` + `nslookup localhost 127.0.0.1` → `dns_ms="<1"`、`dns_scope=wan`、`dns_server=127.0.0.1`（5 次均 `<1`，无 0）。

### 8.3 实现

- `_lc_dns_for_dev`：从 `DNS_TABLE` 取策略 DNS；取不到回退系统 resolver 并标 `dns_scope=local`。
- `_lc_dns_ms`：优先 `curl --dns-servers`（运行时 `curl --version` 探测 c-ares）；否则 busybox `nslookup <domain> <server>`；指定 server 失败再回退系统 resolver（scope 改 local、清空 server）。
- `_lc_sec_to_dns_ms`：秒→整数毫秒；`ms<1` 输出 `"<1"`；0/失败输出空。
- 计时：有纳秒 `date +%N` 用纳秒；busybox 不支持时退回 `/proc/uptime`（10ms 精度），0 仍输出 `"<1"`，绝不回 0。
- JSON `latency` 新增 `dns_scope`、`dns_server`；`dns_ms` 只允许 `null` / 整数 / `"<1"`。
- `linecheck.js` `fmtMs`：`null`→`—`，`"<1"`→`<1ms`，历史 `0` 也显示 `<1ms`。

**selftest**：F-24b 三项全部通过。

---

## 9. A-15 XSS 回归断言

- 新增 `tools/xss-render-check.js`：把真实 `linecheck.js` 放进最小 `E()`/DOM 桩，用 5 组 payload（`<img onerror>`、`<svg onload>`、`iframe srcdoc`、`<script>`、引号/反斜杠/换行）伪造所有字符串字段，跑 `paint()`/`card()`，断言 payload 只以文本节点出现、`innerHTML` 只来自静态 SVG。
- 无 node 时 selftest 退化为静态断言：三个 view 各只有 1 处 `innerHTML`，且为静态 `<svg ...>`；外网字段标识（`w.`/`d.`/`geo`/`nat`/`exit`/`target`）不得出现在 `innerHTML` 行。

**本机用 Node v20.18.0 实测（开发机临时下载，不入仓）**：

```text
$ node --check .../linecheck.js
$ node tools/xss-render-check.js
XSS render check OK: 5 payloads as text nodes, 15 innerHTML writes all static SVG
```

**VM（无 node，静态分支）**：`✓ A-15 静态断言：三个 view 的 innerHTML 各仅 1 处且为静态 SVG，外网字段只经 E() 文本节点`。

---

## 10. 收尾

- `tools/sync-feed.sh` 已执行：feed V5 运行时代码与主源码逐字节一致；并补上 `etc/uci-defaults/99-isp-split` 的复制与校验（此前 sync 漏了这份）。
- `logos/` 与 `overview.js`/`config.js` 未改；只改 `linecheck.js` 的 F-23/F-24b 文案与 `fmtMs`。
- 本机：`274 / 5 / 6`（5 项与基线同集合：4 项 dnsmasq 环境 + 1 项 uid=0 专属）。
- VM：`281 / 0 / 4`（基线 `260 / 0 / 4`，新增 21 项全部通过）。
- 未 push、未 tag；单一 commit 见 `git log -1`。