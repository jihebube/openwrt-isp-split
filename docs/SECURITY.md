# 安全模型与已知边界

本文记录 `AUDIT-SECURITY-v2` 之后仍然成立的**设计取舍**。它不是“没有漏洞”的承诺，
而是把授权面、信任边界和已经立好的回归防线写清楚，避免后续维护者把边界改回去。

## 1. 谁可以控制 isp-split：rpcd ACL 的实际授权面

`luci-app-isp-split/root/usr/share/rpcd/acl.d/luci-app-isp-split.json` 只有两组权限：

| 组 | 实际能力 |
|---|---|
| `read` | `ubus file read/stat`；读 `/etc/isp-split.conf`、`/etc/isp-split` 及其 `state/` 子树 |
| `write` | `ubus file exec`；对 `/usr/sbin/isp-split` 执行**任意子命令** |

关键点：rpcd 的 `file exec` ACL 是**按可执行文件路径**授权的，不按 argv 里的子命令
细分。因此拿到 `write` 的账号等价于拿到：

```text
isp-split wire / apply / fetch / conf set / export / uninstall ...
```

其中 `wire/apply/conf set` 会改 mwan3、nftables 与 `/etc/isp-split.conf`；`uninstall`
会走卸载清理。它仍然**不能**执行 `/bin/sh` 或读 `/etc/shadow`（rpcd 对路径与 argv
分别校验），但“只能读 state”的 `read` 账号已经能看到每条 WAN 的公网 IP、出口 IP、
归属地、STUN 映射和目标域名。

**结论与操作建议**

- 默认安装只有 `root` 拥有该 ACL，这是安全的默认值；
- 多用户固件不要把 `luci-app-isp-split` 的 `write` 授给“受限运维”账号——那是
  root 级别的本工具控制权；
- 只需要看状态页时，只授 `read`；连 `state/` 都不想暴露时，不要授这个 ACL；
- 未来若要把 `write` 收窄到白名单子命令，正确做法是增加一个按 argv 校验的
  wrapper，而不是继续依赖 rpcd 的路径 ACL。当前版本没有实现 wrapper，故本文
  按“write = 任意子命令”如实记录。

## 2. 外部文本 → `last.json` → LuCI：为什么不是 XSS

线路体检会把外网返回的文本写进 `last.json`：

| 来源 | 字段 | 落盘前处理 | 前端渲染 |
|---|---|---|---|
| 百度 / ip-api 归属地 | `geo.location`、`geo.provider` | `_lc_json_esc`：转义 `\` 与 `"`、删 CR/LF/控制字符、TAB→空格 | `E()` 文本节点 |
| 回显源返回 | `exit_ip` | 先过 `_lc_ip_valid` 严格 IPv4，再过 `_lc_json_esc` | `E()` 文本节点 |
| STUN 映射 / 失败详情 | `nat.*`、`nat.probes[]` | `_lc_json_esc`；数字走 `_lc_int` | `E()` 文本节点 |
| 目标域名 / IP | `target.*` | `_lc_json_esc` | `E()` 文本节点 |
| 错误串 | `errors[]` | 仅静态字符串 | `E()` 文本节点 |

`linecheck.js` 里所有外部字符串都作为 `E('tag', {...}, [ string ])` 的**文本子项**；
LuCI 的 `E()` 对非 Node 子项调用 `document.createTextNode()`，不会经过 HTML 解析。
全文只有一处 `innerHTML`，位于 `svgIcon()`，内容来自固定 `ICONS[name]` 映射与数字
`size`，不接受任何 JSON 字段。`overview.js` / `config.js` 同样只有静态图标
`innerHTML`。

**维护红线**

- 不允许把 `last.json` 的任何字段拼进 `innerHTML`、`srcdoc`、`document.write`、
  `eval`、`new Function` 或 `javascript:` URL；
- 新增外部字段时，必须在 shell 侧过 `_lc_json_esc`（数值过 `_lc_int`），前端只用
  `E()` 的文本子项；
- `tools/selftest.sh` 的 XSS 回归用例会伪造全字段 payload：有 node 时用桩 `E()`
  渲染真实 `linecheck.js` 的 `card()` 并断言 payload 只以文本节点出现；没有 node 时
  退化为静态 grep（`innerHTML` 不得与外网字段拼接）。改动渲染层会先撞上这道墙。

`AUDIT-SECURITY-v2` §A-15 的结论是：当前链路**不可利用**；残余风险是非法 JSON
导致页面显示“尚未体检”（可用性/误导），不是脚本执行。

## 3. export 的写文件边界

`isp-split export <fmt> <dir>` 以 root 身份写固定文件名 `isp-<源>.<ext>` 和两份
`README-*.txt`。它不提供任意内容写入，但输出目录和已有文件仍是攻击面：

- 输出目录必须是绝对路径，拒绝 `..`、系统目录（`/etc`、`/usr`、`/www`、
  `/www/*`、`/usr/share/luci` 等），并对 `pwd -P` 解析后的**真实路径**再检查一次，
  防止 `symlink -> /etc` 绕过字面黑名单；
- 所有文件（含 README）先用 `_tmp_next_to` 在同一目录创建随机临时文件，写完
  `mv -f` 落位。`rename` 不跟随符号链接，因此预先铺好的
  `README-mihomo.txt -> /etc/shadow` 不会再被写穿；
- 临时文件用 `mktemp` 的 `O_EXCL` 语义创建，低权用户无法抢注名字。

## 4. uninstall 的 BASE 守卫

`teardown.sh` 的删除根是 `BASE`（默认 `/etc/isp-split`）。A-10 之前它只校验了
空/根/相对路径/`..`，`ISP_SPLIT_BASE=/etc isp-split uninstall` 会直接 `rm -rf /etc`。
现在：

- **永远拒绝** `/`、`/etc`、`/usr`、`/var`、`/bin`、`/sbin`、`/lib`、`/boot`、
  `/dev`、`/proc`、`/sys`、`/www`、`/root`、`/home`、`/tmp`、`/mnt`、`/opt`；
- 真实根（`ISP_SPLIT_DESTDIR` 为空）只接受默认 `/etc/isp-split`；其它目录必须显式
  加 `--i-know-what-im-doing`；
- 沙箱（`DESTDIR` 非空）只接受 `DESTDIR` 子树，防止演练误删宿主；
- 数据目录不再写死 `etc/isp-split`，而是随 `BASE` 推导；`isp-split` 主脚本入口也会
  先拒绝系统目录，避免在 `uninstall` 真正开始前就往 `/etc/work` 写临时文件。

回归用例：`ISP_SPLIT_BASE=/etc isp-split uninstall` 必须被拒绝（`selftest` §26）。

## 5. 构建与发布供应链

`.github/workflows/release.yml` 的约束：

- 所有 action 钉 40 位 commit SHA（`actions/checkout`、`upload-artifact`、
  `download-artifact`、`softprops/action-gh-release`），不使用可变 tag；
- `permissions` 收到 job 级：构建/源码 job 只有 `contents: read`，只有 `release`
  job 需要 `contents: write`；
- `scripts/build-apk.sh` 下载 SDK 后，用上游同目录的 `sha256sums` 校验
  `sha256`；校验文件缺失或不匹配时硬失败，不“跳过校验继续构建”。

## 6. state/cache 权限

`state/` 与 `linecheck/` 缓存包含公网 IP、出口 IP、归属地、STUN 映射与目标域名。
安装脚本与运行时统一收紧：

- 目录 `700`，文件 `600`；
- 体检进程设置 `umask 077`，落位后再次 `chmod`（兼容升级前已存在的 755/644）；
- `linecheck.geo.tsv` 写入前清洗 TAB/CR/LF 并截断长度，避免缓存行列结构被外部
  文本破坏。

## 7. 报告安全问题

这是家用路由器上的开源工具，没有独立的漏洞奖励流程。请优先通过仓库 issue
说明复现步骤；涉及未修复的提权/远程执行时，先不要公开 PoC 细节。