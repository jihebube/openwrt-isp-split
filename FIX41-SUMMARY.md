# FIX41 — 自建 feed + 一键在线安装（收录路线图第一步）

仓库：`openwrt-isp-split`，基线 `3acf1a1`（main），本修复版本仍为 **0.4.1**（只加安装/发布设施，不改运行时）。
**未 push、未 tag**；生产与 VM 均未连接。CI 的 `feed` job 只做了本地等价模拟，未在 GitHub Actions 实跑。

## 0. 交付清单

| 项 | 文件 | 状态 |
|---|---|---|
| D1 一键在线安装 | `scripts/install-online.sh`（新增，755） | ✅ |
| D2 feed 索引生成 | `scripts/build-feed.sh`（新增，755） | ✅ |
| D2 CI 发版后推 feed 分支 | `.github/workflows/release.yml`（`apk-tool` 产物 + `feed` job） | ✅（未实跑） |
| D3 安装章节重写 | `README.md`（新增「安装」四种入口） | ✅ |
| D3 构建文档同步 | `docs/BUILDING.md`（自建 feed / 发布检查单） | ✅ |
| D4 验证 | 本机 shellcheck / ash / 真实 v0.4.1 六包 / opkg+apk 客户端 | ✅（遗留见 §6） |
| 回归断言 | `tools/selftest.sh`（A-12：release/feed 两处写权限 + feed `needs`） | ✅ |
| 交付说明 | 本文件 `FIX41-SUMMARY.md` | ✅ |

提交：一个 commit，`feat: 自建 feed + 在线一键安装（收录第一步）`；不 push 不 tag。

## 1. D1 — `scripts/install-online.sh`

### 1.1 入口

```sh
# 推荐（raw）
curl -fsSL https://raw.githubusercontent.com/jihebube/openwrt-isp-split/main/scripts/install-online.sh | sh
# raw 不通时（jsDelivr）
curl -fsSL https://cdn.jsdelivr.net/gh/jihebube/openwrt-isp-split@main/scripts/install-online.sh | sh
# 无 curl：wget -qO- 同上；也可先下载再执行
wget -O /tmp/install-online.sh <URL> && sh /tmp/install-online.sh
```

### 1.2 行为

1. 校验 `ISP_BASE`（必须 http(s)）与 `ISP_VER`（只允许版本号字符）；探测 `uname -m`、`/etc/openwrt_release` 的 `DISTRIB_ARCH`、`apk`/`opkg`（仅提示，安装不依赖包管理器）
2. 版本解析：
   - `ISP_VER=0.4.1` → `releases/download/v0.4.1/isp-split-0.4.1.tar.gz`
   - 默认 latest → 先取 `releases/latest/download/SHA256SUMS`，从资产名 `isp-split-<ver>.tar.gz` 反推版本（不依赖 GitHub API、不受 API 限额）；取不到时退回 `/releases/latest` 302 的 `Location` 解析 tag
3. **完整落盘**到 `mktemp -d /tmp/isp-split-online.XXXXXX`，做 `SHA256SUMS` 校验（期望/实际都打印），再 `tar -tzf` 验证可解、顶层目录必须是 `isp-split-<ver>`、拒绝绝对路径/`..`
4. 解包到 `/tmp`，执行 `sh <解包>/isp-split-<ver>/scripts/install.sh --all`
5. 打印 `isp-split --version` 输出并与 `ISP_VER` 对照；打印 LuCI 地址（`uci get network.lan.ipaddr`，取不到用 `<路由器IP>`）与 CLI 下一步

### 1.3 可选环境变量（已写进脚本头 + README）

| 变量 | 默认 | 说明 |
|---|---|---|
| `ISP_VER` | 空=latest | 指定版本，如 `0.4.0`；不带 `v` / `-r1` |
| `ISP_BASE` | `https://github.com/jihebube/openwrt-isp-split` | Release 基地址，可换可信加速前缀 |
| `ISP_INSECURE` | `0` | `1` = 跳过 TLS 校验（缺 ca-bundle 时临时用） |
| `ISP_DRY_RUN` | `0` | `1` = 只打印 URL，不下载不安装 |
| `ISP_SKIP_INSTALL` | `0` | `1` = 只下载解包；`ISP_DEST` 指定落点（必须是解析后位于 `/tmp` 的真实目录） |

### 1.4 安全/兼容要点

- busybox ash 兼容：无 `[[`、数组、`local`、`pipefail`；`sh -n`（dash + busybox）与 shellcheck 全绿
- 无 `curl | tar` / `tee`：先落盘、校验、列目录，再解包执行；任何一步失败都不写系统
- curl 缺失自动用 wget；`ISP_INSECURE=1` 对两者分别映射到 `--insecure` / `--no-check-certificate`
- `ISP_VER`/资产名/`TOP` 都做字符与路径校验；`mktemp` 目录只允许 `/tmp` 前缀清理
- 下载失败文案给出四条可执行路径（换镜像 / 检查版本 / 装 ca-bundle / 手动下载）
- 不把校验和说成信任链：`SHA256SUMS` 与包同源，主要防半截/网关替换（README 已注明）

## 2. D2 — `scripts/build-feed.sh` + `feed` 分支

### 2.1 两个调研结论（决定了最终布局）

**① opkg 的 ipk 只有一种容器：gzip 压缩的 tar，不是 Debian ar。**
`file` 对 v0.4.1 的 4 个 ipk 均报 `gzip compressed data`；`tar tzf` 可见
`debian-binary` / `control.tar.gz` / `data.tar.gz` 三个成员。所谓“老格式”是历史上
部分第三方源用 `ar` 拼的 .deb 风格容器，OpenWrt 官方 ipk 一直是 gzip-tar；opkg 只认
自己能解的那一种。故 **ipk/ 单目录**，不做“新旧格式分目录”。

**② apk 3.x 的仓库索引是 `packages.adb`，不是 `APKINDEX.tar.gz`；且必须与 .apk 同目录。**
证据：

```text
$ curl -sI https://downloads.openwrt.org/releases/25.12.0/packages/x86_64/base/packages.adb
HTTP/2 200
$ curl -sI https://downloads.openwrt.org/releases/25.12.0/packages/x86_64/base/APKINDEX.tar.gz
HTTP/2 404
$ apk index ...            # apk 3.0.5 的 v2 索引 applet
ERROR: isp-split-0.4.1-r1.apk: file format not supported (in this applet)
$ apk mkndx ...             # v3 索引 applet
Index has 2 packages (of which 2 are new)
```

- OpenWrt 25.12 官方 `/etc/apk/repositories.d/distfeeds.list` 的每一行都是
  `.../<feed>/packages.adb`（完整文件 URL）
- `apk-repositories(5)` 语义：仓库项就是索引文件；索引目录 = 包目录
- apk 索引没有 `Filename` 字段，包地址由 `索引所在目录 + <name>-<version>.apk` 推导
  （实测 `apk fetch` 正确拉到 `isp-split-0.4.1-r1.apk`）

因此 **没有** 按任务草案在根目录生成 `APKINDEX.tar.gz`：那会是 apk 2.x 格式，apk 3
不认；放在根目录也无法让 apk 找到 `apk/` 下的包。最终用 SDK 的 `apk mkndx` 生成
`apk/packages.adb`，这是当前 OpenWrt 25.12 唯一合规且可用的布局。若未来需要兼容
apk 2.x，再单独生成 `APKINDEX.tar.gz`，不能与这份混用。

### 2.2 输入 / 输出

输入：6 个包（v0.4.1 Release 实测为 ipk×4 + apk×2；`--src` 只扫第一层，支持从
Release 下载或本地构建产物）。默认 `--src dist/`、`--out dist/feed`（`dist/` 已在
`.gitignore`，不会把生成物混进 `feed/op-packages` 这个 Kwrt 打包壳；脚本检测到
`op-packages` 会拒绝输出）。

实测产物（v0.4.1 六包）：

```text
dist/feed/                              ← 对应 feed 分支根
├── ipk/
│   ├── isp-split_0.4.1-1_all.ipk
│   ├── isp-split_0.4.1-r1_all.ipk
│   ├── luci-app-isp-split_0.4.1-1_all.ipk
│   └── luci-app-isp-split_0.4.1-r1_all.ipk
├── apk/
│   ├── isp-split-0.4.1-r1.apk
│   ├── luci-app-isp-split-0.4.1-r1.apk
│   └── packages.adb                    ← apk 3 索引（与 .apk 同目录）
├── Packages                             ← opkg 索引（Filename: ipk/...）
└── Packages.gz                          ← gzip -9n，逐字节等于解压后的 Packages
```

`Packages` 每个条目的关键字段（与官方 `ipkg-make-index.sh` 同口径，其余 control
字段原样保留，含多行 `Description`）：

```text
Package: isp-split
Version: 0.4.1-r1
...
Filename: ipk/isp-split_0.4.1-r1_all.ipk
Size: 161372
SHA256sum: b25c2ff1c727772f795327722f0cba431469f3be831ec58c35cefe1317af245c
Description: ...
```

实现细节：从 ipk 里流式取 `control.tar.gz`→`control`；`Filename/Size/SHA256sum`
插在 `Description` 前；重复 `Package+Version` 直接报错；`Packages.gz` 生成后反向
解压 `cmp` 自检；条目数必须等于 ipk 数。`--keep` 可保留旧包做滚动累积（CI 默认
快照，不用它）。

### 2.3 发布到 `feed` 分支（`.github/workflows/release.yml`）

新增两处：

1. **25.12 build job**：在已解析 `APK_BIN` 后，把 wrapper 背后的
   `staging_dir/host/bin/.apk.bin`（apk-tools 3.0.5，实测可直接运行）复制成
   `apktool/apk`，作为 `apk-tool` artifact 上传。原因是 Ubuntu runner 没有
   apk-tools，而 feed job 需要 `apk mkndx`；这样不用在 CI 里再装一套工具链。
2. **新增 `feed` job**（`needs: [release]`，`permissions: contents: write`）：
   - `download-artifact` 拿全部产物 → `find` 汇总 6 个包并断言数量（不是 6 就失败）
   - `chmod +x apk-tool` → `sh scripts/build-feed.sh --src pkgs --out $RUNNER_TEMP/feed --apk-bin ...`
   - `git checkout --orphan feed-publish` → `git rm -rf .` → **删掉未跟踪的
     `artifacts/`、`pkgs/`**（否则会被 `git add -A` 带进分支）→ 拷入 feed →
     `git commit` → `git push --force origin HEAD:feed`
   - 用 `GITHUB_TOKEN`（job 级 contents: write），不新增 secret；`feed` 为孤立快照，
     不背 main 历史，也不含 `feed/op-packages`

### 2.4 两种 feed URL（发布后生效）

| 客户端 | raw | jsDelivr |
|---|---|---|
| opkg（≤24.10） | `https://raw.githubusercontent.com/jihebube/openwrt-isp-split/feed` | `https://cdn.jsdelivr.net/gh/jihebube/openwrt-isp-split@feed` |
| apk（25.12+） | `https://raw.githubusercontent.com/jihebube/openwrt-isp-split/feed/apk/packages.adb` | `https://cdn.jsdelivr.net/gh/jihebube/openwrt-isp-split@feed/apk/packages.adb` |

生效路径：

- **opkg**：`src/gz isp-split <URL>` → `<URL>/Packages.gz`（取不到再取 `Packages`）
  → 读 `Filename: ipk/<file>` → 下载 `<URL>/ipk/<file>`
- **apk**：仓库项是**完整索引文件 URL** → 索引目录 `.../feed/apk/`
  → 包地址 `<索引目录>/<name>-<version>.apk`
- raw 与 jsDelivr 只是同一分支的两种 CDN；jsDelivr 分支缓存通常十几分钟到数小时，
  刚发版看不到新包时用 raw 或等缓存

## 3. D3 — README / BUILDING

`README.md` 新增「安装」章节，按优先级四种入口：

1. **一键在线安装**：raw + jsDelivr 两条一行命令；`wget -qO-` / 先下载再跑；5 个环境变量表；装旧版示例；LuCI 入口
2. **标准 feed**：opkg 的 `customfeeds.conf` 写法 + apk 的 `repositories.d/customfeeds.list` 写法；两种 URL 都贴；`--allow-untrusted` 的原因；opkg `check_signature` 的例外；快照语义（不保留历史版本）
3. **iStore 手动安装**：四步占位（入口 → 主包直链 → LuCI 包直链 → 刷新），带截图占位注释；明确 iStore 只认 ipk
4. **传统下载安装**：保留原 tar.gz + install.sh、Release apk、opkg ipk 三种姿势

末尾「版本切换与镜像」：`ISP_VER` 旧版、`ISP_BASE` 加速前缀、jsDelivr 缓存、升级保留
`/etc/isp-split.conf`、校验和的信任边界。「快速开始」改为“装好后按顺序跑”，去掉重复安装命令。

`docs/BUILDING.md` 同步：CI 段落补 feed job；发布检查单加“检查 feed 分支”；
原来“自建 opkg 源（可选，仅 ≤24.10）/ apk 源不建议”的旧章节整体替换为
“自建 feed（opkg + apk）”，写明 `packages.adb`、签名限制、`--keep` 与发布方式。

## 4. D4 — 本机验证

### 4.1 语法 / 静态检查

```text
$ shellcheck -s sh scripts/install-online.sh scripts/build-feed.sh
（无输出，exit 0；0.10.0，全级别）
$ busybox sh -n scripts/install-online.sh && echo OK     → OK
$ sh -n scripts/install-online.sh                        → OK（dash）
$ busybox sh -n scripts/build-feed.sh && echo OK         → OK
$ actionlint .github/workflows/release.yml                → exit 0
$ actionlint -shellcheck ... release.yml                  → 仅 3 条改动前就存在的告警
  （line 77 SC2034/SC2016、line 186 SC2012；新增 feed job 无告警）
```

### 4.2 install-online.sh：URL 拼接与真实下载

```text
$ ISP_DRY_RUN=1 sh scripts/install-online.sh
[isp-split] latest -> 0.4.1
  下载: https://github.com/jihebube/openwrt-isp-split/releases/latest/download/isp-split-0.4.1.tar.gz
  校验: https://github.com/jihebube/openwrt-isp-split/releases/latest/download/SHA256SUMS

$ ISP_DRY_RUN=1 ISP_VER=0.4.1 sh scripts/install-online.sh
  下载: https://github.com/jihebube/openwrt-isp-split/releases/download/v0.4.1/isp-split-0.4.1.tar.gz
  校验: https://github.com/jihebube/openwrt-isp-split/releases/download/v0.4.1/SHA256SUMS
```

HEAD 探头（2026-11-11）：

```text
releases/download/v0.4.1/isp-split-0.4.1.tar.gz   200
releases/download/v0.4.1/SHA256SUMS               200
releases/latest/download/SHA256SUMS               200
raw .../main/scripts/install.sh                   200（路径模式验证）
cdn.jsdelivr ...@main/scripts/install.sh          200（路径模式验证）
raw .../feed/Packages.gz                          404（feed 分支尚未 push）
cdn.jsdelivr ...@feed/Packages.gz                 404（同上）
```

真实下载（非 root，`ISP_SKIP_INSTALL=1`，避免写系统）：

```text
$ ISP_SKIP_INSTALL=1 ISP_VER=0.4.1 ISP_DEST=/tmp/fix41/dl-skip sh scripts/install-online.sh
[isp-split] SHA256 校验通过
[isp-split] 已下载并解包到 /tmp/fix41/dl-skip/isp-split-0.4.1
```

`ISP_VER=0.4.0` 同样下载/校验/解包通过（版本切换路径）。脚本在非 root 且
`ISP_SKIP_INSTALL=0` 时会先拒绝（不白下 1.6 MB）；`install.sh` 的 root 检查仍在。

### 4.3 失败路径（必须可读且不写系统）

| 场景 | 结果 |
|---|---|
| `ISP_VER=../evil` | `ISP_VER 含非法字符`，退出 1 |
| `ISP_BASE=file:///etc` | `ISP_BASE 必须是 http(s)://`，退出 1 |
| 坏包 + 正确 SHA256SUMS（本地 HTTP 镜像） | `SHA256 校验失败`，打印期望/实际，退出 1 |
| HTML 冒充 tar.gz + 匹配的 SHA（本地镜像） | `不是有效的 tar.gz`，退出 1 |
| `ISP_DEST=/tmp/../etc` | 解析后为 `/etc`，拒绝，退出 1 |
| build-feed `--out /` / `--out feed`（Kwrt 壳） | 拒绝并提示改用 `dist/feed` |
| build-feed `--apk-bin /bin/true` | `需要 apk-tools 3.x`，退出 1 |
| 同一 `Package+Version` 两个 ipk | `重复的包版本`，退出 1 |

### 4.4 build-feed.sh：真实 v0.4.1 六包

六包来自 `gh release download v0.4.1`（ipk×4 + apk×2 + tar.gz + SHA256SUMS）。

```text
$ sh scripts/build-feed.sh --src /tmp/fix41/assets --out /tmp/fix41/final-feed
Index has 2 packages (of which 2 are new)
[feed] opkg: 4 个 ipk -> Packages / Packages.gz（Filename 前缀 ipk/）
[feed] apk : 2 个 apk -> apk/packages.adb（索引与包同目录）
```

Python 校验（`Packages.gz` 解压后与 `Packages` 完全相同；逐条检查 Filename 存在、
Size、SHA256、必需字段）：

```text
Packages entries: 4
OK isp-split             0.4.1-1   159897 ce389e1c5e29 ipk/isp-split_0.4.1-1_all.ipk
OK isp-split             0.4.1-r1  161372 b25c2ff1c727 ipk/isp-split_0.4.1-r1_all.ipk
OK luci-app-isp-split    0.4.1-1    85618 ec31ba647e4e ipk/luci-app-isp-split_0.4.1-1_all.ipk
OK luci-app-isp-split    0.4.1-r1   85076 3d66f344751a ipk/luci-app-isp-split_0.4.1-r1_all.ipk
```

**真实 opkg 客户端**（24.10.4 SDK 的 host opkg，git `38eccbb1`，本地 HTTP 源）：

```text
$ opkg update
Downloading http://127.0.0.1:8765/final-feed/Packages.gz
Updated list of available packages in .../isp-split
$ opkg info isp-split
Filename: ipk/isp-split_0.4.1-r1_all.ipk
$ opkg download isp-split
Downloading http://127.0.0.1:8765/final-feed/ipk/isp-split_0.4.1-r1_all.ipk
Downloaded isp-split as ./isp-split_0.4.1-r1_all.ipk
```

（`opkg download` 会先抱怨依赖 nftables/curl/socat 不在本测试源，这是测试环境只有
本 feed 的正常现象；下载 URL 与版本选择都已验证：`0.4.1-r1` 胜出。）

**真实 apk 客户端**（apk-tools 3.0.5）：

```text
$ apk search -x isp-split
isp-split-0.4.1-r1
$ apk fetch --repository file:///tmp/fix41/final-feed/apk/packages.adb \
            -o /tmp/fix41/final-apkfetch isp-split luci-app-isp-split
Downloading isp-split-0.4.1-r1
Downloading luci-app-isp-split-0.4.1-r1
→ 两个 .apk 均按索引推导出的文件名落盘
```

未签名索引的 `apk update` 行为也实测过（fakeroot 提供 uid=0 的假 root）：

```text
$ apk update                              # 无 --allow-untrusted
WARNING: opening .../packages.adb: UNTRUSTED signature
OK: 1 distinct packages available          # 本 feed 的包暂不计入
$ apk update --allow-untrusted
OK: 3 distinct packages available          # hello(测试) + isp-split + luci
$ apk add --simulate --allow-untrusted isp-split
（能选中 isp-split-0.4.1-r1，只报依赖 curl/libc/nftables/socat 不在本测试源）
```

即 README 里的 `apk update`（普通）+ `apk add --allow-untrusted` 顺序可用：
`add` 的 flag 会让 apk 以可信源重新加载索引。

**幂等**：同输入连续跑两次，`Packages` / `Packages.gz` / `apk/packages.adb`
sha256 完全一致（GNU gzip `-9n` + mkndx 确定性）。**`--keep`** 实测保留旧版后
索引条目从 4 变 6（0.4.0 + 0.4.1 两套 ipk），`Packages.gz` 同步重建。

**CI 等价模拟**：按 `packages-25.12.6` / `packages-24.10.4` / `source` 三层目录
摆好 artifact（含 `apk-tool/apk`），执行 feed job 的 `find` 汇总 → 恰好 6 个包 →
`build-feed.sh --apk-bin` 成功；再模拟 `git checkout --orphan` + `git rm -rf .` +
删未跟踪目录 + `git add -A`，最终 tree 恰好 9 个文件（4 ipk + 2 apk + Packages +
Packages.gz + packages.adb），没有 artifacts/pkgs 混入。

### 4.5 README / 文档渲染

```text
README.md      code fences 36（偶数、闭合）；HTML 注释 15/15；lc:begin/end 7/7
docs/BUILDING  code fences 16（闭合）；HTML 注释 0/0
表格检查：唯一告警是既有的 `doctor [--profile=page\|full\|deep]` 转义竖线，
          按 Markdown 规则属于单元格内容，不是缺列
标题层级：## 安装 → ### 1..4 / ### 版本切换与镜像 → ## 快速开始 顺序正确
```

## 5. 提交内容与影响面

- 新增 `scripts/install-online.sh`、`scripts/build-feed.sh`
- 修改 `.github/workflows/release.yml`（新增 `apk-tool` 上传 + `feed` job；不动既有 build/release 逻辑）
- 修改 `tools/selftest.sh`（A-12 断言适配 feed job；新增 feed `needs: [release]` 检查）
- 修改 `README.md`（安装章节；运行时/命令/配置章节未动）
- 修改 `docs/BUILDING.md`（feed 章节与检查单）
- 新增本 `FIX41-SUMMARY.md`
- **未改**：`files/`、`Makefile`、LuCI、`install.sh`、版本号、tag；`tools/selftest.sh` 只改 A-12 的 CI 权限断言（不碰运行时用例）

## 6. 未做 / TODO（如实标注）

1. **未 push / 未 tag**：`feed` 分支尚不存在，raw / jsDelivr 的 feed URL 现在必然 404
   （已用 HEAD 探头确认）；`scripts/install-online.sh` 在 raw main 上也还取不到
   （路径模式用现有 `scripts/install.sh` 的 raw/jsDelivr 200 验证）。首次 tag 后
   `feed` job 才会创建分支。
2. **CI `feed` job 未在 GitHub Actions 实跑**：只做了 YAML/actionlint 静态检查与
   本地等价命令模拟（含 6 包计数、apk-tool 使用、孤立分支提交）。真实 runner 上
   还需确认 `.apk.bin` 在 ubuntu-latest 的 glibc 下可执行（本机同架构已实测 3.0.5 可跑）。
3. **未在真实路由器/VM 执行 `install.sh --all`**（按要求不碰生产/VM）：一键脚本的
   下载、SHA 校验、解包、版本切换、失败拒绝均已实测；最后一步复用项目既有的
   `scripts/install.sh`（其自身回归在 `tools/selftest.sh` 覆盖）。真实设备上建议先用
   `ISP_SKIP_INSTALL=1` 看解包树，再 `sh .../scripts/install.sh --all`。
4. **apk feed 未签名**：没有长期私钥，客户端必须 `apk add --allow-untrusted`；
   `apk update` 会提示 `UNTRUSTED signature`。要做签名链需引入项目长期密钥 +
   在 feed 分支发布公钥并让用户安装，属于后续工作。
5. **feed 是快照**：不保留历史版本；要装旧版用 `ISP_VER` 或 Release 页。若要历史
   feed，把 CI 改成拉取旧 `feed` 分支 + `build-feed.sh --keep` 即可（脚本已支持）。
6. **`APKINDEX.tar.gz` 命名与任务草案不同**：按 §2.1 的实测证据改用
   `apk/packages.adb`；这是 apk 3.x 的唯一合规索引，不是省略。

## 7. 回归

`sh tools/selftest.sh`（非 root 主机）最终结果：**通过 356、失败 5、跳过 10**。

- FIX41 引入的 A-12 断言原本写死 `contents: write` 只有 1 处；`feed` job 合法新增了
  第二处写权限。已把断言改为“release / feed 两处、且 release 之前不得出现写权限”，
  并新增 `feed` job 必须 `needs: [release]` 的检查；该项现为 ✓。
- 其余 5 项失败都是环境相关用例，与本修复的改动面无交集：`conf-dir` 探测 1 项
  （依赖 uid=0），`20.3d/e/f/g` 4 项（dnsmasq `--test` 在当前非 root 主机上的降级/
  回显行为）。本修复没有触碰 `files/` 运行时，不能据此判断基线；如需基线对照，
  应在同一非 root 主机上对 `3acf1a1` 重跑一次。
- 本修复新增的两个脚本没有加进 selftest（不影响运行时断言面）；D4 的
  shellcheck / ash / 真实六包 / 真实 opkg+apk 客户端验证见 §4。
