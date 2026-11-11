# 构建与打包

按目标产物选择构建方式：

| 目标固件 | 产物 | 命令 | 要求 |
|---|---|---|---|
| Kwrt / OpenWrt 25.12+（apk） | `.apk` | `scripts/build-apk-docker.sh`（推荐）或 `scripts/build-apk.sh` | Docker，或 Linux x86_64 |
| OpenWrt ≤ 24.10（opkg） | `.ipk` | `scripts/build-ipk.sh` | 无（任何能跑 sh/tar/gzip 的机器） |
| 自编译固件 | 镜像 | 见 [FIRMWARE.md](FIRMWARE.md) | buildroot 环境 |

只想安装、不想构建：直接从 [Releases](../../releases) 下载 `isp-split-*.tar.gz`，在路由器上解包后进目录执行安装脚本。
源码包自带一层 `isp-split-<版本>/`，而 busybox tar 不支持 `--strip-components`，所以是「解包 + 进目录」，不抄 GNU 姿势：

```sh
wget -O /tmp/isp.tgz <Releases 里 isp-split-*.tar.gz 的地址>
mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp
sh /tmp/isp/isp-split-<版本>/scripts/install.sh --all
```

---

## 构建 ipk（零依赖）

```sh
sh scripts/build-ipk.sh
```

不需要 OpenWrt 环境，产物为 `dist/isp-split_<版本>-<发布号>_all.ipk`（另有可选的
`luci-app-isp-split_<版本>-<发布号>_all.ipk`，例如 0.3.0 的产物是
`isp-split_0.3.0-1_all.ipk`）。脚本对产物做容器嗅探式冒烟校验：
必须是 gzip 包裹的 tar（magic `1f 8b`），且成员恰好为
`./debian-binary`、`./control.tar.gz`、`./data.tar.gz`。

安装：`opkg install isp-split_*_all.ipk`

### ipk 容器是 gzip-tar，不是明文 ar

OpenWrt 23.05 / 24.10 官方仓库的 ipk 都是 **gzip 包裹的 tar**（不是 Debian
那种明文 `!<arch>` ar）。opkg 的读取实现只认前者：

- `libbb/unarchive.c` 的 `deb_extract()` 先把整个包当 gzip 流解开，再按 tar
  遍历外层，找到 `control.tar.gz` / `data.tar.gz` 成员后再解内层 gzip；
- 解压由 `gzip_exec()`（`libbb/gzip.c`）完成，实际执行
  `execlp("gzip", "gzip", "-d", "-c", ...)`，对 `!<arch>` 输入直接失败
  （子进程 stderr 被丢弃，用户只能看到最终的 Malformed 报错）；
- 24.10.4 的 opkg 二进制里只有 `get_header_tar`，没有 `get_header_ar`，也没有
  `!<arch>` 字面量。

所以明文 ar 的 ipk 在 23.05/24.10 上无法解析，opkg 会报
`pkg_init_from_file: Malformed package file`。
`build-ipk.sh` 默认产出 gzip-tar；只有极老固件（明文 ar 时代）才需要显式回退：

```sh
ISP_SPLIT_IPK_FORMAT=ar sh scripts/build-ipk.sh
```

`tools/selftest.sh` 的 §19.10 也用同一套嗅探读法（gzip-tar / ar 都能读，
未知格式判失败），并在 §19.10a 断言产物必须是 gzip-tar。

---

## 构建 apk（Docker）

**这是绝大多数人的路径**——因为 apk 只能用 OpenWrt SDK 编译，而 SDK 是 Linux x86_64 程序。

```sh
sh scripts/build-apk-docker.sh            # 默认 25.12.6，产出 apk
sh scripts/build-apk-docker.sh 24.10.4    # 24.10 SDK，产出 ipk
```

首次运行会拉取 debian 镜像、安装编译依赖、下载 SDK（约 273 MB），全程 5-15 分钟。产物在 `dist/sdk-<版本>/`。

**Apple Silicon（M 系列 Mac）**：脚本已用 `--platform linux/amd64` 钉住容器架构。OpenWrt SDK 只有 Linux x86_64 版本，不钉平台时 docker 会拉 `linux/arm64` 的 debian，容器里的 x86_64 工具链直接 `Exec format error`，报错埋在几百行编译日志里。钉住后由 Docker Desktop 的 Rosetta / QEMU 模拟执行，能编但比 x86 主机慢；建议 Docker Desktop ≥ 4.20 并在设置里打开 "Rosetta for x86/amd64 emulation"。容器启动后脚本先核对 `uname -m`，不是 `x86_64` 立刻报错退出，不会把平台问题拖到编译中途。

已验证的宿主依赖（脚本内置）：`perl`（基础镜像的 perl-base 缺少 feeds 脚本所需模块）、`python3-distutils`（prereq 检查需要）。

---

## 构建 apk（原生 Linux）

```sh
sh scripts/build-apk.sh                  # 默认 25.12.6 / x86-64
sh scripts/build-apk.sh 24.10.4 x86/64   # 指定版本与架构
OWRT_WORK=/tmp/sdkbuild sh scripts/build-apk.sh
```

脚本流程：动态解析并下载 SDK → **用上游同目录 `sha256sums` 校验 SDK 的 sha256（A-12；清单缺失或哈希不符直接失败）** → 解压到 `.sdk-build/<SDK 版本>/sdk/`（F-19：按版本分桶，25.12 与 24.10 各自一份，复用前校验目录里的版本标记 `.isp-split-sdk-version`）→ 拷入软件包 → `feeds update/install` → `make defconfig` → `make package/*/compile` → 收集产物到 `dist/sdk-<版本>/`。

宿主要求：Linux x86_64，`build-essential`、`zstd`、`curl`、`git`、`file`、`perl`、`python3-distutils`（Debian 系）。

---

## CI 自动构建

`.github/workflows/release.yml` 已配置：push tag 后自动用 25.12.6 与 24.10.4 两个 SDK 分别编译（调用同一个 `scripts/build-apk.sh`），连同源码包一起发布到 Release；Release 成功后再由 `feed` job 生成 opkg/apk 双索引并推送到独立分支 `feed`。

```sh
git tag v0.2.1 && git push origin v0.2.1
```

---

## 发布检查单

发布新版本时：

1. 更新 `Makefile` 与 `luci-app-isp-split/Makefile` 中的 `PKG_VERSION` / `PKG_RELEASE`
2. 确认 `dist/` 在 `.gitignore` 中（构建产物不入库）
3. 打 tag 并推送，等待 CI 完成
4. 检查 Release 页产物的完整性与 `SHA256SUMS`；ipk 的前两字节应为 `1f 8b`
   （gzip-tar），不是 `21 3c`（明文 ar）
5. 检查 `feed` 分支已更新：`Packages.gz` 与 `apk/packages.adb` 都能拉取，raw 与 jsDelivr 两条 URL 至少各验一次

## 自建 feed（opkg + apk）

`scripts/build-feed.sh` 把 Release 的 6 个包（ipk×4 + apk×2）做成两种标准索引：

```sh
# 本地：--src 指向放包的目录（Release 下载物或 dist/），默认输出 dist/feed
sh scripts/build-feed.sh --src /path/to/packages --out dist/feed
```

产物与目录约定：

| 路径 | 内容 |
|---|---|
| `ipk/*.ipk` | opkg 包（gzip-tar 容器，单目录；OpenWrt 的 ipk 一直是这种，没有新旧格式之分） |
| `Packages` / `Packages.gz` | opkg 索引；`Filename: ipk/...`，含 Size / SHA256sum / Description |
| `apk/*.apk` | apk 包（文件名必须保持 `<name>-<version>.apk`） |
| `apk/packages.adb` | apk 3.x 索引（ADB 容器） |

**apk 索引为什么是 `apk/packages.adb` 而不是根目录 `APKINDEX.tar.gz`**：OpenWrt 25.12 的 apk-tools 3 用 `packages.adb`（官方 feeds 就是 `.../<feed>/packages.adb`）；`APKINDEX.tar.gz` 是 apk 2.x 旧格式，apk 3 的 `index` applet 甚至不接受 v3 包。apk 索引没有 Filename 字段，包地址由“索引所在目录 + `<name>-<version>.apk`”推导，所以索引必须和 `.apk` 同目录。索引由 SDK 的 `apk mkndx` 生成；CI 里 25.12 build job 把 apk-tools 3.0.5 作为 `apk-tool` 产物传给 feed job，本地则自动找 `.sdk-build/*/sdk/staging_dir/host/bin/apk`。

**签名**：本 feed 未签名。apk 客户端需 `apk add --allow-untrusted`（`apk update` 只会提示 UNTRUSTED）；opkg 默认不校验签名，若固件手动开了 `option check_signature` 则需删掉该行或改用一键脚本。

**发布**：`.github/workflows/release.yml` 的 `feed` job 在 Release 成功后下载 6 个包，跑本脚本，再把 `ipk/`、`apk/`、`Packages*` 以孤立快照推到 `feed` 分支（`git push --force`）。raw 与 jsDelivr 两种客户端地址见 README「安装」。

## 出货门：FEATURE_LINECHECK

`FEATURE_LINECHECK` 是**构建期**开关，0.3.0 起默认 `1`（线路体检随包发货）：

| 值 | 用途 | 产物 |
|----|------|------|
| `1` | 默认，正式发行版 | 完整线路体检：`linecheck` 子命令、`lc-run`、LuCI 卡片页与菜单节点、`LINE_CHECK_*` 配置键、`socat` 依赖 |
| `0` | 小闪存 / 特殊渠道的可选剥离版 | 上述内容全部**物理**不进包 |

```sh
# 默认就是完整版（0.3.0+）
sh scripts/build-ipk.sh
sh scripts/build-apk.sh 25.12.6 x86/64

# 需要剥离版时必须显式关掉
FEATURE_LINECHECK=0 sh scripts/build-ipk.sh
FEATURE_LINECHECK=0 sh scripts/build-apk.sh 25.12.6 x86/64
```

默认值只有一处来源：四个 Makefile（主包 / LuCI 包 / feed 两个壳）用
`FEATURE_LINECHECK?=1`，四个脚本用 `${FEATURE_LINECHECK:-1}`，CI 的
`release.yml` 用 `env: FEATURE_LINECHECK: "1"`。`tools/selftest.sh` 的 19.1
会把这条链逐处核对——F7 的教训就是门散在多处、默认值一旦分叉，产物与断言就错位。

剥离由源文件里的 `lc:begin` / `lc:end` 标记驱动，`scripts/strip-linecheck.sh`
是**唯一**实现：手工打包直接调用它，两份 `Build/Prepare`（主包 / LuCI 包）也
调用包目录里逐字节一致的副本 `$(CURDIR)/strip-linecheck.sh`——不再手抄 sed。
标记必须包住内容本体，CSS 的 `.lc-*` 样式体整段在标记内（只包标题注释等于
没包，0.2.3 的泄漏就是这么来的）。

产物必须同时通过（方向必须显式给出，没有默认值）：

- `scripts/verify-package-payload.sh verify --feature=1`：完整版期望面——
  `linecheck` 子命令可调用、`lc-run` 在包里、`linecheck.js` + 菜单节点安装、
  CSS 含 `.lc-*`、conf 有 `LINE_CHECK_*` 键、`Depends` 含 `socat`；
- `scripts/verify-package-payload.sh verify --feature=0`：剥离版期望面——
  grep 零残留、CSS 无 `.lc-*`（0.2.3 的断言资产，仍然可跑）；
- 按容器魔数嗅探 ipk（gzip-tar / ar）与 apk（ADB，`ADBd`），逐个解包；
  未知容器显式失败，绝不在空 glob 上“通过”；
- `scripts/verify-package-payload.sh parity`：本地脚本路径产物与 SDK 路径
  产物 payload 必须逐文件一致（本地绿 ≠ SDK 绿）。

`tools/selftest.sh` 的第 19 节按方向分成两段：§19 是默认完整版的正向断言
（含 VM 上的 `linecheck --json --wan lo` 冒烟与 60s 缓存命中），§19b 是
`FEATURE_LINECHECK=0` 的剥离版子集（原「零残留」用例，显式以 0 模式构建）。

> 0.3.0 起恢复完整源码包（`isp-split-<ver>.tar.gz`，含 docs/tools/selftest）；
> 剥离版只发运行时 install 包 + ipk/apk。

## 常见问题

**安装时报 signature check failed**
本地或 CI 构建的包没有签名。apk 加 `--allow-untrusted`，opkg 关闭签名校验或使用签名源。

**`apk add` 卡在下载 `packages.adb`**
加 `--no-network` 只安装本地包。

**luci-app-isp-split 编译失败**
luci-base 版本与 SDK 不匹配所致，主包不受影响，可跳过（脚本已容错）。

**为什么不能像 ipk 一样手工拼一个 apk**
apk 3 的包格式为 ADB 容器（魔数 `ADBd`），OpenWrt 的 apk 3.0.5 不含 `mkpkg`，且不再接受 v2 tar.gz 格式，SDK 是唯一产出路径。

**为什么 DEPENDS 里没有 mwan3**
官方 feed 的 mwan3 是 iptables 版（2.12.5），`+mwan3` 会在构建时错误解析到它；Kwrt 源中 nft 版包名为 `mwan3-nft`，各源命名不一致。因此改为运行时检查（`install.sh` 与 `tools/router-preflight.sh`）。
