# 构建与打包

按目标产物选择构建方式：

| 目标固件 | 产物 | 命令 | 要求 |
|---|---|---|---|
| Kwrt / OpenWrt 25.12+（apk） | `.apk` | `scripts/build-apk-docker.sh`（推荐）或 `scripts/build-apk.sh` | Docker，或 Linux x86_64 |
| OpenWrt ≤ 24.10（opkg） | `.ipk` | `scripts/build-ipk.sh` | 无（任何能跑 sh/tar/ar 的机器） |
| 自编译固件 | 镜像 | 见 [FIRMWARE.md](FIRMWARE.md) | buildroot 环境 |

只想安装、不想构建：直接从 [Releases](../../releases) 下载 `isp-split-*.tar.gz`，解包后执行 `sh scripts/install.sh --all`。

---

## 构建 ipk（零依赖）

```sh
sh scripts/build-ipk.sh
```

不需要 OpenWrt 环境，产物为 `dist/isp-split_<版本>_all.ipk`。脚本已处理 macOS BSD `ar` 的差异，并对生成的 ipk 做结构校验。

安装：`opkg install isp-split_*_all.ipk`

---

## 构建 apk（Docker）

**这是绝大多数人的路径**——因为 apk 只能用 OpenWrt SDK 编译，而 SDK 是 Linux x86_64 程序。

```sh
sh scripts/build-apk-docker.sh            # 默认 25.12.6，产出 apk
sh scripts/build-apk-docker.sh 24.10.4    # 24.10 SDK，产出 ipk
```

首次运行会拉取 debian 镜像、安装编译依赖、下载 SDK（约 273 MB），全程 5-15 分钟。产物在 `dist/sdk-<版本>/`。

已验证的宿主依赖（脚本内置）：`perl`（基础镜像的 perl-base 缺少 feeds 脚本所需模块）、`python3-distutils`（prereq 检查需要）。

---

## 构建 apk（原生 Linux）

```sh
sh scripts/build-apk.sh                  # 默认 25.12.6 / x86-64
sh scripts/build-apk.sh 24.10.4 x86/64   # 指定版本与架构
OWRT_WORK=/tmp/sdkbuild sh scripts/build-apk.sh
```

脚本流程：动态解析并下载 SDK → 解压到 `.sdk-build/sdk/` → 拷入软件包 → `feeds update/install` → `make defconfig` → `make package/*/compile` → 收集产物到 `dist/sdk-<版本>/`。

宿主要求：Linux x86_64，`build-essential`、`zstd`、`curl`、`git`、`file`、`perl`、`python3-distutils`（Debian 系）。

---

## CI 自动构建

`.github/workflows/release.yml` 已配置：push tag 后自动用 25.12.6 与 24.10.4 两个 SDK 分别编译（调用同一个 `scripts/build-apk.sh`），连同源码包一起发布到 Release。

```sh
git tag v0.2.1 && git push origin v0.2.1
```

---

## 发布检查单

发布新版本时：

1. 更新 `Makefile` 与 `luci-app-isp-split/Makefile` 中的 `PKG_VERSION` / `PKG_RELEASE`
2. 确认 `dist/` 在 `.gitignore` 中（构建产物不入库）
3. 打 tag 并推送，等待 CI 完成
4. 检查 Release 页产物的完整性与 `SHA256SUMS`

## 自建 opkg 软件源（可选，仅 ≤24.10）

```sh
mkdir -p repo/packages && cp dist/*.ipk repo/packages/
cd repo/packages
{
  for f in *.ipk; do
    ar p "$f" control.tar.gz | tar xzO ./control
    echo "Filename: $f"
    echo "Size: $(wc -c < "$f")"
    echo
  done
} > ../Packages && gzip -kf ../Packages
```

客户端添加 `src/gz isp-split <源的 URL>` 后即可 `opkg install`。未签名索引需要客户端关闭签名校验；正式源应使用 usign 签名。

自建 **apk 源不建议**：25.12 的 `packages.adb` 索引只能由 apk-tools 3 生成且默认要求签名，无现成工具链，用 Release 分发更简单。

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
