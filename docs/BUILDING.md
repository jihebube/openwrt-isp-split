# 从源码构建与打包

克隆仓库之后，按"你想产出什么"对号入座：

| 你的目标用户固件 | 产物 | 构建命令 | 难度 |
|---|---|---|---|
| Kwrt / OpenWrt **25.12+**（apk） | `.apk` | `scripts/build-apk-docker.sh`（推荐）或 `build-apk.sh` | 中 |
| OpenWrt **≤ 24.10**（opkg） | `.ipk` | `scripts/build-ipk.sh` | 低（零依赖） |
| 自编译固件 | 镜像 | 见 [build-into-firmware.md](build-into-firmware.md) | 高 |

---

## 1. 只想装，不想构建？

不用构建。到 [Releases](../../releases) 下载 `isp-split-*.tar.gz`，然后：

```sh
wget -O /tmp/isp.tgz <Release 里 tar.gz 的地址>
mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp --strip-components=1
sh /tmp/isp/scripts/install.sh --all
```

---

## 2. 构建 `.ipk`（零依赖）

```sh
sh scripts/build-ipk.sh
```

- **不需要 OpenWrt、不需要 SDK**，任何能跑 `sh` / `tar` / `ar` 的机器都行（macOS / Linux / WSL）
- 产物：`dist/isp-split_<版本>_all.ipk`
- 装到 opkg 系固件：`opkg install *.ipk`
- 脚本已处理 macOS BSD `ar` 丢成员的问题（必须 `-S`），产出做过三成员冒烟校验

---

## 3. 构建 `.apk`（Docker，推荐）

**这是绝大多数人的路径**——因为 apk 只能用 OpenWrt SDK 编译，而 SDK 是 Linux x86_64 程序，macOS 跑不了。

```sh
sh scripts/build-apk-docker.sh           # 默认 25.12.6
sh scripts/build-apk-docker.sh 24.10.4   # 用 24.10 的 SDK，产出 ipk
```

- 只需要 Docker，其他什么都不用装
- 第一次运行会：拉 debian 镜像 → 装编译依赖 → 下载 SDK（约 273 MB）→ 编译，全程 5-15 分钟
- 产物：`dist/sdk-25.12.6/*.apk` 和 `*.ipk`
- **已实测跑通**（在 Debian NAS 的 Docker 里产出 `isp-split-0.1.0-r1.apk`，
  `apk add --no-network --allow-untrusted` 直装成功，postinst 自动生效）

踩过的三个坑（脚本已内置修复，列出来防走弯路）：

| 坑 | 症状 | 修复 |
|---|---|---|
| 容器 perl 是精简的 `perl-base`，缺 `Getopt::Std` | `feeds` 报 `BEGIN failed--compilation aborted at scripts/feeds line 2` | apt 装 `perl` |
| Debian 12 的 python3 默认不带 distutils | `make defconfig` 报 `Please install the Python3 distutils module` | apt 装 `python3-distutils` |
| `make defconfig` 的 prereq 输出走 stdout | 依赖缺失被静默吞掉 | 别把 stdout 全丢弃 |

给装包的人的提示（一起发过去）：

```sh
apk add --no-network --allow-untrusted ./isp-split_*.apk
```

- `--allow-untrusted`：CI/本地编译的包没有签名
- `--no-network`：跳过联网拉索引，避免 `packages.adb` 下载失败刷屏

---

## 4. 构建 `.apk`（原生 Linux）

有 Linux x86_64 机器的话可以不经过 Docker：

```sh
sh scripts/build-apk.sh                  # 默认 25.12.6 / x86-64
sh scripts/build-apk.sh 24.10.4 x86/64   # 指定版本与架构
OWRT_WORK=/tmp/sdkbuild sh scripts/build-apk.sh   # SDK 放别处
```

脚本内部做的事（也就是 Docker 版复用的同一条路径）：

1. 从 `downloads.openwrt.org/releases/<版本>/targets/x86/64/` 动态解析 SDK 文件名并下载（`zst` 或 `xz` 都支持）
2. 解压到 `.sdk-build/sdk/`（只做一次，重复构建不会重新下载）
3. 把仓库的 `Makefile + files/` 与 `luci-app-isp-split/` 拷进 `sdk/package/`
4. `feeds update/install`（解析依赖）→ `make defconfig` → `make package/.../compile`
5. 收集 `bin/packages` 里的产物到 `dist/sdk-<版本>/`

宿主机依赖：`build-essential`、`zstd`、`curl`、`git`、`file`、`perl`（Debian 系一句话装齐的命令在 `build-apk-docker.sh` 里）。

---

## 5. 编译进固件

见 [build-into-firmware.md](build-into-firmware.md)。

**再次强调那个坑**：上游官方 feed 的 mwan3 是 iptables 版（2.12.5），编译固件必须先替换成 nftables 版。Kwrt 用户不受影响（源里直接有 `mwan3-nft`）。

---

## 6. 让 CI 替你构建（fork 即用）

仓库自带 `.github/workflows/release.yml`：fork 之后打 tag 就会自动用 25.12.6 和 24.10.4 两个 SDK 各编译一次，产物自动挂到 Release 上。

```sh
git tag v0.1.0 && git push --tags
```

它调用的就是上面同一个 `scripts/build-apk.sh`，所以"本地能编"和"CI 能编"是同一份逻辑。

---

## 7. 常见问题

**装包时报 `signature check failed`？**
本地/CI 编的包没有签名，加 `--allow-untrusted`（apk）或关闭 opkg 签名校验。

**`apk add` 卡在下载 `packages.adb`？**
加 `--no-network`，只装本地包。

**`luci-app-isp-split` 编译失败？**
luci-base 版本与 SDK 对不上。主包 `isp-split` 不受影响，可以先跳过 luci 包（脚本已容错）。

**为什么不能像 ipk 那样手工拼一个 apk？**
apk 3 的包格式是 ADB 容器（魔数 `ADBd`），`apk mkpkg` 在 OpenWrt 3.0.5 里没编译，v2 格式也被拒——三项实测见 README「打包与安装」。所以 SDK 是唯一路径。

**为什么 `DEPENDS` 里没有 mwan3？**
官方 feed 的 mwan3 是 iptables 版（2.12.5），写 `+mwan3` 会在构建时错误解析到它；Kwrt 源里 nft 版的包名又是 `mwan3-nft`。所以改为运行时强检查（`install.sh` 与 `router-preflight.sh`），并在包描述里说明。
