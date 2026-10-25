# 分发方案

## 先分清两类用户

| 用户固件 | 包管理器 | 能直接给的产物 |
|---|---|---|
| OpenWrt / Kwrt **25.12+** | apk-tools 3.x | ❌ 无法手工打包（见下），只能给源码包 + `install.sh`，或由 CI 用 SDK 编译出 `.apk` |
| OpenWrt **≤ 24.10** | opkg | ✅ `.ipk`，还可以自建软件源 |

**为什么 25.12 不能手工打包**（三项实测）：

- 官方 `.apk` 魔数是 `ADBd` —— apk v3 的 ADB 容器格式，不是 tar
- `apk mkpkg` 子命令在 OpenWrt 的 apk 3.0.5 里没有编译
- 手工造 v2 格式包（tar.gz + `.PKGINFO`）会被拒绝：`ERROR: v2 package format error`

所以 apk 只有 SDK 一条路，而 SDK 是 Linux x86_64 程序（macOS 跑不了）。**把 SDK 编译放进 CI，是这个问题的标准解法**（见 `.github/workflows/release.yml`）。

## 五种渠道对比

| 渠道 | 适用 | 门槛 | 用户体验 |
|---|---|---|---|
| **GitHub Release** | 全部 | 低 | 下载 → 解包 → 一条命令 |
| 自建 opkg 软件源 | ≤24.10 | 中 | `opkg update && opkg install isp-split`，能收更新 |
| 一键脚本（curl \| sh） | 全部 | 低 | 一条命令，但需要信任 |
| LuCI 插件市场 / iStore | 全部 | 高 | 图形化一键装 |
| 提交官方 feed | 全部 | 很高 | `opkg install` 直接装 |

## 具体做法

### 1. GitHub Release（推荐起点）

```sh
sh scripts/build-release.sh          # 产出 dist/ 下的 tar.gz、ipk、SHA256SUMS
gh release create v0.1.0 dist/* --title v0.1.0 --notes "..."
```

发布后用户这样装：

```sh
wget -O /tmp/isp.tgz https://github.com/<你>/<repo>/releases/download/v0.1.0/isp-split-0.1.0.tar.gz
mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp --strip-components=1
sh /tmp/isp/scripts/install.sh --all
```

**打 tag 就自动发包**：仓库里已带 `.github/workflows/release.yml`，`git tag v0.1.0 && git push --tags` 会触发 CI 用 25.12.6 与 24.10.4 两个 SDK 各编译一次，产出 `.apk` 和 `.ipk`，自动建 Release。

> CI 编译出的包是**未签名**的，安装时必须 `--allow-untrusted`。

### 2. 自建 opkg 软件源（仅 ≤24.10 可行）

把 ipk 放到一个可访问的目录，生成索引：

```sh
mkdir -p repo/packages
cp dist/*.ipk repo/packages/
cd repo/packages
# Packages 是一个纯文本摘要，可以用脚本从 ipk 的 control 里生成
for f in *.ipk; do
  ar p "$f" control.tar.gz | tar xzO ./control > /tmp/ctl
  cat /tmp/ctl
  echo "Filename: $f"
  echo "Size: $(wc -c < "$f")"
  echo ""
done > ../Packages
gzip -kf ../Packages
```

客户端：

```sh
echo "src/gz isp-split <你的 opkg 源地址>" >> /etc/opkg/customfeeds.conf
opkg update
opkg install isp-split
```

**签名问题**：没有 `Packages.sig` 时客户端会拒绝。要么在 `/etc/opkg.conf` 加 `option check_signature 0`（降低安全性，不推荐），要么用 `usign` 生成密钥对签名。做正式源就得考虑这条。

**apk 软件源不建议自建**：25.12 的索引是 `packages.adb`，只能由 apk-tools 3 生成，且默认要求签名。没有现成工具链的情况下，投入产出比很低——用 Release 更省事。

### 3. 一键脚本（门槛最低，但要给校验方式）

```sh
wget -O /tmp/isp.tgz https://github.com/OWNER/REPO/releases/latest/download/isp-split.tar.gz
echo "<SHA256SUMS 里这一行的内容>" | sha256sum -c
mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp --strip-components=1
sh /tmp/isp/scripts/install.sh --all
```

> 注意：`OWNER/REPO` 换成实际仓库路径。**不推荐** `curl | sh` 直接管道执行——
> 那等于让对方以 root 跑任意代码，先下载、再校验、最后执行的三段式更负责任。

```sh
wget -O /tmp/isp.tgz https://.../isp-split-0.1.0.tar.gz
echo "567280d3...  /tmp/isp.tgz" | sha256sum -c
```

`curl | sh` 这种模式的安全隐患要讲清楚：它等同于让对方以 root 在你机器上执行任意代码。**建议默认给"下载 + 校验 + 执行"三段式，而不是直接管道**。

### 4. 插件市场 / 官方 feed

- **iStore / OpenWrt 插件市场**：面向中文用户，需要包格式完全合规（含 `PKG_MAINTAINER`、`PKG_LICENSE` 等），并接入它们的仓库流程。
- **官方 feed / immortalwrt**：需要走 PR、代码风格审查、CI 通过、有维护者接手。对脚本类包来说主要是接受度问题（纯 shell 的分流工具通常需要更充分的说明）。

这两条都是长期目标，先把 Release 跑起来更实际。

## 建议的组合

```
GitHub Release  ← 主渠道，附 tar.gz + ipk + SHA256SUMS + CI 编出的 apk
      │
      ├─ 中文用户网络不佳 → Gitee / 阿里云 OSS / Cloudflare R2 做镜像
      │
      └─ ≤24.10 用户多起来 → 再补一个 opkg 源（带 usign 签名）
```

## 分发前必须写进 README 的三件事

1. **支持的平台**：OpenWrt 25.12+ / ≤24.10 各自的安装方式
2. **依赖**：`mwan3`（必须是 nftables 版）、`nftables`、`curl`
3. **卸载方式**：`sh scripts/install.sh --uninstall` 或 `isp-split uninstall`

第 3 条最容易被忽略。一个会改 `/etc/config/mwan3` 的工具，如果用户不知道能干净卸载，几乎没人敢装。
