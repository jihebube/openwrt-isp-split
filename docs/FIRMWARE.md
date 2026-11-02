# 编译进固件

三种方式：

| 方式 | 耗时 | 可替换 mwan3 | 适用 |
|---|---|---|---|
| A. 源码编译（buildroot） | 30-90 分钟 | 是 | 发布自编译固件 |
| B. ImageBuilder + `FILES=` 注入 | 2-5 分钟 | 否 | 向现成镜像添加脚本 |
| C. ImageBuilder + 本地 ipk 仓库 | 3-8 分钟 | 仅 opkg 系 | OpenWrt ≤ 24.10（mwan3 仍需自备 nft 版，见文首「前提」） |

## 前提：mwan3 必须为 nftables 版

上游官方 feed 的 `mwan3` 是 iptables 版（25.12 源里是 2.12.5，24.10 源里是 2.11.16-r5），缺少 `render_config_ipsets`，与本工具不兼容。编译进固件前需将其替换为 nftables 版（[dl12345/mwan3](https://github.com/dl12345/mwan3)，≥ 3.6.0）。

Kwrt 用户不受影响：Kwrt 源内直接提供 `mwan3-nft`。

**24.10 的边界（官方源依赖不可得）**：OpenWrt 24.10 官方 packages 索引里只有 iptables 版
mwan3，**没有** `mwan3-nft`。复核于 24.10.4 官方 packages 索引（x86_64）：

```sh
# 索引里 mwan3 只有一条，且依赖 iptables 系
grep -A2 '^Package: mwan3$' Packages
# Package: mwan3
# Version: 2.11.16-r5
# Depends: libc, ip, ipset, iptables, ip6tables, iptables-mod-conntrack-extra, iptables-mod-ipopt, jshn

grep -c 'mwan3-nft' Packages    # 0：官方源没有 nft 版替代包
```

也就是说，24.10 上不是“装个包”能解决的事：要么按方式 A 自己把 mwan3 换成 nft 版再编进固件，
要么直接上 25.12 + Kwrt 源。只装官方 `mwan3` 的 24.10 固件：`sh scripts/install.sh` 会直接拒绝
（`检测到 iptables 版 mwan3`）；从包安装时，后续 `apply` 也会因为 mwan3 侧没有渲染出 `inet mwan3`
的集合而硬失败——失败在明面上，不会“装好了但没效果”。

确认方法（任一）：

```sh
grep -c render_config_ipsets /lib/mwan3/mwan3.sh   # 必须 ≥ 1
nft list table inet mwan3                           # 表必须存在
```

也可在目标机上运行 `tools/router-preflight.sh`（只读）做完整预检。

## 方式 A：源码编译

```sh
# 1. 取源码
git clone --depth 1 -b v25.12.6 https://github.com/openwrt/openwrt.git
cd openwrt
./scripts/feeds update -a
./scripts/feeds install -a

# 2. 替换 mwan3 为 nftables 版
rm -rf feeds/packages/net/mwan3
git clone --depth 1 https://github.com/dl12345/mwan3.git feeds/packages/net/mwan3

# 3. 放入本项目的包
mkdir -p package/isp-split
cp -r /path/to/openwrt-isp-split/{Makefile,files} package/isp-split/
mkdir -p package/luci-app-isp-split
cp -r /path/to/openwrt-isp-split/luci-app-isp-split/. package/luci-app-isp-split/

# 4. 选中（必须 =y，=m 只编译成独立包不进镜像）
cat >> .config <<'EOF'
CONFIG_PACKAGE_isp-split=y
CONFIG_PACKAGE_luci-app-isp-split=y
EOF
make defconfig

# 5. 编译
make -j4 V=s
```

产物在 `bin/targets/<架构>/`，包清单在同目录 `*.manifest` 中应包含 `isp-split`。

## 方式 B：ImageBuilder + FILES 注入

```sh
BASE=https://downloads.openwrt.org/releases/25.12.6/targets/x86/64
wget "$BASE/openwrt-imagebuilder-25.12.6-x86-64.Linux-x86_64.tar.zst"
mkdir -p ib && tar --zstd -xf openwrt-imagebuilder-*.tar.zst -C ib
cd ib/openwrt-imagebuilder-*/   # 包内自带一层顶层目录，进目录即可（busybox tar 没有 --strip-components）

# 把本项目的文件铺进 rootfs
mkdir -p files
cp -r /path/to/openwrt-isp-split/files/. files/
chmod 0755 files/usr/sbin/isp-split files/etc/init.d/isp-split \
           files/usr/lib/isp-split/build.sh files/etc/uci-defaults/99-isp-split

# LuCI 页面
L=/path/to/openwrt-isp-split/luci-app-isp-split
mkdir -p files/www/luci-static/resources/view/isp-split
cp "$L"/htdocs/luci-static/resources/view/isp-split/*.js \
   files/www/luci-static/resources/view/isp-split/
mkdir -p files/usr/share/luci/menu.d files/usr/share/rpcd/acl.d
cp "$L"/root/usr/share/luci/menu.d/luci-app-isp-split.json files/usr/share/luci/menu.d/
cp "$L"/root/usr/share/rpcd/acl.d/luci-app-isp-split.json files/usr/share/rpcd/acl.d/

make image \
  PROFILE=generic \
  PACKAGES="luci mwan3 nftables curl" \
  FILES=files
```

> **警告**：上游官方 feed 的 `mwan3` 为 iptables 版，上面的 `PACKAGES="... mwan3 ..."` 会安装错误版本；需先替换为 nft 版，或改用含 `mwan3-nft` 的自定义 feed（见文首「前提」）。

注意：`FILES=` 只复制文件、不执行包的 postinst，自启与定时任务由包内自带的 `/etc/uci-defaults/99-isp-split` 在首次启动时完成。

## 方式 C：ImageBuilder + 本地 ipk 仓库（≤ 24.10）

```sh
sh scripts/build-ipk.sh
mkdir -p repo && cp dist/*.ipk repo/
cd repo
{
  for f in *.ipk; do
    ar p "$f" control.tar.gz | tar xzO ./control
    echo "Filename: $f"
    echo "Size: $(wc -c < "$f")"
    echo
  done
} > Packages && gzip -kf Packages
cd ..

cd ib
make image PROFILE=generic \
  PACKAGES="luci mwan3 nftables curl isp-split" \
  --repository "local,file://$(cd ../repo && pwd)"
```

> **警告**：上游官方 feed 的 `mwan3` 为 iptables 版，上面的 `PACKAGES="... mwan3 ..."` 会安装错误版本；需先替换为 nft 版，或改用含 `mwan3-nft` 的自定义 feed（见文首「前提」）。

25.12 的 apk 索引（`packages.adb`）无法手工生成，此方式仅适用于 opkg 系。24.10 属于此方式，
但官方 24.10 源里没有 `mwan3-nft`（见文首「24.10 的边界」）：本地仓库必须一并放 nft 版 mwan3，
否则 `PACKAGES="... mwan3 ..."` 拉到的还是 iptables 版。

## 首次启动初始化

打入固件时包管理器不会执行 postinst，包内自带的 `/etc/uci-defaults/99-isp-split` 会在首次启动时完成：

- `/etc/init.d/isp-split enable`（开机自动 `apply`）
- 写入 cron `17 4 * * * isp-split refresh` 并启用 cron 服务

该脚本执行后会被 OpenWrt 自动删除。

## 关于数据文件

不建议将 IP 段数据预置进固件：数据每日变化，内置快照会过时并占用约 400 kB 空间。首次启动后由 cron 自动拉取；部署现场无外网时才考虑预置快照：

```sh
mkdir -p files/etc/isp-split/data
cp /path/to/snapshot/*.txt files/etc/isp-split/data/
```

## 刷入后验证

```sh
# 包与自启
apk list -I 2>/dev/null | grep isp-split    # 或 opkg list-installed
ls -l /etc/rc.d/S*isp-split

# mwan3 为 nft 版（关键）
grep -c render_config_ipsets /lib/mwan3/mwan3.sh

# 只读预检与生效
isp-split plan
isp-split check
isp-split sync && isp-split verify

# 故障排查
logread | grep -i isp-split
```
