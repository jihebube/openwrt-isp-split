# 把 isp-split 编译进固件

三种做法，从"最正统"到"最快"：

| 方式 | 耗时 | 能进 menuconfig | 能否替换 mwan3 | 适合 |
|---|---|---|---|---|
| A. 源码编译（buildroot） | 30-90 分钟 | ✅ | ✅ | 正式发布自编译固件 |
| B. ImageBuilder + FILES 注入 | 2-5 分钟 | ❌ | ❌ | 只把自己的脚本塞进现成镜像 |
| C. ImageBuilder + 本地 ipk 仓库 | 3-8 分钟 | ❌ | ⚠️ 仅 opkg 系 | ≤24.10 |

---

## 前置条件：mwan3 必须是 nftables 版

**这是最容易踩的坑**：OpenWrt 官方 feed 里的 `mwan3` 是 **iptables 版**，而本项目依赖 nftables 版（`mwan3-nft`，≥ 3.6.0，来自 [dl12345/mwan3](https://github.com/dl12345/mwan3)）。

官方版没有 `render_config_ipsets` 函数，`table inet mwan3` 根本不会存在，`isp-split` 的所有命令都会报错退出。

编进固件前先确认：

```sh
grep -c render_config_ipsets /lib/mwan3/mwan3.sh   # 必须 >= 1
nft list table inet mwan3                          # 必须存在
```

固件编译时必须**先替换 mwan3 的包源码**，否则镜像里带的是错的。

> **Kwrt 用户例外**：Kwrt 的软件源里直接就有 nftables 版（包名 `mwan3-nft`），
> `apk add mwan3-nft` 即可，**不需要**做下面这步替换。这条只针对基于
> 上游 openwrt/packages feed 自编译固件的场景——官方 feed 里的 mwan3
> 是 iptables 版（2.12.5），刚从源码核实过。

---

## 方案 A：源码编译（推荐）

产出完整可控的固件，也是唯一能同时替换 mwan3 的方式。

### 1. 取源码

```sh
git clone --depth 1 -b v25.12.6 https://github.com/openwrt/openwrt.git
cd openwrt
./scripts/feeds update -a
./scripts/feeds install -a
```

### 2. 用 nftables 版 mwan3 覆盖官方 feed 里的版本

```sh
rm -rf feeds/packages/net/mwan3
git clone --depth 1 https://github.com/dl12345/mwan3.git feeds/packages/net/mwan3

# 确认是 nft 版
grep -c render_config_ipsets feeds/packages/net/mwan3/files/usr/lib/mwan3/mwan3.sh
```

> 如果该仓库的目录结构与 feed 不符，直接把它的 `Makefile` 与 `files/` 放到 `package/mwan3/` 下也可以，`package/` 优先级高于 `feeds/`。

### 3. 放入本项目的两个包

```sh
mkdir -p package/isp-split
cp -r /path/to/openwrt-isp-split/{Makefile,files} package/isp-split/

mkdir -p package/luci-app-isp-split
cp -r /path/to/openwrt-isp-split/luci-app-isp-split/. package/luci-app-isp-split/
```

### 4. 选中（必须 `=y`，不能 `=m`）

交互式：

```sh
make menuconfig
```

- `Network → Routing and Redirection → isp-split` → 按 `y`
- `LuCI → 3. Applications → luci-app-isp-split` → 按 `y`

非交互（可写进构建脚本）：

```sh
cat >> .config <<'EOF'
CONFIG_PACKAGE_isp-split=y
CONFIG_PACKAGE_luci-app-isp-split=y
EOF
make defconfig
```

> `=m` 是编译成单独的包而不进镜像，这里必须 `=y`。

### 5. 编译

```sh
make -j$(nproc) V=s
```

产物在 `bin/targets/x86/64/`，例如：

```
openwrt-25.12.6-x86-64-generic-squashfs-combined-efi.img.gz
```

### 6. 确认包真的进去了

```sh
# 看镜像里的包清单（squashfs 镜像可以直接挂载检查）
mkdir -p /tmp/img && zcat bin/targets/x86/64/*.img.gz | dd of=/tmp/img/root.img bs=1M
# 或直接用 rootfs 清单文件
grep isp-split bin/targets/x86/64/*.manifest
```

编完后 `*.manifest` 里应该有 `isp-split` 和 `luci-app-isp-split` 两行。

---

## 方案 B：ImageBuilder + FILES 注入（最快）

不编译工具链，几分钟出镜像。**但它只能注入文件，不能替换 mwan3**——所以前提是你的 mwan3 已经是 nft 版（或你另有办法解决）。

```sh
BASE=https://downloads.openwrt.org/releases/25.12.6/targets/x86/64
wget "$BASE/openwrt-imagebuilder-25.12.6-x86-64.Linux-x86_64.tar.zst"
mkdir -p ib && tar --zstd -xf openwrt-imagebuilder-*.tar.zst -C ib --strip-components=1
cd ib

# 把本项目的文件直接铺进 rootfs
mkdir -p files
cp -r /path/to/openwrt-isp-split/files/. files/
chmod 0755 files/usr/sbin/isp-split
chmod 0755 files/etc/init.d/isp-split
chmod 0755 files/usr/lib/isp-split/build.sh
chmod 0755 files/etc/uci-defaults/99-isp-split

# LuCI 页面（不在 files/ 布局里，单独拷）
L=/path/to/openwrt-isp-split/luci-app-isp-split
mkdir -p files/www/luci-static/resources/view/isp-split
cp "$L"/htdocs/luci-static/resources/view/isp-split/*.js \
   files/www/luci-static/resources/view/isp-split/

mkdir -p files/usr/share/luci/menu.d
cp "$L"/root/usr/share/luci/menu.d/luci-app-isp-split.json files/usr/share/luci/menu.d/

mkdir -p files/usr/share/rpcd/acl.d
cp "$L"/root/usr/share/rpcd/acl.d/luci-app-isp-split.json files/usr/share/rpcd/acl.d/

make image \
  PROFILE=generic \
  PACKAGES="luci luci-ssl mwan3 nftables curl" \
  FILES=files
```

产物在 `bin/targets/x86/64/`。

**注意两点**：

1. `FILES=` 只是复制文件，**不会执行包的 postinst**。所以自启软链要靠项目自带的 `/etc/uci-defaults/99-isp-split` 在首次启动时补上（已提供，见下文）。
2. `PACKAGES` 里如果写 `mwan3`，装的是官方 iptables 版。要么先确认你的固件里 mwan3 已是 nft 版，要么走方案 A。

---

## 方案 C：ImageBuilder + 本地 ipk 仓库（仅 ≤24.10）

opkg 系可以给 ImageBuilder 指定本地仓库，把 isp-split 当正常包装进去。

```sh
# 1) 建本地仓库
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
} > Packages
gzip -kf Packages
cd ..

# 2) 让 ImageBuilder 用它
cd ib
make image PROFILE=generic \
  PACKAGES="luci mwan3 nftables curl isp-split" \
  --repository "local,file://$(cd ../repo && pwd)"
```

无签名索引需要 ImageBuilder 放开校验，否则要按 `docs/distribute.md` 里的办法用 usign 签名。

**25.12 的 apk 索引（`packages.adb`）无法手工生成**，所以方案 C 只在 opkg 系可行。

---

## 首次启动初始化

打进固件时包管理器不会跑 postinst，自启软链缺失。项目已带：

```
files/etc/uci-defaults/99-isp-split
```

首次启动时它会：

- `/etc/init.d/isp-split enable` —— 建立 `/etc/rc.d/S*isp-split`，开机自动 `apply`
- 写入 cron `17 4 * * * isp-split refresh` 并启用 cron 服务
- 记一条 syslog

脚本执行后会被 OpenWrt 自动删除（uci-defaults 的标准行为）。

---

## 关于数据文件

**不要把 IP 段数据预先打进固件**：数据每天都在变，内置一份只会让你在首次开机时用上过时数据，而且会占镜像空间（约 400 kB）。

首次开机后由 cron 自动 `refresh` 拉取；想在部署时立即生效，手动跑一次：

```sh
isp-split fetch && isp-split apply
```

如果你确实需要"离线可用"（比如批量刷机、现场无外网），可以预置快照：

```sh
mkdir -p files/etc/isp-split/data
cp /path/to/snapshot/*.txt files/etc/isp-split/data/
```

但记得这些数据会随时间失效。

---

## 刷入后验证清单

```sh
# 1. 包在不在
grep isp-split /rom/etc/openwrt_release 2>/dev/null; opkg list-installed 2>/dev/null | grep isp-split
apk list -I 2>/dev/null | grep isp-split

# 2. 自启有没有生效
ls -l /etc/rc.d/S*isp-split

# 3. mwan3 是不是 nft 版（最关键）
grep -c render_config_ipsets /lib/mwan3/mwan3.sh
nft list table inet mwan3

# 4. 只读预演
isp-split plan
isp-split check

# 5. 正式生效
isp-split sync && isp-split verify
```

任何一步失败，先看 `/etc/rc.d` 和 mwan3 版本，其次看 syslog：

```sh
logread | grep -i isp-split
```
