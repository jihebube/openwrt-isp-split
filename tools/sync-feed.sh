#!/bin/sh
# 把主源码同步进 feed/op-packages 打包壳（kiddin9/op-packages 每12h抓此目录）
# 发版流程必跑：版本字符串/任何 files/ 或 luci 代码变更后执行，否则 Kwrt 源滞后。
set -e
cd "$(dirname "$0")/.."
cp -f files/usr/sbin/isp-split          feed/op-packages/isp-split/files/usr/sbin/isp-split
cp -f files/etc/isp-split.conf          feed/op-packages/isp-split/files/etc/isp-split.conf 2>/dev/null || true
cp -f files/etc/init.d/isp-split        feed/op-packages/isp-split/files/etc/init.d/isp-split 2>/dev/null || true
# LuCI：整树对齐（排除 feed 侧不需要的内容）
cp -rf luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/. feed/op-packages/luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/ 2>/dev/null || true
cp -rf luci-app-isp-split/htdocs/luci-static/resources/isp-split/. feed/op-packages/luci-app-isp-split/htdocs/luci-static/resources/isp-split/ 2>/dev/null || true
cp -rf luci-app-isp-split/root/. feed/op-packages/luci-app-isp-split/root/ 2>/dev/null || true
# feed Makefile 的版本跟主 Makefile 走（PKG_RELEASE 由 kiddin9 sync 自动改写，这里不管）
V=$(grep '^PKG_VERSION:=' Makefile | sed 's/.*:=//')
sed -i "s/^PKG_VERSION:=.*/PKG_VERSION:=$V/" feed/op-packages/isp-split/Makefile feed/op-packages/luci-app-isp-split/Makefile
echo "feed 壳已同步 (PKG_VERSION=$V)"
