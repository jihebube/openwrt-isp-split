#!/bin/sh
# 把主源码同步进 feed/op-packages 打包壳（kiddin9/op-packages 每12h抓此目录）
# 发版流程必跑：版本字符串/任何 files/ 或 luci 代码变更后执行，否则 Kwrt 源滞后。
set -e
cd "$(dirname "$0")/.."
cp -f files/usr/sbin/isp-split          feed/op-packages/isp-split/files/usr/sbin/isp-split
cp -f files/etc/isp-split.conf          feed/op-packages/isp-split/files/etc/isp-split.conf 2>/dev/null || true
cp -f files/etc/init.d/isp-split        feed/op-packages/isp-split/files/etc/init.d/isp-split 2>/dev/null || true
mkdir -p feed/op-packages/isp-split/files/usr/lib/isp-split
# 数据管线与体检运行时的全部文件：下方逐字节校验覆盖 build.sh/*.awk，
# 只拷 lc-run 会让 build.sh 在改版后悄悄漂移（cmp 失败才暴露）。
cp -f files/usr/lib/isp-split/* feed/op-packages/isp-split/files/usr/lib/isp-split/
# 两个包 Makefile 与主源码逐字节一致：FEATURE_LINECHECK / strip 规则不会漂移
cp -f Makefile                          feed/op-packages/isp-split/Makefile
cp -f luci-app-isp-split/Makefile       feed/op-packages/luci-app-isp-split/Makefile
# 剥离实现只有一个来源：scripts/strip-linecheck.sh。feed 是独立 clone，
# 包目录里看不到仓库的 scripts/，所以每个包目录自带一份（逐字节一致，下方校验）。
# Build/Prepare 用 $(CURDIR)/strip-linecheck.sh 调用它，不再手抄 sed。
cp -f strip-linecheck.sh                feed/op-packages/isp-split/strip-linecheck.sh
cp -f luci-app-isp-split/strip-linecheck.sh feed/op-packages/luci-app-isp-split/strip-linecheck.sh
# LuCI：整树对齐（排除 feed 侧不需要的内容）
cp -rf luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/. feed/op-packages/luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/ 2>/dev/null || true
cp -rf luci-app-isp-split/htdocs/luci-static/resources/isp-split/. feed/op-packages/luci-app-isp-split/htdocs/luci-static/resources/isp-split/ 2>/dev/null || true
cp -rf luci-app-isp-split/root/. feed/op-packages/luci-app-isp-split/root/ 2>/dev/null || true
# feed Makefile 的版本跟主 Makefile 走（PKG_RELEASE 由 kiddin9 sync 自动改写，这里不管）
V=$(grep '^PKG_VERSION:=' Makefile | sed 's/.*:=//')
sed -i "s/^PKG_VERSION:=.*/PKG_VERSION:=$V/" feed/op-packages/isp-split/Makefile feed/op-packages/luci-app-isp-split/Makefile

# 逐字节校验：feed 里的运行时代码必须与主源码完全相同（版本号在 Makefile 里单独对齐）。
_bad=0
for f in usr/sbin/isp-split etc/isp-split.conf etc/init.d/isp-split \
         usr/lib/isp-split/lc-run usr/lib/isp-split/build.sh \
         usr/lib/isp-split/cidr2range.awk usr/lib/isp-split/merge.awk \
         usr/lib/isp-split/exclude.awk usr/lib/isp-split/range2cidr.awk \
         usr/lib/isp-split/rules-splice.awk usr/lib/isp-split/badcidr.awk \
         usr/lib/isp-split/ispdiff.awk; do
	[ -f "files/$f" ] || continue
	cmp -s "files/$f" "feed/op-packages/isp-split/files/$f" || { echo "不一致: $f" >&2; _bad=1; }
done
for f in htdocs/luci-static/resources/view/isp-split/overview.js \
         htdocs/luci-static/resources/view/isp-split/config.js \
         htdocs/luci-static/resources/view/isp-split/linecheck.js \
         htdocs/luci-static/resources/isp-split/isp-split.css \
         root/usr/share/luci/menu.d/luci-app-isp-split.json \
         root/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json \
         root/usr/share/rpcd/acl.d/luci-app-isp-split.json; do
	cmp -s "luci-app-isp-split/$f" "feed/op-packages/luci-app-isp-split/$f" || { echo "不一致: $f" >&2; _bad=1; }
done
# 剥离脚本：仓库两份副本 + feed 两份，全部与 scripts/strip-linecheck.sh 逐字节一致
for f in ./strip-linecheck.sh \
         luci-app-isp-split/strip-linecheck.sh \
         feed/op-packages/isp-split/strip-linecheck.sh \
         feed/op-packages/luci-app-isp-split/strip-linecheck.sh; do
	cmp -s scripts/strip-linecheck.sh "$f" || { echo "剥离脚本不一致: $f" >&2; _bad=1; }
done
[ "$_bad" = "0" ] || { echo "feed 同步校验失败" >&2; exit 1; }
echo "feed 壳已同步 (PKG_VERSION=$V)，运行时代码逐字节一致"
