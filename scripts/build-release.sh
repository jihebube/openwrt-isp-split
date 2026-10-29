#!/bin/sh
# 生成可直接分发的产物
#
#   dist/isp-split-<ver>.tar.gz      源码 + 安装脚本（所有版本通用，含 25.12/apk）
#   dist/isp-split_<ver>-1_all.ipk   opkg 系（≤24.10）
#   dist/SHA256SUMS                  校验和
#
# 用法：sh scripts/build-release.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VER=$(sed -n 's/^PKG_VERSION:=//p' Makefile | head -1)
REL=$(sed -n 's/^PKG_RELEASE:=//p' Makefile | head -1)
[ -n "$VER" ] || { echo "无法从 Makefile 读取 PKG_VERSION" >&2; exit 1; }
REL=${REL:-1}
# 与 Makefile / build-ipk.sh / install.sh 同一个出货门。
#   1 = 完整功能版：发“源码 + 安装脚本”整包（含 docs/tools/selftest）。
#   0 = 纯修复版：不发源码包；只发运行时的 install 包 + ipk，且在打包时
#       物理剥离线路体检（docs/tools 本来就不进这个包）。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-0}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
NAME=isp-split-$VER

OUT=$ROOT/dist
WORK=$(mktemp -d 2>/dev/null) || WORK=$(mktemp -d /tmp/isp-split-build.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"

echo "== 版本 $VER-$REL =="

# 1) 源码 / 安装包
STAGE=$WORK/$NAME
mkdir -p "$STAGE"
if [ "$FEATURE_LINECHECK" = "1" ]; then
	cp -a Makefile LICENSE README.md .gitignore "$STAGE/" 2>/dev/null || true
	cp -a files scripts docs luci-app-isp-split tools "$STAGE/"
	# 主包 Build/Prepare 用 $(CURDIR)/strip-linecheck.sh，包目录必须自带
	cp -a strip-linecheck.sh "$STAGE/"
	# 去掉不该分发的本地文件
	rm -rf "$STAGE/tools/fixtures" 2>/dev/null || true
	TARBALL=$OUT/$NAME.tar.gz
else
	# 0 版不发源码包：只发运行时 + 安装脚本，且运行时已物理剥离。
	# LuCI 只暂存会被安装的 htdocs/root：包目录里的 Makefile 与
	# strip-linecheck.sh 自带 `lc:begin` / linecheck 字样，整目录剥离会被
	# 自己的零残留断言误杀。
	cp -a files LICENSE "$STAGE/"
	mkdir -p "$STAGE/luci-app-isp-split"
	cp -a luci-app-isp-split/htdocs luci-app-isp-split/root "$STAGE/luci-app-isp-split/"
	mkdir -p "$STAGE/scripts"
	cp -a scripts/install.sh "$STAGE/scripts/"
	sh "$ROOT/scripts/strip-linecheck.sh" "$STAGE/files" >/dev/null
	sh "$ROOT/scripts/strip-linecheck.sh" "$STAGE/luci-app-isp-split" >/dev/null
	TARBALL=$OUT/$NAME-install.tar.gz
fi

# 附一份最简安装说明
cat > "$STAGE/INSTALL.txt" <<EOF
isp-split $VER-$REL
====================

OpenWrt 25.12 及以上（apk 系，无法手工打包，用脚本安装）：

  sh scripts/install.sh --all

OpenWrt 24.10 及以下（opkg 系）：

  opkg install isp-split_${VER}-${REL}_all.ipk

安装后先只读预演，确认无误再生效：

  isp-split plan
  isp-split check
  isp-split sync
  isp-split verify

卸载：

  sh scripts/install.sh --uninstall
EOF

( cd "$WORK" && tar czf "$TARBALL" "$NAME" )
echo "  ✓ $(basename "$TARBALL")"

# 2) ipk（opkg 系）
if [ -x scripts/build-ipk.sh ]; then
	sh scripts/build-ipk.sh >/dev/null 2>&1 && echo "  ✓ isp-split_${VER}-${REL}_all.ipk" ||
		echo "  ! ipk 构建失败，已跳过"
fi

# 3) 校验和
(
	cd "$OUT"
	rm -f SHA256SUMS
	for f in *.tar.gz *.ipk *.apk; do
		[ -f "$f" ] || continue
		case "$f" in
		*"$NAME"*|*"_${VER}-"*) sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" ;;
		esac
	done > SHA256SUMS
)
echo "  ✓ SHA256SUMS"

echo
echo "== 发布清单 =="
ls -lh "$OUT" | sed 's/^/  /'
