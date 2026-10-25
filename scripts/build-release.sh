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
NAME=isp-split-$VER

OUT=$ROOT/dist
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"

echo "== 版本 $VER-$REL =="

# 1) 源码 + 安装脚本包（通用）
STAGE=$WORK/$NAME
mkdir -p "$STAGE"
cp -a Makefile LICENSE README.md .gitignore "$STAGE/" 2>/dev/null || true
cp -a files scripts docs luci-app-isp-split tools "$STAGE/"

# 去掉不该分发的本地文件
rm -rf "$STAGE/tools/fixtures" 2>/dev/null || true

# 附一份最简安装说明
cat > "$STAGE/INSTALL.txt" <<EOF
isp-split $VER-$REL
====================

OpenWrt 25.12 及以上（apk 系，无法手工打包，用脚本安装）：

  sh scripts/install.sh --all

OpenWrt 24.10 及以下（opkg 系）：

  sh scripts/build-ipk.sh
  opkg install dist/isp-split_${VER}-${REL}_all.ipk

安装后先只读预演，确认无误再生效：

  isp-split plan
  isp-split check
  isp-split sync
  isp-split verify

卸载：

  sh scripts/install.sh --uninstall
EOF

( cd "$WORK" && tar czf "$OUT/$NAME.tar.gz" "$NAME" )
echo "  ✓ $NAME.tar.gz"

# 2) ipk（opkg 系）
if [ -x scripts/build-ipk.sh ]; then
	sh scripts/build-ipk.sh >/dev/null 2>&1 && echo "  ✓ isp-split_${VER}-${REL}_all.ipk" ||
		echo "  ! ipk 构建失败，已跳过"
fi

# 3) 校验和
(
	cd "$OUT"
	rm -f SHA256SUMS
	for f in *.tar.gz *.ipk; do
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
