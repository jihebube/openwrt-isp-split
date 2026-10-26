#!/bin/sh
# 构建 opkg 可安装的 .ipk
#
# 适用：opkg 系的 OpenWrt（≤ 24.10，以及仍用 opkg 的衍生固件）
# 不适用：OpenWrt 25.12+ 已改用 apk-tools 3.x，包格式完全不同，
#        请在 SDK / buildroot 中用仓库根目录的 Makefile 编译。
#
# 用法：sh scripts/build-ipk.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PKG=isp-split
# 版本只从主 Makefile 读取，避免 build-ipk 与 PKG_VERSION/ISP_VERSION 漂移
VER=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/Makefile" | head -1 | tr -d '[:space:]')
REL=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/Makefile" | head -1 | tr -d '[:space:]')
[ -n "$VER" ] || { echo "无法从 $ROOT/Makefile 读取 PKG_VERSION" >&2; exit 1; }
REL=${REL:-1}
ARCH=all
OUT=$ROOT/dist
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

[ -f "$ROOT/files/usr/sbin/isp-split" ] || { echo "找不到源码，请在仓库根目录运行" >&2; exit 1; }

mkdir -p "$OUT" "$WORK/data" "$WORK/control"

# ---- data ----
cp -a "$ROOT/files/." "$WORK/data/"
# 数据目录留给运行时创建，但先建好免得首次 apply 报错
mkdir -p "$WORK/data/etc/isp-split/data"
chmod 755 "$WORK/data/usr/sbin/isp-split" \
	"$WORK/data/etc/init.d/isp-split" \
	"$WORK/data/usr/lib/isp-split/build.sh"

# ---- control ----
cat > "$WORK/control/control" <<EOF
Package: $PKG
Version: $VER-$REL
Depends: nftables, curl
Source: https://github.com/jihebube/openwrt-isp-split
SourceName: $PKG
License: MIT
Section: net
Architecture: $ARCH
Installed-Size: $(du -sk "$WORK/data" | cut -f1)
Description: ISP-aware policy routing for mwan3 (nftables native)
EOF

echo "/etc/isp-split.conf" > "$WORK/control/conffiles"

cat > "$WORK/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/isp-split enable >/dev/null 2>&1 || true
logger -t isp-split "已安装。先运行 'isp-split plan' 预演，再 'isp-split sync'"
exit 0
EOF

cat > "$WORK/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/usr/sbin/isp-split uninstall >/dev/null 2>&1 || true
exit 0
EOF

chmod 755 "$WORK/control/postinst" "$WORK/control/prerm"

# ---- 打包 ----
# .ipk = ar 归档，成员依次为 debian-binary / control.tar.gz / data.tar.gz
( cd "$WORK/data" && tar czf "$WORK/data.tar.gz" . )
( cd "$WORK/control" && tar czf "$WORK/control.tar.gz" . )
printf '2.0\n' > "$WORK/debian-binary"

IPK=$OUT/${PKG}_${VER}-${REL}_${ARCH}.ipk
rm -f "$IPK"

# GNU ar 会写符号表，BSD ar 不会；用 rc 并清掉可能残留的旧文件
# 关键：必须加 S（不生成符号表）。BSD ar 默认会尝试 ranlib，
# 对非目标文件的成员直接丢弃，产出一个只有 __.SYMDEF 的空壳归档。
( cd "$WORK" && ar rcS "$IPK" debian-binary control.tar.gz data.tar.gz ) ||
	( cd "$WORK" && ar rc "$IPK" debian-binary control.tar.gz data.tar.gz )

# 冒烟校验：必须正好三个成员
_n=$(ar t "$IPK" 2>/dev/null | grep -cE '^(debian-binary|control\.tar\.gz|data\.tar\.gz)$' || true)
[ "$_n" -eq 3 ] || {
	echo "归档成员不正确（$ _n 个），可能是 ar 的平台差异" >&2
	ar t "$IPK" >&2
	exit 1
}

echo "已生成: $IPK  ($(du -h "$IPK" | cut -f1))"
echo
echo "归档内容:"
ar t "$IPK" | sed 's/^/  /'
echo
echo "包元信息:"
sed 's/^/  /' "$WORK/control/control"
