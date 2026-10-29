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
# 出货门：0.2.3 默认 0（构建期物理剥离），0.3.0 功能版用 1。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-0}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
OUT=$ROOT/dist
WORK=$(mktemp -d 2>/dev/null) || WORK=$(mktemp -d /tmp/isp-split-build.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

[ -f "$ROOT/files/usr/sbin/isp-split" ] || { echo "找不到源码，请在仓库根目录运行" >&2; exit 1; }

# 没有 ar 的固件（部分 OpenWrt 精简镜像）也能本地打包：直接写 ar 头。
# 与 `ar rcS` 等价（不写符号表），§19 在 VM 上因此可以真正解包断言。
_mkar() { # <out> <member>...
	_out=$1
	shift
	printf '!<arch>\n' > "$_out"
	for _m in "$@"; do
		_sz=$(wc -c < "$_m" | tr -d ' ')
		printf '%-16s%-12s%-6s%-6s%-8s%-10s`\n' "$(basename "$_m")" 0 0 0 100644 "$_sz" >> "$_out"
		cat "$_m" >> "$_out"
		if [ $((_sz % 2)) -eq 1 ]; then printf '\n' >> "$_out"; fi
	done
	return 0
}

mkdir -p "$OUT" "$WORK/data" "$WORK/control"

# ---- data ----
cp -a "$ROOT/files/." "$WORK/data/"
if [ "$FEATURE_LINECHECK" != "1" ]; then
	sh "$ROOT/scripts/strip-linecheck.sh" "$WORK/data" >/dev/null
fi
# 数据目录留给运行时创建，但先建好免得首次 apply 报错
mkdir -p "$WORK/data/etc/isp-split/data"
chmod 755 "$WORK/data/usr/sbin/isp-split" \
	"$WORK/data/etc/init.d/isp-split" \
	"$WORK/data/usr/lib/isp-split/build.sh"

# ---- control ----
cat > "$WORK/control/control" <<EOF
Package: $PKG
Version: $VER-$REL
Depends: nftables, curl$( [ "$FEATURE_LINECHECK" = "1" ] && printf ', socat' )
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
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache* 2>/dev/null
logger -t isp-split "已安装。先运行 'isp-split plan' 预演，再 'isp-split sync'"
exit 0
EOF

cat > "$WORK/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
# opkg 升级时以 prerm upgrade <version> 调用；升级不能清数据/删规则
[ "$1" = "upgrade" ] && exit 0
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
if [ "${ISP_SPLIT_NO_AR:-0}" != "1" ] && command -v ar >/dev/null 2>&1; then
	( cd "$WORK" && ar rcS "$IPK" debian-binary control.tar.gz data.tar.gz ) ||
		( cd "$WORK" && ar rc "$IPK" debian-binary control.tar.gz data.tar.gz )
else
	( cd "$WORK" && _mkar "$IPK" debian-binary control.tar.gz data.tar.gz )
fi

# 冒烟校验：必须正好三个成员
if command -v ar >/dev/null 2>&1; then
	_n=$(ar t "$IPK" 2>/dev/null | grep -cE '^(debian-binary|control\.tar\.gz|data\.tar\.gz)$' || true)
else
	_n=$(head -c 8 "$IPK" | grep -c '^!<arch>' || true)
	[ "$_n" -eq 1 ] && _n=3
fi
[ "$_n" -eq 3 ] || {
	echo "归档成员不正确（$_n 个），可能是 ar 的平台差异" >&2
	exit 1
}

# ---- luci-app-isp-split（可选页面，同一套剥离规则）----
if [ -d "$ROOT/luci-app-isp-split" ]; then
	LW=$WORK/luci
	mkdir -p "$LW/data/www/luci-static/resources/view/isp-split" \
		"$LW/data/www/luci-static/resources/isp-split/logos" \
		"$LW/data/usr/share/luci/menu.d" "$LW/data/usr/share/rpcd/acl.d" \
		"$LW/control"
	cp -a "$ROOT/luci-app-isp-split/htdocs/luci-static/resources/isp-split/." \
		"$LW/data/www/luci-static/resources/isp-split/"
	cp -a "$ROOT/luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/." \
		"$LW/data/www/luci-static/resources/view/isp-split/"
	cp -a "$ROOT/luci-app-isp-split/root/usr/share/luci/menu.d/." "$LW/data/usr/share/luci/menu.d/"
	cp -a "$ROOT/luci-app-isp-split/root/usr/share/rpcd/acl.d/." "$LW/data/usr/share/rpcd/acl.d/"
	if [ "$FEATURE_LINECHECK" != "1" ]; then
		sh "$ROOT/scripts/strip-linecheck.sh" "$LW/data" >/dev/null
	fi
	cat > "$LW/control/control" <<LCTL
Package: luci-app-isp-split
Version: $VER-$REL
Depends: isp-split, luci-base
Source: https://github.com/jihebube/openwrt-isp-split
SourceName: luci-app-isp-split
License: MIT
Section: luci
Architecture: all
Installed-Size: $(du -sk "$LW/data" | cut -f1)
Description: LuCI page for isp-split
LCTL
	cat > "$LW/control/postinst" <<'LPOST'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache* 2>/dev/null
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
exit 0
LPOST
	chmod 755 "$LW/control/postinst"
	( cd "$LW/data" && tar czf "$LW/data.tar.gz" . )
	( cd "$LW/control" && tar czf "$LW/control.tar.gz" . )
	printf '2.0\n' > "$LW/debian-binary"
	LIPK=$OUT/luci-app-isp-split_${VER}-${REL}_${ARCH}.ipk
	rm -f "$LIPK"
	if [ "${ISP_SPLIT_NO_AR:-0}" != "1" ] && command -v ar >/dev/null 2>&1; then
		( cd "$LW" && ar rcS "$LIPK" debian-binary control.tar.gz data.tar.gz ) ||
			( cd "$LW" && ar rc "$LIPK" debian-binary control.tar.gz data.tar.gz )
	else
		( cd "$LW" && _mkar "$LIPK" debian-binary control.tar.gz data.tar.gz )
	fi
	echo "已生成: $LIPK  ($(du -h "$LIPK" | cut -f1))"
fi

echo "已生成: $IPK  ($(du -h "$IPK" | cut -f1))"
echo
echo "归档内容:"
ar t "$IPK" | sed 's/^/  /'
echo
echo "包元信息:"
sed 's/^/  /' "$WORK/control/control"
