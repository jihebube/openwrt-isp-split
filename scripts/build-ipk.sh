#!/bin/sh
# 构建 opkg 可安装的 .ipk
#
# 产物容器与 OpenWrt 23.05/24.10 官方一致：外层 gzip 包一个 tar，成员为
# ./debian-binary / ./control.tar.gz / ./data.tar.gz。不是 Debian 那种明文
# ar（!<arch>）——opkg 的 libbb/deb_extract 只会先 gunzip 外层再按 tar
# 遍历成员，明文 ar 在 23.05+ 上直接 "Malformed package file"。
# 极老固件（明文 ar 时代）可显式回退：
#   ISP_SPLIT_IPK_FORMAT=ar sh scripts/build-ipk.sh
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
# 出货门：1 = 完整功能（默认，含线路体检与 socat 依赖）；
#         0 = 构建期物理剥离（剥离版，需显式指定）。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-1}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
OUT=$ROOT/dist
WORK=$(mktemp -d 2>/dev/null) || WORK=$(mktemp -d /tmp/isp-split-build.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# 容器格式：tar = gzip-tar（默认，23.05/24.10 官方同款）；ar = 历史明文 ar
IPK_FORMAT=${ISP_SPLIT_IPK_FORMAT:-tar}
case "$IPK_FORMAT" in
tar|ar) ;;
*) echo "ISP_SPLIT_IPK_FORMAT 只能是 tar 或 ar" >&2; exit 1 ;;
esac

[ -f "$ROOT/files/usr/sbin/isp-split" ] || { echo "找不到源码，请在仓库根目录运行" >&2; exit 1; }

# 仅 ISP_SPLIT_IPK_FORMAT=ar 时用到：给极老 opkg 的明文 ar。
# 没有 ar 的机器也能打包：直接写 ar 头，与 `ar rcS` 等价（不写符号表）。
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
# 权限归一化：cp -a 会把工作区的权限位一路带进包里。0.3.0 实测过一次：
# isp-split.css 在工作区被改成 0600 → 装到设备上 uhttpd 读不了 → 静态资源 403，
# LuCI 页面裸奔（无样式）。git checkout 出来是 644，但本地直接打包/安装会中招，
# 所以打包侧显式归一：目录 755、文件 644，再单独抬可执行文件。
find "$WORK/data" -type d -exec chmod 755 {} \;
find "$WORK/data" -type f -exec chmod 644 {} \;
chmod 755 "$WORK/data/usr/sbin/isp-split" \
	"$WORK/data/etc/init.d/isp-split" \
	"$WORK/data/usr/lib/isp-split/build.sh" \
	"$WORK/data/etc/uci-defaults/99-isp-split"
if [ -f "$WORK/data/usr/lib/isp-split/lc-run" ]; then
	chmod 755 "$WORK/data/usr/lib/isp-split/lc-run"
fi

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
# 内层 data.tar.gz / control.tar.gz 始终是 gzip 压缩的 tar；外层容器二选一：
#   tar（默认）：gzip + tar，成员 ./debian-binary ./control.tar.gz ./data.tar.gz
#   ar（兼容）：明文 !<arch>，只有极老 opkg 认，23.05+ 会拒绝
( cd "$WORK/data" && tar czf "$WORK/data.tar.gz" . )
( cd "$WORK/control" && tar czf "$WORK/control.tar.gz" . )
printf '2.0\n' > "$WORK/debian-binary"

_ipk_pack() { # <dir> <out>
	case "$IPK_FORMAT" in
	tar)
		# ./ 前缀与官方产物一致；opkg 匹配成员时会自己剥掉 "./"
		( cd "$1" && tar czf "$2" ./debian-binary ./control.tar.gz ./data.tar.gz )
		;;
	ar)
		# GNU ar 会写符号表，BSD ar 不会；必须加 S（不生成符号表）。
		# BSD ar 默认会尝试 ranlib，对非目标文件的成员直接丢弃，
		# 产出一个只有 __.SYMDEF 的空壳归档。
		if command -v ar >/dev/null 2>&1; then
			( cd "$1" && ar rcS "$2" debian-binary control.tar.gz data.tar.gz ) ||
				( cd "$1" && ar rc "$2" debian-binary control.tar.gz data.tar.gz )
		else
			( cd "$1" && _mkar "$2" debian-binary control.tar.gz data.tar.gz )
		fi
		;;
	esac
}

_ipk_check() { # <ipk>：容器 magic 正确且恰好三个成员
	_n=0
	case "$IPK_FORMAT" in
	tar)
		printf '\037\213' > "$WORK/.magic.gz"
		if ! dd if="$1" bs=1 count=2 2>/dev/null | cmp -s - "$WORK/.magic.gz"; then
			echo "容器 magic 不是 1f 8b（gzip-tar）" >&2
			return 1
		fi
		_n=$(tar tzf "$1" 2>/dev/null |
			grep -cE '^(\./)?(debian-binary|control\.tar\.gz|data\.tar\.gz)$' || true)
		;;
	ar)
		if command -v ar >/dev/null 2>&1; then
			_n=$(ar t "$1" 2>/dev/null |
				grep -cE '^(debian-binary|control\.tar\.gz|data\.tar\.gz)$' || true)
		else
			_n=$(head -c 8 "$1" | grep -c '^!<arch>' || true)
			[ "$_n" -eq 1 ] && _n=3
		fi
		;;
	esac
	[ "$_n" -eq 3 ]
}

IPK=$OUT/${PKG}_${VER}-${REL}_${ARCH}.ipk
rm -f "$IPK"
_ipk_pack "$WORK" "$IPK" || { echo "打包失败: $IPK" >&2; exit 1; }

# 冒烟校验：不要用 `... | head -N && echo ✓` 这种恒真判断
_ipk_check "$IPK" || {
	echo "归档结构不正确（格式=$IPK_FORMAT，成员=${_n:-0} 个）" >&2
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
	# 同一套权限归一化（静态资源必须 uhttpd 可读；0600 会变成 403 裸页面）
	find "$LW/data" -type d -exec chmod 755 {} \;
	find "$LW/data" -type f -exec chmod 644 {} \;
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
	_ipk_pack "$LW" "$LIPK" || { echo "打包失败: $LIPK" >&2; exit 1; }
	_ipk_check "$LIPK" || {
		echo "归档结构不正确: $LIPK（格式=$IPK_FORMAT，成员=${_n:-0} 个）" >&2
		exit 1
	}
	echo "已生成: $LIPK  ($(du -h "$LIPK" | cut -f1))"
fi

echo "已生成: $IPK  ($(du -h "$IPK" | cut -f1))"
echo
echo "归档内容（$IPK_FORMAT 容器）:"
if [ "$IPK_FORMAT" = tar ]; then
	tar tzf "$IPK" | sed 's/^/  /'
elif command -v ar >/dev/null 2>&1; then
	ar t "$IPK" | sed 's/^/  /'
else
	echo "  (无 ar 命令，跳过列表)"
fi
echo
echo "包元信息:"
sed 's/^/  /' "$WORK/control/control"
