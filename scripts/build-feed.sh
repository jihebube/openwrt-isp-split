#!/bin/sh
# 生成标准 opkg / apk 双格式 feed（供独立分支 feed 发布）
#
# 输入：包产物目录里的 *.ipk 与 *.apk（Release 的 6 个包：ipk×4 + apk×2）
# 输出：
#   <out>/ipk/<pkg>.ipk
#   <out>/apk/<pkg>.apk
#   <out>/Packages         opkg 索引（Filename 指向 ipk/）
#   <out>/Packages.gz      同一份索引的 gzip（opkg 优先取它）
#   <out>/apk/packages.adb apk 3.x 索引（必须与 .apk 同目录）
#
# 用法：
#   sh scripts/build-feed.sh --src /path/to/packages [--out dist/feed]
#                            [--apk-bin /path/to/apk] [--keep]
#
#   --src     包目录；默认 dist/（本地构建产物）。只扫描该目录第一层。
#   --out     输出目录；默认 dist/feed。默认先清空 ipk/ 与 apk/（快照语义）。
#   --apk-bin apk-tools 3.x 可执行文件；默认依次找 $APK_BIN、.sdk-build/*/sdk/.../apk、
#             以及 PATH 里的 apk。CI 里由 25.12 build job 上传的 apk-tool 产物提供。
#   --keep    保留输出目录里已有的 ipk/apk（滚动累积），索引按目录里全部包重建。
#
# 为什么 apk 索引用 packages.adb 而不是 APKINDEX.tar.gz（调研结论，0.4.1 实测）：
#   OpenWrt 25.12 的 apk-tools 3.0.5 仓库索引文件名是 packages.adb（ADB 容器），
#   官方 feeds 就是 .../<feed>/packages.adb；APKINDEX.tar.gz 是 apk 2.x 的旧格式，
#   apk 3 的 `index` applet 甚至不接受 v3 包（"file format not supported"）。
#   而且 apk 索引没有 Filename 字段，包地址 = 索引所在目录 + <name>-<version>.apk，
#   所以 packages.adb 必须放在 apk/ 里，不能像 opkg 的 Packages 那样放根目录。
#
# 为什么 ipk 只有一个目录（调研结论）：
#   OpenWrt 的 .ipk 一直是 gzip 压缩的 tar（debian-binary + control.tar.gz +
#   data.tar.gz），不是 Debian 的 ar 容器；opkg 只认这一种。0.3.0 起官方 ipk 与
#   本项目产物同容器，故 ipk/ 单目录即可，不存在"老格式/新格式分目录"。
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/dist"
OUT="$ROOT/dist/feed"
APK_BIN=${APK_BIN:-}
KEEP=0

say() { printf '[feed] %s\n' "$*"; }
warn() { printf '[feed] 警告: %s\n' "$*" >&2; }
die() { printf '[feed] 错误: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
用法: sh scripts/build-feed.sh [--src DIR] [--out DIR] [--apk-bin FILE] [--keep]

  --src     包目录（*.ipk / *.apk，只扫第一层）；默认 dist/
  --out     输出目录；默认 dist/feed
  --apk-bin apk-tools 3.x 可执行文件；默认自动找 $APK_BIN、
            .sdk-build/*/sdk/staging_dir/host/bin/apk 或 PATH 里的 apk
  --keep    保留输出目录里已有的 ipk/apk（默认先清空，快照语义）

产物:
  ipk/<pkg>.ipk  apk/<pkg>.apk
  Packages  Packages.gz      opkg 索引（Filename 带 ipk/ 前缀）
  apk/packages.adb           apk 3.x 索引（必须与 .apk 同目录）
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--src)
		[ $# -ge 2 ] || die "--src 需要参数"
		SRC=$2
		shift 2
		;;
	--out)
		[ $# -ge 2 ] || die "--out 需要参数"
		OUT=$2
		shift 2
		;;
	--apk-bin)
		[ $# -ge 2 ] || die "--apk-bin 需要参数"
		APK_BIN=$2
		shift 2
		;;
	--keep)
		KEEP=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "未知参数: $1（--help 看用法）" ;;
	esac
done

[ -d "$SRC" ] || die "包目录不存在: $SRC"

TMP=$(mktemp -d /tmp/isp-split-feed.XXXXXX 2>/dev/null) ||
	TMP=$(mktemp -d 2>/dev/null) ||
	die "无法创建临时目录"
cleanup() {
	case "${TMP:-}" in
	/tmp/isp-split-feed.* | /tmp/tmp.*) rm -rf "$TMP" ;;
	esac
}
trap cleanup EXIT

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		return 1
	fi
}

# 从 ipk 里取出 control 文本。OpenWrt 的 ipk 是 gzip-tar，成员名可能是
# ./control.tar.gz 或 control.tar.gz；control 同理。
ipk_control() {
	_ipk=$1
	_ctrl_tar=""
	for _m in ./control.tar.gz control.tar.gz; do
		if tar -tzf "$_ipk" "$_m" >/dev/null 2>&1; then
			_ctrl_tar=$_m
			break
		fi
	done
	[ -n "$_ctrl_tar" ] || return 1
	for _m in ./control control; do
		if tar -xzOf "$_ipk" "$_ctrl_tar" 2>/dev/null | tar -tzf - 2>/dev/null | grep -qx -- "$_m"; then
			tar -xzOf "$_ipk" "$_ctrl_tar" 2>/dev/null | tar -xzOf - "$_m" 2>/dev/null
			return 0
		fi
	done
	return 1
}

# apk 3.x 检测：必须是 apk-tools 3（2.x 的 index 不认 v3 包）
detect_apk() {
	for _c in \
		"$ROOT"/.sdk-build/*/sdk/staging_dir/host/bin/apk \
		"$ROOT"/.sdk-build/*/sdk/staging_dir/host/bin/.apk.bin; do
		[ -n "$_c" ] || continue
		[ -x "$_c" ] || continue
		if "$_c" --version 2>/dev/null | grep -q 'apk-tools 3\.'; then
			printf '%s\n' "$_c"
			return 0
		fi
	done
	if command -v apk >/dev/null 2>&1 &&
		apk --version 2>/dev/null | grep -q 'apk-tools 3\.'; then
		command -v apk
		return 0
	fi
	return 1
}

# ---- 输出目录 ----
mkdir -p "$OUT" || die "无法创建输出目录: $OUT"
OUT=$(cd "$OUT" && pwd)
case "$OUT" in
/ | "$ROOT") die "拒绝把 feed 输出到 $OUT（会覆盖仓库/根目录）" ;;
esac
if [ -d "$OUT/op-packages" ]; then
	die "$OUT 是 Kwrt 打包壳目录（含 op-packages），不是在线 feed 输出目录；请用 --out dist/feed"
fi
if [ "$KEEP" = 1 ]; then
	mkdir -p "$OUT/ipk" "$OUT/apk"
else
	# 只删本脚本生成的三类路径，别的文件（例如手工放的 README）不动
	rm -rf "$OUT/ipk" "$OUT/apk"
	rm -f "$OUT/Packages" "$OUT/Packages.gz"
	mkdir -p "$OUT/ipk" "$OUT/apk"
fi

# ---- opkg: ipk/ + Packages(+gz) ----
: > "$OUT/Packages"
: > "$TMP/seen"
ipk_n=0

for f in "$SRC"/*.ipk; do
	[ -f "$f" ] || continue
	base=${f##*/}
	case "$base" in
	*[!A-Za-z0-9._+~-]*) die "包文件名含不安全字符: $base" ;;
	esac
	cp -f "$f" "$OUT/ipk/$base" || die "复制失败: $base"

	control=$(ipk_control "$OUT/ipk/$base") ||
		die "读不出 control（不是合法 ipk？）: $base"
	pkg=$(printf '%s\n' "$control" | sed -n 's/^Package: //p' | head -1)
	ver=$(printf '%s\n' "$control" | sed -n 's/^Version: //p' | head -1)
	arch=$(printf '%s\n' "$control" | sed -n 's/^Architecture: //p' | head -1)
	if [ -z "$pkg" ] || [ -z "$ver" ] || [ -z "$arch" ]; then
		die "control 缺 Package/Version/Architecture: $base"
	fi
	if printf '%s\n' "$control" | grep -qE '^(Filename|Size|SHA256sum):'; then
		die "control 里已含 feed 字段（Filename/Size/SHA256sum），拒绝重复写入: $base"
	fi
	key="$pkg $ver"
	if grep -Fqx -- "$key" "$TMP/seen"; then
		die "重复的包版本: $key（$base）"
	fi
	printf '%s\n' "$key" >> "$TMP/seen"
	[ "$arch" = "all" ] || warn "$pkg 的 Architecture=$arch（feed 不是纯 noarch）"

	size=$(wc -c < "$OUT/ipk/$base" | tr -d ' ')
	[ "$size" -gt 0 ] || die "包为空: $base"
	sha=$(sha256_of "$OUT/ipk/$base") || die "系统缺少 sha256sum/shasum，无法生成索引"

	# 与 OpenWrt 官方 ipkg-make-index.sh 同口径：在 Description 前插入
	# Filename / Size / SHA256sum，其余 control 字段原样保留（含多行 Description）。
	# Filename 带 ipk/ 前缀：opkg 的下载地址 = feed URL + "/" + Filename。
	printf '%s\n' "$control" | awk \
		-v fn="ipk/$base" -v sz="$size" -v sha="$sha" '
		BEGIN { done = 0 }
		!done && /^Description:/ {
			print "Filename: " fn
			print "Size: " sz
			print "SHA256sum: " sha
			done = 1
		}
		{ print }
		END {
			if (!done) {
				print "Filename: " fn
				print "Size: " sz
				print "SHA256sum: " sha
			}
		}' >> "$OUT/Packages"
	printf '\n' >> "$OUT/Packages"
	ipk_n=$((ipk_n + 1))
done

[ "$ipk_n" -gt 0 ] || die "在 $SRC 里没有找到 .ipk"

command -v gzip >/dev/null 2>&1 || die "缺少 gzip（opkg 索引需要 Packages.gz）"
gzip -9n -c "$OUT/Packages" > "$OUT/Packages.gz" || die "gzip 失败"
if ! gzip -dc "$OUT/Packages.gz" | cmp -s - "$OUT/Packages"; then
	die "Packages.gz 与 Packages 不一致"
fi
entries=$(grep -c '^Package: ' "$OUT/Packages" || true)
[ "$entries" -eq "$ipk_n" ] ||
	die "Packages 条目数 $entries 与 ipk 数量 $ipk_n 不符"

# ---- apk: apk/ + packages.adb ----
: > "$TMP/apk-seen"
apk_n=0
for f in "$SRC"/*.apk; do
	[ -f "$f" ] || continue
	base=${f##*/}
	case "$base" in
	*[!A-Za-z0-9._+~-]*) die "包文件名含不安全字符: $base" ;;
	esac
	# apk 3 按 <name>-<version>.apk 推导下载地址，文件名不能随意改
	cp -f "$f" "$OUT/apk/$base" || die "复制失败: $base"
	apk_n=$((apk_n + 1))
done

[ "$apk_n" -gt 0 ] || die "在 $SRC 里没有找到 .apk"

if [ -n "$APK_BIN" ]; then
	[ -x "$APK_BIN" ] || die "--apk-bin 不可执行: $APK_BIN"
	APK=$APK_BIN
else
	APK=$(detect_apk) || die "找不到 apk-tools 3.x。
  - 本地：用 SDK 里的 apk（.sdk-build/*/sdk/staging_dir/host/bin/apk）
  - CI：由 25.12 build job 上传 apk-tool 产物，再用 --apk-bin 指过去
  - 也可显式指定：APK_BIN=/path/to/apk sh scripts/build-feed.sh ..."
fi
"$APK" --version 2>/dev/null | grep -q 'apk-tools 3\.' ||
	die "需要 apk-tools 3.x（当前: $("$APK" --version 2>&1 | head -1)）"

# mkndx 在 apk/ 目录内运行，索引里的包地址才与 .apk 同级
(
	cd "$OUT/apk" &&
		"$APK" mkndx --allow-untrusted -o packages.adb ./*.apk
) || die "apk mkndx 失败"
[ -s "$OUT/apk/packages.adb" ] || die "apk 索引为空"
[ "$(dd if="$OUT/apk/packages.adb" bs=4 count=1 2>/dev/null)" = "ADBd" ] ||
	die "apk 索引不是 ADB 容器（apk-tools 版本不对？）"

# ---- 汇总 ----
say "完成：$OUT"
say "  opkg: $ipk_n 个 ipk -> Packages / Packages.gz（Filename 前缀 ipk/）"
say "  apk : $apk_n 个 apk -> apk/packages.adb（索引与包同目录）"
printf '\n'
find "$OUT" -type f | sort | while IFS= read -r _f; do
	printf '  %s\n' "${_f#"$OUT"/}"
done
