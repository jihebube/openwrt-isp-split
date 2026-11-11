#!/bin/sh
# 在线一键安装 —— 不依赖仓库已解包，从 GitHub Release 拉源码包再走 install.sh
#
# 用法（root）：
#   curl -fsSL https://raw.githubusercontent.com/jihebube/openwrt-isp-split/main/scripts/install-online.sh | sh
#   wget -qO- <同一个 URL> | sh
#   # raw 不通时换 jsDelivr：
#   curl -fsSL https://cdn.jsdelivr.net/gh/jihebube/openwrt-isp-split@main/scripts/install-online.sh | sh
#
#   也可以先下载再执行（便于先读一遍脚本）：
#   wget -O /tmp/install-online.sh <URL> && sh /tmp/install-online.sh
#
# 环境变量：
#   ISP_VER       指定版本（如 0.4.0）；默认空 = Release latest。不带 v 前缀、不带 -r1
#   ISP_BASE      Release 基地址；默认 https://github.com/jihebube/openwrt-isp-split
#                 可换成可信的 GitHub 加速前缀（脚本仍用 SHA256SUMS 校验）
#   ISP_INSECURE  1 = 跳过 TLS 证书校验（仅老固件缺 ca-bundle 时临时用）
#   ISP_DRY_RUN   1 = 只打印将用的 URL，不下载不安装
#   ISP_SKIP_INSTALL 1 = 只下载解包，不执行安装（配 ISP_DEST 指定落点）
#   ISP_DEST      ISP_SKIP_INSTALL=1 时的解包目录，默认 /tmp/isp-split-<版本>，必须是 /tmp 下
#
# 设计约束：
#   - busybox ash 兼容：无 bashism、无数组、无 pipefail；curl 与 wget 二选一
#   - 不做 `curl ... | tar` 的管道解包：先完整落盘 + SHA256 校验 + tar 列表检查，
#     再解到 /tmp 执行。下载/校验任何一步失败都不会动系统。
#   - 目标机不需要 git、不需要 SDK；apk/opkg 只用于探测系统类型并打印提示，
#     安装仍走项目自带的 scripts/install.sh（与 25.12 无 SDK 场景同一条路径）。
set -eu

BASE=${ISP_BASE:-https://github.com/jihebube/openwrt-isp-split}
VER=${ISP_VER:-}
INSECURE=${ISP_INSECURE:-0}
DRY_RUN=${ISP_DRY_RUN:-0}
SKIP_INSTALL=${ISP_SKIP_INSTALL:-0}
DEST=${ISP_DEST:-}

say() { printf '[isp-split] %s\n' "$*"; }
warn() { printf '[isp-split] 警告: %s\n' "$*" >&2; }
die() { printf '[isp-split] 错误: %s\n' "$*" >&2; exit 1; }

# 结尾斜杠会让 URL 拼出 //，统一去掉
while :; do
	case "$BASE" in
	*/) BASE=${BASE%/} ;;
	*) break ;;
	esac
done
case "$BASE" in
http://* | https://*) ;;
*) die "ISP_BASE 必须是 http(s):// 地址，当前: $BASE" ;;
esac
case "$INSECURE" in 0 | 1) ;; *) die "ISP_INSECURE 只能是 0 或 1" ;; esac
case "$DRY_RUN" in 0 | 1) ;; *) die "ISP_DRY_RUN 只能是 0 或 1" ;; esac
case "$SKIP_INSTALL" in 0 | 1) ;; *) die "ISP_SKIP_INSTALL 只能是 0 或 1" ;; esac

# root 检查：install.sh 自己也会查，这里提前查是为了不白下载 1.6 MB
if [ "$DRY_RUN" != 1 ] && [ "$SKIP_INSTALL" != 1 ] && [ "$(id -u)" != 0 ]; then
	die "需要 root 权限（请用 root 登录路由器，或 sudo -i 后重试）"
fi

# ---- 依赖探测 ----
command -v tar >/dev/null 2>&1 || die "缺少 tar（busybox 自带即可）"
if command -v curl >/dev/null 2>&1; then
	HAVE_CURL=1
elif command -v wget >/dev/null 2>&1; then
	HAVE_CURL=0
else
	die "需要 curl 或 wget 之一（OpenWrt 默认带 uclient-fetch/wget）"
fi

TMP=""
cleanup() {
	case "${TMP:-}" in
	/tmp/isp-split-online.* | /tmp/tmp.*) rm -rf "$TMP" ;;
	esac
}
trap cleanup EXIT
trap 'exit 130' INT TERM

TMP=$(mktemp -d /tmp/isp-split-online.XXXXXX 2>/dev/null) ||
	TMP=$(mktemp -d 2>/dev/null) ||
	die "无法创建临时目录"
case "$TMP" in
/tmp/*) ;;
*) die "临时目录不在 /tmp 下（$TMP），拒绝继续" ;;
esac

# fetch <url> <outfile>：失败会删掉半截文件，返回非零
fetch() {
	_f_url=$1
	_f_out=$2
	rm -f "$_f_out"
	if [ "$HAVE_CURL" = 1 ]; then
		if [ "$INSECURE" = 1 ]; then
			curl -fsSL --insecure -o "$_f_out" "$_f_url" || { rm -f "$_f_out"; return 1; }
		else
			curl -fsSL -o "$_f_out" "$_f_url" || { rm -f "$_f_out"; return 1; }
		fi
	else
		if [ "$INSECURE" = 1 ]; then
			wget -q --no-check-certificate -O "$_f_out" "$_f_url" || { rm -f "$_f_out"; return 1; }
		else
			wget -q -O "$_f_out" "$_f_url" || { rm -f "$_f_out"; return 1; }
		fi
	fi
	[ -s "$_f_out" ]
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		return 1
	fi
}

# latest 的 tag 解析兜底：GitHub 的 /releases/latest 会 302 到 /releases/tag/vX.Y.Z。
# 主路径是直接读 latest/download/SHA256SUMS（不用解析 HTTP 头），这里只在前者失败时用。
probe_latest_tag() {
	_p_url="$BASE/releases/latest"
	_p_loc=""
	if [ "$HAVE_CURL" = 1 ]; then
		_p_loc=$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$_p_url" 2>/dev/null) || _p_loc=""
	else
		_p_loc=$(wget -S --spider -O /dev/null "$_p_url" 2>&1 |
			awk 'tolower($1) == "location:" {print $2}' | tail -1) || _p_loc=""
	fi
	_p_loc=${_p_loc%%\?*}
	case "$_p_loc" in
	*/releases/tag/v*) printf '%s\n' "${_p_loc##*/releases/tag/}" ;;
	*) return 1 ;;
	esac
}

# ---- 解析版本与下载地址 ----
ASSET=""
DL_BASE=""
SUMS_FILE="$TMP/SHA256SUMS"
HAVE_SUMS=0

if [ -n "$VER" ]; then
	VER=${VER#v}
	case "$VER" in
	"" | *[!0-9A-Za-z._-]*) die "ISP_VER 含非法字符: $VER（只接受 0.4.1 这样的版本号）" ;;
	esac
	DL_BASE="$BASE/releases/download/v$VER"
	ASSET="isp-split-$VER.tar.gz"
	say "指定版本: $VER"
else
	# 主路径：latest/download/SHA256SUMS 的资产名就是 isp-split-<版本>.tar.gz，
	# 既拿到版本又拿到校验清单，不需要解析 JSON，也不受 API 限额影响。
	if fetch "$BASE/releases/latest/download/SHA256SUMS" "$SUMS_FILE"; then
		HAVE_SUMS=1
		ASSET=$(awk '$2 ~ /^isp-split-[0-9][0-9A-Za-z._-]*\.tar\.gz$/ {print $2}' "$SUMS_FILE" | head -1)
		[ -n "$ASSET" ] ||
			die "latest 的 SHA256SUMS 里找不到 isp-split-*.tar.gz（Release 资产不完整）"
		VER=${ASSET#isp-split-}
		VER=${VER%.tar.gz}
		DL_BASE="$BASE/releases/latest/download"
		say "latest -> $VER"
	else
		warn "取不到 latest 的 SHA256SUMS，改用 /releases/latest 跳转解析版本"
		TAG=$(probe_latest_tag) ||
			die "无法解析 latest 版本。可显式指定：ISP_VER=0.4.1 sh install-online.sh"
		VER=${TAG#v}
		DL_BASE="$BASE/releases/download/$TAG"
		ASSET="isp-split-$VER.tar.gz"
		say "latest -> $VER"
	fi
fi

# 资产名只允许 isp-split-<ver>.tar.gz，防止 SHA256SUMS 内容被替换成 ../ 路径
case "$ASSET" in
isp-split-*.tar.gz) ;;
*) die "资产名异常: $ASSET" ;;
esac
case "$ASSET" in
*/*) die "资产名含路径分隔符: $ASSET" ;;
esac
DL_URL="$DL_BASE/$ASSET"
SUMS_URL="$DL_BASE/SHA256SUMS"

# ---- 平台信息（只用于提示，安装走 install.sh） ----
ARCH=$(uname -m 2>/dev/null || printf 'unknown')
DIST_ARCH=""
if [ -f /etc/openwrt_release ]; then
	DIST_ARCH=$(sed -n "s/^DISTRIB_ARCH=['\"]*\([^'\"]*\).*/\1/p" /etc/openwrt_release 2>/dev/null | head -1)
fi
if command -v apk >/dev/null 2>&1; then
	PKG_MGR="apk（OpenWrt 25.12+）"
elif command -v opkg >/dev/null 2>&1; then
	PKG_MGR="opkg（OpenWrt 24.10 及以下）"
else
	PKG_MGR="未检测到 apk/opkg"
fi
[ -n "$DIST_ARCH" ] || DIST_ARCH=$ARCH
say "平台: $ARCH / $DIST_ARCH；包管理器: $PKG_MGR"
if [ "$PKG_MGR" = "未检测到 apk/opkg" ]; then
	warn "这不像 OpenWrt；install.sh 仍会尝试复制文件，但依赖与 LuCI 可能不可用"
fi

if [ "$DRY_RUN" = 1 ]; then
	say "试运行（ISP_DRY_RUN=1），未下载任何文件："
	printf '  版本:   %s\n' "$VER"
	printf '  下载:   %s\n' "$DL_URL"
	printf '  校验:   %s\n' "$SUMS_URL"
	printf '  解包:   %s/isp-split-%s\n' "$TMP" "$VER"
	printf '  安装:   sh <解包目录>/isp-split-%s/scripts/install.sh --all\n' "$VER"
	exit 0
fi

# ---- 下载 + 校验 ----
DL="$TMP/$ASSET"
say "下载 $DL_URL"
if ! fetch "$DL_URL" "$DL"; then
	die "下载失败: $DL_URL
可能原因与处理：
  1) GitHub/raw 被阻断：脚本本身可换 jsDelivr 入口；Release 资产可换可信加速前缀：
     ISP_BASE=https://<可信加速前缀>/https://github.com/jihebube/openwrt-isp-split sh install-online.sh
  2) 版本写错：ISP_VER=$VER 需与 Release 的 isp-split-$VER.tar.gz 完全对应（不带 v、不带 -r1）
  3) 证书错误：opkg/apk 安装 ca-bundle（或 ca-certificates）；临时可用 ISP_INSECURE=1
  4) 也可以手动下载上面的 URL，解包后执行 scripts/install.sh --all"
fi
[ -s "$DL" ] || die "下载文件为空: $DL_URL"

if [ "$HAVE_SUMS" != 1 ]; then
	if fetch "$SUMS_URL" "$SUMS_FILE"; then
		HAVE_SUMS=1
	else
		warn "未取到 SHA256SUMS，跳过校验（HTTPS 仍可保证传输来源；介意请手动下载核对）"
	fi
fi

if [ "$HAVE_SUMS" = 1 ]; then
	WANT_SHA=$(awk -v a="$ASSET" '$2 == a {print $1}' "$SUMS_FILE" | head -1)
	[ -n "$WANT_SHA" ] || die "SHA256SUMS 中没有 $ASSET（Release 资产与版本不匹配）"
	GOT_SHA=$(sha256_of "$DL") || die "系统缺少 sha256sum/shasum，无法校验；请先安装 coreutils-sha256sum 或手动核对后再装"
	[ "$GOT_SHA" = "$WANT_SHA" ] ||
		die "SHA256 校验失败：
  期望 $WANT_SHA
  实际 $GOT_SHA
文件可能在传输中被截断/替换（常见于被网关劫持的镜像）。请重试或换镜像；不要继续安装。"
	say "SHA256 校验通过"
fi

# ---- 解包前检查 ----
tar -tzf "$DL" >/dev/null 2>&1 ||
	die "下载的文件不是有效的 tar.gz（可能被网关/镜像替换成了 HTML）"
TOP=$(tar -tzf "$DL" | sed -n '1p' | cut -d/ -f1)
[ -n "$TOP" ] || die "压缩包内没有文件"
[ "$TOP" = "isp-split-$VER" ] ||
	die "压缩包顶层目录是 $TOP，与版本 $VER 不符（Release 资产命名变了？）"
if tar -tzf "$DL" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
	die "压缩包含绝对路径或 .. 路径，拒绝解包"
fi

if [ "$SKIP_INSTALL" = 1 ]; then
	[ -n "$DEST" ] || DEST="/tmp/isp-split-$VER"
	mkdir -p "$DEST" || die "无法创建 $DEST"
	# 先 cd 解析掉 .. 与符号链接，再判断前缀：只允许 /tmp 下的真实目录，
	# 否则 ISP_DEST=/tmp/../etc 这种会在 rm -rf 时打穿到 /etc。
	DEST_ABS=$(cd "$DEST" && pwd) || die "无法解析 ISP_DEST: $DEST"
	case "$DEST_ABS" in
	/tmp/*) ;;
	*) die "ISP_DEST 解析后必须在 /tmp 下，当前: $DEST_ABS" ;;
	esac
	[ "$DEST_ABS" != "/tmp" ] || die "ISP_DEST 不能是 /tmp 本身"
	rm -rf "$DEST_ABS"
	mkdir -p "$DEST_ABS" || die "无法创建 $DEST_ABS"
	tar -xzf "$DL" -C "$DEST_ABS" || die "解包失败: $DEST_ABS"
	say "已下载并解包到 $DEST_ABS/$TOP（ISP_SKIP_INSTALL=1，未安装）"
	say "手动安装：sh $DEST_ABS/$TOP/scripts/install.sh --all"
	exit 0
fi

mkdir -p "$TMP/unpack" || die "无法创建解包目录"
tar -xzf "$DL" -C "$TMP/unpack" || die "解包失败"
SRC="$TMP/unpack/$TOP"
[ -f "$SRC/scripts/install.sh" ] || die "包内缺少 scripts/install.sh（资产不完整）"

# ---- 安装 ----
say "执行 sh scripts/install.sh --all"
if ! sh "$SRC/scripts/install.sh" --all </dev/null; then
	die "安装脚本失败（临时目录会随退出清理）。可用
  ISP_SKIP_INSTALL=1 sh install-online.sh
重新下载解包到 /tmp 后逐步执行 scripts/install.sh，便于排查。"
fi

# ---- 自检 + 下一步 ----
say "安装完成，版本自检："
if command -v isp-split >/dev/null 2>&1; then
	VOUT=$(isp-split --version 2>/dev/null | head -1) || VOUT=""
	if [ -n "$VOUT" ]; then
		printf '  %s\n' "$VOUT"
		case "$VOUT" in
		*" $VER") say "版本核对通过（期望 $VER）" ;;
		*) warn "版本与期望不符：期望 $VER，实际 $VOUT" ;;
		esac
	else
		warn "isp-split --version 无输出，请手动执行 isp-split --version 检查"
	fi
else
	warn "PATH 里找不到 isp-split，请检查 /usr/sbin/isp-split"
fi

LAN_IP=""
if command -v uci >/dev/null 2>&1; then
	LAN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null) || LAN_IP=""
fi
[ -n "$LAN_IP" ] || LAN_IP="<路由器IP>"

printf '\n'
say "下一步："
printf '  1) 浏览器打开 LuCI：http://%s/cgi-bin/luci/admin/network/isp-split\n' "$LAN_IP"
printf '     菜单：网络 → 运营商分流（升级后请 Ctrl-F5 强刷）\n'
printf '  2) 命令行：isp-split init → plan → check → sync → verify\n'
printf '  3) 环境体检：isp-split doctor\n'
printf '  卸载：isp-split uninstall（或重跑本脚本前先卸载旧版亦可）\n'
