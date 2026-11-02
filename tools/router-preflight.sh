#!/bin/sh
# 真机部署前的只读预检
#
# 逐项确认路由器是否满足 isp-split 的运行前提。
# 全程只读：不改配置、不写文件、不重启任何服务。
#
# 用法：sh tools/router-preflight.sh
# 退出码：0 = 可以部署；1 = 有阻断项；2 = 只有可忽略的提醒
#
# 判据的归属（fix34 起）：固件 / 内存 / nft 版本 / mwan3-nft 存在性 / 依赖
# 二进制这五项，与设备上的 `isp-split doctor` 是**同一份实现**——
# files/usr/lib/isp-split/doctor.sh 里的 doc_* 函数。本文件只负责取数、
# 排版与汇总，不再自己写 `grep render_config_ipsets` 之类的判据。
# 这样 doctor 与 preflight 不会各说一套（F7 的根因就是两处实现）。
set -u

# 判据库：设备上优先 /usr/lib/isp-split/doctor.sh；在仓库里直接跑时回落到
# tools/../files/usr/lib/isp-split/doctor.sh。允许用 ISP_SPLIT_DOCTOR_LIB 覆盖。
DOCTOR_LIB=${ISP_SPLIT_DOCTOR_LIB:-}
if [ -z "$DOCTOR_LIB" ]; then
	for _pl_cand in /usr/lib/isp-split/doctor.sh \
		"$(cd "$(dirname "$0")" 2>/dev/null && pwd)/../files/usr/lib/isp-split/doctor.sh"; do
		[ -f "$_pl_cand" ] && {
			DOCTOR_LIB=$_pl_cand
			break
		}
	done
fi
if [ -z "$DOCTOR_LIB" ] || [ ! -f "$DOCTOR_LIB" ]; then
	echo "找不到 doctor.sh（环境体检的判据实现）" >&2
	echo "  设备上应在 /usr/lib/isp-split/doctor.sh；仓库内跑时应在 files/usr/lib/isp-split/doctor.sh" >&2
	echo "  可用 ISP_SPLIT_DOCTOR_LIB=<路径> 显式指定" >&2
	exit 1
fi
. "$DOCTOR_LIB"

PASS=0
FAIL=0
WARN=0
FAIL_LIST=""

ok()   { printf '  ✓ %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  ✗ %s\n' "$1"; FAIL=$((FAIL + 1)); FAIL_LIST="$FAIL_LIST\n      - $1"; }
# 阻断项的补充说明：只打印，不计入失败数
detail() { printf '      · %s\n' "$1"; FAIL_LIST="$FAIL_LIST\n      · $1"; }
warn() { printf '  ⚠ %s\n' "$1"; WARN=$((WARN + 1)); }
info() { printf '  · %s\n' "$1"; }

hdr() {
	echo
	echo "== $1 =="
}

# 依赖二进制清单（一次探测，后面各处复用；与 doctor 的 host.bins 同源）
doc_bins

# ---------------------------------------------------------------- 0. 环境

hdr "0. 环境识别"
if doc_host_firmware; then
	ok "固件: ${DOC_FW_DESC:-$DOC_FW_ID $DOC_FW_RELEASE} (${DOC_ARCH:-$(uname -m)})"
else
	bad "不是 OpenWrt 环境（/etc/openwrt_release 不存在）"
	echo
	echo "== 结论 =="
	echo "无法在此环境运行，停止检查。"
	exit 1
fi
# 内存：只提示不计数（判据与 doctor 的 host.mem 同源；数据管线的峰值在几 MB，
# 这里不给阻断，避免在 32MB 内存的老机器上误杀可用配置）
doc_host_mem >/dev/null
info "内存: 共 ${DOC_MEM_TOTAL_KB} kB，可用 ${DOC_MEM_AVAIL_KB} kB（${DOC_MEM_VERDICT}）"

if [ "$(id -u)" != "0" ]; then
	warn "当前不是 root，部分检查可能失败"
fi

# ---------------------------------------------------------------- 1. mwan3

hdr "1. mwan3（核心前提）"
if doc_mwan3_installed; then
	ok "mwan3 已安装"
else
	bad "mwan3 未安装 —— 本项目必须运行在 mwan3 之上"
fi

if doc_mwan3_is_nft; then
	ok "mwan3 是 nftables 版（render_config_ipsets 存在）"
else
	bad "mwan3 是 iptables 版 —— 本项目不支持"
	bad "  需要替换为 nftables 版: https://github.com/dl12345/mwan3 (>= 3.6.0)"
fi

if doc_nft_version; then
	ok "nft: ${DOC_NFT_FULL:-$DOC_NFT_VERSION}"
else
	bad "缺少 nft 命令"
fi

if doc_mwan3_table; then
	ok "table inet mwan3 存在（mwan3-nft 正在运行）"
else
	bad "table inet mwan3 不存在 —— mwan3-nft 未启动，或装的仍是 iptables 版"
fi

# ---------------------------------------------------------------- 2. 策略

hdr "2. mwan3 策略"
_needed="wan_only wanb_only balanced"
_missing=""
for p in $_needed; do
	if [ "$(uci -q get "mwan3.$p" 2>/dev/null)" = "policy" ]; then
		ok "策略 $p 存在"
	else
		bad "策略 $p 不存在 —— 需在 MultiWAN 管理器创建，或先跑 isp-split bootstrap"
		_missing="$_missing $p"
	fi
done

# ---------------------------------------------------------------- 3. 数据源

hdr "3. 数据源与工具"
if doc_bin_have curl; then
	ok "curl: $(curl --version 2>/dev/null | head -1 | awk '{print $1, $2}')"
else
	bad "缺少 curl（apk add curl / opkg install curl）"
fi

if curl -fsI --connect-timeout 8 https://ispip.clang.cn/chinatelecom.txt 2>/dev/null | head -1 | grep -q 200; then
	ok "数据源 ispip.clang.cn 可达"
else
	bad "数据源 ispip.clang.cn 不可达 —— 检查外网/防火墙"
	detail "常见原因：更新源自己的 IP 落在某个已启用的集合里，"
	detail "而该集合对应的线路恰好不可用（见 README 已知限制第 6 条）"
fi

if doc_bin_have conntrack; then
	ok "conntrack: 已安装（verify-domains 需要）"
else
	warn "缺 conntrack（tools/verify-domains.sh 需要）: apk add conntrack"
fi

# ---------------------------------------------------------------- 4. 规则锚点

hdr "4. mwan3 现有规则"
_anchor=$(uci -q show mwan3 2>/dev/null | grep -cE '=rule$')
if [ "${_anchor:-0}" -gt 0 ]; then
	ok "已有 $_anchor 条 mwan3 规则，本项目会插在它们之前"
	nft list chain inet mwan3 mwan3_rules 2>/dev/null |
		grep -vE '^[[:space:]]*(table|chain|type|})' |
		sed 's/^/      现有: /' | head -5
else
	warn "mwan3 里没有任何规则 —— 没有锚点，本项目规则会追加到链末尾"
fi

# ---------------------------------------------------------------- 5. DNS（可选功能）

hdr "5. dnsmasq（仅多线路 DNS 功能需要）"
if doc_bin_have dnsmasq; then
	ok "dnsmasq: $(dnsmasq --version 2>/dev/null | head -1 | sed 's/Dnsmasq version //')"
	if dnsmasq --help 2>/dev/null | grep -q conf-dir; then
		ok "支持 conf-dir（多线路 DNS 可用）"
	else
		bad "dnsmasq 不支持 conf-dir，多线路 DNS 功能不可用"
	fi
	# 域名→nftset 钉线的前置条件（F-5）：OpenWrt 基础版 dnsmasq 是
	# no-ipset no-nftset，必须 dnsmasq-full。只提示，不阻断。
	_nft_opts=$(dnsmasq --version 2>/dev/null |
		sed -n 's/^Compile time options:[[:space:]]*//p' | head -1)
	case " $_nft_opts " in
	*" no-nftset "*)
		warn "dnsmasq 未编译 nftset（no-nftset）—— 域名钉线不可用"
		warn "  （server=/域名/IP@接口 的多线路 DNS 不受影响；需要钉线请装 dnsmasq-full）"
		;;
	*" nftset "* | *" +nftset "*)
		ok "dnsmasq 支持 nftset（域名钉线的前置条件满足）"
		;;
	*)
		warn "无法从 dnsmasq --version 确认 nftset 能力（缺少 Compile time options）"
		warn "  按不支持处理：域名钉线不可用（多线路 DNS 不受影响）"
		;;
	esac
else
	bad "缺少 dnsmasq"
fi

# ---------------------------------------------------------------- 6. 已安装状态

hdr "6. 当前安装状态"
if [ -x /usr/sbin/isp-split ]; then
	ok "isp-split 已安装: $(/usr/sbin/isp-split --version 2>/dev/null || echo '未知版本')"
	# 0.3.3 起 doctor 的判据实现必须在设备上，否则 `isp-split doctor` 会拒绝运行
	if [ -f /usr/lib/isp-split/doctor.sh ]; then
		ok "doctor 判据在设备上（/usr/lib/isp-split/doctor.sh）"
	else
		warn "设备上缺 /usr/lib/isp-split/doctor.sh：isp-split doctor 会拒绝运行（重装同版本包）"
	fi
else
	info "尚未安装（预期内）"
fi

if [ -n "$(uci -q show mwan3 2>/dev/null | grep 'isp_')" ]; then
	ok "mwan3 配置里已有 isp_ 规则（可能已执行过 wire）"
	nft list chain inet mwan3 mwan3_rules 2>/dev/null |
		grep -c "daddr @" | sed 's/^/      渲染中的集合规则: /'
else
	info "mwan3 里还没有 isp_ 规则（预期内）"
fi

# ---------------------------------------------------------------- 汇总

hdr "汇总"
echo "  通过: $PASS   阻断: $FAIL   提醒: $WARN"

if [ "$FAIL" -gt 0 ]; then
	echo
	echo "结论: 存在 $FAIL 个阻断项，先解决再部署："
	printf '%b\n' "$FAIL_LIST"
	exit 1
fi

if [ "$WARN" -gt 0 ]; then
	echo
	echo "结论: 可以部署。有 $WARN 项提醒，不影响核心功能。"
	exit 2
fi

echo
echo "结论: 全部通过，可以部署。"
echo
echo "下一步："
echo "  isp-split doctor                 环境体检（六项兼容矩阵，只读）"
echo "  isp-split bootstrap              净机骨架预演（默认 dry-run）"
echo "  sh scripts/install.sh --all      安装（含每日自动更新）"
echo "  isp-split plan                   只读预演"
echo "  isp-split check                  nft 干跑校验"
echo "  isp-split sync                   正式生效"
echo "  isp-split verify                 核对渲染结果"
exit 0
