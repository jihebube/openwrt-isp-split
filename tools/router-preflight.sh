#!/bin/sh
# 真机部署前的只读预检
#
# 逐项确认路由器是否满足 isp-split 的运行前提。
# 全程只读：不改配置、不写文件、不重启任何服务。
#
# 用法：sh tools/router-preflight.sh
# 退出码：0 = 可以部署；1 = 有阻断项；2 = 只有可忽略的提醒

set -u

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

# ---------------------------------------------------------------- 0. 环境

hdr "0. 环境识别"
if [ -f /etc/openwrt_release ]; then
	. /etc/openwrt_release
	ok "固件: ${DISTRIB_DESCRIPTION:-$DISTRIB_ID $DISTRIB_RELEASE} ($(uname -m))"
else
	bad "不是 OpenWrt 环境（/etc/openwrt_release 不存在）"
	echo
	echo "== 结论 =="
	echo "无法在此环境运行，停止检查。"
	exit 1
fi

if [ "$(id -u)" != "0" ]; then
	warn "当前不是 root，部分检查可能失败"
fi

# ---------------------------------------------------------------- 1. mwan3

hdr "1. mwan3（核心前提）"
if [ -f /lib/mwan3/mwan3.sh ]; then
	ok "mwan3 已安装"
else
	bad "mwan3 未安装 —— 本项目必须运行在 mwan3 之上"
fi

if grep -q render_config_ipsets /lib/mwan3/mwan3.sh 2>/dev/null; then
	ok "mwan3 是 nftables 版（render_config_ipsets 存在）"
else
	bad "mwan3 是 iptables 版 —— 本项目不支持"
	bad "  需要替换为 nftables 版: https://github.com/dl12345/mwan3 (>= 3.6.0)"
fi

if command -v nft >/dev/null 2>&1; then
	ok "nft: $(nft --version 2>/dev/null | head -1)"
else
	bad "缺少 nft 命令"
fi

if nft list table inet mwan3 >/dev/null 2>&1; then
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
		bad "策略 $p 不存在 —— 需在 MultiWAN 管理器创建"
		_missing="$_missing $p"
	fi
done

# ---------------------------------------------------------------- 3. 数据源

hdr "3. 数据源与工具"
if command -v curl >/dev/null 2>&1; then
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

if command -v conntrack >/dev/null 2>&1; then
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
if command -v dnsmasq >/dev/null 2>&1; then
	ok "dnsmasq: $(dnsmasq --version 2>/dev/null | head -1 | sed 's/Dnsmasq version //')"
	if dnsmasq --help 2>/dev/null | grep -q conf-dir; then
		ok "支持 conf-dir（多线路 DNS 可用）"
	else
		bad "dnsmasq 不支持 conf-dir，多线路 DNS 功能不可用"
	fi
	if dnsmasq --version 2>/dev/null | grep -q "no-nftset"; then
		warn "dnsmasq 编译时去掉了 nftset —— mwan3 原生的域名→nftset 不可用"
		warn "  （本项目的 server=/域名/IP@接口 不受影响）"
	else
		ok "dnsmasq 支持 nftset"
	fi
else
	bad "缺少 dnsmasq"
fi

# ---------------------------------------------------------------- 6. 已安装状态

hdr "6. 当前安装状态"
if [ -x /usr/sbin/isp-split ]; then
	ok "isp-split 已安装: $(/usr/sbin/isp-split --version 2>/dev/null || echo '未知版本')"
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
echo "  sh scripts/install.sh --all      安装（含每日自动更新）"
echo "  isp-split plan                   只读预演"
echo "  isp-split check                  nft 干跑校验"
echo "  isp-split sync                   正式生效"
echo "  isp-split verify                 核对渲染结果"
exit 0
