#!/bin/sh
# count-attrib.sh —— 兜底计数器"增量归因"只读工具（BUG-21 收尾 / FIX23）
#
# 解决的问题：生产上"DNS 轮"期间 isp_fallback 计数器会涨，但涨出来的包
# 到底是不是 DNS？本工具在同一个时间窗口里同时取三个只读口径，直接给出
# 判定：
#
#   1. isp_fallback 计数器增量            —— 待解释的增量
#   2. 窗口内 DNS 流实际走过的包数        —— 来自 /proc/net/nf_conntrack，
#                                            DNS 能贡献的物理上界
#   3. DNS 流的 conntrack mark            —— 决定响应包会不会经过规则链
#
# 判定逻辑（本工具唯一的"结论"，其余都是原始数据）：
#   Δ兜底 == 0                  → 计数器正确，DNS 没有被计入
#   0 < Δ兜底 <= DNS 实际包数   → 排除条件没生效（形状不对/未 apply），需重建
#   Δ兜底 > DNS 实际包数        → 超出部分是**非 DNS 流量**（或重复计数），
#                                 不可能全部来自 DNS
#
# 全程只读：只 list nft、只读 /proc，不插入/删除任何规则，不改配置。
#
# 用法：
#   sh count-attrib.sh [窗口秒数] [DNS 服务器 IP]
#   sh count-attrib.sh 20 223.5.5.5
#
# 环境变量（给自检注入用，生产不用设）：
#   NFT            nft 命令（默认 nft）
#   NF_CONNTRACK   conntrack 表路径（默认 /proc/net/nf_conntrack）
set -u

INTERVAL=${1:-20}
DNSSRV=${2:-}
NFT=${NFT:-nft}
NFC=${NF_CONNTRACK:-/proc/net/nf_conntrack}

say() { printf '%s\n' "$*"; }
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

case "$INTERVAL" in
'' | *[!0-9]*) die "窗口秒数必须是正整数: $INTERVAL" ;;
esac
[ "$INTERVAL" -ge 2 ] || die "窗口至少 2 秒"

command -v "$NFT" >/dev/null 2>&1 || die "找不到 nft"
$NFT list table inet mwan3 >/dev/null 2>&1 || die "nft 表 inet mwan3 不存在（mwan3 没运行？）"

fb_packets() {
	$NFT list counter inet mwan3 isp_fallback 2>/dev/null |
		grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1
}

# DNS 流快照：一行一条流 —— "<key> <双向包数合计> <是否打标>"
# key 用无序的 (addr:port > addr:port) 对，保证同一流两个方向归并到一起。
dns_snapshot() {
	[ -r "$NFC" ] || return 0
	awk -v srv="$DNSSRV" '
	function absr(line,   a, n, i, src, dst, sp, dp, k1, k2) {
		n = split(line, a, " ")
		src = dst = sp = dp = "__"
		for (i = 1; i <= n; i++) {
			if (a[i] ~ /^src=/) src = substr(a[i], 5)
			else if (a[i] ~ /^dst=/) dst = substr(a[i], 5)
			else if (a[i] ~ /^sport=/) sp = substr(a[i], 7)
			else if (a[i] ~ /^dport=/) dp = substr(a[i], 7)
		}
		k1 = src ":" sp ">" dst ":" dp
		k2 = dst ":" dp ">" src ":" sp
		return (k1 < k2) ? (k1 "|" k2) : (k2 "|" k1)
	}
	{
		if ($3 != "tcp" && $3 != "udp") next
		line = $0
		if (line !~ /(^| )sport=53( |$)/ && line !~ /(^| )dport=53( |$)/) next
		if (srv != "" && index(line, "=" srv " ") == 0 && index(line, "=" srv "\n") == 0) next
		total = 0
		n = split(line, a, " ")
		for (i = 1; i <= n; i++)
			if (a[i] ~ /^packets=/) total += substr(a[i], 9)
		mark = "0"
		for (i = 1; i <= n; i++)
			if (a[i] ~ /^mark=/) mark = substr(a[i], 6)
		k = absr(line)
		pk[k] += total
		if (mark != "0" && mark != "") mk[k] = 1
		else if (!(k in mk)) mk[k] = 0
	}
	END { for (k in pk) printf "%s %d %d\n", k, pk[k], mk[k] }
	' "$NFC" 2>/dev/null | sort
}

rule_shape() {
	_lines=$($NFT -a list chain inet mwan3 mwan3_rules 2>/dev/null |
		grep 'counter name "isp_fallback"')
	_n=$(printf '%s\n' "$_lines" | grep -c 'counter name "isp_fallback"' || true)
	if [ "${_n:-0}" -eq 0 ]; then
		echo "missing"
	elif printf '%s\n' "$_lines" | grep -q 'th sport != 53' &&
		printf '%s\n' "$_lines" | grep -q 'ct state new'; then
		echo "current"
	elif printf '%s\n' "$_lines" | grep -q 'th sport != 53'; then
		echo "dns-both-sides-no-ctnew"
	elif printf '%s\n' "$_lines" | grep -q 'th dport != 53'; then
		echo "dns-dport-only"
	else
		echo "no-dns-exclusion"
	fi
}

TMPD=$(mktemp -d 2>/dev/null) || TMPD=$(mktemp -d /tmp/count-attrib.XXXXXX) ||
	{ echo "无法创建临时目录" >&2; exit 1; }
mkdir -p "$TMPD"
trap 'rm -rf "$TMPD"' EXIT INT TERM

SHAPE=$(rule_shape)
FB0=$(fb_packets); FB0=${FB0:-0}
dns_snapshot > "$TMPD/before"

say "== 兜底计数器归因（窗口 ${INTERVAL}s，只读）"
say "规则形状: $SHAPE"
case "$SHAPE" in
current) say "  ✓ 两条规则、双侧 53 排除、ct state new（当前版本期望形状）" ;;
dns-both-sides-no-ctnew) say "  ! 双侧 53 已排除，但没有 ct state new：未打标的连接会按包重复计数" ;;
dns-dport-only) say "  ! 只排除了 dport=53（BUG-21 半修形状）：响应包会被计入，建议 isp-split apply" ;;
no-dns-exclusion) say "  ! 完全没有排除 DNS：查询和响应都会被计入，建议 isp-split apply" ;;
missing) say "  ! 链上没有兜底计数规则：status 的兜底行不会增长" ;;
esac
say "起始兜底计数: $FB0"
[ -n "$DNSSRV" ] && say "DNS 服务器过滤: $DNSSRV"
say "采样中…（现在开始跑你的 DNS 轮）"
sleep "$INTERVAL"

FB1=$(fb_packets); FB1=${FB1:-0}
dns_snapshot > "$TMPD/after"

# 逐流做差：新流整条计入；同一 key 的计数倒退（旧流过期 + 新流复用同一
# 四元组）按新流整条计入，避免出现负增量。
DNS_PKTS=$(awk '
	FNR == NR { if (NF >= 3) prev[$1] = $2; next }
	NF >= 3 { d = $2 - (prev[$1] + 0); if (d < 0) d = $2; s += d }
	END { print s + 0 }
' "$TMPD/before" "$TMPD/after")

DNS_FLOWS=$(grep -c . "$TMPD/after" 2>/dev/null || true); DNS_FLOWS=${DNS_FLOWS:-0}
DNS_MARKED=$(awk 'NF >= 3 && $3 == 1' "$TMPD/after" 2>/dev/null | grep -c . || true)
DNS_MARKED=${DNS_MARKED:-0}
FB_DELTA=$((FB1 - FB0))

say ""
say "-- 窗口内实测"
say "  兜底计数增量           : $FB_DELTA 包"
say "  窗口内新增/增长的 DNS 流: ${DNS_FLOWS} 条在表（其中已打标 ${DNS_MARKED} 条）"
say "  DNS 流实际走过         : $DNS_PKTS 包（双向合计，来自 nf_conntrack）"
say ""
say "-- 判定"
if [ ! -r "$NFC" ]; then
	say "  ? 读不到 $NFC（需要 root）：只能报告兜底增量，不做 DNS 归因。"
	say "    用 root 重跑，或改用: nft list counter inet mwan3 isp_fallback 加"
	say "    /proc/net/nf_conntrack 里 dport=53 / sport=53 的 packets 手工对账。"
elif [ "$FB_DELTA" -eq 0 ]; then
	say "  ✓ 兜底计数没有增长：DNS 没有被计入（与当前规则形状一致）"
	say "    如果别处观测到的数字仍然在涨，那它测的不是这个计数器，"
	say "    或者不是这台设备/这个窗口。"
elif [ "$FB_DELTA" -le "$DNS_PKTS" ]; then
	say "  兜底增量($FB_DELTA) ≤ DNS 包数($DNS_PKTS)：增量可以由 DNS 解释。"
	say "  当前形状是 '$SHAPE'——排除条件没生效，执行 isp-split apply 重建。"
else
	OVER=$((FB_DELTA - DNS_PKTS))
	say "  ✗ 兜底增量($FB_DELTA) > DNS 包数($DNS_PKTS)："
	say "    至少 $OVER 包不可能是 DNS。再取一次同样长度的静默窗口做对照；"
	say "    静默窗口也有同量级增量，就说明是 LAN 里其他未命中流量。"
fi
say ""
say "提示：本工具只读，不改规则。形状不对时用 isp-split apply 重建"
say "      （status 是只读的，不会自动修）。"
