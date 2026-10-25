#!/bin/sh
# 多域名 / 多节点 / 多运营商 端到端验证
#
# 验证的不变量：
#   目标 IP 归属某个启用的运营商集合
#     -> 该集合配置的策略
#     -> 实际 conntrack mark
#   三者必须一致。
#   未命中任何启用集合的 IP 不应被打标（mark 应为 0）。
#
# 用法：
#   sh tools/verify-domains.sh                 # 内置域名列表
#   sh tools/verify-domains.sh a.com b.com     # 自选域名
#   MAXIPS=5 sh tools/verify-domains.sh        # 每个域名最多取 5 个 A 记录
#
# 依赖：nft、conntrack、nslookup、ping
set -u

CONF=${ISP_SPLIT_CONF:-/etc/isp-split.conf}
MAXIPS=${MAXIPS:-3}

[ -f "$CONF" ] || { echo "读不到 $CONF" >&2; exit 1; }
. "$CONF"
[ -n "${ISP_TABLE:-}" ] || { echo "$CONF 里没有 ISP_TABLE" >&2; exit 1; }

command -v nft >/dev/null || { echo "缺少 nft" >&2; exit 1; }
command -v conntrack >/dev/null || { echo "缺少 conntrack（apk add conntrack）" >&2; exit 1; }
nft list table inet mwan3 >/dev/null 2>&1 || { echo "table inet mwan3 不存在" >&2; exit 1; }

DEFAULT_DOMAINS="
www.baidu.com
www.qq.com
www.jd.com
www.taobao.com
mirrors.aliyun.com
mirrors.huaweicloud.com
mirrors.tencent.com
mirrors.ustc.edu.cn
mirrors.tuna.tsinghua.edu.cn
upos-sz-mirrorcos.bilivideo.com
dl.steam.clngaa.com
files.steam.nsclouds.cn
github.com
"

if [ $# -gt 0 ]; then
	DOMAINS="$*"
else
	DOMAINS=$DEFAULT_DOMAINS
fi

# ---------------------------------------------------------------- 基础函数

hex2dec() {
	awk -v h="$1" 'BEGIN {
		gsub(/^0x/, "", h)
		n = 0
		for (i = 1; i <= length(h); i++) {
			c = index("0123456789abcdef", tolower(substr(h, i, 1))) - 1
			if (c < 0) { print -1; exit }
			n = n * 16 + c
		}
		print n
	}'
}

# 取 ISP_TABLE 的某一列：col <行号> <列号>
_field() {
	awk -v row="$1" -v col="$2" -v tbl="$ISP_TABLE" 'BEGIN {
		n = split(tbl, rows, "\n")
		for (i = 1; i <= n; i++) {
			if (rows[i] == "") continue
			cnt++
			if (cnt != row) continue
			split(rows[i], f, ":")
			print f[col]
			exit
		}
	}'
}

_table_rows() {
	printf '%s\n' "$ISP_TABLE" | awk 'NF { n++ } END { print n }'
}

# 策略的首个 mark（十进制）
policy_mark() {
	_h=$(nft list chain inet mwan3 "mwan3_policy_$1" 2>/dev/null |
		awk '/mark set/ {
			for (i = 1; i <= NF; i++)
				if ($i == "|") { print $(i + 1); exit }
		}')
	if [ -z "$_h" ]; then
		echo "-1"
	else
		hex2dec "$_h"
	fi
}

set_of_ip() {
	for _s in $ENABLED_SETS; do
		if nft get element inet mwan3 "$_s" "{ $1 }" >/dev/null 2>&1; then
			echo "$_s"
			return
		fi
	done
	echo "-"
}

mark_of_ip() {
	conntrack -L 2>/dev/null | grep "dst=$1 " |
		grep -oE 'mark=[0-9]+' | head -1 | cut -d= -f2
}

# ---------------------------------------------------------------- 建立映射

_rows=$(_table_rows)
ENABLED_SETS=""
i=1
while [ "$i" -le "$_rows" ]; do
	_src=$(_field "$i" 1)
	_set=$(_field "$i" 2)
	_pol=$(_field "$i" 3)
	_en=$(_field "$i" 4)
	if [ "$_en" = "1" ]; then
		ENABLED_SETS="$ENABLED_SETS $_set"
		_m=$(policy_mark "$_pol")
		eval "POLICY_OF_${_set}=\$_pol"
		eval "MARK_OF_${_set}=\$_m"
		eval "CNT_${_set}=0"
	fi
	i=$((i + 1))
done

echo "== 启用集合 =="
for _s in $ENABLED_SETS; do
	eval "_p=\$POLICY_OF_${_s}"
	eval "_m=\$MARK_OF_${_s}"
	printf '  %-12s -> %-12s mark=%s\n' "$_s" "$_p" "$_m"
done
echo

# ---------------------------------------------------------------- 主循环

printf '%-34s %-17s %-11s %-11s %6s  %s\n' "域名" "IP" "集合" "策略" "mark" "判定"
printf '%-34s %-17s %-11s %-11s %6s  %s\n' "----------------------------------" \
	"-----------------" "-----------" "-----------" "------" "------"

_ok=0
_bad=0
_neutral=0
_nip=0
_badlist=""

for d in $DOMAINS; do
	# 支持直接传 IP：启用 othernet 一类集合后，DNS 服务器本身可能被
	# 规则分走导致解析失败，此时直接给 IP 更可靠
	case "$d" in
	*[0-9].[0-9]*.[0-9]*.[0-9]*)
		ips="$d"
		;;
	*)
		ips=$(nslookup "$d" 2>/dev/null | awk '/^Address/ { print $NF }' |
			grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n "$MAXIPS")
		;;
	esac

	if [ -z "$ips" ]; then
		printf '%-34s %s\n' "$d" "（解析失败或无 A 记录）"
		continue
	fi

	for ip in $ips; do
		_nip=$((_nip + 1))
		conntrack -D -d "$ip" >/dev/null 2>&1
		ping -c 1 -W 1 "$ip" >/dev/null 2>&1
		sleep 1

		set=$(set_of_ip "$ip")
		mark=$(mark_of_ip "$ip")
		[ -n "$mark" ] || mark=0

		if [ "$set" = "-" ]; then
			pol="（落兜底）"
			if [ "$mark" = "0" ]; then
				verdict="✓ 未打标"
				_neutral=$((_neutral + 1))
			else
				verdict="? 未命中集合却有 mark"
				_bad=$((_bad + 1))
			fi
		else
			eval "_c=\$CNT_${set}"; _c=$((_c + 1)); eval "CNT_${set}=\$_c"
			eval "pol=\$POLICY_OF_${set}"
			eval "exp=\$MARK_OF_${set}"
			if [ "$mark" = "$exp" ]; then
				verdict="✓"
				_ok=$((_ok + 1))
			else
				verdict="✗ 期望 $exp"
				_bad=$((_bad + 1))
				_badlist="$_badlist $ip($set)"
			fi
		fi

		printf '%-34s %-17s %-11s %-11s %6s  %s\n' "$d" "$ip" "$set" "$pol" "$mark" "$verdict"
	done
done

# ---------------------------------------------------------------- 汇总

echo
echo "== 汇总 =="
echo "  测试 IP 总数: $_nip"
echo "  命中集合且 mark 一致: $_ok"
echo "  未命中集合、未打标: $_neutral"
echo "  异常: $_bad"
[ -n "$_badlist" ] && echo "  异常明细:$_badlist"

echo
echo "== 各集合命中 IP 数 =="
for _s in $ENABLED_SETS; do
	eval "_c=\$CNT_${_s}"
	printf '  %-12s %s\n' "$_s" "${_c:-0}"
done

echo
if [ "$_bad" -eq 0 ]; then
	echo "结论：分流映射全部一致。"
	exit 0
else
	echo "结论：存在 $_bad 处不一致，请检查 /etc/mwan3 的规则与策略。"
	exit 1
fi
