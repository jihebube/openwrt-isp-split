#!/bin/sh
# 多域名 / 多节点 / 多运营商 端到端验证
#
# 不变量（按 wire / rules-splice 现行语义重写，F-24 / F-25）：
#
#   1. 目标 IP 归属"顺着 mwan3_rules 从上往下第一个包含它的启用集合"
#      -> 该集合配置的策略
#      -> 该策略能打出的 mark 之一
#      -> 实际 conntrack mark
#
#   2. 未命中任何启用集合的 IP，期望 mark 由**兜底规则**决定：
#        · default_rule（0.0.0.0/0 的 catch-all，直接跳策略或经
#          mwan3_rule_default_rule_v4 间接跳）启用时，流量会拿到兜底策略的
#          mark —— 不能再要求 mark=0；
#        · 没有兜底规则时才是 0。
#
# 旧实现的两个原理性错误（v0.1.0 起从未改动，审计 F-24/F-25 行号证据）：
#   · 未命中集合一律要求 mark=0 —— 推荐配置里 default_rule 是开着的，
#     正常打标全被判成"未命中集合却有 mark"，工具必然刷假异常；
#   · 策略 mark 只取"第一个 | value"当唯一期望值 —— 多成员策略
#     （numgen random mod N vmap { ... : jump mwan3_or_meta_0xNNN }）会按
#     权重落到任意成员的 mark，比对单值必然误判。
#
# 现在：
#   · 策略期望面 = 该策略链所有可能打出的成员 mark 集合（单成员是直接
#     mark set；多成员读 vmap/jump 到的 mwan3_or_meta_* 链），外加"最后一跳"
#     的 last_resort 单独识别；
#   · last_resort mark 不当作"对"，而是报"策略无可用成员"——说明该集合的
#     线路全下线，流量没走到用户想要的线路，属于要处理的异常；
#   · 未命中集合的期望 mark = 兜底规则的策略 mark（没有兜底才是 0）；
#   · 顺带校验顺序：本工具的 @isp_* 规则必须排在第一条 catch-all 之前，
#     排在后面时如实报"规则不会命中"，而不是拿 mark 差异去猜。
#
# 用法：
#   sh tools/verify-domains.sh                 # 内置域名列表
#   sh tools/verify-domains.sh a.com 1.2.3.4   # 自选域名 / 直接给 IP
#   MAXIPS=5 sh tools/verify-domains.sh        # 每个域名最多取 5 个 A 记录
#   sh tools/verify-domains.sh --help
#
# 依赖：nft、conntrack、nslookup、ping（都需要 root）
#
# 夹具模式（selftest 用，不碰内核）：设 ISP_VERIFY_FIXTURES=<dir>，目录里放
#   nft_chain_<chain>.txt   对应链的规则行（mwan3_rules / mwan3_policy_* 等）
#   nft_set_<set>.txt       集合元素：每行一个 CIDR / 单地址 / 起止区间，
#                           也接受 nft 的 elements = { ... } 排版
#   dns.txt                 "<域名> <IP>" 逐行
#   conntrack.txt           "<dst=IP> ... mark=<十进制>" 逐行
# 只换 I/O 层，判定逻辑与真机走同一条代码路径。
set -u

FIX=${ISP_VERIFY_FIXTURES:-}
CONF=${ISP_SPLIT_CONF:-/etc/isp-split.conf}
MAXIPS=${MAXIPS:-3}
PING=${VERIFY_PING:-1}

usage() {
	sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

hex2dec() {
	printf '%s\n' "$1" | awk '{
		s = tolower($0)
		sub(/^0x/, "", s)
		n = 0
		for (i = 1; i <= length(s); i++) {
			c = index("0123456789abcdef", substr(s, i, 1)) - 1
			if (c < 0) { print -1; exit }
			n = n * 16 + c
		}
		printf "%d\n", n
	}'
}

ip2dec() {
	printf '%s\n' "$1" | awk -F. '
		NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ &&
		$3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {
			printf "%d\n", $1 * 16777216 + $2 * 65536 + $3 * 256 + $4
			exit
		}
		{ print -1 }'
}

is_ipv4() {
	case "${1:-}" in
	"" | *[!0-9.]* | .* | *.) return 1 ;;
	esac
	printf '%s\n' "$1" | awk -F. '
		NF == 4 { for (i = 1; i <= 4; i++) if ($i + 0 > 255) exit 1; exit 0 }
		{ exit 1 }'
}

# ---------------------------------------------------------------- I/O 层

_nft_chain() { # <chain>：输出该链的规则行；链不存在返回 1
	if [ -n "$FIX" ]; then
		[ -f "$FIX/nft_chain_$1.txt" ] || return 1
		cat "$FIX/nft_chain_$1.txt"
		return 0
	fi
	nft list chain inet mwan3 "$1" >/dev/null 2>&1 || return 1
	nft list chain inet mwan3 "$1" 2>/dev/null |
		sed -n "/chain $1 {/,/^\t}/p" | sed '1d;$d'
}

_nft_set_raw() { # <set>：输出集合元素原文；集合不存在返回 1
	if [ -n "$FIX" ]; then
		[ -f "$FIX/nft_set_$1.txt" ] || return 1
		cat "$FIX/nft_set_$1.txt"
		return 0
	fi
	nft list set inet mwan3 "$1" >/dev/null 2>&1 || return 1
	nft list set inet mwan3 "$1" 2>/dev/null
}

_resolve() { # <域名>：输出 IP，每行一个
	if [ -n "$FIX" ]; then
		[ -f "$FIX/dns.txt" ] || return 0
		awk -v d="$1" '$1 == d { print $2 }' "$FIX/dns.txt" | head -n "$MAXIPS"
		return 0
	fi
	nslookup "$1" 2>/dev/null | awk '/^Address/ { print $NF }' |
		grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n "$MAXIPS"
}

_mark_of_ip() { # <IP>：输出 conntrack mark（十进制）；没有则输出空
	if [ -n "$FIX" ]; then
		[ -f "$FIX/conntrack.txt" ] || return 0
		awk -v ip="$1" '
			index($0, "dst=" ip) {
				if (match($0, /mark=[0-9]+/)) {
					print substr($0, RSTART + 5, RLENGTH - 5)
					exit
				}
			}' "$FIX/conntrack.txt"
		return 0
	fi
	conntrack -L 2>/dev/null | grep "dst=$1 " | grep -oE 'mark=[0-9]+' |
		head -1 | cut -d= -f2
}

_fire_traffic() { # <IP>：清 conntrack 再打一个包，让连接在表里留痕
	[ -z "$FIX" ] || return 0
	conntrack -D -d "$1" >/dev/null 2>&1
	if [ "$PING" = "1" ]; then
		ping -c 1 -W 1 "$1" >/dev/null 2>&1
		sleep 1
	fi
	return 0
}

# ---------------------------------------------------------------- 集合成员

# 集合元素 -> "起 止" 十进制区间（每行一对）。兼容 CIDR、单地址、A-B 区间
# 与 nft 的 elements = { ... } 排版（逗号/换行/多行都当分隔符）。
_set_ranges() { # <set>
	_nft_set_raw "$1" | awk '
		function ip2n(s,   a, n, i) {
			n = split(s, a, ".")
			if (n != 4) return -1
			for (i = 1; i <= 4; i++)
				if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return -1
			return a[1] * 16777216 + a[2] * 65536 + a[3] * 256 + a[4] + 0
		}
		{
			s = $0
			gsub(/[{},]/, " ", s)
			gsub(/elements[[:space:]]*=/, " ", s)
			n = split(s, t, /[[:space:]]+/)
			for (i = 1; i <= n; i++) {
				tok = t[i]
				if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
					split(tok, p, "/")
					base = ip2n(p[1]); bits = p[2] + 0
					if (base < 0 || bits < 0 || bits > 32) continue
					size = 2 ^ (32 - bits)
					start = int(base / size) * size
					printf "%d %d\n", start, start + size - 1
				} else if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
					split(tok, r, "-")
					a = ip2n(r[1]); b = ip2n(r[2])
					if (a >= 0 && b >= a) printf "%d %d\n", a, b
				} else if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
					a = ip2n(tok)
					if (a >= 0) printf "%d %d\n", a, a
				}
			}
		}'
}

_ip_in_ranges() { # <十进制 IP> <ranges 文件>
	awk -v ip="$1" '{ if (ip >= $1 && ip <= $2) { found = 1; exit } }
		END { exit(found ? 0 : 1) }' "$2"
}

# ---------------------------------------------------------------- 策略 mark

# 策略链可能打出的 mark。输出 "<kind> <十进制>"，kind = member | last。
#   member: 各成员能设的 mark（单成员直接 mark set；多成员读 mwan3_or_meta_*）
#   last  : 最后一跳（default / unreachable / blackhole），单独识别
_policy_marks() { # <策略名>
	_pm_dump=$(_nft_chain "mwan3_policy_$1") || return 1
	_pm_own=$(printf '%s\n' "$_pm_dump" |
		grep -o '|[[:space:]]*0x[0-9a-fA-F][0-9a-fA-F]*' |
		sed 's/[^0-9a-fA-Fx]//g')
	_pm_or=""
	# 一行里可能有多个 jump（vmap { 0-2 : jump A, 3-4 : jump B }），
	# 必须逐个抓，不能用贪婪 sed 取最后一个。
	for _pm_c in $(printf '%s\n' "$_pm_dump" |
		grep -o 'mwan3_or_meta_[A-Za-z0-9_]*' | sort -u); do
		_pm_cd=$(_nft_chain "$_pm_c" 2>/dev/null) || continue
		_pm_vals=$(printf '%s\n' "$_pm_cd" |
			grep -o '|[[:space:]]*0x[0-9a-fA-F][0-9a-fA-F]*' |
			sed 's/[^0-9a-fA-Fx]//g')
		[ -n "$_pm_vals" ] || continue
		_pm_or="$_pm_or
$_pm_vals"
	done
	# 本链最后一个 OR 值 = last_resort；其余本链 OR 值 + 子链 OR 值 = 成员
	_pm_last=""
	if [ -n "$_pm_own" ]; then
		_pm_last=$(printf '%s\n' "$_pm_own" | tail -1)
		_pm_own=$(printf '%s\n' "$_pm_own" | sed '$d')
	fi
	_pm_all=$(printf '%s\n%s\n' "$_pm_own" "$_pm_or" | sed '/^[[:space:]]*$/d' | sort -u)
	for _pm_h in $_pm_all; do
		_pm_d=$(hex2dec "$_pm_h")
		[ "$_pm_d" -ge 0 ] || continue
		# 只看运营商字段（mwan3 的 MMX_MASK=0x3f00）
		printf 'member %d\n' "$((_pm_d & 0x3f00))"
	done
	if [ -n "$_pm_last" ]; then
		_pm_d=$(hex2dec "$_pm_last")
		[ "$_pm_d" -ge 0 ] && printf 'last %d\n' "$((_pm_d & 0x3f00))"
	fi
	return 0
}

_policy_members() { # <策略名>：成员 mark（空格分隔，末尾带空格）
	_policy_marks "$1" | awk '$1 == "member" { printf "%s ", $2 }'
}

_policy_last() { # <策略名>：last_resort mark
	_policy_marks "$1" | awk '$1 == "last" { print $2; exit }'
}

_fmt_marks() { # "1280 1536 " -> "1280, 1536"
	printf '%s' "${1:-}" | sed 's/ *$//' | tr ' ' ','
}

# ---------------------------------------------------------------- 主流程

for _a in "$@"; do
	case "$_a" in
	-h | --help) usage 0 ;;
	esac
done

if [ -n "$FIX" ]; then
	[ -d "$FIX" ] || { echo "夹具目录不存在: $FIX" >&2; exit 2; }
else
	command -v nft >/dev/null || { echo "缺少 nft" >&2; exit 2; }
	command -v conntrack >/dev/null || { echo "缺少 conntrack（apk add conntrack）" >&2; exit 2; }
	nft list table inet mwan3 >/dev/null 2>&1 || { echo "table inet mwan3 不存在" >&2; exit 2; }
fi

[ -f "$CONF" ] || { echo "读不到 $CONF" >&2; exit 2; }
. "$CONF"
[ -n "${ISP_TABLE:-}" ] || { echo "$CONF 里没有 ISP_TABLE" >&2; exit 2; }

WORK=$(mktemp -d 2>/dev/null) || WORK=$(mktemp -d /tmp/verify-domains.XXXXXX) ||
	{ echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT INT TERM

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

_rules_file=$WORK/mwan3_rules.txt
if ! _nft_chain mwan3_rules >"$_rules_file"; then
	echo "读不到 mwan3_rules 链（mwan3 未运行？）" >&2
	exit 2
fi

# ---- 1. ISP_TABLE -> 启用集合 / 策略 / 链上位置 ----

SETS=""
while IFS= read -r _row; do
	case "$_row" in "" | \#*) continue ;; esac
	_oldifs=$IFS
	IFS=':'
	# shellcheck disable=SC2086
	set -- $_row
	IFS=$_oldifs
	[ $# -ge 4 ] || continue
	_set=$2
	_pol=$3
	_en=$4
	[ "$_en" = "1" ] || continue
	case " $SETS " in *" $_set "*) continue ;; esac
	SETS="$SETS $_set"
	eval "PSET_POLICY_$_set=\$_pol"
	eval "PSET_LINE_$_set=0"
	eval "PSET_MISSING_$_set=0"

	if _set_ranges "$_set" > "$WORK/ranges.$_set" 2>/dev/null; then
		[ -s "$WORK/ranges.$_set" ] || eval "PSET_MISSING_$_set=1"
	else
		eval "PSET_MISSING_$_set=1"
	fi

	_ln=$(awk -v s="daddr @$_set " 'index($0, s) { print NR; exit }' "$_rules_file")
	eval "PSET_LINE_$_set=\${_ln:-0}"
done <<EOF
$(printf '%s\n' "$ISP_TABLE")
EOF

if [ -z "$SETS" ]; then
	echo "ISP_TABLE 里没有启用的运营商行（第 4 列为 1）" >&2
	exit 2
fi

# ---- 2. 兜底规则（catch-all）----
# 只认三种：0.0.0.0/0 直连 policy jump、经 mwan3_rule_default_rule_v4 的
# 间接跳转、以及"纯 mark 条件"的 policy jump（不含 ip saddr/daddr 前置匹配）。
CATCH_LINE=0
CATCH_POL=""
_ln=0
while IFS= read -r _l; do
	_ln=$((_ln + 1))
	case "$_l" in
	*'ip daddr 0.0.0.0/0'*)
		_p=$(printf '%s\n' "$_l" |
			sed -n 's/.*\(jump\|goto\) mwan3_policy_\([A-Za-z0-9_]*\).*/\2/p')
		if [ -n "$_p" ]; then
			CATCH_LINE=$_ln
			CATCH_POL=$_p
			break
		fi
		;;
	*'mwan3_rule_default_rule_v4'*)
		_ch=$(_nft_chain mwan3_rule_default_rule_v4 2>/dev/null) || _ch=""
		_p=$(printf '%s\n' "$_ch" |
			sed -n 's/.*\(jump\|goto\) mwan3_policy_\([A-Za-z0-9_]*\).*/\2/p' | head -1)
		if [ -n "$_p" ]; then
			CATCH_LINE=$_ln
			CATCH_POL=$_p
			break
		fi
		;;
	*'meta mark'*'jump mwan3_policy_'*)
		case "$_l" in
		*'ip saddr'* | *'ip daddr'*) continue ;;
		esac
		case "$_l" in
		*'== 0x0'* | *'== 0x00000000'*)
			CATCH_LINE=$_ln
			CATCH_POL=$(printf '%s\n' "$_l" |
				sed -n 's/.*\(jump\|goto\) mwan3_policy_\([A-Za-z0-9_]*\).*/\2/p')
			break
			;;
		esac
		;;
	esac
done < "$_rules_file"

CATCH_MEMBERS=""
CATCH_LAST=""
if [ -n "$CATCH_POL" ]; then
	CATCH_MEMBERS=$(_policy_members "$CATCH_POL")
	CATCH_LAST=$(_policy_last "$CATCH_POL")
fi

# ---- 3. 打印"启用集合 -> 策略 -> 可用 mark" ----

echo "== 启用集合 =="
for _s in $SETS; do
	eval "_p=\$PSET_POLICY_$_s"
	eval "_ln=\$PSET_LINE_$_s"
	eval "_missing=\$PSET_MISSING_$_s"
	_m=$(_policy_members "$_p")
	_l=$(_policy_last "$_p")
	if [ "$_missing" = "1" ]; then
		printf '  %-12s -> %-14s ✗ 集合不在 nft 里或为空（wire 未跑？）\n' "$_s" "$_p"
	elif [ -z "$_m" ]; then
		printf '  %-12s -> %-14s ✗ 策略链没有任何成员 mark（无成员在线？）\n' "$_s" "$_p"
	else
		printf '  %-12s -> %-14s mark 期望 {%s}' "$_s" "$_p" "$(_fmt_marks "$_m")"
		[ -n "$_l" ] && printf '（无成员时回落 %s）' "$_l"
		if [ "$_ln" = "0" ]; then
			printf ' ✗ 链上找不到 @%s 规则' "$_s"
		elif [ -n "$CATCH_LINE" ] && [ "$_ln" -gt "$CATCH_LINE" ]; then
			printf ' ✗ 位于兜底规则（第 %s 行）之后' "$CATCH_LINE"
		fi
		printf '\n'
	fi
done
echo
if [ -n "$CATCH_POL" ]; then
	printf '兜底规则: 第 %s 行 -> mwan3_policy_%s（未命中集合的流量期望 mark {%s}）\n' \
		"$CATCH_LINE" "$CATCH_POL" "$(_fmt_marks "$CATCH_MEMBERS")"
else
	echo "兜底规则: 无（unmatched 流量期望 mark = 0）"
fi
echo

# ---- 4. 主循环 ----

printf '%-30s %-15s %-9s %-14s %10s %6s  %s\n' \
	"域名" "IP" "集合" "策略" "期望" "实际" "判定"
printf '%-30s %-15s %-9s %-14s %10s %6s  %s\n' \
	"------------------------------" "---------------" "---------" \
	"--------------" "----------" "------" "------"

_ok=0
_bad=0
_neutral=0
_nip=0
_badlist=""

for d in $DOMAINS; do
	case "$d" in
	*[0-9].[0-9]*.[0-9]*.[0-9]*) ips="$d" ;;
	*) ips=$(_resolve "$d") ;;
	esac

	if [ -z "$ips" ]; then
		printf '%-30s %s\n' "$d" "（解析失败或无 A 记录）"
		continue
	fi

	for ip in $ips; do
		is_ipv4 "$ip" || continue
		_nip=$((_nip + 1))
		_ipd=$(ip2dec "$ip")
		_fire_traffic "$ip"
		mark=$(_mark_of_ip "$ip")
		[ -n "$mark" ] || mark=0

		set=""
		for _s in $SETS; do
			eval "_missing=\$PSET_MISSING_$_s"
			[ "$_missing" = "1" ] && continue
			[ -f "$WORK/ranges.$_s" ] || continue
			if _ip_in_ranges "$_ipd" "$WORK/ranges.$_s"; then
				set=$_s
				break
			fi
		done

		if [ -n "$set" ]; then
			eval "_pol=\$PSET_POLICY_$set"
			eval "_ln=\$PSET_LINE_$set"
			_exp=$(_policy_members "$_pol")
			_last=$(_policy_last "$_pol")
			eval "_c=\${CNT_$set:-0}"
			eval "CNT_$set=$((_c + 1))"
			_expd=$(_fmt_marks "$_exp")

			if [ -n "$CATCH_LINE" ] && [ "$_ln" != "0" ] && [ "$_ln" -gt "$CATCH_LINE" ]; then
				verdict="✗ 规则在兜底之后（不会命中）"
				_bad=$((_bad + 1))
				_badlist="$_badlist $ip($set:顺序)"
			elif [ -z "$_exp" ]; then
				verdict="✗ 策略 $_pol 无成员 mark"
				_bad=$((_bad + 1))
				_badlist="$_badlist $ip($set:空策略)"
			elif [ "$mark" = "$_last" ] && ! printf ' %s ' "$_exp" | grep -q " $mark "; then
				verdict="! 策略无可用成员（回落 $mark）"
				_bad=$((_bad + 1))
				_badlist="$_badlist $ip($set:无成员在线)"
			elif printf ' %s ' "$_exp" | grep -q " $mark "; then
				verdict="✓"
				_ok=$((_ok + 1))
			else
				verdict="✗ 期望 {$_expd}"
				_bad=$((_bad + 1))
				_badlist="$_badlist $ip($set:mark=$mark 期望 $_expd)"
			fi
			printf '%-30s %-15s %-9s %-14s %10s %6s  %s\n' \
				"$d" "$ip" "$set" "$_pol" "$_expd" "$mark" "$verdict"
		else
			# 未命中任何启用集合：期望值由兜底规则决定，不是恒等于 0
			if [ -n "$CATCH_POL" ]; then
				_pol=$CATCH_POL
				_exp=$CATCH_MEMBERS
				_expd=$(_fmt_marks "$_exp")
				if printf ' %s ' "$_exp" | grep -q " $mark "; then
					verdict="✓ 未命中集合（按兜底打标）"
					_neutral=$((_neutral + 1))
				elif [ -n "$CATCH_LAST" ] && [ "$mark" = "$CATCH_LAST" ]; then
					verdict="! 兜底策略无可用成员（回落 $mark）"
					_bad=$((_bad + 1))
					_badlist="$_badlist $ip(兜底:无成员在线)"
				else
					verdict="✗ 期望兜底 {$_expd}"
					_bad=$((_bad + 1))
					_badlist="$_badlist $ip(兜底:mark=$mark 期望 $_expd)"
				fi
			else
				_pol="（无兜底）"
				_expd=0
				if [ "$mark" = "0" ]; then
					verdict="✓ 未打标"
					_neutral=$((_neutral + 1))
				else
					verdict="✗ 无兜底规则却有 mark"
					_bad=$((_bad + 1))
					_badlist="$_badlist $ip(无兜底:mark=$mark)"
				fi
			fi
			printf '%-30s %-15s %-9s %-14s %10s %6s  %s\n' \
				"$d" "$ip" "-" "$_pol" "$_expd" "$mark" "$verdict"
		fi
	done
done

# ---- 5. 汇总 ----

echo
echo "== 汇总 =="
echo "  测试 IP 总数: $_nip"
echo "  命中集合且 mark 一致: $_ok"
echo "  未命中集合、mark 与兜底一致: $_neutral"
echo "  异常: $_bad"
[ -n "$_badlist" ] && echo "  异常明细:$_badlist"

echo
echo "== 各集合命中 IP 数 =="
for _s in $SETS; do
	eval "_c=\${CNT_$_s:-0}"
	printf '  %-12s %s\n' "$_s" "${_c:-0}"
done

echo
if [ "$_nip" -eq 0 ]; then
	echo "结论：没有可测试的 IP（解析全失败？），无法判定。"
	exit 1
fi
if [ "$_bad" -eq 0 ]; then
	echo "结论：分流映射全部一致。"
	exit 0
fi
echo "结论：存在 $_bad 处不一致，请检查 /etc/config/mwan3 的规则与策略。"
exit 1
