#!/bin/sh
# 离线自检：不需要路由器、不需要联网。
#   1. 数据管线：互斥化后任意两个集合不得有交集
#   2. 规则注入：顺序正确、重复执行幂等
# 用法：sh tools/selftest.sh
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIB=$ROOT/files/usr/lib/isp-split
FIX=$ROOT/tools/fixtures
TMP=$(mktemp -d 2>/dev/null) ||
	TMP=$(mktemp -d /tmp/isp-split-selftest.XXXXXX 2>/dev/null) ||
	{ echo "无法创建临时目录" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok() { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
ng() { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail + 1)); }

echo "== 1. 数据管线"
sh "$LIB/build.sh" "$FIX/raw" "$TMP/out" "isp_a isp_b isp_c isp_d" 2>/dev/null

# 任意两个集合不得有交集
cat "$TMP"/out/*.txt > "$TMP/all.txt"
if awk -f "$LIB/cidr2range.awk" "$TMP/all.txt" | sort | awk '
	{
		if (NR > 1 && $1 + 0 <= prev_end) { print "重叠: " prev_start "-" prev_end " 与 " $1 "-" $2; bad = 1 }
		prev_start = $1; prev_end = $2 + 0
	}
	END { exit (bad ? 1 : 0) }
'; then
	ok "各运营商集合互不相交"
else
	ng "仍存在重叠区间"
fi

# 高优先级集合必须完整保留，被完全覆盖的集合应清空
if grep -qx '10.1.0.0/16' "$TMP/out/isp_a.txt"; then
	ok "高优先级集合未被削弱"
else
	ng "高优先级集合内容异常"
fi

if [ ! -s "$TMP/out/isp_c.txt" ]; then
	ok "被完全覆盖的集合已清空"
else
	ng "被覆盖的集合未清空（应为空）: $(cat "$TMP/out/isp_c.txt")"
fi

if grep -qx '10.0.0.0/25' "$TMP/out/isp_b.txt"; then
	ng "低优先级集合仍持有已被占用的 10.0.0.0/25"
else
	ok "低优先级集合已让出被占用地址"
fi

if grep -qx '8.8.8.0/24' "$TMP/out/isp_d.txt"; then
	ok "无关集合未受影响"
else
	ng "无关集合内容异常"
fi

echo "== 2. 规则注入"
cat > "$TMP/rules.txt" <<'EOF'
config rule 'isp_a'
	option ipset 'isp_a'
	option use_policy 'wan_only'
	option family 'ipv4'
	option isp_split '1'

config rule 'isp_b'
	option ipset 'isp_b'
	option use_policy 'wanb_only'
	option family 'ipv4'
	option isp_split '1'

EOF

ANCHOR='dest_port|src_port|default_rule|https|internet'
awk -v insert="$TMP/rules.txt" -v anchor="$ANCHOR" \
	-f "$LIB/rules-splice.awk" "$FIX/mwan3" > "$TMP/w1"
awk -v insert="$TMP/rules.txt" -v anchor="$ANCHOR" \
	-f "$LIB/rules-splice.awk" "$TMP/w1" > "$TMP/w2"

order=$(grep -oE "^config rule '[^']+'" "$TMP/w1" | sed "s/.*'\(.*\)'/\1/" | tr '\n' ' ')
expect="nas_all pc_wan isp_a isp_b https default_rule_v4 "
if [ "$order" = "$expect" ]; then
	ok "规则顺序正确: $order"
else
	ng "规则顺序错误: $order （期望: $expect）"
fi

if cmp -s "$TMP/w1" "$TMP/w2"; then
	ok "重复注入幂等"
else
	ng "重复注入产生了差异"
fi

# 移除：注入空片段应恢复原样
: > "$TMP/empty.txt"
awk -v insert="$TMP/empty.txt" -v anchor="$ANCHOR" \
	-f "$LIB/rules-splice.awk" "$TMP/w1" > "$TMP/w3"
if cmp -s "$FIX/mwan3" "$TMP/w3"; then
	ok "卸载后配置完全还原"
else
	ng "卸载后配置未能还原"
fi

echo "== 3. 坏 CIDR 防御"
printf '1.2.3.4/abc\n10.0.0.0/8\n' > "$TMP/bad.raw"
_bad_out=$(awk -f "$LIB/cidr2range.awk" "$TMP/bad.raw")
case "$_bad_out" in
*"0000000000 4294967295"*)
	ng "坏前缀被当成 /0"
	;;
*"0167772160 "*)
	ok "坏前缀被跳过，合法 /8 正常解析"
	;;
*)
	ng "坏 CIDR 防御输出异常: $_bad_out"
	;;
esac
if awk -f "$LIB/badcidr.awk" "$TMP/bad.raw" | grep -q '^1:'; then
	ok "badcidr 能识别坏前缀"
else
	ng "badcidr 未识别坏前缀"
fi

echo "== 4. DNS 旁路：mwan3 reload 竞态恢复"
mkdir -p "$TMP/fakebin"
cat > "$TMP/fakebin/nft" <<'FAKE_NFT'
#!/bin/sh
S=${FAKE_NFT_STATE:?}
mkdir -p "$S"
[ "$1" = "-a" ] && shift
cmd=$1; shift
case "$cmd" in
list)
	case "$*" in
	*"chain inet mwan3 mwan3_output"*)
		p=0; [ -f "$S/polls" ] && p=$(cat "$S/polls")
		p=$((p + 1)); echo "$p" > "$S/polls"
		ready=0; [ -f "$S/ready" ] && ready=1
		[ "$p" -ge "${FAKE_NFT_READY_AFTER:-3}" ] && ready=1 && : > "$S/ready"
		echo "table inet mwan3 {"
		echo "	chain mwan3_output {"
		echo "		type route hook output priority mangle; policy accept;"
		if [ "$ready" = 1 ]; then
			echo "		jump mwan3_rules"
			if [ -f "$S/rules" ]; then
				n=0
				while IFS= read -r r; do
					n=$((n + 1)); echo "		$r # handle $n"
				done < "$S/rules"
			fi
		fi
		echo "	}"
		echo "}"
		exit 0
		;;
	*"chain inet mwan3 mwan3_rules"*)
		echo "table inet mwan3 { chain mwan3_rules { } }"
		exit 0
		;;
	*"chain inet mwan3 mwan3_policy_"*) exit 0 ;;
	*"table inet mwan3"*) exit 0 ;;
	*"set inet mwan3"*) exit 0 ;;
	*) exit 1 ;;
	esac
	;;
insert)
	[ -f "$S/ready" ] || {
		echo "Error: Could not process rule: Device or resource busy" >&2
		exit 1
	}
	# 模拟真 nft 语法：comment 是规则级属性，后面不能再有 verdict/语句。
	_cseen=0
	for _a in "$@"; do
		if [ "$_cseen" = "1" ]; then _cseen=2; continue; fi
		if [ "$_cseen" = "2" ]; then
			echo "Error: syntax error, unexpected $_a (comment must be last)" >&2
			exit 1
		fi
		[ "$_a" = "comment" ] && _cseen=1
	done
	echo "$*" | sed 's/comment isp-split-dns/comment "isp-split-dns"/' >> "$S/rules"
	c=0; [ -f "$S/inserts" ] && c=$(cat "$S/inserts")
	c=$((c + 1)); echo "$c" > "$S/inserts"
	if [ -n "${FAKE_NFT_FLUSH_AFTER_INSERT:-}" ] && [ "$c" -eq "$FAKE_NFT_FLUSH_AFTER_INSERT" ]; then
		rm -f "$S/ready"; echo 0 > "$S/polls"
	fi
	exit 0
	;;
delete)
	h=""; for a in "$@"; do h=$a; done
	[ -f "$S/rules" ] || exit 0
	awk -v h="$h" 'NR != h' "$S/rules" > "$S/rules.new" && mv "$S/rules.new" "$S/rules"
	exit 0
	;;
esac
exit 1
FAKE_NFT
chmod +x "$TMP/fakebin/nft"
cat > "$TMP/fakebin/logger" <<'FAKE_LOGGER'
#!/bin/sh
exit 0
FAKE_LOGGER
chmod +x "$TMP/fakebin/logger"

cat > "$TMP/dns.conf" <<'DNS_CONF'
DNS_TABLE="
wan_only:223.5.5.5
wanb_only:119.29.29.29
"
DNS_MODE="bind"
DNS_CONF
cat > "$TMP/dns-bad.conf" <<'DNS_BAD'
DNS_TABLE="
wan_only:not-an-ip
"
DNS_MODE="bind"
DNS_BAD
cat > "$TMP/dns-mark.conf" <<'DNS_MARK'
DNS_TABLE="
wan_only:223.5.5.5
"
DNS_MODE="mark"
DNS_MARK
cat > "$TMP/dns-changed.conf" <<'DNS_CHANGED'
DNS_TABLE="
wan_only:9.9.9.9
"
DNS_MODE="bind"
DNS_CHANGED

# 只取主脚本的函数定义（去掉 main 的 case），在隔离的 PATH 下直接调 _dns_bypass。
sed '/^# ---------------------------------------------------------------- main$/,$d' \
	"$ROOT/files/usr/sbin/isp-split" > "$TMP/isp-lib.sh"

dns_case() {
	_state=$1
	_ready_after=$2
	_flush_after=$3
	_conf=$4
	(
		PATH="$TMP/fakebin:$PATH"
		FAKE_NFT_STATE="$_state"
		FAKE_NFT_READY_AFTER="$_ready_after"
		FAKE_NFT_FLUSH_AFTER_INSERT="$_flush_after"
		ISP_SPLIT_CONF="$_conf"
		DNS_RETRY_TRIES=8
		DNS_RETRY_DELAY=0
		export PATH FAKE_NFT_STATE FAKE_NFT_READY_AFTER \
			FAKE_NFT_FLUSH_AFTER_INSERT ISP_SPLIT_CONF DNS_RETRY_TRIES DNS_RETRY_DELAY
		. "$TMP/isp-lib.sh"
		_dns_bypass 1
	)
}

rm -rf "$TMP/nft1"; mkdir -p "$TMP/nft1"
if dns_case "$TMP/nft1" 3 2 "$TMP/dns.conf" >/dev/null 2>&1; then
	_n=$(grep -c 'comment "isp-split-dns"' "$TMP/nft1/rules" 2>/dev/null || echo 0)
	_bad=$(grep -vc 'counter return comment "isp-split-dns"$' "$TMP/nft1/rules" 2>/dev/null || true)
	if [ "$_n" -eq 4 ] && [ "$_bad" -eq 0 ]; then
		ok "mwan3 重建竞态下 4 条 DNS 旁路规则全部恢复（comment 收尾）"
	else
		ng "bind 模式 DNS 规则异常: $_n 条，$_bad 条 comment 不在行尾（期望 4/0）"
	fi
else
	ng "mwan3 重建竞态下 DNS 旁路恢复失败"
fi

# 幂等：同一 DNS_TABLE 连续再跑两次，每次都应先按 comment 删旧再重插。
_dns_idem=1
_i=0
while [ "$_i" -lt 2 ]; do
	_i=$((_i + 1))
	if dns_case "$TMP/nft1" 1 0 "$TMP/dns.conf" >/dev/null 2>&1; then
		_n=$(grep -c 'comment "isp-split-dns"' "$TMP/nft1/rules" 2>/dev/null || echo 0)
		[ "$_n" -eq 4 ] || { _dns_idem=0; break; }
	else
		_dns_idem=0
		break
	fi
done
if [ "$_dns_idem" -eq 1 ]; then
	ok "连续 3 次 dns 后仍为 4 条（按 comment 删除旧规则，无叠加）"
else
	ng "重复 dns 后规则数异常: ${_n:-调用失败}（期望 4）"
fi

# 改 DNS_TABLE：旧 IP 的规则必须被清掉，只保留新 IP 的 2 条。
if dns_case "$TMP/nft1" 1 0 "$TMP/dns-changed.conf" >/dev/null 2>&1; then
	_n=$(grep -c 'comment "isp-split-dns"' "$TMP/nft1/rules" 2>/dev/null || echo 0)
	_old=$(grep -c '223.5.5.5' "$TMP/nft1/rules" 2>/dev/null || true)
	_new=$(grep -c '9.9.9.9' "$TMP/nft1/rules" 2>/dev/null || true)
	if [ "$_n" -eq 2 ] && [ "$_old" -eq 0 ] && [ "$_new" -eq 2 ]; then
		ok "DNS_TABLE 变更后旧规则已清、新规则就位（2 条）"
	else
		ng "DNS_TABLE 变更后残留异常: 总数 $_n，旧 IP $_old，新 IP $_new（期望 2/0/2）"
	fi
else
	ng "DNS_TABLE 变更后 dns 调用失败"
fi

rm -rf "$TMP/nft2"; mkdir -p "$TMP/nft2"
if dns_case "$TMP/nft2" 999 0 "$TMP/dns.conf" >/dev/null 2>&1; then
	ng "mwan3 始终未就绪时未返回失败"
else
	ok "mwan3 始终未就绪时明确失败（非 0）"
fi

rm -rf "$TMP/nft3"; mkdir -p "$TMP/nft3"
if dns_case "$TMP/nft3" 1 0 "$TMP/dns-bad.conf" >/dev/null 2>&1; then
	ng "非法 DNS 被当成成功"
else
	ok "DNS_TABLE 配置错误立即失败（非 0）"
fi

rm -rf "$TMP/nft4"; mkdir -p "$TMP/nft4"
if dns_case "$TMP/nft4" 1 0 "$TMP/dns-mark.conf" >/dev/null 2>&1; then
	_n=$(grep -c 'comment "isp-split-dns"' "$TMP/nft4/rules" 2>/dev/null || echo 0)
	_j=$(grep -c 'counter jump mwan3_policy_wan_only comment "isp-split-dns"$' \
		"$TMP/nft4/rules" 2>/dev/null || true)
	if [ "$_n" -eq 2 ] && [ "$_j" -eq 2 ]; then
		ok "mark 模式 2 条规则 comment 收尾且 jump 目标正确"
	else
		ng "mark 模式 DNS 规则异常: $_n 条，$_j 条形状不符（期望 2/2）"
	fi
else
	ng "mark 模式 DNS 旁路恢复失败"
fi

echo "== 5. nft 语句构造"
# comment 是规则级属性，必须是规则的最后一条语句。真 nft 对
#   ... counter comment "x" return
# 会报 "syntax error, unexpected return"。这里静态扫描源码里的
# nft insert/add rule 语句（自动拼接反斜杠续行）做回归检查。
cat > "$TMP/comment-last.awk" <<'COMMENT_LAST_AWK'
function report(msg) { printf "%s\n", msg; bad = 1 }
function flush(   pos, tail) {
	if (buf !~ /comment/) { buf = ""; return }
	pos = match(buf, /comment[[:space:]]+"[^"]*"/)
	if (pos == 0) {
		report("无法定位 comment 参数: " buf)
		buf = ""
		return
	}
	tail = substr(buf, RSTART + RLENGTH)
	# 去掉 shell 层的重定向/命令替换收尾，它们不属于 nft 语句本身。
	sub(/[[:space:]]*2>&1.*$/, "", tail)
	sub(/[[:space:]]*2>.*$/, "", tail)
	sub(/[[:space:]]*\).*$/, "", tail)
	sub(/[[:space:]]*;.*$/, "", tail)
	if (tail !~ /^[[:space:]]*$/)
		report("comment 不是最后一条语句: " buf)
	buf = ""
}
FNR == 1 { collecting = 0; buf = "" }
/^[[:space:]]*#/ { next }
/nft[[:space:]].*(insert|add)[[:space:]]+rule/ {
	buf = $0
	if ($0 ~ /\\[[:space:]]*$/) { collecting = 1; next }
	flush()
	next
}
collecting {
	buf = buf " " $0
	if ($0 ~ /\\[[:space:]]*$/) next
	collecting = 0
	flush()
}
END {
	if (collecting) flush()
	exit bad
}
COMMENT_LAST_AWK

# 先证明检查器能抓住历史错误写法，避免它本身变成永远通过的假阳性。
printf '%s\n' \
	'nft insert rule inet mwan3 mwan3_output ip daddr 223.5.5.5 udp dport 53 counter comment "isp-split-dns" return' \
	> "$TMP/bad-comment.nft"
if _bad_scan=$(awk -f "$TMP/comment-last.awk" "$TMP/bad-comment.nft" 2>&1); then
	ng "静态检查漏掉了 comment 位于 verdict 之前的语句"
else
	ok "静态检查能识别 comment 位于 verdict 之前"
fi

if _scan=$(awk -f "$TMP/comment-last.awk" "$ROOT/files/usr/sbin/isp-split" 2>&1); then
	ok "源码中所有 nft 规则 comment 均位于规则末尾"
else
	ng "源码中存在 comment 未收尾的 nft 规则"
	printf '%s\n' "$_scan" | sed 's/^/    /'
fi

echo "== 6. conf set 失败退出码"
cat > "$TMP/conf.conf" <<'CONF_FILE'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
CONF_FILE
cp "$TMP/conf.conf" "$TMP/conf.before"
_pwn="/tmp/isp-split-selftest-pwn.$$"
rm -f "$_pwn"
if ISP_SPLIT_CONF="$TMP/conf.conf" sh "$ROOT/files/usr/sbin/isp-split" \
	conf set domain_split "x\$(id>$_pwn):wan_only" >/dev/null 2>&1; then
	ng "非法配置值被接受（退出码为 0）"
else
	ok "非法配置值被拒绝且退出码非 0"
fi
if [ -e "$_pwn" ]; then
	ng "非法值中的命令替换被执行"
	rm -f "$_pwn"
else
	ok "非法值中的命令替换未执行"
fi
if cmp -s "$TMP/conf.before" "$TMP/conf.conf"; then
	ok "校验失败未改动配置文件"
else
	ng "校验失败后配置文件被改动"
fi
if ISP_SPLIT_CONF="$TMP/conf.conf" sh "$ROOT/files/usr/sbin/isp-split" \
	conf set bogus x >/dev/null 2>&1; then
	ng "未知配置项退出码为 0"
else
	ok "未知配置项退出码非 0"
fi

echo "== 7. dnsmasq 实际 conf-dir 探测（BUG-6）"
# 模拟生产实机：UCI confdir 为空，但 /var/etc/dnsmasq.conf.cfgXXXX 里
# 写着 conf-dir=/tmp/dnsmasq.cfgXXXX.d（OpenClash 接管 DNS 的形态）。
mkdir -p "$TMP/bug6/fakebin" "$TMP/bug6/var/etc" \
	"$TMP/bug6/run/cfg01411c.d" "$TMP/bug6/run/other.d" \
	"$TMP/bug6/run/default.d" "$TMP/bug6/run/legacy.d" "$TMP/bug6/run/uci.d"
cat > "$TMP/bug6/fakebin/uci" <<'FAKE_UCI'
#!/bin/sh
[ -n "${FAKE_UCI_LOG:-}" ] && printf '%s\n' "$*" >> "$FAKE_UCI_LOG"
if [ -n "${FAKE_UCI_CONFDIR:-}" ]; then
	case "$*" in
	*"get dhcp.@dnsmasq[0].confdir"*)
		printf '%s\n' "$FAKE_UCI_CONFDIR"
		exit 0
		;;
	esac
fi
exit 1
FAKE_UCI
chmod +x "$TMP/bug6/fakebin/uci"
cat > "$TMP/bug6/conf" <<'BUG6_CONF'
ISP_TABLE=""
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
BUG6_CONF
cat > "$TMP/bug6/var/etc/dnsmasq.conf.cfg01411c" <<EOF
# dnsmasq 实际运行配置（OpenClash 生成）
conf-dir=$TMP/bug6/run/cfg01411c.d/
conf-dir=$TMP/bug6/run/other.d,*.conf
EOF

_bug6_detect() {
	# $1 = runtime glob；$2 = fake uci confdir
	(
		PATH="$TMP/bug6/fakebin:$TMP/fakebin:$PATH"
		ISP_SPLIT_CONF="$TMP/bug6/conf"
		ISP_SPLIT_BASE="$TMP/bug6/base"
		DNSMASQ_CONF_GLOB="$1"
		DNSMASQ_DEFAULT_DIR="$TMP/bug6/run/default.d"
		DNSDIR="$TMP/bug6/run/legacy.d"
		FAKE_UCI_CONFDIR="$2"
		FAKE_UCI_LOG="$TMP/bug6/uci.log"
		export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE DNSMASQ_CONF_GLOB \
			DNSMASQ_DEFAULT_DIR DNSDIR FAKE_UCI_CONFDIR FAKE_UCI_LOG
		. "$TMP/isp-lib.sh"
		_dns_confdir_detect >/dev/null
		printf '%s|%s|%s\n' "$DNS_CONFDIR_SOURCE" "$DNS_CONFDIR_DIRS" \
			"$(_dns_confdir_first "$DNS_CONFDIR_DIRS")"
	)
}

_bug6_out=$(_bug6_detect "$TMP/bug6/var/etc/dnsmasq.conf.*" "")
_bug6_expect="runtime|$TMP/bug6/run/cfg01411c.d $TMP/bug6/run/other.d|$TMP/bug6/run/cfg01411c.d"
if [ "$_bug6_out" = "$_bug6_expect" ]; then
	ok "UCI 为空时按实际运行配置选目录（含尾斜杠/多目录）: ${_bug6_out#*|}"
else
	ng "conf-dir 探测结果错误: $_bug6_out（期望: $_bug6_expect）"
fi

# 无 /var/etc 运行配置时，UCI 仍是权威源（测试机无 OpenClash 不回归）。
_bug6_uci=$(_bug6_detect "$TMP/bug6/empty.dnsmasq.conf.*" "$TMP/bug6/run/uci.d")
_bug6_uci_expect="uci|$TMP/bug6/run/uci.d|$TMP/bug6/run/uci.d"
if [ "$_bug6_uci" = "$_bug6_uci_expect" ]; then
	ok "无运行配置时回落到 UCI confdir"
else
	ng "UCI 回落结果错误: $_bug6_uci（期望: $_bug6_uci_expect）"
fi

# 卸载：探测路径下没有状态文件，也必须按探测结果删片段，且不碰 UCI。
for _d in cfg01411c.d other.d default.d legacy.d; do
	: > "$TMP/bug6/run/$_d/isp-split.conf"
done
rm -f "$TMP/bug6/uci.log"
(
	PATH="$TMP/bug6/fakebin:$TMP/fakebin:$PATH"
	ISP_SPLIT_CONF="$TMP/bug6/conf"
	ISP_SPLIT_BASE="$TMP/bug6/base"
	DNSMASQ_CONF_GLOB="$TMP/bug6/var/etc/dnsmasq.conf.*"
	DNSMASQ_DEFAULT_DIR="$TMP/bug6/run/default.d"
	DNSDIR="$TMP/bug6/run/legacy.d"
	FAKE_UCI_CONFDIR=""
	FAKE_UCI_LOG="$TMP/bug6/uci.log"
	export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE DNSMASQ_CONF_GLOB \
		DNSMASQ_DEFAULT_DIR DNSDIR FAKE_UCI_CONFDIR FAKE_UCI_LOG
	. "$TMP/isp-lib.sh"
	_restore_dns_confdir
)
_bug6_left=""
for _d in cfg01411c.d other.d default.d legacy.d; do
	[ -e "$TMP/bug6/run/$_d/isp-split.conf" ] && _bug6_left="$_bug6_left $_d"
done
if [ -z "$_bug6_left" ] && ! grep -qE ' (set|delete|commit)( |$)' "$TMP/bug6/uci.log" 2>/dev/null; then
	ok "卸载按探测结果清理全部片段，且未改写 UCI"
else
	ng "卸载清理异常：残留${_bug6_left:- 无}，uci 调用: $(tr '\n' ';' < "$TMP/bug6/uci.log" 2>/dev/null)"
fi

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
