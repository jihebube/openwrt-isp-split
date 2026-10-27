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
	ok "卸载后配置恢复原样"
else
	ng "卸载后配置未能恢复原样"
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

echo "== 8. verify/status 链形状判定（BUG-7 / BUG-8）"
# 生产实机 mwan3_rules 的真实形状：用户 saddr 规则在链首、本工具
# @isp 规则在中间、default 规则在链尾且是 mwan3 3.6 的间接跳转。
mkdir -p "$TMP/bug78/fakebin"
cat > "$TMP/bug78/fakebin/nft" <<'FAKE_NFT78'
#!/bin/sh
[ "$1" = "-a" ] && shift
cmd=$1; shift
case "$cmd" in
list)
	case "$*" in
	"table inet mwan3") exit 0 ;;
	"chain inet mwan3 mwan3_rules")
		echo "table inet mwan3 {"
		echo "	chain mwan3_rules {"
		sed 's/^/		/' "$FAKE_NFT_FIXTURE"
		echo "	}"
		echo "}"
		exit 0
		;;
	"chain inet mwan3 mwan3_rule_default_rule_v4")
		[ -n "${FAKE_NFT_CHILD_FIXTURE:-}" ] || exit 1
		echo "table inet mwan3 {"
		echo "	chain mwan3_rule_default_rule_v4 {"
		sed 's/^/		/' "$FAKE_NFT_CHILD_FIXTURE"
		echo "	}"
		echo "}"
		exit 0
		;;
	"chain inet mwan3 mwan3_output") exit 0 ;;
	"set inet mwan3 "*) exit 1 ;;
	"counter inet mwan3 "*) exit 1 ;;
	*) exit 0 ;;
	esac
	;;
*) exit 1 ;;
esac
FAKE_NFT78
chmod +x "$TMP/bug78/fakebin/nft"
cat > "$TMP/bug78/fakebin/uci" <<'FAKE_UCI78'
#!/bin/sh
case "$*" in
*"get mwan3.default_rule_v4.enabled"*)
	if [ "${FAKE_UCI_DEFAULT_MODE:-}" = "missing" ]; then exit 1; fi
	if [ "${FAKE_UCI_DEFAULT_MODE:-}" = "disabled" ]; then
		echo 0
	else
		echo 1
	fi
	exit 0
	;;
*"get mwan3.default_rule_v4"*)
	[ "${FAKE_UCI_DEFAULT_MODE:-}" = "missing" ] && exit 1
	echo rule
	exit 0
	;;
esac
exit 1
FAKE_UCI78
chmod +x "$TMP/bug78/fakebin/uci"
cat > "$TMP/bug78/conf" <<'BUG78_CONF'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
cmcc:isp_cmcc:wanb_only:1
cernet:isp_cernet:wan_only:1
"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
COUNT_FALLBACK="0"
BUG78_CONF

_bug78_run() {
	_fixture=$1
	_child=$2
	_mode=$3
	shift 3
	(
		PATH="$TMP/bug78/fakebin:$PATH"
		ISP_SPLIT_CONF="$TMP/bug78/conf"
		ISP_SPLIT_BASE="$TMP/bug78/base"
		FAKE_NFT_FIXTURE="$_fixture"
		FAKE_NFT_CHILD_FIXTURE="$_child"
		FAKE_UCI_DEFAULT_MODE="$_mode"
		export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE \
			FAKE_NFT_FIXTURE FAKE_NFT_CHILD_FIXTURE FAKE_UCI_DEFAULT_MODE
		. "$TMP/isp-lib.sh"
		"$@"
	)
}

_bug78_prod="$FIX/mwan3_rules.prod.nft"
_bug78_child="$FIX/mwan3_rule_default_rule_v4.nft"
_bug78_bad="$FIX/mwan3_rules.bad-order.nft"
_bug78_direct="$FIX/mwan3_rules.direct.nft"
_bug78_user="$FIX/mwan3_rules.user-policy.nft"

# BUG-7：链首用户 saddr 规则不是 catch-all，4 条 @isp 规则必须全 ✓。
_bug78_out=$(_bug78_run "$_bug78_prod" "$_bug78_child" present cmd_verify)
_bug78_yes=$(printf '%s\n' "$_bug78_out" | grep -c '✓ @isp_')
_bug78_no=$(printf '%s\n' "$_bug78_out" | grep -c '✗')
if [ "$_bug78_yes" -eq 4 ] && [ "$_bug78_no" -eq 0 ]; then
	ok "真实链形状下 verify 4 条 @isp 规则全部 ✓"
else
	ng "真实链形状下 verify 结果异常: ${_bug78_yes} ✓ / ${_bug78_no} ✗（期望 4/0）"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# 用户自己带端口条件的直接 policy jump 不是 catch-all，不能把 @isp 规则
# 误判到它之后（“纯 mark 条件”才属于无条件兜底）。
_bug78_out=$(_bug78_run "$_bug78_user" "$_bug78_child" present cmd_verify)
_bug78_yes=$(printf '%s\n' "$_bug78_out" | grep -c '✓ @isp_')
_bug78_no=$(printf '%s\n' "$_bug78_out" | grep -c '✗')
if [ "$_bug78_yes" -eq 4 ] && [ "$_bug78_no" -eq 0 ]; then
	ok "用户 tcp dport policy 规则不被误判为 catch-all"
else
	ng "用户 tcp dport policy 规则被误判: ${_bug78_yes} ✓ / ${_bug78_no} ✗（期望 4/0）"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# BUG-8：链尾是 ip daddr 0.0.0.0/0 jump mwan3_rule_default_rule_v4，
# 且子链内确有 policy jump，status 不得再报“渲染异常”。
_bug78_out=$(_bug78_run "$_bug78_prod" "$_bug78_child" present cmd_status)
if ! printf '%s\n' "$_bug78_out" | grep -q '渲染异常' &&
   printf '%s\n' "$_bug78_out" | grep -q '已参与负载均衡'; then
	ok "间接跳转 default 形态下 status 不再误报渲染异常"
else
	ng "间接跳转 default 形态下 status 仍误报"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# 直接形态：ip daddr 0.0.0.0/0 ... jump mwan3_policy_<default> 同样通过。
_bug78_out=$(_bug78_run "$_bug78_direct" "$_bug78_child" present cmd_status)
if ! printf '%s\n' "$_bug78_out" | grep -q '渲染异常' &&
   printf '%s\n' "$_bug78_out" | grep -q '已参与负载均衡'; then
	ok "直接 policy jump default 形态下 status 正常识别"
else
	ng "直接 policy jump default 形态识别失败"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# 子链读不到时降级为警告，仍不能报“渲染异常”。
_bug78_out=$(_bug78_run "$_bug78_prod" "" present cmd_status)
if ! printf '%s\n' "$_bug78_out" | grep -q '渲染异常' &&
   printf '%s\n' "$_bug78_out" | grep -q '未能确认子链内的 mark==0 policy jump'; then
	ok "子链校验失败时降级为警告，不误报渲染异常"
else
	ng "子链校验失败时未按预期降级"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# 反例：规则真的排在 0.0.0.0/0 之后，仍必须报 ✗。
_bug78_out=$(_bug78_run "$_bug78_bad" "$_bug78_child" present cmd_verify)
_bug78_yes=$(printf '%s\n' "$_bug78_out" | grep -c '✓ @isp_')
_bug78_no=$(printf '%s\n' "$_bug78_out" |
	grep -c '✗ @isp_tel 位于第一条 catch-all 之后')
if [ "$_bug78_yes" -eq 3 ] && [ "$_bug78_no" -eq 1 ]; then
	ok "真正排在 0.0.0.0/0 之后的规则仍报 ✗（未削弱正确告警）"
else
	ng "catch-all 之后的规则告警异常: ${_bug78_yes} ✓ / ${_bug78_no} ✗（期望 3/1）"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# BUG-2 回归：enabled=0 仍走“已被禁用 + 启用命令”，不是渲染异常。
_bug78_out=$(_bug78_run "$_bug78_prod" "$_bug78_child" disabled cmd_status)
if printf '%s\n' "$_bug78_out" | grep -q '已被禁用（enabled=0）' &&
   printf '%s\n' "$_bug78_out" | grep -q 'enabled=1' &&
   ! printf '%s\n' "$_bug78_out" | grep -q '渲染异常'; then
	ok "enabled=0 仍沿用 BUG-2 的禁用提示"
else
	ng "enabled=0 提示路径被破坏"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi

# 无 default_rule_v4 section：提示未配置，不报渲染异常。
_bug78_out=$(_bug78_run "$_bug78_prod" "$_bug78_child" missing cmd_status)
if printf '%s\n' "$_bug78_out" | grep -q '未配置 mwan3 的 default_rule_v4' &&
   ! printf '%s\n' "$_bug78_out" | grep -q '渲染异常'; then
	ok "未配置 default_rule_v4 时提示未配置，不误报渲染异常"
else
	ng "未配置 default_rule_v4 时提示异常"
	printf '%s\n' "$_bug78_out" | sed 's/^/    /'
fi


echo "== 9. conf/rollback/export 的静默失败（BUG-9 ~ BUG-13）"
mkdir -p "$TMP/bug9"
cat > "$TMP/bug9/uci" <<'FAKE_UCI9'
#!/bin/sh
case "$*" in
*"show mwan3"*)
	printf 'mwan3.wan_only=policy\nmwan3.wanb_only=policy\n'
	exit 0
	;;
esac
exit 1
FAKE_UCI9
chmod +x "$TMP/bug9/uci"

# 在隔离子 shell 里只加载函数定义，然后直接调用 lib 里的函数。
_bug9_run() {
	_c=$1
	shift
	(
		PATH="$TMP/bug9:$PATH"
		ISP_SPLIT_CONF="$_c"
		export PATH ISP_SPLIT_CONF
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		"$@"
	)
}

# BUG-9a：配置里没有这个键时，conf set 必须真的写进去（旧实现静默无操作）
cat > "$TMP/bug9/no-key.conf" <<'CONF9A'
DNS_MODE="bind"
DNS_TABLE=""
CONF9A
if _bug9_run "$TMP/bug9/no-key.conf" conf_set isp_table "a:isp_a:wan_only:1" >/dev/null 2>&1 &&
   grep -q '^ISP_TABLE="a:isp_a:wan_only:1"$' "$TMP/bug9/no-key.conf"; then
	ok "键不存在时 conf set 会追加写入（不再静默无操作）"
else
	ng "键不存在时 conf set 仍未写入"
fi

# BUG-9b：单引号写法也必须能改，并且回读得到新值
cat > "$TMP/bug9/squote.conf" <<'CONF9B'
DNS_MODE='bind'
DNS_TABLE='wan_only:1.1.1.1'
ISP_TABLE="a:isp_a:wan_only:1"
CONF9B
_bug9_run "$TMP/bug9/squote.conf" conf_set dns_table "wan_only:9.9.9.9" >/dev/null 2>&1
_bug9_got=$(_bug9_run "$TMP/bug9/squote.conf" _conf_val DNS_TABLE)
if [ "$_bug9_got" = "wan_only:9.9.9.9" ]; then
	ok "单引号写法的键也能被 conf set 改写（回读一致）"
else
	ng "单引号写法的键改写失败，回读到: '$_bug9_got'"
fi

# BUG-9c：值里带空行属于正常输入，不能被"回读校验"误判成写入失败
_bug9_rc=0
_bug9_run "$TMP/bug9/squote.conf" conf_set isp_table "a:isp_a:wan_only:1

b:isp_b:wanb_only:0" >/dev/null 2>&1 || _bug9_rc=1
_bug9_rows=$(_bug9_run "$TMP/bug9/squote.conf" conf_get | grep -c '^isp	')
if [ "$_bug9_rc" -eq 0 ] && [ "$_bug9_rows" -eq 2 ]; then
	ok "值中夹空行时仍能写入（2 行）"
else
	ng "值中夹空行写入失败（rc=$_bug9_rc，读到 $_bug9_rows 行）"
fi

# BUG-10：空 ISP_TABLE 必须被拒绝，且文件保持原样
if _bug9_run "$TMP/bug9/no-key.conf" conf_set isp_table "" >/dev/null 2>&1; then
	ng "空 ISP_TABLE 被接受（会把整张表清空）"
else
	ok "空 ISP_TABLE 被拒绝（非 0）"
fi
if grep -q '^ISP_TABLE="a:isp_a:wan_only:1"$' "$TMP/bug9/no-key.conf"; then
	ok "空 ISP_TABLE 被拒后原配置未改动"
else
	ng "空 ISP_TABLE 被拒后配置被改动"
fi

# BUG-11：历史快照为空时 rollback 必须拒绝，且不能动现有数据
mkdir -p "$TMP/bug11/base/data" "$TMP/bug11/base/.history/20260101-000000"
printf '1.2.3.0/24\n' > "$TMP/bug11/base/data/isp_a.txt"
cat > "$TMP/bug11/conf" <<'CONF11'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
CONF11
if ( PATH="$TMP/bug9:$PATH" ISP_SPLIT_CONF="$TMP/bug11/conf" \
	ISP_SPLIT_BASE="$TMP/bug11/base" BASE="$TMP/bug11/base" \
	export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE BASE
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	cmd_rollback ) >/dev/null 2>&1; then
	ng "空历史快照的 rollback 返回成功（会清空全部集合）"
else
	if [ -s "$TMP/bug11/base/data/isp_a.txt" ]; then
		ok "空历史快照时 rollback 拒绝执行，现有数据未改动"
	else
		ng "空历史快照时 rollback 仍删除了现有数据"
	fi
fi

# BUG-13：sing-box 导出必须是 source 格式对象，而不是裸 JSON 数组
mkdir -p "$TMP/bug13/data"
printf '1.2.3.0/24\n5.6.0.0/16\n' > "$TMP/bug13/data/a.txt"
cat > "$TMP/bug13/conf" <<'CONF13'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
CONF13
_bug13_run() {
	(
		PATH="$TMP/bug9:$PATH"
		ISP_SPLIT_CONF="$TMP/bug13/conf"
		ISP_SPLIT_BASE="$TMP/bug13"
		export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		"$@"
	)
}
if _bug13_run cmd_export singbox "$TMP/bug13/out" >/dev/null 2>&1 &&
   grep -q '"version": 1' "$TMP/bug13/out/isp-a.json" 2>/dev/null &&
   grep -q '"ip_cidr"' "$TMP/bug13/out/isp-a.json" 2>/dev/null &&
   ! head -1 "$TMP/bug13/out/isp-a.json" | grep -qx '\['; then
	ok "sing-box 导出为 source 格式对象（{\"version\":1,\"rules\":[{\"ip_cidr\":[...]}]}）"
else
	ng "sing-box 导出格式仍不是 sing-box 可解析的 source 格式"
fi

# BUG-13b：未知格式要在建目录之前就失败（不留下空目录）
if _bug13_run cmd_export bogus "$TMP/bug13/bogus-dir" >/dev/null 2>&1; then
	ng "未知导出格式返回成功"
elif [ -d "$TMP/bug13/bogus-dir" ]; then
	ng "未知导出格式仍创建了输出目录"
else
	ok "未知导出格式直接失败且不创建目录"
fi

# BUG-14：CRLF 保存的配置不能把运营商行静默丢掉
printf 'ISP_TABLE="\r\nchinatelecom:isp_tel:wan_only:1\r\nunicom_cnc:isp_uni:wanb_only:1\r\n"\r\nDNS_MODE="bind"\r\nDNS_TABLE=""\r\n' \
	> "$TMP/bug9/crlf.conf"
_bug9_n=$(_bug9_run "$TMP/bug9/crlf.conf" conf_get | grep -c '^isp	')
if [ "$_bug9_n" -eq 2 ]; then
	ok "CRLF 配置被正确规范化（2 行运营商均可读）"
else
	ng "CRLF 配置解析异常: 读到 $_bug9_n 行（期望 2）"
fi

echo "== 10. 安全回归（SEC-1 ~ SEC-9）"

# 统一的“跑一个子命令”入口：隔离的 PATH + 独立 BASE/CONF。
_sec_run() {
	(
		PATH="$TMP/fakebin:$PATH"
		ISP_SPLIT_CONF="$1"
		ISP_SPLIT_BASE="$2"
		ISP_SPLIT_CRONTAB="${3:-$TMP/sec/crontabs/root}"
		DNSMASQ_SERVICE=/bin/true
		DNS_RETRY_TRIES=1
		DNS_RETRY_DELAY=0
		MWAN3_READY_TRIES=1
		MWAN3_READY_DELAY=0
		export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_CRONTAB \
			DNSMASQ_SERVICE DNS_RETRY_TRIES DNS_RETRY_DELAY \
			MWAN3_READY_TRIES MWAN3_READY_DELAY
		shift 3 2>/dev/null || true
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		"$@"
	)
}
mkdir -p "$TMP/sec/crontabs"
printf 'ISP_TABLE="a:isp_a:wan_only:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' \
	> "$TMP/cron.conf"

# SEC-1：crontab 中转文件不能跟随符号链接（旧实现写穿到 /tmp/.ispcron 目标）
printf 'SENTINEL\n' > "$TMP/sec/cron-victim"
ln -sf "$TMP/sec/cron-victim" "$TMP/sec/crontabs/root"
printf '0 4 * * * /bin/true # isp-split\n' > "$TMP/sec/other"
if _sec_run "$TMP/cron.conf" "$TMP/sec/base" "$TMP/sec/crontabs/root" \
	_cron_rewrite '17 4 * * * /usr/sbin/isp-split refresh # isp-split' >/dev/null 2>&1; then
	if [ "$(cat "$TMP/sec/cron-victim")" = "SENTINEL" ] &&
		[ ! -L "$TMP/sec/crontabs/root" ] &&
		grep -q 'isp-split refresh' "$TMP/sec/crontabs/root"; then
		ok "crontab 改写不跟随符号链接（SEC-1）"
	else
		ng "crontab 改写仍然写穿了符号链接（SEC-1）"
	fi
else
	ng "_cron_rewrite 执行失败（SEC-1）"
fi

# SEC-2：ISP_CRON 只能是 5 段 cron 时间字段（它会原样进 crontab）
if _sec_run "$TMP/cron.conf" "$TMP/sec/base" "$TMP/sec/crontabs/root" \
	_cron_expr_ok '* * * * * root id > /tmp/x' >/dev/null 2>&1; then
	ng "ISP_CRON 中夹带命令仍被接受（SEC-2）"
elif _sec_run "$TMP/cron.conf" "$TMP/sec/base" "$TMP/sec/crontabs/root" \
	_cron_expr_ok '17 4 * * *' >/dev/null 2>&1; then
	ok "ISP_CRON 只接受 5 段时间字段（SEC-2）"
else
	ng "合法 ISP_CRON 被误判为非法（SEC-2）"
fi

# SEC-3：dnsmasq conf-dir 只接受 root 属主且组/他人不可写的目录，
#        且伪造的 ps 行（参数里带 dnsmasq --conf-dir=...）不能被采信
mkdir -p "$TMP/sec/world" "$TMP/sec/evil/run"
chmod 777 "$TMP/sec/world"
if _sec_run "$TMP/cron.conf" "$TMP/sec/base" "$TMP/sec/crontabs/root" \
	_dns_dir_ok "$TMP/sec/world" >/dev/null 2>&1; then
	ng "组/他人可写的 conf-dir 被当成可信目录（SEC-3）"
else
	ok "组/他人可写的 conf-dir 被拒绝（SEC-3）"
fi
if _sec_run "$TMP/cron.conf" "$TMP/sec/base" "$TMP/sec/crontabs/root" \
	_dns_dir_ok relative/dir >/dev/null 2>&1; then
	ng "相对路径 conf-dir 被接受（SEC-3）"
else
	ok "相对路径 conf-dir 被拒绝（SEC-3）"
fi
cat > "$TMP/sec/fakebin-ps" <<EOF
#!/bin/sh
echo "  999 root 1234 S sh -c sleep 60"
echo "  998 root 1234 S dnsmasq --conf-dir=$TMP/sec/evil"
EOF
chmod +x "$TMP/sec/fakebin-ps"
mkdir -p "$TMP/sec/psbin"
cp "$TMP/sec/fakebin-ps" "$TMP/sec/psbin/ps"
if _sec_detect=$(
	PATH="$TMP/sec/psbin:$TMP/fakebin:$PATH"
	ISP_SPLIT_CONF="$TMP/cron.conf"
	ISP_SPLIT_BASE="$TMP/sec/base"
	DNSMASQ_CONF_GLOB="$TMP/sec/no-such-conf.*"
	DNSMASQ_DEFAULT_DIR="$TMP/sec/default.d"
	export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	_dns_confdir_detect >/dev/null
	printf '%s' "$DNS_CONFDIR_SOURCE"
); then
	if [ "$_sec_detect" = "ps" ]; then
		ng "伪造的 ps 行仍被采信为 dnsmasq conf-dir（SEC-3）"
	else
		ok "伪造的 ps 行不再影响 conf-dir 探测（SEC-3）"
	fi
fi

# SEC-4：只接受 https 镜像；单文件体积有上限
printf 'ISP_TABLE="a:isp_a:wan_only:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\nISP_MIRROR="http://mirror.test"\n' \
	> "$TMP/sec/http.conf"
if _sec_run "$TMP/sec/http.conf" "$TMP/sec/base4" "$TMP/sec/crontabs/root" \
	cmd_fetch >/dev/null 2>&1; then
	ng "明文 HTTP 镜像仍被接受（SEC-4）"
else
	ok "明文 HTTP 镜像被拒绝（SEC-4）"
fi
mkdir -p "$TMP/sec/mirror" "$TMP/sec/secbin"
cat > "$TMP/sec/secbin/uclient-fetch" <<'FAKE_FETCH'
#!/bin/sh
out=""
url=""
while [ $# -gt 0 ]; do
	case "$1" in
	-O) out=$2; shift 2 ;;
	-q) shift ;;
	-T) shift 2 ;;
	*) url=$1; shift ;;
	esac
done
[ -n "$out" ] || exit 1
cp "$SEC_MIRROR/${url##*/}" "$out"
FAKE_FETCH
chmod +x "$TMP/sec/secbin/uclient-fetch"
printf 'https://mirror.test\n' > "$TMP/sec/mirror-url"
printf 'ISP_TABLE="a:isp_a:wan_only:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' > "$TMP/sec/fetch.conf"
awk 'BEGIN { for (i = 0; i < 5000; i++) printf "%01024d\n", i }' > "$TMP/sec/mirror/a.txt"
if SEC_MIRROR="$TMP/sec/mirror" PATH="$TMP/sec/secbin:$PATH" \
	ISP_SPLIT_CONF="$TMP/sec/fetch.conf" ISP_SPLIT_BASE="$TMP/sec/base4" \
	ISP_MIRROR="https://mirror.test" \
	sh "$ROOT/files/usr/sbin/isp-split" fetch >/dev/null 2>&1; then
	ng "超大源文件仍被接受（SEC-4）"
else
	ok "超大源文件被拒绝（SEC-4）"
fi

# SEC-5：分步投毒熔断（总量上限 + 相对上一份的增幅）
printf '1.0.0.0/8\n2.0.0.0/8\n3.0.0.0/8\n4.0.0.0/8\n5.0.0.0/8\n6.0.0.0/8\n' \
	> "$TMP/sec/mirror/a.txt"
_sec_fetch() {
	SEC_MIRROR="$TMP/sec/mirror" PATH="$TMP/sec/secbin:$PATH" \
		ISP_SPLIT_CONF="$TMP/sec/fetch.conf" ISP_SPLIT_BASE="$TMP/sec/base5" \
		ISP_MIRROR="https://mirror.test" \
		sh "$ROOT/files/usr/sbin/isp-split" fetch
}
if _sec_fetch >/dev/null 2>&1 && [ -f "$TMP/sec/base5/data/.sets" ]; then
	ok "首次 fetch 写入 .sets（SEC-5 前置）"
else
	ng "首次 fetch 失败或未写 .sets（SEC-5 前置）"
fi
i=1
: > "$TMP/sec/mirror/a.txt"
while [ $i -le 18 ]; do
	echo "$i.0.0.0/8" >> "$TMP/sec/mirror/a.txt"
	i=$((i + 1))
done
if _sec_fetch >/dev/null 2>&1; then
	ng "地址数翻三倍的更新仍被接受（SEC-5）"
else
	ok "地址数翻三倍的更新被拒绝（SEC-5）"
fi
if ISP_SPLIT_FORCE_FETCH=1 SEC_MIRROR="$TMP/sec/mirror" PATH="$TMP/sec/secbin:$PATH" \
	ISP_SPLIT_CONF="$TMP/sec/fetch.conf" ISP_SPLIT_BASE="$TMP/sec/base5" \
	ISP_MIRROR="https://mirror.test" \
	sh "$ROOT/files/usr/sbin/isp-split" fetch >/dev/null 2>&1; then
	ok "ISP_SPLIT_FORCE_FETCH=1 可显式放行（SEC-5）"
else
	ng "ISP_SPLIT_FORCE_FETCH=1 未生效（SEC-5）"
fi

# SEC-6：读取侧复校验——非法集合名/策略名进不了 nft/uci 参数
printf 'ISP_TABLE="a:isp_a;flushruleset:wan_only:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' \
	> "$TMP/sec/inject.conf"
if _sec_run "$TMP/sec/inject.conf" "$TMP/sec/base6" "$TMP/sec/crontabs/root" \
	cmd_plan >/dev/null 2>&1; then
	ng "非法集合名（含 ;）仍被 cmd_plan 接受（SEC-6）"
else
	ok "非法集合名被读取侧拒绝（SEC-6）"
fi
printf 'ISP_TABLE="a:isp_a:wan_only;id:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' \
	> "$TMP/sec/inject2.conf"
if _sec_run "$TMP/sec/inject2.conf" "$TMP/sec/base6" "$TMP/sec/crontabs/root" \
	cmd_export text "$TMP/sec/export6" >/dev/null 2>&1; then
	ng "非法策略名仍被 cmd_export 接受（SEC-6）"
else
	ok "非法策略名被 cmd_export 拒绝（SEC-6）"
fi

# SEC-7：export 不得写入系统目录；目标位置的符号链接不被跟随
mkdir -p "$TMP/sec/export7/data"
printf '1.2.3.0/24\n' > "$TMP/sec/export7/data/a.txt"
printf 'ISP_TABLE="a:isp_a:wan_only:1"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' \
	> "$TMP/sec/export7/conf"
if _sec_run "$TMP/sec/export7/conf" "$TMP/sec/export7" "$TMP/sec/crontabs/root" \
	cmd_export text /etc/init.d >/dev/null 2>&1; then
	ng "export 仍允许写入 /etc/init.d（SEC-7）"
else
	ok "export 拒绝写入系统目录（SEC-7）"
fi
_mkdir_out=$TMP/sec/export7/out
mkdir -p "$_mkdir_out"
printf 'SENTINEL7\n' > "$TMP/sec/export7/victim.txt"
ln -sf "$TMP/sec/export7/victim.txt" "$_mkdir_out/isp-a.txt"
if _sec_run "$TMP/sec/export7/conf" "$TMP/sec/export7" "$TMP/sec/crontabs/root" \
	cmd_export text "$_mkdir_out" >/dev/null 2>&1 &&
	[ "$(cat "$TMP/sec/export7/victim.txt")" = "SENTINEL7" ] &&
	[ ! -L "$_mkdir_out/isp-a.txt" ]; then
	ok "export 不跟随目标符号链接（SEC-7）"
else
	ng "export 仍会写穿符号链接（SEC-7）"
fi

# SEC-8：表值里的通配符会让 `for row in $ISP_TABLE` 拿文件名当配置行
printf 'ISP_TABLE="a:isp_a:wan_only:1 *"\nDNS_TABLE=""\nDOMAIN_SPLIT=""\nDNS_MODE="bind"\n' \
	> "$TMP/sec/glob.conf"
mkdir -p "$TMP/sec/globcwd"
: > "$TMP/sec/globcwd/attacker:isp_pwn:wan_only:1"
if ( cd "$TMP/sec/globcwd" && ISP_SPLIT_CONF="$TMP/sec/glob.conf" \
	ISP_SPLIT_BASE="$TMP/sec/base8" sh "$ROOT/files/usr/sbin/isp-split" plan ) \
	>/dev/null 2>&1; then
	ng "含通配符的 ISP_TABLE 仍被接受（SEC-8）"
else
	ok "含通配符的 ISP_TABLE 在入口被拒绝（SEC-8）"
fi

# SEC-9：BASE 会被 rm -rf，必须挡住 "/" 与相对路径
if ISP_SPLIT_CONF="$TMP/sec/fetch.conf" ISP_SPLIT_BASE=/ \
	sh "$ROOT/files/usr/sbin/isp-split" status >/dev/null 2>&1; then
	ng "ISP_SPLIT_BASE=/ 仍被接受（SEC-9）"
else
	ok "ISP_SPLIT_BASE=/ 被拒绝（SEC-9）"
fi
if ISP_SPLIT_CONF="$TMP/sec/fetch.conf" ISP_SPLIT_BASE=relative \
	sh "$ROOT/files/usr/sbin/isp-split" status >/dev/null 2>&1; then
	ng "相对路径 ISP_SPLIT_BASE 仍被接受（SEC-9）"
else
	ok "相对路径 ISP_SPLIT_BASE 被拒绝（SEC-9）"
fi

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
