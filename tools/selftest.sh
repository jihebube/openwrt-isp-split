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

# 非 root 环境提示：SEC-3 起 dnsmasq conf-dir 要求属主为 root（_dns_dir_ok
# 校验 uid=0），所以 BUG-6 的「conf-dir 探测」与「卸载清理」2 项在非 root
# 机器上必然失败。这是安全加固的正确行为，不是回归；这 2 项由 root VM 覆盖。
if [ "$(id -u)" -ne 0 ]; then
	echo "提示：当前为非 root 环境，2 项依赖 uid=0 的 conf-dir 用例（BUG-6）预计失败；"
	echo "      属安全加固的正确行为，已由 root 环境（VM）覆盖。其余用例结果不受影响。"
fi

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
_bug78_no=$(printf '%s\n' "$_bug78_out" | grep -c '✗ @isp_')
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
_bug78_no=$(printf '%s\n' "$_bug78_out" | grep -c '✗ @isp_')
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
	ISP_MIRROR="https://mirror.test" ISP_SPLIT_LIB="$LIB" \
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
		ISP_MIRROR="https://mirror.test" ISP_SPLIT_LIB="$LIB" \
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
	ISP_MIRROR="https://mirror.test" ISP_SPLIT_LIB="$LIB" \
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

echo "== 11. OpenClash fake-ip 启动告警（BUG-17）"
# fake-ip 下假 IP（198.18.0.0/15）不在任何运营商集合里，规则静默不命中。
# 用例只检查「是否告警」，不依赖真实 nft/uci。
mkdir -p "$TMP/bug17/fakebin" "$TMP/bug17/base"
cat > "$TMP/bug17/fakebin/uci" <<'FAKE_UCI17'
#!/bin/sh
case "$*" in
*"get openclash.config.en_mode"*)
	printf '%s\n' "${FAKE_OC_MODE:-redir-host}"
	exit 0
	;;
*"get openclash.config.enable"*)
	printf '%s\n' "${FAKE_OC_ENABLE:-1}"
	exit 0
	;;
esac
exit 1
FAKE_UCI17
cat > "$TMP/bug17/fakebin/nft" <<'FAKE_NFT17'
#!/bin/sh
[ "$1" = "-a" ] && shift
case "$*" in
"list table inet mwan3") exit 0 ;;
*"chain inet mwan3 mwan3_rules"*)
	printf 'table inet mwan3 {\n\tchain mwan3_rules {\n'
	printf '\t\tip daddr 10.0.0.0/8 counter jump mwan3_policy_wan_only\n'
	printf '\t}\n}\n'
	exit 0
	;;
esac
exit 1
FAKE_NFT17
chmod +x "$TMP/bug17/fakebin/uci" "$TMP/bug17/fakebin/nft"
cat > "$TMP/bug17/conf" <<'BUG17_CONF'
ISP_TABLE="chinatelecom:isp_tel:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
COUNT_FALLBACK="0"
BUG17_CONF

_bug17_run() {
	_b17_mode=$1
	_b17_en=$2
	shift 2
	(
		PATH="$TMP/bug17/fakebin:$PATH"
		ISP_SPLIT_CONF="$TMP/bug17/conf"
		ISP_SPLIT_BASE="$TMP/bug17/base"
		DNSMASQ_CONF_GLOB="$TMP/bug17/no-such-conf.*"
		DNSMASQ_DEFAULT_DIR="$TMP/bug17/default.d"
		FAKE_OC_MODE="$_b17_mode"
		FAKE_OC_ENABLE="$_b17_en"
		export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE DNSMASQ_CONF_GLOB \
			DNSMASQ_DEFAULT_DIR FAKE_OC_MODE FAKE_OC_ENABLE
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		"$@"
	)
}

_b17_warn='检测到 OpenClash fake-ip 模式'

# 三个只读命令都必须在首行告警（status 的告警在表头之前）
_b17_out=$(_bug17_run fake-ip 1 cmd_plan 2>&1)
if printf '%s\n' "$_b17_out" | head -1 | grep -q "$_b17_warn"; then
	ok "fake-ip 下 plan 首行告警"
else
	ng "fake-ip 下 plan 未告警"
	printf '%s\n' "$_b17_out" | sed 's/^/    /'
fi

_b17_out=$(_bug17_run fake-ip 1 cmd_verify 2>&1)
if printf '%s\n' "$_b17_out" | head -1 | grep -q "$_b17_warn"; then
	ok "fake-ip 下 verify 首行告警"
else
	ng "fake-ip 下 verify 未告警"
	printf '%s\n' "$_b17_out" | sed 's/^/    /'
fi

_b17_out=$(_bug17_run fake-ip 1 cmd_status 2>&1)
if printf '%s\n' "$_b17_out" | head -1 | grep -q "$_b17_warn"; then
	ok "fake-ip 下 status 首行告警"
else
	ng "fake-ip 下 status 未告警"
	printf '%s\n' "$_b17_out" | sed 's/^/    /'
fi

# status --json 的 stdout 必须仍是纯 JSON（LuCI 直接解析），告警只能走 stderr
_b17_json=$(_bug17_run fake-ip 1 cmd_status --json 2>/dev/null)
_b17_json_err=$(_bug17_run fake-ip 1 cmd_status --json 2>&1 >/dev/null)
if printf '%s' "$_b17_json" | grep -q '^\[' &&
	! printf '%s' "$_b17_json" | grep -q "$_b17_warn" &&
	printf '%s\n' "$_b17_json_err" | grep -q "$_b17_warn"; then
	ok "status --json 的 stdout 仍为纯 JSON，告警走 stderr"
else
	ng "status --json 被告警污染或未告警"
	printf '    stdout: %s\n    stderr: %s\n' "$_b17_json" "$_b17_json_err"
fi

# redir-host 是正常模式，三个命令都不该出现告警
_b17_quiet=1
for _b17_c in cmd_plan cmd_verify cmd_status; do
	_b17_out=$(_bug17_run redir-host 1 "$_b17_c" 2>&1)
	printf '%s\n' "$_b17_out" | grep -q "$_b17_warn" && _b17_quiet=0
done
if [ "$_b17_quiet" -eq 1 ]; then
	ok "redir-host 下 plan/verify/status 均不告警"
else
	ng "redir-host 下出现误告警"
fi

# en_mode 的变体写法（fakeip，无连字符）同样要识别
_b17_out=$(_bug17_run fakeip 1 cmd_plan 2>&1)
if printf '%s\n' "$_b17_out" | grep -q "$_b17_warn"; then
	ok "en_mode=fakeip（无连字符）同样告警"
else
	ng "en_mode=fakeip 未被识别"
fi

# OpenClash 未启用（enable=0）时不告警：模式值残留不代表正在生效
_b17_out=$(_bug17_run fake-ip 0 cmd_plan 2>&1)
if ! printf '%s\n' "$_b17_out" | grep -q "$_b17_warn"; then
	ok "OpenClash enable=0 时不告警"
else
	ng "OpenClash 未启用仍告警"
fi

echo "== 12. 多数据源管线（0.2.1 默认双源）"
# 目标：证明"默认双源"在不破坏老配置的前提下工作
#   1. 老配置（没有 ISP_SOURCES）行为与 0.1.x 完全一致
#   2. 0.2.1 默认模板：yfgao 主源 + clang 校验 + ISP_VERIFY_ENABLE=1 自动生效
#   3. 用户改 ISP_SOURCES 后，sources.tsv 里旧源（如单源时代的 ispip）被清理
#   4. 双源正常：diff 通过，数据更新，存档落盘
#   5. 校验源挂：降级继续（退出 0），连续 3 天失败后升级为拒绝（退出 3）
#   6. 分歧超阈值：拒绝更新（退出 3）+ quarantine 留档 + 旧数据不动
#   7. 主源挂：冻结（非 0 退出），旧数据不动
# 全部离线：用假 uclient-fetch 把 URL 映射到 tools/fixtures/multisource。

MS=$TMP/ms
mkdir -p "$MS/bin" "$MS/mirror/ispip.clang.cn" "$MS/mirror/china-operator-ip.yfgao.com"
# BUG-25 起 plan 会预检策略成员；section 12 只关心数据源部分，给一组
# 最小可用的假 uci，避免把“VM 上有没有 mwan3 策略”混进数据管线用例。
cat > "$MS/bin/uci" <<'MS_UCI'
#!/bin/sh
case "$*" in
*"get mwan3.wan_only.use_member"*) echo ms_wan; exit 0 ;;
*"get mwan3.wanb_only.use_member"*) echo ms_wanb; exit 0 ;;
*"get mwan3.ms_wan.interface"*) echo wan1; exit 0 ;;
*"get mwan3.ms_wanb.interface"*) echo wan2; exit 0 ;;
*"get mwan3.ms_wan"* | *"get mwan3.ms_wanb"*) echo member; exit 0 ;;
*"get mwan3.wan1"* | *"get mwan3.wan2"*) echo interface; exit 0 ;;
*"get mwan3.wan_only"* | *"get mwan3.wanb_only"*) echo policy; exit 0 ;;
esac
exit 1
MS_UCI
chmod +x "$MS/bin/uci"
cat > "$MS/bin/uclient-fetch" <<'MS_FETCH'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
	case "$1" in
	-O) out=$2; shift 2 ;;
	-q) shift ;;
	-T) shift 2 ;;
	*) url=$1; shift ;;
	esac
done
[ -n "$out" ] || exit 1
rel=$(printf '%s' "$url" | sed 's|^https\?://||')
[ -f "$MS_MIRROR/$rel" ] || exit 1
cp "$MS_MIRROR/$rel" "$out"
MS_FETCH
chmod +x "$MS/bin/uclient-fetch"

cp "$FIX/multisource/clang/chinatelecom.txt" "$MS/mirror/ispip.clang.cn/chinatelecom.txt"
cp "$FIX/multisource/clang/unicom_cnc.txt" "$MS/mirror/ispip.clang.cn/unicom_cnc.txt"
cp "$FIX/multisource/clang/cmcc.txt" "$MS/mirror/ispip.clang.cn/cmcc.txt"
cp "$FIX/multisource/clang/cernet.txt" "$MS/mirror/ispip.clang.cn/cernet.txt"
cp "$FIX/multisource/yfgao/chinanet.txt" "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
cp "$FIX/multisource/yfgao/unicom.txt" "$MS/mirror/china-operator-ip.yfgao.com/unicom.txt"
cp "$FIX/multisource/yfgao/cmcc.txt" "$MS/mirror/china-operator-ip.yfgao.com/cmcc.txt"
cp "$FIX/multisource/yfgao/cernet.txt" "$MS/mirror/china-operator-ip.yfgao.com/cernet.txt"

cat > "$MS/ms.conf" <<'MS_CONF'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_MIRROR="https://ispip.clang.cn"
ISP_SOURCES="
clang:primary:https://ispip.clang.cn
yfgao:verify:https://china-operator-ip.yfgao.com
"
ISP_SOURCE_FILES="
clang:chinatelecom=chinatelecom,unicom_cnc=unicom_cnc
yfgao:chinatelecom=chinanet,unicom_cnc=unicom
"
ISP_VERIFY_ENABLE=1
MS_CONF

# 老配置：没有 ISP_SOURCES / ISP_SOURCE_FILES / ISP_VERIFY_ENABLE
cat > "$MS/legacy.conf" <<'MS_LEGACY'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_MIRROR="https://ispip.clang.cn"
MS_LEGACY

# 非法角色：只能在 primary/verify/audit 里选
cat > "$MS/badrole.conf" <<'MS_BADROLE'
ISP_TABLE="chinatelecom:isp_tel:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_MIRROR="https://ispip.clang.cn"
ISP_SOURCES="
clang:primary:https://ispip.clang.cn
yfgao:mirror:https://china-operator-ip.yfgao.com
"
MS_BADROLE

_ms_run() {
	_ms_conf=$1
	_ms_base=$2
	shift 2
	(
		PATH="$MS/bin:$PATH"
		MS_MIRROR="$MS/mirror"
		ISP_SPLIT_CONF="$_ms_conf"
		ISP_SPLIT_BASE="$_ms_base"
		ISP_SPLIT_LIB="$LIB"
		export PATH MS_MIRROR ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
		sh "$ROOT/files/usr/sbin/isp-split" "$@"
	)
}

# --- 12.1 双源正常 ---
rm -rf "$MS/base-ok"
if _ms_run "$MS/ms.conf" "$MS/base-ok" fetch >"$MS/ok.log" 2>&1 &&
	[ -s "$MS/base-ok/data/chinatelecom.txt" ] &&
	[ "$(wc -l < "$MS/base-ok/data/chinatelecom.txt" | tr -d ' ')" = "6" ]; then
	ok "双源正常：主源出数据、集合构建成功"
else
	ng "双源正常流程失败"
	sed 's/^/    /' "$MS/ok.log"
fi

if grep -q '^yfgao	verify	[0-9]*	0	100.00' "$MS/base-ok/state/sources.tsv" 2>/dev/null; then
	ok "双源正常：Jaccard=100% 记入 state/sources.tsv"
else
	ng "state/sources.tsv 未记录 Jaccard"
	sed 's/^/    /' "$MS/base-ok/state/sources.tsv" 2>/dev/null
fi

if [ -f "$MS/base-ok/raw/clang/chinatelecom.txt" ] &&
	[ -f "$MS/base-ok/raw/yfgao/chinanet.txt" ]; then
	ok "双源正常：两源 raw 存档各自独立（raw/<源名>/）"
else
	ng "两源 raw 存档缺失"
	find "$MS/base-ok/raw" -type f 2>/dev/null | sed 's/^/    /'
fi

if _ms_run "$MS/ms.conf" "$MS/base-ok" diff >"$MS/diff.log" 2>&1; then
	ok "diff 子命令基于存档可重算且不误报（退出 0）"
else
	ng "diff 子命令对一致数据返回非 0"
	sed 's/^/    /' "$MS/diff.log"
fi

# --- 12.2 0.2.1 默认模板：主源 yfgao + 校验自动启用 ---
# 直接使用仓库里的 files/etc/isp-split.conf（含完整 10 行 ISP_TABLE），
# 验证模板本身能跑通：4 类启用运营商全部映射，另外 6 类未映射且关闭应被跳过。
cp "$ROOT/files/etc/isp-split.conf" "$MS/default.conf"

if grep -q '^yfgao:primary:' "$ROOT/files/etc/isp-split.conf" &&
	grep -q '^clang:verify:' "$ROOT/files/etc/isp-split.conf" &&
	grep -q '^ISP_VERIFY_ENABLE=1' "$ROOT/files/etc/isp-split.conf"; then
	ok "0.2.1 默认模板：yfgao 主源 + clang 校验 + 校验默认开启"
else
	ng "0.2.1 默认模板的源声明/开关不正确"
fi

rm -rf "$MS/base-default"
if _ms_run "$MS/default.conf" "$MS/base-default" fetch >"$MS/default.log" 2>&1 &&
	[ -s "$MS/base-default/data/chinatelecom.txt" ] &&
	[ -s "$MS/base-default/data/cernet.txt" ] &&
	[ -d "$MS/base-default/raw/clang" ]; then
	ok "默认模板直接可跑：4 类启用运营商全部映射，校验源自动参与 diff"
else
	ng "默认模板 fetch 失败或未自动启用校验"
	sed 's/^/    /' "$MS/default.log" 2>/dev/null
fi

if _ms_run "$MS/default.conf" "$MS/base-default" health --json 2>/dev/null |
	grep -q '"verify_enabled":true' &&
	_ms_run "$MS/default.conf" "$MS/base-default" health --json 2>/dev/null |
	grep -q '"name":"clang","label":"clang","role":"verify".*"status":"ok"'; then
	ok "默认模板的 health --json 标出 verify_enabled=true / clang 正常"
else
	ng "默认模板的 health --json 未标出校验已启用"
	_ms_run "$MS/default.conf" "$MS/base-default" health --json 2>&1 |
		sed 's/^/    /'
fi

# --- 12.3 sources.tsv 残留清理（单源 -> 双源切换） ---
# 先用老配置跑一次，留下单源时代的 ispip 行；再切到双源，旧行必须消失。
rm -rf "$MS/base-stale"
_ms_run "$MS/legacy.conf" "$MS/base-stale" fetch >/dev/null 2>&1
if grep -q '^ispip	' "$MS/base-stale/state/sources.tsv" 2>/dev/null; then
	ok "残留清理前置：单源 fetch 写入 ispip 行"
else
	ng "残留清理前置失败：sources.tsv 里没有 ispip"
fi
if _ms_run "$MS/ms.conf" "$MS/base-stale" fetch >"$MS/stale.log" 2>&1; then
	if grep -q '^ispip	' "$MS/base-stale/state/sources.tsv" 2>/dev/null; then
		ng "切到双源后 ispip 残留仍在 sources.tsv"
	else
		ok "切到双源后 sources.tsv 的 ispip 残留被清理"
	fi
else
	ng "残留清理场景的 fetch 失败"
	sed 's/^/    /' "$MS/stale.log" 2>/dev/null
fi

# 再手动塞一条已不在配置里的源，确认 status/health 读路径也会清掉它。
printf 'oldisp\tprimary\t1700000000\t2\t\tstale\n' \
	>> "$MS/base-stale/state/sources.tsv"
_ms_stale_json=$(_ms_run "$MS/ms.conf" "$MS/base-stale" health --json 2>/dev/null)
if printf '%s' "$_ms_stale_json" | grep -q '"name":"oldisp"' ||
	grep -q '^oldisp	' "$MS/base-stale/state/sources.tsv" 2>/dev/null; then
	ng "health 读路径未清理 stale 源 oldisp"
else
	ok "health 读路径清理 stale 源，且不再显示"
fi
if grep -q '^yfgao	' "$MS/base-stale/state/sources.tsv" 2>/dev/null &&
	grep -q '^clang	' "$MS/base-stale/state/sources.tsv" 2>/dev/null; then
	ok "残留清理保留当前声明的 yfgao/clang 行"
else
	ng "残留清理误删了当前源"
	sed 's/^/    /' "$MS/base-stale/state/sources.tsv" 2>/dev/null
fi

# --- 12.4 老配置单源兼容（必须与 0.1.x 一致） ---
rm -rf "$MS/base-legacy"
if _ms_run "$MS/legacy.conf" "$MS/base-legacy" fetch >"$MS/legacy.log" 2>&1 &&
	[ -s "$MS/base-legacy/data/chinatelecom.txt" ] &&
	[ -d "$MS/base-legacy/raw/ispip" ] &&
	[ ! -d "$MS/base-legacy/raw/yfgao" ]; then
	ok "老配置（无 ISP_SOURCES）单源行为不变，且不触发多源路径"
else
	ng "老配置兼容性被破坏"
	sed 's/^/    /' "$MS/legacy.log" 2>/dev/null
	find "$MS/base-legacy" -maxdepth 2 2>/dev/null | sed 's/^/    /'
fi

if _ms_run "$MS/legacy.conf" "$MS/base-legacy" health --json 2>/dev/null |
	grep -q '"name":"ispip"'; then
	ok "老配置在源健康度里显示为单源 ispip"
else
	ng "老配置的源健康度未显示 ispip"
fi

# --- 12.5 校验源挂：降级继续 ---
rm -f "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
rm -rf "$MS/base-degrade"
_ms_run "$MS/ms.conf" "$MS/base-degrade" fetch >"$MS/degrade.log" 2>&1
_ms_rc=$?
if [ "$_ms_rc" -eq 0 ] && [ -s "$MS/base-degrade/data/chinatelecom.txt" ]; then
	ok "校验源不可用：仍用主源更新（退出 0，降级）"
else
	ng "校验源不可用导致更新失败（退出 $_ms_rc，应降级为 0）"
	sed 's/^/    /' "$MS/degrade.log"
fi
if _ms_run "$MS/ms.conf" "$MS/base-degrade" health --json 2>/dev/null |
	grep -q '"status":"degraded"'; then
	ok "校验源降级状态出现在 health --json"
else
	ng "health --json 未标出降级"
	_ms_run "$MS/ms.conf" "$MS/base-degrade" health --json 2>&1 | sed 's/^/    /'
fi
if _ms_run "$MS/ms.conf" "$MS/base-degrade" plan 2>/dev/null |
	grep -q '数据源健康度'; then
	ok "plan 输出包含"数据源健康度"区块"
else
	ng "plan 未输出数据源健康度"
fi

# --- 12.6 连续失败达到上限：升级为拒绝更新 ---
_ms_run "$MS/ms.conf" "$MS/base-degrade" fetch >/dev/null 2>&1
_ms_run "$MS/ms.conf" "$MS/base-degrade" fetch >/dev/null 2>&1
if _ms_run "$MS/ms.conf" "$MS/base-degrade" fetch >"$MS/escalate.log" 2>&1; then
	ng "校验源连续失败 3 天仍未拒绝更新"
else
	_ms_rc=$?
	if [ "$_ms_rc" -eq 3 ]; then
		ok "校验源连续失败达上限后拒绝更新（退出 3）"
	else
		ng "连续失败后的退出码是 $_ms_rc（期望 3）"
		sed 's/^/    /' "$MS/escalate.log"
	fi
fi

# --- 12.7 分歧超阈值：拒绝 + quarantine 留档 + 旧数据不动 ---
cp "$FIX/multisource/yfgao-drift/chinanet.txt" "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
cp "$FIX/multisource/yfgao/unicom.txt" "$MS/mirror/china-operator-ip.yfgao.com/unicom.txt"
rm -rf "$MS/base-drift"
# 先建立一份正常数据，再让校验源漂移
cp "$FIX/multisource/yfgao/chinanet.txt" "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
_ms_run "$MS/ms.conf" "$MS/base-drift" fetch >/dev/null 2>&1
_ms_before=$(cat "$MS/base-drift/data/chinatelecom.txt" 2>/dev/null | md5sum | awk '{print $1}')
cp "$FIX/multisource/yfgao-drift/chinanet.txt" "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
if _ms_run "$MS/ms.conf" "$MS/base-drift" fetch >"$MS/drift.log" 2>&1; then
	ng "分歧超阈值仍被接受（应退出 3）"
else
	_ms_rc=$?
	if [ "$_ms_rc" -eq 3 ]; then
		ok "分歧超阈值拒绝更新（退出 3）"
	else
		ng "分歧超阈值的退出码是 $_ms_rc（期望 3）"
	fi
fi
_ms_after=$(cat "$MS/base-drift/data/chinatelecom.txt" 2>/dev/null | md5sum | awk '{print $1}')
if [ "$_ms_before" = "$_ms_after" ]; then
	ok "拒绝更新时旧数据未被改动"
else
	ng "拒绝更新后数据被改动"
fi
if find "$MS/base-drift/quarantine" -name '*.only-verify.txt' 2>/dev/null |
	grep -q . &&
	grep -rq '100.0.0.0/24' "$MS/base-drift/quarantine" 2>/dev/null; then
	ok "差异段写入 quarantine/<日期>/（含 100.0.0.0/24）"
else
	ng "quarantine 未留下差异段"
	find "$MS/base-drift/quarantine" -type f 2>/dev/null | sed 's/^/    /'
fi

# --- 12.8 主源不可用：冻结，旧数据不动 ---
rm -rf "$MS/base-freeze"
cp "$FIX/multisource/yfgao/chinanet.txt" "$MS/mirror/china-operator-ip.yfgao.com/chinanet.txt"
_ms_run "$MS/ms.conf" "$MS/base-freeze" fetch >/dev/null 2>&1
_ms_before=$(cat "$MS/base-freeze/data/chinatelecom.txt" 2>/dev/null | md5sum | awk '{print $1}')
mv "$MS/mirror/ispip.clang.cn/chinatelecom.txt" "$MS/mirror/ispip.clang.cn/.hidden"
if _ms_run "$MS/ms.conf" "$MS/base-freeze" fetch >"$MS/freeze.log" 2>&1; then
	ng "主源不可用时仍返回成功"
else
	ok "主源不可用时冻结并返回非 0"
fi
mv "$MS/mirror/ispip.clang.cn/.hidden" "$MS/mirror/ispip.clang.cn/chinatelecom.txt"
_ms_after=$(cat "$MS/base-freeze/data/chinatelecom.txt" 2>/dev/null | md5sum | awk '{print $1}')
if [ "$_ms_before" = "$_ms_after" ]; then
	ok "主源失败时旧数据未被改动"
else
	ng "主源失败后数据被改动"
fi

# --- 12.9 非法源角色被拒绝 ---
if _ms_run "$MS/badrole.conf" "$MS/base-bad" fetch >/dev/null 2>&1; then
	ng "非法源角色（mirror）仍被接受"
else
	ok "非法源角色被拒绝"
fi

echo "== 13. 兜底计数默认排除 DNS（BUG-21）"
# 真 nft 不接受一条规则里同时出现 udp dport 和 tcp dport，所以排除 DNS
# 必须拆两条：非 tcp/udp（保留 ICMP 等）+ tcp/udp 且 dport/sport 都不是 53。
# DNS 查询 dport=53、DNS 响应 sport=53，两侧都要排除，否则响应包会漏进
# 兜底计数（BUG-21 第一版只排 dport 的残留问题）。
# 这里用假 nft 检查 _fallback_counter 实际下发的规则形状和幂等重建路径；
# 13.8 在 root + 本机 DNS 可用时用真 nft 做一次查询/响应语义验证。
FB=$TMP/fb
mkdir -p "$FB/bin"
cat > "$FB/bin/nft" <<'FAKE_FB_NFT'
#!/bin/sh
S=${FAKE_FB_STATE:?}
mkdir -p "$S"
[ -f "$S/rules" ] || : > "$S/rules"
log() { echo "$*" >> "$S/log"; }
next_h() {
	h=$(cat "$S/hnext" 2>/dev/null || echo 100)
	h=$((h + 1))
	echo "$h" > "$S/hnext"
	echo "$h"
}
[ "$1" = "-a" ] && shift
cmd=$1; shift
case "$cmd" in
list)
	case "$*" in
	*"counter inet mwan3 isp_fallback"*) exit 0 ;;
	*"chain inet mwan3 mwan3_rules"*)
		echo "table inet mwan3 {"
		echo "	chain mwan3_rules {"
		sed 's/^/		/' "$S/rules"
		echo "	}"
		echo "}"
		exit 0
		;;
	*) exit 1 ;;
	esac
	;;
add)
	log "add $*"
	case "$1" in
	counter) exit 0 ;;
	rule)
		shift 4 # rule inet mwan3 mwan3_rules
		h=$(next_h)
		printf '%s # handle %s\n' "$*" "$h" >> "$S/rules"
		exit 0
		;;
	esac
	exit 1
	;;
insert)
	log "insert $*"
	shift 4
	[ "${1:-}" = "position" ] || exit 1
	pos=$2
	shift 2
	h=$(next_h)
	awk -v pos="$pos" -v line="$* # handle $h" '
		$0 ~ ("# handle " pos "$") { print line }
		{ print }
	' "$S/rules" > "$S/rules.new" && mv "$S/rules.new" "$S/rules"
	exit 0
	;;
delete)
	log "delete $*"
	h=""
	for a in "$@"; do h=$a; done
	awk -v h="$h" '$0 !~ ("# handle " h "$")' "$S/rules" > "$S/rules.new" &&
		mv "$S/rules.new" "$S/rules"
	exit 0
	;;
esac
exit 1
FAKE_FB_NFT
chmod +x "$FB/bin/nft"

cat > "$TMP/fb.conf" <<'FB_CONF'
COUNT_FALLBACK="1"
FB_CONF
cat > "$TMP/fb0.conf" <<'FB0_CONF'
COUNT_FALLBACK="1"
COUNT_FALLBACK_SKIP_DNS="0"
FB0_CONF

fb_state() {
	rm -rf "$1"
	mkdir -p "$1"
	: > "$1/rules"
	: > "$1/log"
}
fb_run() {
	(
		PATH="$FB/bin:$PATH"
		FAKE_FB_STATE="$1"
		ISP_SPLIT_CONF="$2"
		export PATH FAKE_FB_STATE ISP_SPLIT_CONF
		. "$TMP/isp-lib.sh"
		_fallback_counter
	)
}

# --- 13.1 默认（skip=1）：插到锚点前，两条规则形状正确 ---
fb_state "$FB/s1"
cat > "$FB/s1/rules" <<'FB_RULES'
ip daddr @isp_tel meta mark & 0x00003f00 == 0x00000000 jump mwan3_policy_wan_only # handle 1
tcp dport 443 jump mwan3_policy_wan_only # handle 2
FB_RULES
if fb_run "$FB/s1" "$TMP/fb.conf" >/dev/null 2>&1; then
	_fb_other=$(grep -c 'meta l4proto != tcp meta l4proto != udp counter name "isp_fallback"' "$FB/s1/log" 2>/dev/null || true)
	_fb_dns=$(grep -c 'meta l4proto { tcp, udp } th dport != 53 th sport != 53 counter name "isp_fallback"' "$FB/s1/log" 2>/dev/null || true)
	_fb_pos=$(grep -c '^insert .*position 2 ' "$FB/s1/log" 2>/dev/null || true)
	_fb_n=$(grep -c 'counter name "isp_fallback"' "$FB/s1/rules" 2>/dev/null || true)
	if [ "${_fb_other:-0}" -eq 1 ] && [ "${_fb_dns:-0}" -eq 1 ] &&
	   [ "${_fb_pos:-0}" -eq 2 ] && [ "${_fb_n:-0}" -eq 2 ] &&
	   sed -n '2p' "$FB/s1/rules" | grep -q 'meta l4proto != tcp' &&
	   sed -n '3p' "$FB/s1/rules" | grep -q 'th dport != 53' &&
	   sed -n '3p' "$FB/s1/rules" | grep -q 'th sport != 53' &&
	   sed -n '2p' "$FB/s1/rules" | grep -q 'ct state new' &&
	   sed -n '3p' "$FB/s1/rules" | grep -q 'ct state new'; then
		ok "默认排除 DNS：插在锚点前，两条规则形状正确且相邻（双侧 53 + ct state new）"
	else
		ng "默认排除 DNS 的规则形状异常（other=$_fb_other dns=$_fb_dns pos=$_fb_pos n=$_fb_n）"
		sed 's/^/    /' "$FB/s1/log"
	fi
else
	ng "默认配置下 _fallback_counter 调用失败"
fi

# --- 13.2 skip=0：保持单条旧形状（无 l4proto / 无 dport） ---
fb_state "$FB/s2"
if fb_run "$FB/s2" "$TMP/fb0.conf" >/dev/null 2>&1; then
	_fb_add=$(grep -c '^add rule' "$FB/s2/log" 2>/dev/null || true)
	if [ "${_fb_add:-0}" -eq 1 ] &&
	   grep -q 'meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new counter name "isp_fallback"' "$FB/s2/rules" &&
	   ! grep -qE 'meta l4proto|dport != 53|sport != 53' "$FB/s2/rules"; then
		ok "COUNT_FALLBACK_SKIP_DNS=0 保持单条形状（不排除 DNS，但仍只计首包）"
	else
		ng "COUNT_FALLBACK_SKIP_DNS=0 的规则形状不是旧形状"
		sed 's/^/    /' "$FB/s2/log"
	fi
else
	ng "COUNT_FALLBACK_SKIP_DNS=0 时 _fallback_counter 调用失败"
fi

# --- 13.3 旧规则 + 默认配置：必须重建为两条新规则 ---
fb_state "$FB/s3"
echo 'meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 counter name "isp_fallback" # handle 1' > "$FB/s3/rules"
if fb_run "$FB/s3" "$TMP/fb.conf" >/dev/null 2>&1; then
	_fb_del=$(grep -c '^delete ' "$FB/s3/log" 2>/dev/null || true)
	_fb_add=$(grep -c '^add rule' "$FB/s3/log" 2>/dev/null || true)
	_fb_n=$(grep -c 'counter name "isp_fallback"' "$FB/s3/rules" 2>/dev/null || true)
	if [ "${_fb_del:-0}" -eq 1 ] && [ "${_fb_add:-0}" -eq 2 ] && [ "${_fb_n:-0}" -eq 2 ] &&
	   grep -q 'th dport != 53' "$FB/s3/rules" &&
	   grep -q 'th sport != 53' "$FB/s3/rules" &&
	   [ "$(grep -c 'ct state new' "$FB/s3/rules")" -eq 2 ]; then
		ok "旧单条规则在默认配置下重建为两条新规则（含 ct state new）"
	else
		ng "旧规则重建异常（delete=$_fb_del add=$_fb_add n=$_fb_n）"
	fi
else
	ng "旧规则重建时 _fallback_counter 调用失败"
fi

# --- 13.4 新规则 + 默认配置：幂等，不重复插入 ---
fb_state "$FB/s4"
cat > "$FB/s4/rules" <<'FB_NEW_RULES'
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto != tcp meta l4proto != udp counter name "isp_fallback" # handle 1
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto { tcp, udp } th dport != 53 th sport != 53 counter name "isp_fallback" # handle 2
FB_NEW_RULES
if fb_run "$FB/s4" "$TMP/fb.conf" >/dev/null 2>&1; then
	if [ ! -s "$FB/s4/log" ] &&
	   [ "$(grep -c 'counter name "isp_fallback"' "$FB/s4/rules")" -eq 2 ]; then
		ok "新规则形状已存在时幂等（无 delete/insert/add）"
	else
		ng "新规则幂等失败（日志非空或规则数不是 2）"
		sed 's/^/    /' "$FB/s4/log"
	fi
else
	ng "新规则幂等检查时 _fallback_counter 调用失败"
fi

# --- 13.5 新规则 + skip=0：切回旧形状 ---
fb_state "$FB/s5"
cp "$FB/s4/rules" "$FB/s5/rules"
if fb_run "$FB/s5" "$TMP/fb0.conf" >/dev/null 2>&1; then
	_fb_del=$(grep -c '^delete ' "$FB/s5/log" 2>/dev/null || true)
	_fb_n=$(grep -c 'counter name "isp_fallback"' "$FB/s5/rules" 2>/dev/null || true)
	if [ "${_fb_del:-0}" -eq 2 ] && [ "${_fb_n:-0}" -eq 1 ] &&
	   ! grep -qE 'meta l4proto|dport != 53|sport != 53' "$FB/s5/rules" &&
	   grep -q 'ct state new' "$FB/s5/rules"; then
		ok "COUNT_FALLBACK_SKIP_DNS=0 时两条新规则切回单条形状（仍保留 ct state new）"
	else
		ng "切回旧形状异常（delete=$_fb_del n=$_fb_n）"
	fi
else
	ng "切回旧形状时 _fallback_counter 调用失败"
fi

# --- 13.6 BUG-21 半修形状（只排 dport 53）：必须重建为双侧排除 ---
# 这是上一轮遗留问题的回归用例：旧规则只带 th dport != 53，
# DNS 响应包（sport=53）仍会被计入。
fb_state "$FB/s6"
cat > "$FB/s6/rules" <<'FB_HALF_RULES'
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 meta l4proto != tcp meta l4proto != udp counter name "isp_fallback" # handle 1
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 meta l4proto { tcp, udp } th dport != 53 counter name "isp_fallback" # handle 2
FB_HALF_RULES
if fb_run "$FB/s6" "$TMP/fb.conf" >/dev/null 2>&1; then
	_fb_del=$(grep -c '^delete ' "$FB/s6/log" 2>/dev/null || true)
	_fb_add=$(grep -c '^add rule' "$FB/s6/log" 2>/dev/null || true)
	_fb_n=$(grep -c 'counter name "isp_fallback"' "$FB/s6/rules" 2>/dev/null || true)
	if [ "${_fb_del:-0}" -eq 2 ] && [ "${_fb_add:-0}" -eq 2 ] && [ "${_fb_n:-0}" -eq 2 ] &&
	   grep -q 'th dport != 53' "$FB/s6/rules" &&
	   grep -q 'th sport != 53' "$FB/s6/rules" &&
	   [ "$(grep -c 'ct state new' "$FB/s6/rules")" -eq 2 ]; then
		ok "半修形状（只排 dport 53）在默认配置下重建为双侧排除 + ct state new"
	else
		ng "半修形状未被重建（delete=$_fb_del add=$_fb_add n=$_fb_n）"
	fi
else
	ng "半修形状重建时 _fallback_counter 调用失败"
fi

# --- 13.7 nft 渲染顺序颠倒（sport 在 dport 前）时仍幂等 ---
# 不能因为 nft 归一化顺序不同就每次 apply 都重建规则。
fb_state "$FB/s7"
cat > "$FB/s7/rules" <<'FB_REV_RULES'
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto != tcp meta l4proto != udp counter name "isp_fallback" # handle 1
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto { tcp, udp } th sport != 53 th dport != 53 counter name "isp_fallback" # handle 2
FB_REV_RULES
if fb_run "$FB/s7" "$TMP/fb.conf" >/dev/null 2>&1; then
	if [ ! -s "$FB/s7/log" ] &&
	   [ "$(grep -c 'counter name "isp_fallback"' "$FB/s7/rules")" -eq 2 ]; then
		ok "dport/sport 条件顺序颠倒时形状检查仍通过（幂等，无重建）"
	else
		ng "条件顺序颠倒导致误判并重建"
		sed 's/^/    /' "$FB/s7/log"
	fi
else
	ng "条件顺序颠倒时 _fallback_counter 调用失败"
fi

# --- 13.8 真 nft 语义：DNS 查询与响应都不进兜底（root + 本机 DNS 时） ---
# 在独立表里复刻计数条件，用 nslookup 触发一次真实 UDP 查询+响应：
# 出向 udp dport 53 与入向 udp sport 53 各有一个直接计数器，
# 另有一对 dport/sport 双侧排除计数器；期望直接计数 >0、排除计数 =0。
# 非 root / 无 nft / 本机无 DNS 时跳过，不影响离线用例。
_nft_bin=$(command -v nft 2>/dev/null || true)
if [ "$(id -u)" -eq 0 ] && [ -n "$_nft_bin" ] && command -v nslookup >/dev/null 2>&1; then
	FB_T=selftest_fb_dns
	"$_nft_bin" delete table inet "$FB_T" >/dev/null 2>&1 || true
	if "$_nft_bin" add table inet "$FB_T" >/dev/null 2>&1 &&
	   "$_nft_bin" add chain inet "$FB_T" out '{ type filter hook output priority 0; }' >/dev/null 2>&1 &&
	   "$_nft_bin" add chain inet "$FB_T" in '{ type filter hook input priority 0; }' >/dev/null 2>&1 &&
	   "$_nft_bin" add counter inet "$FB_T" q >/dev/null 2>&1 &&
	   "$_nft_bin" add counter inet "$FB_T" qe >/dev/null 2>&1 &&
	   "$_nft_bin" add counter inet "$FB_T" r >/dev/null 2>&1 &&
	   "$_nft_bin" add counter inet "$FB_T" re >/dev/null 2>&1 &&
	   "$_nft_bin" add rule inet "$FB_T" out oif lo udp dport 53 counter name q >/dev/null 2>&1 &&
	   "$_nft_bin" add rule inet "$FB_T" out oif lo meta l4proto '{ tcp, udp }' th dport != 53 th sport != 53 counter name qe >/dev/null 2>&1 &&
	   "$_nft_bin" add rule inet "$FB_T" in iif lo udp sport 53 counter name r >/dev/null 2>&1 &&
	   "$_nft_bin" add rule inet "$FB_T" in iif lo meta l4proto '{ tcp, udp }' th dport != 53 th sport != 53 counter name re >/dev/null 2>&1; then
		nslookup www.example.com 127.0.0.1 >/dev/null 2>&1 || true
		_fb_pkt() {
			"$_nft_bin" list counter inet "$FB_T" "$1" 2>/dev/null |
				sed -n 's/.*packets \([0-9][0-9]*\).*/\1/p' | head -1
		}
		_fb_q=$(_fb_pkt q)
		_fb_qe=$(_fb_pkt qe)
		_fb_r=$(_fb_pkt r)
		_fb_re=$(_fb_pkt re)
		"$_nft_bin" delete table inet "$FB_T" >/dev/null 2>&1 || true
		# 只有"查询和响应都真实发生"时才能验证排除语义。VM 上 dnsmasq
		# 未监听 127.0.0.1:53、或响应被防火墙丢掉时 r=0，这是环境不可用，
		# 不是排除规则错误——跳过，不要误报失败。
		if [ "${_fb_q:-0}" -eq 0 ] || [ "${_fb_r:-0}" -eq 0 ]; then
			echo "  - 跳过真 nft 语义测试：127.0.0.1:53 无完整 DNS 查询/响应（q=$_fb_q r=$_fb_r）"
		elif [ "${_fb_q:-0}" -gt 0 ] && [ "${_fb_r:-0}" -gt 0 ] &&
		     [ "${_fb_qe:-0}" -eq 0 ] && [ "${_fb_re:-0}" -eq 0 ]; then
			ok "真 nft：DNS 查询(q=$_fb_q)与响应(r=$_fb_r)均被双侧排除计数(${_fb_qe}/${_fb_re})"
		else
			ng "真 nft：DNS 排除语义不符（q=$_fb_q qe=$_fb_qe r=$_fb_r re=$_fb_re）"
		fi
	else
		"$_nft_bin" delete table inet "$FB_T" >/dev/null 2>&1 || true
		echo "  - 跳过真 nft 语义测试：临时表/链创建失败（当前环境不支持）"
	fi
else
	echo "  - 跳过真 nft 语义测试：需要 root + nft + nslookup（离线形状用例已覆盖）"
fi


# --- 13.9 上一版已发布的形状（双侧 53、没有 ct state new）必须重建 ---
# 0.2.1 目前装在生产上的就是这一版：只排 DNS，但按包计数。
fb_state "$FB/s9"
cat > "$FB/s9/rules" <<'FB_S9'
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 meta l4proto != tcp meta l4proto != udp counter name "isp_fallback" # handle 1
meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 meta l4proto { tcp, udp } th dport != 53 th sport != 53 counter name "isp_fallback" # handle 2
FB_S9
if fb_run "$FB/s9" "$TMP/fb.conf" >/dev/null 2>&1; then
	_fb_del=$(grep -c '^delete ' "$FB/s9/log" 2>/dev/null || true)
	_fb_add=$(grep -c '^add rule' "$FB/s9/log" 2>/dev/null || true)
	if [ "${_fb_del:-0}" -eq 2 ] && [ "${_fb_add:-0}" -eq 2 ] &&
	   [ "$(grep -c 'ct state new' "$FB/s9/rules")" -eq 2 ]; then
		ok "上一版形状（无 ct state new）重建为按连接计数"
	else
		ng "上一版形状未被重建（delete=$_fb_del add=$_fb_add）"
		sed 's/^/    /' "$FB/s9/log"
	fi
else
	ng "上一版形状重建时 _fallback_counter 调用失败"
fi

echo "== 14. 兜底增量归因工具（tools/count-attrib.sh，只读）"
CA=$ROOT/tools/count-attrib.sh
if [ -f "$CA" ] && sh -n "$CA" 2>/dev/null; then
	ok "count-attrib.sh 语法检查通过"
else
	ng "count-attrib.sh 缺失或语法错误"
fi

# 假 nft + 假 conntrack：让工具在离线环境跑完整流程。
# 兜底计数器每次读取后自增 CA_STEP，模拟"窗口内涨了 CA_STEP 包"。
mkdir -p "$TMP/ca/bin"
cat > "$TMP/ca/bin/nft" <<'FAKE_CA_NFT'
#!/bin/sh
S=${CA_STATE:?}
echo "$*" >> "$S/calls"
case "$*" in
"list table inet mwan3") cat "$S/table"; exit 0 ;;
"list counter inet mwan3 isp_fallback")
	v=$(cat "$S/fb")
	step=$(cat "$S/step")
	echo $((v + step)) > "$S/fb"
	echo "counter isp_fallback { packets $v bytes $((v * 70)) }"
	exit 0
	;;
"-a list chain inet mwan3 mwan3_rules") cat "$S/chain"; exit 0 ;;
"list chain inet mwan3 mwan3_rules") cat "$S/chain"; exit 0 ;;
esac
exit 0
FAKE_CA_NFT
chmod +x "$TMP/ca/bin/nft"

ca_state() { # $1=state dir $2=fb step $3=before ct file
	rm -rf "$1"
	mkdir -p "$1"
	: > "$1/table"
	echo "$2" > "$1/step"
	echo 0 > "$1/fb"
	cat > "$1/chain" <<'CA_CHAIN'
table inet mwan3 {
	chain mwan3_rules {
		meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto != tcp meta l4proto != udp counter name "isp_fallback"
		meta nfproto ipv4 meta mark & 0x00003f00 == 0x00000000 ct state new meta l4proto { tcp, udp } th dport != 53 th sport != 53 counter name "isp_fallback"
	}
}
CA_CHAIN
	cp "$3" "$1/ct"
}

cat > "$TMP/ca/ct1" <<'CA_CT1'
ipv4 2 udp 17 25 src=192.168.10.9 dst=223.5.5.5 sport=40001 dport=53 packets=2 bytes=140 src=223.5.5.5 dst=192.168.10.9 sport=53 dport=40001 packets=2 bytes=180 mark=0 use=1
ipv4 2 tcp 6 300 src=192.168.10.9 dst=1.2.3.4 sport=50000 dport=443 packets=9 bytes=900 src=1.2.3.4 dst=192.168.10.9 sport=443 dport=50000 packets=9 bytes=900 mark=0 use=1
CA_CT1
cat > "$TMP/ca/ct2" <<'CA_CT2'
ipv4 2 udp 17 25 src=192.168.10.9 dst=223.5.5.5 sport=40001 dport=53 packets=4 bytes=280 src=223.5.5.5 dst=192.168.10.9 sport=53 dport=40001 packets=4 bytes=360 mark=0 use=1
ipv4 2 tcp 6 300 src=192.168.10.9 dst=1.2.3.4 sport=50000 dport=443 packets=9 bytes=900 src=1.2.3.4 dst=192.168.10.9 sport=443 dport=50000 packets=9 bytes=900 mark=0 use=1
CA_CT2

# 14.1 兜底没涨、DNS 涨了 → 判定"DNS 没被计入"
ca_state "$TMP/ca/s1" 0 "$TMP/ca/ct1"
_ca_out=$(
	PATH="$TMP/ca/bin:$PATH" NFT=nft NF_CONNTRACK="$TMP/ca/s1/ct" CA_STATE="$TMP/ca/s1" \
		export PATH NFT NF_CONNTRACK CA_STATE
	( sleep 1; cp "$TMP/ca/ct2" "$TMP/ca/s1/ct" ) &
	sh "$CA" 2 223.5.5.5
	wait
)
if printf '%s\n' "$_ca_out" | grep -q '规则形状: current' &&
   printf '%s\n' "$_ca_out" | grep -q '兜底计数没有增长'; then
	ok "归因：兜底增量为 0 时判定 DNS 未被计入"
else
	ng "归因误判（兜底 0 + DNS 有流量）"
	printf '%s\n' "$_ca_out" | sed 's/^/    /'
fi

# 14.2 兜底涨 8、DNS 实际只有 4 包 → 判定"至少 4 包不可能是 DNS"
ca_state "$TMP/ca/s2" 8 "$TMP/ca/ct1"
_ca_out=$(
	PATH="$TMP/ca/bin:$PATH" NFT=nft NF_CONNTRACK="$TMP/ca/s2/ct" CA_STATE="$TMP/ca/s2" \
		export PATH NFT NF_CONNTRACK CA_STATE
	( sleep 1; cp "$TMP/ca/ct2" "$TMP/ca/s2/ct" ) &
	sh "$CA" 2 223.5.5.5
	wait
)
if printf '%s\n' "$_ca_out" | grep -q '兜底增量(8)' &&
   printf '%s\n' "$_ca_out" | grep -q '至少 4 包不可能是 DNS'; then
	ok "归因：兜底增量超过 DNS 实际包数时给出下界"
else
	ng "归因下界判定不符（期望 8 包 / DNS 4 包）"
	printf '%s\n' "$_ca_out" | sed 's/^/    /'
fi

# 14.4 读不到 conntrack（非 root）时不做归因，只报增量
_ca_out=$(
	PATH="$TMP/ca/bin:$PATH" NFT=nft NF_CONNTRACK=/nonexistent-ca CA_STATE="$TMP/ca/s2" \
		export PATH NFT NF_CONNTRACK CA_STATE
	sh "$CA" 2 2>/dev/null
)
if printf '%s\n' "$_ca_out" | grep -q '读不到 /nonexistent-ca'; then
	ok "归因：读不到 conntrack 时不做 DNS 归因（只报增量）"
else
	ng "读不到 conntrack 时仍给出了归因结论"
	printf '%s\n' "$_ca_out" | sed 's/^/    /'
fi

# 14.3 工具必须只读：假 nft 记录了全部调用，只能出现 list
if [ -s "$TMP/ca/s2/calls" ] &&
   ! grep -qE '^(add|delete|insert|flush|replace)' "$TMP/ca/s2/calls"; then
	ok "归因工具全程只读（$(wc -l < "$TMP/ca/s2/calls" | tr -d ' ') 次调用全是 list）"
else
	ng "归因工具出现了写操作：$(grep -E '^(add|delete|insert|flush|replace)' "$TMP/ca/s2/calls" 2>/dev/null | head -3)"
fi

echo "== 15. 0.2.2 回归（B-1/B-2/B-3/B-4/B-7/F-5）"
B123=$TMP/b123
mkdir -p "$B123/bin"
cat > "$B123/bin/nft" <<'FAKE_NFT_B123'
#!/bin/sh
[ "$1" = "-a" ] && shift
cmd=$1; shift
case "$cmd" in
list)
	case "$*" in
	"table inet mwan3") exit 0 ;;
	"chain inet mwan3 mwan3_rules")
		cat <<'NFT_CHAIN'
table inet mwan3 {
	chain mwan3_rules {
		ip daddr @isp_a meta mark & 0x00003f00 == 0x00000000 jump mwan3_policy_wan_only
	}
}
NFT_CHAIN
		exit 0
		;;
	"chain inet mwan3 mwan3_output") exit 1 ;;
	"counter inet mwan3 isp_fallback")
		echo 'counter isp_fallback { packets 944 bytes 119518 }'
		exit 0
		;;
	"set inet mwan3 "*) exit 1 ;;
	esac
	;;
esac
exit 0
FAKE_NFT_B123
cat > "$B123/bin/uci" <<'FAKE_UCI_B123'
#!/bin/sh
# BUG-25 起 plan 会预检策略成员：这里提供一组最小可用的 policy/member。
case "$*" in
*"get mwan3.wan_only.use_member"*) echo wan_m1_w3; exit 0 ;;
*"get mwan3.wanb_only.use_member"*) echo wanb_m1_w2; exit 0 ;;
*"get mwan3.wan_m1_w3.interface"*) echo wan1; exit 0 ;;
*"get mwan3.wanb_m1_w2.interface"*) echo wan2; exit 0 ;;
*"get mwan3.wan_m1_w3"* | *"get mwan3.wanb_m1_w2"*) echo member; exit 0 ;;
*"get mwan3.wan1"* | *"get mwan3.wan2"*) echo interface; exit 0 ;;
*"get mwan3.wan_only"* | *"get mwan3.wanb_only"*) echo policy; exit 0 ;;
*"show mwan3"*)
	printf 'mwan3.wan_only=policy\nmwan3.wanb_only=policy\n'
	exit 0
	;;
esac
exit 1
FAKE_UCI_B123
chmod +x "$B123/bin/nft" "$B123/bin/uci"

mkdir -p "$B123/tmp"
b123_run() { # $1=conf $2=command...
	_c=$1
	shift
	(
		PATH="$B123/bin:$PATH"
		TMPDIR="$B123/tmp"
		ISP_SPLIT_CONF="$_c"
		ISP_SPLIT_BASE="$B123/base"
		ISP_SPLIT_LIB="$LIB"
		ISP_SPLIT_MWAN3="$B123/mwan3"
		DNSMASQ_CONF_GLOB="$B123/no-such-dnsmasq.conf.*"
		DNSMASQ_DEFAULT_DIR="$B123/dnsmasq.d"
		export PATH TMPDIR ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB \
			ISP_SPLIT_MWAN3 DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR
		sh "$ROOT/files/usr/sbin/isp-split" "$@"
	)
}

# ---- B-1：注释行（含前导空白）不得进入 conf get / plan ----
cat > "$B123/conf-b1" <<'B1_CONF'
DNS_MODE="bind"
DNS_TABLE="
wan_only:223.5.5.5
# 移动先观察一段时间:wanb_only:119.29.29.29
"
DOMAIN_SPLIT="
# 域名注释:bilibili.com:wanb_only
bilivideo.com:wanb_only
"
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
   # 前导空白的注释:isp_cmcc:wanb_only:0
unicom_cnc:isp_uni:wanb_only:1
"
B1_CONF
_b1_get=$(b123_run "$B123/conf-b1" conf get 2>/dev/null)
_b1_isp=$(printf '%s\n' "$_b1_get" | grep -c '^isp	')
_b1_dns=$(printf '%s\n' "$_b1_get" | grep -c '^dns	')
_b1_dom=$(printf '%s\n' "$_b1_get" | grep -c '^domain	')
if [ "$_b1_isp" -eq 2 ] && [ "$_b1_dns" -eq 1 ] && [ "$_b1_dom" -eq 1 ] &&
   ! printf '%s\n' "$_b1_get" | grep -q '移动先观察'; then
	ok "B-1 conf get 跳过注释行（2 运营商 / 1 DNS / 1 域名）"
else
	ng "B-1 conf get 仍把注释当数据行: isp=$_b1_isp dns=$_b1_dns domain=$_b1_dom"
	printf '%s\n' "$_b1_get" | sed 's/^/    /'
fi

b123_run "$B123/conf-b1" plan > "$B123/plan.out" 2>&1
_b1_rc=$?
if [ "$_b1_rc" -eq 0 ] && grep -q 'isp_tel' "$B123/plan.out" &&
   ! grep -q '错误: ISP_TABLE 的源名' "$B123/plan.out" &&
   grep -q 'dnsmasq nftset 能力' "$B123/plan.out"; then
	ok "B-1 带注释的 ISP_TABLE 下 plan 正常完成（并输出 nftset 检测项）"
else
	ng "B-1 plan 仍因注释行失败（rc=$_b1_rc）"
	sed 's/^/    /' "$B123/plan.out" | tail -12
fi

# 双保险：_row_check_row 对带前导空白的注释行直接放行
if ( ISP_SPLIT_CONF="$B123/conf-b1" ISP_SPLIT_BASE="$B123/base" \
	ISP_SPLIT_LIB="$LIB" \
	export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	_row_check_row '   # 注释:isp_x:wan_only:0' ) >/dev/null 2>&1; then
	ok "B-1 _row_check_row 放行带前导空白的注释行"
else
	ng "B-1 _row_check_row 仍把注释行判成非法数据"
fi

# ---- B-2：verify 兜底提示只看 COUNT_FALLBACK，与 DNS_TABLE 无关 ----
cat > "$B123/conf-b2a" <<'B2A_CONF'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
COUNT_FALLBACK="1"
B2A_CONF
cat > "$B123/conf-b2b" <<'B2B_CONF'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE="wan_only:223.5.5.5"
DOMAIN_SPLIT=""
COUNT_FALLBACK="0"
B2B_CONF
# 假 nft 的链里没有 counter name：COUNT_FALLBACK=1 必须提示
b123_run "$B123/conf-b2a" verify > "$B123/v-a.out" 2>&1
# COUNT_FALLBACK=0 时即使 DNS_TABLE 有值也不能误报
b123_run "$B123/conf-b2b" verify > "$B123/v-b.out" 2>&1
if grep -q '兜底计数规则缺失' "$B123/v-a.out" &&
   ! grep -q '兜底计数规则缺失' "$B123/v-b.out"; then
	ok "B-2 verify 兜底提示由 COUNT_FALLBACK 决定（1=提示，0=不提示）"
else
	ng "B-2 verify 兜底提示判定仍错误"
	echo "    COUNT_FALLBACK=1 + DNS_TABLE 空:"
	grep '兜底计数' "$B123/v-a.out" | sed 's/^/      /'
	echo "    COUNT_FALLBACK=0 + DNS_TABLE 有值:"
	grep '兜底计数' "$B123/v-b.out" | sed 's/^/      /'
fi

# ---- B-3：status 兜底行必须有单位换算 ----
cat > "$B123/conf-b3" <<'B3_CONF'
ISP_TABLE="a:isp_a:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
COUNT_FALLBACK="1"
B3_CONF
b123_run "$B123/conf-b3" status > "$B123/status.out" 2>&1
_b3_row=$(grep '^兜底' "$B123/status.out" | head -1)
case "$_b3_row" in
*116.7KiB*) _b3_ok=1 ;;
*) _b3_ok=0 ;;
esac
if [ "$_b3_ok" = "1" ] && ! printf '%s' "$_b3_row" | grep -q '119518'; then
	ok "B-3 status 兜底行流量已换算为 116.7KiB（不再是裸字节）"
else
	ng "B-3 status 兜底行仍是裸字节: $_b3_row"
fi

# ---- B-4：wire 收敛带标记的孤儿 ipset 段，uninstall 按标记全删 ----
B4=$TMP/b4
mkdir -p "$B4/bin"
cat > "$B4/bin/uci" <<'FAKE_UCI_B4'
#!/bin/sh
S=${FAKE_UCI_STATE:?}
[ "$1" = "-q" ] && shift
cmd=$1
shift
case "$cmd" in
show)
	[ "${1:-}" = "mwan3" ] || exit 1
	cat "$S/show" 2>/dev/null
	exit 0
	;;
get)
	p=${1#mwan3.}
	sec=${p%%.*}
	rest=${p#*.}
	[ "$rest" = "$p" ] && exit 1
	[ -f "$S/data/$sec.$rest" ] || exit 1
	cat "$S/data/$sec.$rest"
	exit 0
	;;
delete)
	sec=${1#mwan3.}
	[ -f "$S/data/$sec.name" ] || exit 1
	rm -f "$S/data/$sec".*
	grep -v "^mwan3\.$sec=" "$S/show" > "$S/show.new" 2>/dev/null
	mv "$S/show.new" "$S/show"
	exit 0
	;;
commit)
	echo commit >> "$S/commit.log"
	exit 0
	;;
esac
exit 1
FAKE_UCI_B4
chmod +x "$B4/bin/uci"
cat > "$B4/conf" <<'B4_CONF'
ISP_TABLE="
telecom:isp_tel:wan_only:1
unicom:isp_uni:wanb_only:1
cmcc:isp_cmcc:wanb_only:0
"
DNS_TABLE="wan_only:223.5.5.5"
DOMAIN_SPLIT=""
DNS_MODE="bind"
B4_CONF
: > "$B4/mwan3"

b4_state() {
	rm -rf "$1"
	mkdir -p "$1/data"
	cat > "$1/show" <<'B4_SHOW'
mwan3.wan_only=policy
mwan3.ipset_isp_tel=ipset
mwan3.ipset_isp_uni=ipset
mwan3.ipset_isp_cmcc=ipset
mwan3.ipset_isp_old=ipset
mwan3.ipset_isp_keep=ipset
mwan3.ipset_isp_legacy=ipset
mwan3.mywg=ipset
mwan3.rule_tel=rule
B4_SHOW
	# 段名是 ipset_<集合名>；当前启用：isp_tel / isp_uni；
	# 禁用：isp_cmcc；改名遗留：isp_old；无标记旧段：isp_legacy。
	printf 'isp_tel\n' > "$1/data/ipset_isp_tel.name"
	printf '1\n' > "$1/data/ipset_isp_tel.isp_split"
	printf 'isp_uni\n' > "$1/data/ipset_isp_uni.name"
	printf '1\n' > "$1/data/ipset_isp_uni.isp_split"
	printf 'isp_cmcc\n' > "$1/data/ipset_isp_cmcc.name"
	printf '1\n' > "$1/data/ipset_isp_cmcc.isp_split"
	printf 'isp_old\n' > "$1/data/ipset_isp_old.name"
	printf '1\n' > "$1/data/ipset_isp_old.isp_split"
	printf 'isp_keep\n' > "$1/data/ipset_isp_keep.name"
	printf '1\n' > "$1/data/ipset_isp_keep.isp_split"
	printf 'isp_legacy\n' > "$1/data/ipset_isp_legacy.name"
	printf 'mywg\n' > "$1/data/mywg.name"
	printf 'isp_keep\n' > "$1/data/rule_tel.ipset"
	: > "$1/commit.log"
}

b4_run() { # $1=state dir $2=function
	(
		PATH="$B4/bin:$PATH"
		FAKE_UCI_STATE="$1"
		ISP_SPLIT_CONF="$B4/conf"
		ISP_SPLIT_BASE="$B4/base"
		ISP_SPLIT_MWAN3="$B4/mwan3"
		export PATH FAKE_UCI_STATE ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_MWAN3
		. "$TMP/isp-lib.sh"
		"$2"
	)
}

b4_state "$B4/s1"
b4_run "$B4/s1" _prune_orphan_ipsets > "$B4/prune.log" 2>&1
_b4_left=$(grep '=ipset$' "$B4/s1/show" | sed 's/^mwan3\.//; s/=ipset$//' | tr '\n' ' ')
_b4_expect='ipset_isp_tel ipset_isp_uni ipset_isp_keep ipset_isp_legacy mywg '
if [ "$_b4_left" = "$_b4_expect" ] &&
   grep -q '已清理孤儿 ipset 段 ipset_isp_old' "$B4/prune.log" &&
   grep -q '仍被 mwan3 规则引用，保留' "$B4/prune.log" &&
   grep -q '没有 isp_split 标记，保留不动' "$B4/prune.log"; then
	ok "B-4 wire 只删带标记且无引用的孤儿段（保留当前/被引用/无标记段）"
else
	ng "B-4 孤儿段收敛结果异常: [$_b4_left]（期望: [$_b4_expect]）"
	sed 's/^/    /' "$B4/prune.log"
fi

b4_run "$B4/s1" _uninstall_ipsets > "$B4/uninstall.log" 2>&1
_b4_left=$(grep '=ipset$' "$B4/s1/show" | sed 's/^mwan3\.//; s/=ipset$//' | tr '\n' ' ')
if [ "$_b4_left" = "ipset_isp_legacy mywg " ]; then
	ok "B-4 uninstall 按 isp_split 标记全删，无标记段保持不动"
else
	ng "B-4 uninstall 后残留异常: [$_b4_left]（期望: [ipset_isp_legacy mywg ]）"
	sed 's/^/    /' "$B4/uninstall.log"
fi

# ---- B-7：版本串三处同源，PKG_RELEASE 全部为 1 ----
_v_script=$(sed -n 's/^ISP_VERSION="\(.*\)"$/\1/p' "$ROOT/files/usr/sbin/isp-split" | head -1)
_v_main=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/Makefile" | head -1)
_v_luci=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/luci-app-isp-split/Makefile" | head -1)
_v_feed1=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/feed/op-packages/isp-split/Makefile" | head -1)
_v_feed2=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/feed/op-packages/luci-app-isp-split/Makefile" | head -1)
_r_main=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/Makefile" | head -1)
_r_luci=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/luci-app-isp-split/Makefile" | head -1)
_r_feed1=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/feed/op-packages/isp-split/Makefile" | head -1)
_r_feed2=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/feed/op-packages/luci-app-isp-split/Makefile" | head -1)
if [ -n "$_v_script" ] && [ "$_v_script" = "$_v_main" ] &&
   [ "$_v_main" = "$_v_luci" ] && [ "$_v_main" = "$_v_feed1" ] &&
   [ "$_v_main" = "$_v_feed2" ] &&
   [ "$_r_main" = "1" ] && [ "$_r_luci" = "1" ] &&
   [ "$_r_feed1" = "1" ] && [ "$_r_feed2" = "1" ]; then
	ok "B-7 版本串同源（$_v_script），PKG_RELEASE 全部为 1"
else
	ng "B-7 版本串不一致: script=$_v_script main=$_v_main luci=$_v_luci feed=$_v_feed1/$_v_feed2 release=$_r_main/$_r_luci/$_r_feed1/$_r_feed2"
fi

# ---- 16. 线路体检（0.3.0 透视更新） ----
echo "== 16. 线路体检（0.3.0）"
LCF=$TMP/lc-fix
LCCONF=$TMP/lc.conf
LCBASE=$TMP/lc-base
rm -rf "$LCBASE" "$LCF"
mkdir -p "$LCBASE"
cp "$ROOT/files/etc/isp-split.conf" "$LCCONF"

if sh "$ROOT/tools/linecheck-fixtures.sh" "$LCF" >/dev/null 2>&1 &&
   [ "$(wc -c <"$LCF/stun-32.bin")" -eq 32 ] &&
   [ "$(wc -c <"$LCF/stun-84.bin")" -eq 84 ]; then
	ok "STUN fixture 生成（32/84 字节、超时、坏包）"
else
	ng "STUN fixture 生成失败"
fi

# 只加载函数，不执行主分发
lc_lib() {
	(
		ISP_SPLIT_CONF="$LCCONF" ISP_SPLIT_BASE="$LCBASE" ISP_SPLIT_LIB="$LIB" \
			ISP_SPLIT_LIB_ONLY=1
		export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB ISP_SPLIT_LIB_ONLY
		. "$ROOT/files/usr/sbin/isp-split"
		"$@"
	)
}

# 16.1 IP 分类（公网 / CGNAT / 私网 / 非法）
_lc_bad=0
for _pair in \
	100.64.1.2:cgnat 100.127.255.254:cgnat 100.128.0.1:public \
	10.1.2.3:private 172.16.5.4:private 172.32.1.1:public \
	192.168.1.1:private 8.8.8.8:public 127.0.0.1:private \
	198.18.0.1:private 1.2.3.256:invalid bad:invalid; do
	_ip=${_pair%:*}
	_want=${_pair#*:}
	_got=$(lc_lib _lc_ip_class "$_ip")
	[ "$_got" = "$_want" ] || { _lc_bad=1; echo "    $_ip 期望 $_want，实际 $_got"; }
done
[ "$_lc_bad" -eq 0 ] && ok "IP 分类：公网 / CGNAT / 私网 / 非法（12 组边界）" ||
	ng "IP 分类存在错误"

# 16.2 NAT 五态判定
_lc_nat() { lc_lib _lc_nat_verdict "$@" | cut -d'|' -f1; }
_lc_bad=0
[ "$(_lc_nat 100.64.1.2 cgnat 1.2.3.4:5 1.2.3.4:5 5)" = cgnat ] || _lc_bad=1
[ "$(_lc_nat 203.0.113.5 public 203.0.113.5:5000 203.0.113.5:5000 5000)" = public ] || _lc_bad=1
[ "$(_lc_nat 203.0.113.5 public 1.2.3.4:40000 1.2.3.4:40000 40000)" = cone ] || _lc_bad=1
[ "$(_lc_nat 203.0.113.5 public 1.2.3.4:40000 1.2.3.5:40001 40000)" = symmetric ] || _lc_bad=1
[ "$(_lc_nat 203.0.113.5 public - - 40000)" = unknown ] || _lc_bad=1
[ "$(_lc_nat 203.0.113.5 public 10.0.0.5:40000 10.0.0.5:40000 40000)" = cgnat ] || _lc_bad=1
[ "$_lc_bad" -eq 0 ] && ok "NAT 五态判定：CGNAT / 公网 / 锥形 / 对称 / 未知（+多层 NAT）" ||
	ng "NAT 五态判定存在错误"

# 16.3 STUN 纯 shell 解析（32/84 字节 + 坏包）
_lc_parse() { lc_lib _lc_stun_parse "$1" 112233445566778899aabbcc; }
_lc_bad=0
for _f in stun-32 stun-84; do
	[ "$(_lc_parse "$LCF/$_f.bin")" = "121.20.198.57 44653" ] || { _lc_bad=1; echo "    $_f 解析失败"; }
done
for _f in stun-timeout stun-bad-magic stun-bad-txid stun-bad-type stun-short stun-bad-len; do
	[ -z "$(_lc_parse "$LCF/$_f.bin")" ] || { _lc_bad=1; echo "    $_f 应被拒绝"; }
done
[ "$_lc_bad" -eq 0 ] && ok "STUN 解析：32/84 字节成功，坏 magic/txid/type/长度/截断全部丢弃" ||
	ng "STUN 解析存在错误"

# 16.4 评分规则 + 硬上限
_lc_score_res() {
	(
		ISP_SPLIT_CONF="$LCCONF" ISP_SPLIT_BASE="$LCBASE" ISP_SPLIT_LIB="$LIB" 			ISP_SPLIT_LIB_ONLY=1
		export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB ISP_SPLIT_LIB_ONLY
		. "$ROOT/files/usr/sbin/isp-split"
		_lc_score "$@"
		echo "$SC_TOTAL|$SC_GRADE|$SC_LAT_PTS|$SC_CAPS"
	)
}
_lc_bad=0
_r=$(_lc_score_res public 40 3 0 full 1 1)
[ "${_r%%|*}" = "96" ] && [ "$(echo "$_r" | cut -d'|' -f2)" = "A" ] || { _lc_bad=1; echo "    全通公网: $_r"; }
_r=$(_lc_score_res cgnat 30 5 0 full 1 1)
[ "${_r%%|*}" = "66" ] && [ "$(echo "$_r" | cut -d'|' -f2)" = "C" ] || { _lc_bad=1; echo "    CGNAT: $_r"; }
_r=$(_lc_score_res symmetric 45 10 0 full 1 1)
[ "${_r%%|*}" = "63" ] && [ "$(echo "$_r" | cut -d'|' -f2)" = "C" ] || { _lc_bad=1; echo "    对称: $_r"; }
_r=$(_lc_score_res public 40 12 30 full 1 1)
[ "${_r%%|*}" = "69" ] && echo "$_r" | grep -q "丢包 > 20%" || { _lc_bad=1; echo "    丢包上限: $_r"; }
# 跨网基线：30ms 原本 26 分，必须被压到 15
_r=$(_lc_score_res public 30 3 0 full 0 1)
[ "$(echo "$_r" | cut -d'|' -f3)" = "15" ] || { _lc_bad=1; echo "    跨网基线延迟项: $_r"; }
[ "$_lc_bad" -eq 0 ] && ok "评分：96/A、CGNAT 66/C、对称 63/C、丢包上限 69/C、跨网延迟≤15" ||
	ng "评分规则存在错误"

# 16.5 JSON schema + 五态（夹具全离线）
lc_run_conf() { # <conf> [args...]
	_conf=$1
	shift
	ISP_SPLIT_CONF="$_conf" ISP_SPLIT_BASE="$LCBASE" \
		ISP_SPLIT_LC_WANS="wan1|wan1|1|online|203.0.113.5 wan2|wan2|1|online|100.64.1.2" \
		ISP_SPLIT_LC_EXIT_IPS="198.51.100.7,198.51.100.8" \
		ISP_SPLIT_LC_LAT="dns=5,tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5" \
		ISP_SPLIT_LC_FORCE_SAME=1 \
		ISP_SPLIT_LC_STUN="ok:1.2.3.4:40000|ok:1.2.3.4:40000" \
		ISP_SPLIT_LC_GEO_TEXT="河北省 唐山市 联通|baidu" \
		ISP_SPLIT_LC_RESOLVE_IPS="124.236.19.250" \
		ISP_SPLIT_LC_ISP="chinatelecom" \
		sh "$ROOT/files/usr/sbin/isp-split" linecheck "$@"
}
lc_run() { lc_run_conf "$LCCONF" "$@"; }

JQ=
command -v jsonfilter >/dev/null 2>&1 && JQ=jsonfilter
lc_run --json >"$TMP/lc1.json" 2>"$TMP/lc1.err"
if [ -s "$TMP/lc1.json" ] && ! grep -q '^{"version":"0.3.0"' "$TMP/lc1.json"; then
	ng "linecheck --json 顶层形状异常"
elif [ -n "$JQ" ]; then
	_v=$(jsonfilter -i "$TMP/lc1.json" -e '@.version' 2>/dev/null)
	_n=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[*].iface' 2>/dev/null | wc -l)
	_g=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[0].score.grade' 2>/dev/null)
	_b=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[0].score.breakdown[*].key' 2>/dev/null | wc -l)
	_t=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[1].score.total' 2>/dev/null)
	_c=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[1].nat.type' 2>/dev/null)
	if [ "$_v" = "0.3.0" ] && [ "$_n" = "2" ] && [ -n "$_g" ] && [ "$_b" = "4" ] &&
	   [ -n "$_t" ] && [ "$_c" = "cgnat" ]; then
		ok "JSON schema：version/2 条 WAN/score 四段明细/嵌套 NAT 完整"
	else
		ng "JSON schema 不完整: version=$_v wans=$_n grade=$_g breakdown=$_b total=$_t nat=$_c"
	fi
else
	grep -q '"breakdown":\[' "$TMP/lc1.json" && grep -q '"caps":\[' "$TMP/lc1.json" &&
		ok "JSON schema 关键字段存在（无 jsonfilter，仅结构检查）" ||
		ng "JSON schema 关键字段缺失"
fi

# 16.6 缓存命中 / --force / --wan
sleep 1
lc_run --json >"$TMP/lc2.json" 2>/dev/null
lc_run --json --force >"$TMP/lc3.json" 2>/dev/null
lc_run --json --wan wan2 >"$TMP/lc4.json" 2>/dev/null
if [ -n "$JQ" ]; then
	_c1=$(jsonfilter -i "$TMP/lc2.json" -e '@.cached')
	_a1=$(jsonfilter -i "$TMP/lc2.json" -e '@.age')
	_c2=$(jsonfilter -i "$TMP/lc3.json" -e '@.cached')
	_n3=$(jsonfilter -i "$TMP/lc4.json" -e '@.wans[*].iface' 2>/dev/null | wc -l)
	_i3=$(jsonfilter -i "$TMP/lc4.json" -e '@.wans[0].iface')
	if [ "$_c1" = "true" ] && [ "$_a1" -ge 1 ] 2>/dev/null &&
	   [ "$_c2" = "false" ] && [ "$_n3" = "1" ] && [ "$_i3" = "wan2" ]; then
		ok "结果缓存：60s 内 cached=true（age=$_a1），--force 重算，--wan 只返回指定线"
	else
		ng "缓存/--force/--wan 异常: cached=$_c1 age=$_a1 force=$_c2 n=$_n3 iface=$_i3"
	fi
else
	grep -q '"cached":true' "$TMP/lc2.json" && grep -q '"cached":false' "$TMP/lc3.json" &&
		ok "缓存/--force 关键字段正确（无 jsonfilter）" || ng "缓存/--force 异常"
fi

# 16.7 socat 缺失降级（不能带 STUN 夹具，否则不会走 socat 缺失分支）
lc_run_nostun() {
	ISP_SPLIT_CONF="$LCCONF" ISP_SPLIT_BASE="$LCBASE" 		ISP_SPLIT_LC_WANS="wan1|wan1|1|online|203.0.113.5" 		ISP_SPLIT_LC_EXIT_IPS="198.51.100.7" 		ISP_SPLIT_LC_LAT="dns=5,tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5" 		ISP_SPLIT_LC_FORCE_SAME=1 ISP_SPLIT_LC_NO_SOCAT=1 		ISP_SPLIT_LC_GEO_TEXT="x|baidu" ISP_SPLIT_LC_RESOLVE_IPS="124.236.19.250" 		sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --force
}
lc_run_nostun >"$TMP/lc-socat.json" 2>/dev/null
if grep -q '"socat":false' "$TMP/lc-socat.json" &&
   grep -q '"type":"unknown"' "$TMP/lc-socat.json" &&
   grep -q 'socat 未安装' "$TMP/lc-socat.json"; then
	ok "socat 缺失：全局 socat=false、NAT 降级 unknown 并提示安装"
else
	ng "socat 缺失降级异常"
fi

# 16.8 归属地关闭：不发请求、状态 off
sed 's/^LINE_CHECK_GEO=1$/LINE_CHECK_GEO=0/' "$LCCONF" >"$TMP/lc-geo0.conf"
lc_run_conf "$TMP/lc-geo0.conf" --json --force >"$TMP/lc-geo0.json" 2>/dev/null
if grep -q '"geo_enabled":false' "$TMP/lc-geo0.json" &&
   grep -q '"status":"off"' "$TMP/lc-geo0.json"; then
	ok "LINE_CHECK_GEO=0：JSON geo_enabled=false、状态 off，不发起第三方请求"
else
	ng "归属地关闭行为异常"
fi

# 16.9 坏包 fixture 走完整链路：两个探测点都坏 → 未知 + 明确提示
mkdir -p "$TMP/lc-fxbad"
cp "$LCF/stun-bad-magic.bin" "$TMP/lc-fxbad/stun-1.bin"
cp "$LCF/stun-bad-txid.bin" "$TMP/lc-fxbad/stun-2.bin"
( export ISP_SPLIT_LC_STUN_FIXTURE_DIR="$TMP/lc-fxbad"; lc_run --json --force ) >"$TMP/lc-bad.json" 2>/dev/null
if grep -q '"type":"unknown"' "$TMP/lc-bad.json" &&
   grep -q '响应校验失败' "$TMP/lc-bad.json"; then
	ok "坏包 fixture：解析层丢弃，NAT 判未知且提示响应校验失败"
else
	ng "坏包 fixture 处理异常"
fi

# ---- 16.10 后台体检（BUG-23）：--background 起、last.json 落盘、锁释放 ----
rm -rf "$LCBASE/state"
lc_bg() { lc_run --background "$@"; }
lc_ms_now() {
	if [ -r /proc/uptime ]; then
		awk '{ printf "%d", $1 * 1000 }' /proc/uptime
	else
		date +%s
	fi
}
lc_wait_for() { # <秒> <测试表达式…>：等到条件成立
	_i=0
	while [ "$_i" -lt "$1" ]; do
		shift
		if eval "$*"; then return 0; fi
		sleep 1
		_i=$((_i + 1))
	done
	return 1
}

lc_bg >"$TMP/lc-bg1.json" 2>"$TMP/lc-bg1.err"
_bg1_rc=$?
if [ "$_bg1_rc" = "0" ] && grep -q '"started":true' "$TMP/lc-bg1.json" &&
   ! grep -q '"wans"' "$TMP/lc-bg1.json"; then
	ok "--background：立刻返回 started=true 的状态行，不带探测结果（调用方不被阻塞）"
else
	ng "--background 启动异常（rc=$_bg1_rc）：$(cat "$TMP/lc-bg1.json" 2>/dev/null)"
fi

if lc_wait_for 15 '[ -f "$LCBASE/state/linecheck/last.json" ]' &&
   lc_wait_for 15 '[ ! -d "$LCBASE/state/linecheck.lock" ]'; then
	ok "后台探测完成：last.json 落盘、锁目录自动释放（进程退出即解锁）"
else
	ng "后台探测收尾异常：last.json 或锁目录未按预期出现/消失"
fi

if [ -n "$JQ" ]; then
	_bg_cmd=$(jsonfilter -i "$LCBASE/state/linecheck/last.json" -e '@.command' 2>/dev/null)
	_bg_n=$(jsonfilter -i "$LCBASE/state/linecheck/last.json" -e '@.wans[*].iface' 2>/dev/null | wc -l)
	_bg_gen=$(jsonfilter -i "$LCBASE/state/linecheck/last.json" -e '@.generated' 2>/dev/null)
	if [ "$_bg_cmd" = "linecheck" ] && [ "$_bg_n" = "2" ] && [ "$_bg_gen" -gt 0 ] 2>/dev/null; then
		ok "last.json 是完整快照：command=linecheck、2 条 WAN、generated=$_bg_gen（页面只读这一个文件）"
	else
		ng "last.json 内容异常: command=$_bg_cmd wans=$_bg_n generated=$_bg_gen"
	fi
else
	grep -q '"command":"linecheck"' "$LCBASE/state/linecheck/last.json" &&
		ok "last.json 是完整快照（无 jsonfilter，仅结构检查）" ||
		ng "last.json 内容异常"
fi

# ---- 16.11 缓存新鲜时 --background 不再起探测 ----
lc_bg >"$TMP/lc-bg2.json" 2>/dev/null
if grep -q '"started":false' "$TMP/lc-bg2.json" && grep -q '"cached":true' "$TMP/lc-bg2.json"; then
	ok "--background：60s 缓存仍新鲜时返回 started=false/cached=true，不重复探测"
else
	ng "--background 未正确短路新鲜缓存：$(cat "$TMP/lc-bg2.json" 2>/dev/null)"
fi

# ---- 16.12 锁去重：已有一次在跑时 --background 返回 running ----
rm -rf "$LCBASE/state/linecheck" "$LCBASE/state/linecheck.lock"
sleep 30 &
_lc_fake=$!
mkdir -p "$LCBASE/state/linecheck.lock"
printf '%s\n' "$_lc_fake" >"$LCBASE/state/linecheck.lock/pid"
date +%s >"$LCBASE/state/linecheck.lock/started"
lc_bg >"$TMP/lc-bg3.json" 2>/dev/null
if grep -q '"started":false' "$TMP/lc-bg3.json" && grep -q '"running":true' "$TMP/lc-bg3.json" &&
   grep -q "\"pid\":$_lc_fake" "$TMP/lc-bg3.json" &&
   [ ! -f "$LCBASE/state/linecheck/last.json" ]; then
	ok "锁去重：已有体检在跑时 --background 只返回 running=true/pid，不重复起第二个探测"
else
	ng "锁去重失败：$(cat "$TMP/lc-bg3.json" 2>/dev/null)"
fi

# 前台 CLI 抢同一把锁：没有新鲜缓存时不能返回半截数据，退出码 4
lc_run --json >"$TMP/lc-run-locked.json" 2>"$TMP/lc-run-locked.err"
_locked_rc=$?
if [ "$_locked_rc" = "4" ] && grep -q '"running":true' "$TMP/lc-run-locked.json"; then
	ok "前台 linecheck --json 撞锁：输出 running=true 并以退出码 4 结束（不返回半截数据）"
else
	ng "前台撞锁行为异常（rc=$_locked_rc）：$(cat "$TMP/lc-run-locked.json" 2>/dev/null)"
fi
kill "$_lc_fake" 2>/dev/null
wait "$_lc_fake" 2>/dev/null
rm -rf "$LCBASE/state/linecheck.lock"

# ---- 16.13 崩溃残留：pid 已死的 tmp 目录 + 半截缓存（BUG-24 的现场）----
mkdir -p "$LCBASE/state/linecheck.tmp.999999" "$LCBASE/state/linecheck"
: >"$LCBASE/state/linecheck/geo.tsv"
lc_run --json --force >"$TMP/lc-recover.json" 2>/dev/null
if [ ! -d "$LCBASE/state/linecheck.tmp.999999" ] &&
   [ -f "$LCBASE/state/linecheck/meta" ] && [ -f "$LCBASE/state/linecheck/last.json" ]; then
	ok "崩溃残留清理：pid 已死的 linecheck.tmp.* 被扫掉，半截缓存被替换成完整缓存"
else
	ng "崩溃残留清理异常：$(ls -d "$LCBASE"/state/linecheck* 2>/dev/null | tr '\n' ' ')"
fi

# 命中缓存的那次调用也要顺手扫掉死 pid 的探测目录（SIGKILL 走不到 trap）
mkdir -p "$LCBASE/state/linecheck.tmp.888888"
lc_run --json >"$TMP/lc-cached-sweep.json" 2>/dev/null
if [ ! -d "$LCBASE/state/linecheck.tmp.888888" ] &&
   grep -q '"cached":true' "$TMP/lc-cached-sweep.json"; then
	ok "命中缓存的调用也会清理死 pid 的 linecheck.tmp.*（不必等下一次真实探测）"
else
	ng "命中缓存时未清理死 pid 探测目录"
fi

# ---- 16.14 trap 清理：正常退出与 SIGTERM 都要删掉探测目录和锁 ----
lc_trap_probe() { # <模式 exit|term>
	_it_tmp=$LCBASE/state/linecheck.tmp.$1
	ISP_SPLIT_CONF="$LCCONF" ISP_SPLIT_BASE="$LCBASE" ISP_SPLIT_LIB_ONLY=1 \
		sh -c '
		. "$1" >/dev/null 2>&1
		_d=$2
		mkdir -p "$_d/linecheck.tmp.$3" "$_d/linecheck.lock"
		_lc_tmp="$_d/linecheck.tmp.$3"
		printf "%s\n" "$$" >"$_d/linecheck.lock/pid"
		LC_LOCK_OWNER=1
		_lc_trap_on
		if [ "$4" = "term" ]; then
			# 用 1s 循环而不是单个长 sleep：TERM 到来时 shell 能立刻进 trap
			_n=0
			while [ "$_n" -lt 30 ]; do sleep 1; _n=$((_n + 1)); done
		else
			exit 0
		fi
	' _ "$ROOT/files/usr/sbin/isp-split" "$LCBASE/state" "$1" "$2"
}
lc_trap_probe 424242 exit >/dev/null 2>&1
if [ ! -d "$LCBASE/state/linecheck.tmp.424242" ] && [ ! -d "$LCBASE/state/linecheck.lock" ]; then
	ok "trap 清理：正常退出后探测目录与锁都不残留"
else
	ng "trap 清理失败（exit 路径）：$(ls -d "$LCBASE"/state/linecheck* 2>/dev/null | tr '\n' ' ')"
fi

lc_trap_probe 424243 term >/dev/null 2>&1 &
_lc_term_wrap=$!
sleep 2
# 锁里的 pid 就是那个 trap shell 自己的 pid
_lc_term_pid=$(cat "$LCBASE/state/linecheck.lock/pid" 2>/dev/null)
[ -n "$_lc_term_pid" ] && kill -TERM "$_lc_term_pid" 2>/dev/null
wait "$_lc_term_wrap" 2>/dev/null
if [ ! -d "$LCBASE/state/linecheck.tmp.424243" ] && [ ! -d "$LCBASE/state/linecheck.lock" ]; then
	ok "trap 清理：SIGTERM（rpcd 超时/用户中断）也会删掉探测目录与锁"
else
	ng "trap 清理失败（TERM 路径）：$(ls -d "$LCBASE"/state/linecheck* 2>/dev/null | tr '\n' ' ')"
fi

# ---- 16.15 cached:true 短路：不探测、耗时 < 1 秒 ----
lc_run --json --force >/dev/null 2>&1
_t0=$(lc_ms_now)
lc_run --json >"$TMP/lc-fast.json" 2>/dev/null
_t1=$(lc_ms_now)
_fast_dt=$((_t1 - _t0))
if grep -q '"cached":true' "$TMP/lc-fast.json" && [ "$_fast_dt" -lt 1000 ]; then
	ok "缓存短路：cached=true 且耗时 ${_fast_dt}ms（<1000ms），不再全量探测"
else
	ng "缓存短路异常：耗时 ${_fast_dt}ms，cached=$(grep -o '"cached":[a-z]*' "$TMP/lc-fast.json" 2>/dev/null)"
fi

# ---- 16.16 缓存不因 --force 之外的路径被“半截目录”破坏 ----
if [ -z "$(ls -d "$LCBASE"/state/linecheck.tmp.* 2>/dev/null)" ]; then
	ok "state 目录干净：没有任何 linecheck.tmp.* 残留"
else
	ng "state 目录仍有 tmp 残留：$(ls -d "$LCBASE"/state/linecheck.tmp.* 2>/dev/null | tr '\n' ' ')"
fi

echo "== 17. BUG-25 首装绑定策略（init / wire 预检 / verify / uninstall）"
B25=$TMP/b25
mkdir -p "$B25/bin" "$B25/tmp"
cat > "$B25/bin/uci" <<'FAKE_UCI_B25'
#!/bin/sh
S=${FAKE_UCI_STATE:?}
[ "$1" = "-q" ] && shift
[ "$1" = "-c" ] && shift 2
cmd=$1
shift
split_path() {
	P=$1
	CFG=${P%%.*}
	REST=${P#*.}
	SEC=${REST%%.*}
	OPT=""
	[ "$REST" != "$SEC" ] && OPT=${REST#*.}
}
case "$cmd" in
show)
	[ "${1:-}" = "mwan3" ] || exit 1
	cat "$S/show" 2>/dev/null
	exit 0
	;;
get)
	split_path "$1"
	if [ "$CFG" = "mwan3" ]; then
		if [ -z "$OPT" ]; then
			grep -q "^mwan3\.$SEC=" "$S/show" 2>/dev/null || exit 1
			sed -n "s/^mwan3\.$SEC=//p" "$S/show" | head -1
			exit 0
		fi
		[ -f "$S/data/$SEC.$OPT" ] || exit 1
		tr '\n' ' ' < "$S/data/$SEC.$OPT" | sed 's/ $//'
		exit 0
	fi
	if [ "$CFG" = "network" ]; then
		if [ -z "$OPT" ]; then
			[ -f "$S/net/$SEC.type" ] || exit 1
			cat "$S/net/$SEC.type"
			exit 0
		fi
		[ -f "$S/net/$SEC.$OPT" ] || exit 1
		cat "$S/net/$SEC.$OPT"
		exit 0
	fi
	exit 1
	;;
set)
	split_path "${1%%=*}"
	VAL=${1#*=}
	[ "$CFG" = "mwan3" ] || exit 1
	if [ -z "$OPT" ]; then
		grep -q "^mwan3\.$SEC=" "$S/show" 2>/dev/null ||
			echo "mwan3.$SEC=$VAL" >> "$S/show"
	else
		printf '%s\n' "$VAL" > "$S/data/$SEC.$OPT"
	fi
	exit 0
	;;
add_list)
	split_path "${1%%=*}"
	VAL=${1#*=}
	[ "$CFG" = "mwan3" ] || exit 1
	[ -n "$OPT" ] || exit 1
	printf '%s\n' "$VAL" >> "$S/data/$SEC.$OPT"
	exit 0
	;;
delete)
	split_path "$1"
	[ "$CFG" = "mwan3" ] || exit 1
	if [ -z "$OPT" ]; then
		rm -f "$S/data/$SEC".*
		grep -v "^mwan3\.$SEC=" "$S/show" > "$S/show.new" 2>/dev/null
		mv "$S/show.new" "$S/show"
	else
		rm -f "$S/data/$SEC.$OPT"
	fi
	exit 0
	;;
commit)
	echo commit >> "$S/commit.log"
	exit 0
	;;
revert)
	echo revert >> "$S/revert.log"
	exit 0
	;;
esac
exit 1
FAKE_UCI_B25
cat > "$B25/bin/nft" <<'FAKE_NFT_B25'
#!/bin/sh
[ "$1" = "-a" ] && shift
cmd=$1
shift
case "$cmd" in
list)
	case "$*" in
	"table inet mwan3") exit 0 ;;
	"chain inet mwan3 mwan3_rules")
		echo "table inet mwan3 {"
		echo "	chain mwan3_rules {"
		echo "		ip daddr @isp_tel meta mark & 0x00003f00 == 0x00000000 jump mwan3_policy_wan_only"
		echo "	}"
		echo "}"
		exit 0
		;;
	"chain inet mwan3 mwan3_output") exit 0 ;;
	"counter inet mwan3 isp_fallback")
		echo 'counter isp_fallback { packets 0 bytes 0 }'
		exit 0
		;;
	*) exit 1 ;;
	esac
	;;
esac
exit 0
FAKE_NFT_B25
chmod +x "$B25/bin/uci" "$B25/bin/nft"

cat > "$B25/conf" <<'B25_CONF'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
cmcc:isp_cmcc:wanb_only:0
"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
COUNT_FALLBACK="0"
B25_CONF
cat > "$B25/conf-protect" <<'B25_CONF2'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
cmcc:isp_cmcc:isp_only:1
"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
COUNT_FALLBACK="0"
B25_CONF2
cp "$FIX/mwan3" "$B25/mwan3"

b25_iface() { # <state> <name> <enabled> <proto> <device>
	echo "mwan3.$2=interface" >> "$1/show"
	printf '%s\n' "$3" > "$1/data/$2.enabled"
	printf 'ipv4\n' > "$1/data/$2.family"
	printf 'interface\n' > "$1/net/$2.type"
	printf '%s\n' "$4" > "$1/net/$2.proto"
	printf '%s\n' "$5" > "$1/net/$2.device"
}

b25_reset() { # <state> [with-disabled-defaults]
	rm -rf "$1"
	mkdir -p "$1/data" "$1/net"
	: > "$1/show"
	: > "$1/commit.log"
	b25_iface "$1" wan1 1 static wan1
	b25_iface "$1" wan2 1 pppoe eth2
	if [ "${2:-}" = "defaults" ]; then
		b25_iface "$1" wan 0 dhcp eth0
		b25_iface "$1" wanb 0 dhcp eth1
	fi
}

b25_policy() { # <state> <policy> <member> <iface> [marked]
	echo "mwan3.$2=policy" >> "$1/show"
	echo "mwan3.$2.use_member=$3" >> "$1/show"
	echo "mwan3.$3=member" >> "$1/show"
	echo "$3" > "$1/data/$2.use_member"
	printf '%s\n' "$4" > "$1/data/$3.interface"
	if [ "${5:-}" = "marked" ]; then
		echo 1 > "$1/data/$2.isp_split"
		echo 1 > "$1/data/$3.isp_split"
	fi
	return 0
}

b25_run() { # <state> <conf> <args...>
	_b25_st=$1
	_b25_cf=$2
	shift 2
	(
		PATH="$B25/bin:$PATH"
		TMPDIR="$B25/tmp"
		FAKE_UCI_STATE="$_b25_st"
		ISP_SPLIT_CONF="$_b25_cf"
		ISP_SPLIT_BASE="$B25/base"
		ISP_SPLIT_LIB="$LIB"
		ISP_SPLIT_MWAN3="$B25/mwan3"
		DNSMASQ_CONF_GLOB="$B25/no-such-dnsmasq.conf.*"
		DNSMASQ_DEFAULT_DIR="$B25/dnsmasq.d"
		export PATH TMPDIR FAKE_UCI_STATE ISP_SPLIT_CONF ISP_SPLIT_BASE \
			ISP_SPLIT_LIB ISP_SPLIT_MWAN3 DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR
		sh "$ROOT/files/usr/sbin/isp-split" "$@"
	)
}

b25_lib() { # <state> <conf> <function> [args]
	_b25_st=$1
	_b25_cf=$2
	shift 2
	(
		PATH="$B25/bin:$PATH"
		TMPDIR="$B25/tmp"
		FAKE_UCI_STATE="$_b25_st"
		ISP_SPLIT_CONF="$_b25_cf"
		ISP_SPLIT_BASE="$B25/base"
		ISP_SPLIT_LIB="$LIB"
		ISP_SPLIT_MWAN3="$B25/mwan3"
		export PATH TMPDIR FAKE_UCI_STATE ISP_SPLIT_CONF ISP_SPLIT_BASE \
			ISP_SPLIT_LIB ISP_SPLIT_MWAN3
		. "$TMP/isp-lib.sh"
		"$@"
	)
}

# ---- 17.1 干净环境：wire/plan 必须硬失败并提示 init ----
b25_reset "$B25/s1" defaults
cp "$FIX/mwan3" "$B25/mwan3"
b25_run "$B25/s1" "$B25/conf" wire > "$B25/wire-missing.log" 2>&1
_b25_rc=$?
if [ "$_b25_rc" -ne 0 ] &&
   grep -q "策略 'wan_only' 不存在于 mwan3" "$B25/wire-missing.log" &&
   grep -q '运行 isp-split init 绑定线路' "$B25/wire-missing.log"; then
	ok "17.1 策略缺失时 wire 硬失败并提示 isp-split init（rc=$_b25_rc）"
else
	ng "17.1 wire 未按预期硬失败/提示（rc=$_b25_rc）"
	sed 's/^/    /' "$B25/wire-missing.log"
fi
if ! grep -q '^mwan3.wan_only=' "$B25/s1/show"; then
	ok "17.1 预检失败发生在写 UCI 之前（未产生半套策略段）"
else
	ng "17.1 预检失败后仍写入了策略段"
fi

cp "$FIX/mwan3" "$B25/mwan3"
b25_run "$B25/s1" "$B25/conf" plan > "$B25/plan-missing.log" 2>&1
_b25_rc=$?
if [ "$_b25_rc" -ne 0 ] && grep -q '运行 isp-split init 绑定线路' "$B25/plan-missing.log"; then
	ok "17.2 策略缺失时 plan 硬失败并提示 init（rc=$_b25_rc）"
else
	ng "17.2 plan 未按预期硬失败/提示（rc=$_b25_rc）"
	sed 's/^/    /' "$B25/plan-missing.log"
fi

# ---- 17.3 init 非交互绑定：接口发现 + policy/member 标记 ----
b25_reset "$B25/s2" defaults
cp "$FIX/mwan3" "$B25/mwan3"
b25_run "$B25/s2" "$B25/conf" init \
	--bind wan_only=wan1 --bind wanb_only=wan2 --assume-yes \
	> "$B25/init.log" 2>&1
_b25_rc=$?
_b25_disc_ok=0
grep -q 'mwan3 接口发现' "$B25/init.log" &&
	grep -q 'wan2.*pppoe.*eth2' "$B25/init.log" &&
	grep -q 'wan1.*static.*wan1' "$B25/init.log" && _b25_disc_ok=1
if [ "$_b25_rc" -eq 0 ] && [ "$_b25_disc_ok" = "1" ] &&
   grep -q '^mwan3.wan_only=policy$' "$B25/s2/show" &&
   grep -q '^mwan3.isp_split_wan_only_m1=member$' "$B25/s2/show" &&
   [ "$(cat "$B25/s2/data/isp_split_wan_only_m1.interface")" = "wan1" ] &&
   [ "$(cat "$B25/s2/data/isp_split_wanb_only_m1.interface")" = "wan2" ] &&
   [ "$(cat "$B25/s2/data/wan_only.isp_split")" = "1" ] &&
   [ "$(cat "$B25/s2/data/isp_split_wan_only_m1.isp_split")" = "1" ] &&
   [ "$(cat "$B25/s2/data/wan_only.use_member")" = "isp_split_wan_only_m1" ]; then
	ok "17.3 init 发现接口并生成带 isp_split 标记的 policy/member（接口对应正确）"
else
	ng "17.3 init 生成结果异常（rc=$_b25_rc，发现清单=$_b25_disc_ok）"
	sed 's/^/    /' "$B25/init.log" | head -30
fi
if grep -q '== init 完成，以下为 plan 摘要' "$B25/init.log" &&
   grep -q '^isp_tel' "$B25/init.log"; then
	ok "17.4 init 结束后自动输出 plan 摘要"
else
	ng "17.4 init 未自动输出 plan 摘要"
fi

# ---- 17.5 init 后 wire 通过、verify 有策略检查行 ----
b25_run "$B25/s2" "$B25/conf" wire > "$B25/wire-ok.log" 2>&1
_b25_rc=$?
if [ "$_b25_rc" -eq 0 ] && grep -q '规则已注入' "$B25/wire-ok.log"; then
	ok "17.5 init 后 wire 通过（rc=0）"
else
	ng "17.5 init 后 wire 仍失败（rc=$_b25_rc）"
	sed 's/^/    /' "$B25/wire-ok.log"
fi
b25_run "$B25/s2" "$B25/conf" verify > "$B25/verify.log" 2>&1
if grep -q '== 策略存在且有成员' "$B25/verify.log" &&
   grep -q '✓ wan_only: isp_split_wan_only_m1(wan1)' "$B25/verify.log" &&
   grep -q '✓ wanb_only: isp_split_wanb_only_m1(wan2)' "$B25/verify.log"; then
	ok "17.5 verify 新增策略检查行并显示 ✓（策略存在且有成员）"
else
	ng "17.5 verify 策略检查行缺失或未显示 ✓"
	sed 's/^/    /' "$B25/verify.log" | sed -n '/策略存在且有成员/,/策略成员状态/p'
fi

# ---- 17.6 幂等：复跑 init 不产生重复 policy/member ----
cp "$B25/s2/show" "$B25/show.before"
b25_run "$B25/s2" "$B25/conf" init \
	--bind wan_only=wan1 --bind wanb_only=wan2 --assume-yes \
	> "$B25/init-again.log" 2>&1
_b25_rc=$?
_b25_pol=$(grep -c '=policy$' "$B25/s2/show")
_b25_mem=$(grep -c '=member$' "$B25/s2/show")
if [ "$_b25_rc" -eq 0 ] && [ "$_b25_pol" -eq 2 ] && [ "$_b25_mem" -eq 2 ] &&
   cmp -s "$B25/show.before" "$B25/s2/show" &&
   [ "$(wc -l < "$B25/s2/data/wan_only.use_member" | tr -d ' ')" = "1" ]; then
	ok "17.6 复跑 init 幂等（policy=$_b25_pol member=$_b25_mem，无重复段）"
else
	ng "17.6 复跑 init 产生重复段/差异（rc=$_b25_rc policy=$_b25_pol member=$_b25_mem）"
	diff "$B25/show.before" "$B25/s2/show" | sed 's/^/    /'
fi

# ---- 17.7 无标记同名段保护：报错且不覆盖 ----
b25_reset "$B25/s3"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s3" isp_only isp_only_m1 wan1
b25_run "$B25/s3" "$B25/conf-protect" init \
	--bind wan_only=wan1 --bind wanb_only=wan2 --bind isp_only=wan1 --assume-yes \
	> "$B25/init-protect.log" 2>&1
_b25_rc=$?
if [ "$_b25_rc" -ne 0 ] &&
   grep -q "已存在同名策略 'isp_only' 且没有 isp_split 标记" "$B25/init-protect.log" &&
   [ ! -f "$B25/s3/data/isp_only.isp_split" ] &&
   [ "$(cat "$B25/s3/data/isp_only.use_member")" = "isp_only_m1" ] &&
   [ "$(cat "$B25/s3/data/isp_only_m1.interface")" = "wan1" ]; then
	ok "17.7 无标记同名策略报错且未被覆盖（isp_only 保持原成员）"
else
	ng "17.7 无标记同名策略保护失败（rc=$_b25_rc）"
	sed 's/^/    /' "$B25/init-protect.log" | tail -8
fi

# ---- 17.8 孤儿策略/成员清理：带标记且不再被 ISP_TABLE 引用才删 ----
b25_reset "$B25/s4"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s4" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s4" old_pol old_m1 wan1 marked
b25_policy "$B25/s4" used_pol used_m1 wan1 marked
b25_policy "$B25/s4" user_pol user_m1 wan2
echo "mwan3.rule_keep=rule" >> "$B25/s4/show"
echo "used_pol" > "$B25/s4/data/rule_keep.use_policy"
b25_lib "$B25/s4" "$B25/conf" _prune_orphan_policies > "$B25/prune-pol.log" 2>&1
_b25_left=$(grep '=policy$' "$B25/s4/show" | sed 's/^mwan3\.//; s/=policy$//' | tr '\n' ' ')
if [ "$_b25_left" = "wan_only used_pol user_pol " ] &&
   grep -q '已清理孤儿策略段 old_pol' "$B25/prune-pol.log" &&
   grep -q '仍被 mwan3 规则引用，保留' "$B25/prune-pol.log" &&
   ! grep -q '^mwan3.old_m1=' "$B25/s4/show" &&
   grep -q '^mwan3.user_pol=' "$B25/s4/show"; then
	ok "17.8 只清理带标记且无引用的孤儿策略/成员（保留被规则引用与无标记段）"
else
	ng "17.8 孤儿策略清理结果异常: [$_b25_left]"
	sed 's/^/    /' "$B25/prune-pol.log"
fi

# ---- 17.9 uninstall 按标记删 policy/member，无标记段不动 ----
b25_policy "$B25/s4" keep_pol keep_m1 wan2
b25_lib "$B25/s4" "$B25/conf" _uninstall_policies > "$B25/uninstall-pol.log" 2>&1
_b25_left=$(grep '=policy$' "$B25/s4/show" | sed 's/^mwan3\.//; s/=policy$//' | tr '\n' ' ')
if [ "$_b25_left" = "user_pol keep_pol " ] &&
   ! grep -q '^mwan3.isp_split_' "$B25/s4/show" &&
   grep -q '^mwan3.keep_m1=' "$B25/s4/show"; then
	ok "17.9 uninstall 按 isp_split 标记删除 init 段，无标记策略/成员保持不动"
else
	ng "17.9 uninstall 后残留异常: [$_b25_left]"
	sed 's/^/    /' "$B25/uninstall-pol.log"
fi

# ---- 17.10 policy-check --json：LuCI 首装提示条的数据源 ----
b25_reset "$B25/s5"
cp "$FIX/mwan3" "$B25/mwan3"
b25_run "$B25/s5" "$B25/conf" policy-check --json > "$B25/pc-missing.json" 2>&1
_b25_missing=$(cat "$B25/pc-missing.json")
b25_run "$B25/s5" "$B25/conf" init \
	--bind wan_only=wan1 --bind wanb_only=wan2 --assume-yes >/dev/null 2>&1
b25_run "$B25/s5" "$B25/conf" policy-check --json > "$B25/pc-ok.json" 2>&1
_b25_ok=$(cat "$B25/pc-ok.json")
if printf '%s' "$_b25_missing" | grep -q '"ok":false' &&
   printf '%s' "$_b25_missing" | grep -q '"name":"wan_only"' &&
   printf '%s' "$_b25_ok" | grep -q '"ok":true'; then
	ok "17.10 policy-check --json 正确报告缺失/已绑定（供 LuCI 提示条）"
else
	ng "17.10 policy-check --json 输出异常"
	printf '%s\n' "$_b25_missing" "$_b25_ok" | sed 's/^/    /'
fi

# ---- 17.11 --assume-yes 无 --bind：LuCI 一键初始化的默认映射 ----
b25_reset "$B25/s6"
cp "$FIX/mwan3" "$B25/mwan3"
b25_run "$B25/s6" "$B25/conf" init --assume-yes > "$B25/init-auto.log" 2>&1
_b25_rc=$?
if [ "$_b25_rc" -eq 0 ] &&
   [ "$(cat "$B25/s6/data/isp_split_wan_only_m1.interface")" = "wan1" ] &&
   [ "$(cat "$B25/s6/data/isp_split_wanb_only_m1.interface")" = "wan2" ] &&
   grep -q 'wan_only.*-> wan1' "$B25/init-auto.log" &&
   grep -q 'wanb_only.*-> wan2' "$B25/init-auto.log"; then
	ok "17.11 --assume-yes 无 --bind 时按顺序默认绑定（LuCI 一键初始化）"
else
	ng "17.11 --assume-yes 默认绑定异常（rc=$_b25_rc）"
	sed 's/^/    /' "$B25/init-auto.log" | head -25
fi

echo
echo "通过 $pass 项，失败 $fail 项"
if [ "$fail" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
	echo "（非 root 环境：依赖 uid=0 属主校验的 2 项属预期失败，已由 VM 覆盖）"
fi
[ "$fail" -eq 0 ]
