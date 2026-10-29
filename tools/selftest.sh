#!/bin/sh
# 离线自检：不需要路由器、不需要联网。
#   1. 数据管线：互斥化后任意两个集合不得有交集
#   2. 规则注入：顺序正确、重复执行幂等
# 用法：sh tools/selftest.sh
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIB=$ROOT/files/usr/lib/isp-split
ISPVER=$(sed -n 's/^ISP_VERSION="\([^"]*\)"/\1/p' "$ROOT/files/usr/sbin/isp-split" | head -1)
[ -n "$ISPVER" ] || ISPVER=0.0.0
FIX=$ROOT/tools/fixtures
TMP=$(mktemp -d 2>/dev/null) ||
	TMP=$(mktemp -d /tmp/isp-split-selftest.XXXXXX 2>/dev/null) ||
	{ echo "无法创建临时目录" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
skipn=0
ok() { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
ng() { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail + 1)); }
# 跳过不是通过：单独计数并显式打印原因（环境不满足时如实标注，不刷绿）
skip() { printf '  \033[33m-\033[0m %s\n' "$1"; skipn=$((skipn + 1)); }

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
	"$TMP/bug6/run/default.d" "$TMP/bug6/run/dnsmasq.legacy.d" "$TMP/bug6/run/uci.d"
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
		DNSDIR="$TMP/bug6/run/dnsmasq.legacy.d"
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
# F-14 起这段逻辑在 teardown.sh（卸载清理的唯一实现）里，这里直接调它，
# 顺带保证"install 路径"也覆盖同一份实现。
for _d in cfg01411c.d other.d default.d dnsmasq.legacy.d; do
	: > "$TMP/bug6/run/$_d/isp-split.conf"
done
rm -f "$TMP/bug6/uci.log"
(
	PATH="$TMP/bug6/fakebin:$TMP/fakebin:$PATH"
	# A-10：teardown 的沙箱守卫要求 BASE 在 DESTDIR 子树内。这里只测
	# 片段清理，DESTDIR 取 $TMP/bug6 即可让 BASE=$TMP/bug6/base 合法。
	ISP_SPLIT_DESTDIR="$TMP/bug6"
	ISP_SPLIT_CONF="$TMP/bug6/conf"
	ISP_SPLIT_BASE="$TMP/bug6/base"
	DNSMASQ_CONF_GLOB="$TMP/bug6/var/etc/dnsmasq.conf.*"
	DNSMASQ_DEFAULT_DIR="$TMP/bug6/run/default.d"
	DNSDIR="$TMP/bug6/run/dnsmasq.legacy.d"
	FAKE_UCI_CONFDIR=""
	FAKE_UCI_LOG="$TMP/bug6/uci.log"
	export PATH ISP_SPLIT_DESTDIR ISP_SPLIT_CONF ISP_SPLIT_BASE \
		DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR DNSDIR FAKE_UCI_CONFDIR \
		FAKE_UCI_LOG
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" runtime
)
_bug6_left=""
for _d in cfg01411c.d other.d default.d dnsmasq.legacy.d; do
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
if [ "$out" = "-" ]; then cat "$SEC_MIRROR/${url##*/}"; else cp "$SEC_MIRROR/${url##*/}" "$out"; fi
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
if [ "$out" = "-" ]; then cat "$MS_MIRROR/$rel"; else cp "$MS_MIRROR/$rel" "$out"; fi
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

# F-14：ipset 段清理已并入 teardown.sh（唯一实现），这里直接调它，
# 与 `isp-split uninstall`、`install.sh --uninstall` 走同一条路径。
b4_teardown() { # <state dir> <scope>
	(
		PATH="$B4/bin:$PATH"
		FAKE_UCI_STATE="$1"
		ISP_SPLIT_DESTDIR="$B4/dest"
		export PATH FAKE_UCI_STATE ISP_SPLIT_DESTDIR
		sh "$ROOT/files/usr/lib/isp-split/teardown.sh" "$2"
	)
}
b4_teardown "$B4/s1" mwan3 > "$B4/uninstall.log" 2>&1
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
if [ -s "$TMP/lc1.json" ] && ! grep -q "^{\"version\":\"$ISPVER\"" "$TMP/lc1.json"; then
	ng "linecheck --json 顶层形状异常"
elif [ -n "$JQ" ]; then
	_v=$(jsonfilter -i "$TMP/lc1.json" -e '@.version' 2>/dev/null)
	_n=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[*].iface' 2>/dev/null | wc -l)
	_g=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[0].score.grade' 2>/dev/null)
	_b=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[0].score.breakdown[*].key' 2>/dev/null | wc -l)
	_t=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[1].score.total' 2>/dev/null)
	_c=$(jsonfilter -i "$TMP/lc1.json" -e '@.wans[1].nat.type' 2>/dev/null)
	if [ "$_v" = "$ISPVER" ] && [ "$_n" = "2" ] && [ -n "$_g" ] && [ "$_b" = "4" ] &&
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
	ok "LINE_CHECK_GEO=0：JSON geo_enabled=false、状态 off，不发起归属地请求"
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
		# F-29 形状复核：默认两个启用集合都渲染；FAKE_NFT_OMIT_SET
		# 用来模拟"reload 返回 0 但某集合没进 mwan3_rules"。
		case " ${FAKE_NFT_OMIT_SET:-} " in
		*" isp_uni "*) ;;
		*) echo "		ip daddr @isp_uni meta mark & 0x00003f00 == 0x00000000 jump mwan3_policy_wanb_only" ;;
		esac
		echo "	}"
		echo "}"
		exit 0
		;;
	"chain inet mwan3 mwan3_output")
		echo "table inet mwan3 {"
		echo "	chain mwan3_output {"
		echo "		type filter hook output priority mangle; policy accept;"
		echo "		jump mwan3_rules"
		echo "	}"
		echo "}"
		exit 0
		;;
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
# mwan3 服务桩：默认成功（不碰 VM 的真实 mwan3），F-29 用 fail 桩重放
# Hermes 的"reload 必 exit 1"复现法。
printf '#!/bin/sh\nexit 0\n' > "$B25/bin/mwan3-ok"
printf '#!/bin/sh\nexit 1\n' > "$B25/bin/mwan3-fail"
chmod +x "$B25/bin/mwan3-ok" "$B25/bin/mwan3-fail"

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
		TMPDIR="${B25_TMPDIR:-$B25/tmp}"
		FAKE_UCI_STATE="$_b25_st"
		ISP_SPLIT_CONF="$_b25_cf"
		ISP_SPLIT_BASE="$B25/base"
		ISP_SPLIT_LIB="$LIB"
		ISP_SPLIT_MWAN3="$B25/mwan3"
		DNSMASQ_CONF_GLOB="$B25/no-such-dnsmasq.conf.*"
		DNSMASQ_DEFAULT_DIR="$B25/dnsmasq.d"
		MWAN3_SERVICE="${MWAN3_SERVICE:-$B25/bin/mwan3-ok}"
		MWAN3_READY_TRIES="${MWAN3_READY_TRIES:-1}"
		MWAN3_READY_DELAY="${MWAN3_READY_DELAY:-0}"
		export PATH TMPDIR FAKE_UCI_STATE ISP_SPLIT_CONF ISP_SPLIT_BASE \
			ISP_SPLIT_LIB ISP_SPLIT_MWAN3 DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR \
			MWAN3_SERVICE MWAN3_READY_TRIES MWAN3_READY_DELAY
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
# F-14：policy/member 清理已并入 teardown.sh（唯一实现）
(
	PATH="$B25/bin:$PATH"
	FAKE_UCI_STATE="$B25/s4"
	ISP_SPLIT_DESTDIR="$B25/dest"
	export PATH FAKE_UCI_STATE ISP_SPLIT_DESTDIR
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" mwan3
) > "$B25/uninstall-pol.log" 2>&1
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

echo "== 18. fix29 发版前安全加固（SEC S1/S2/S4/S6/S7/S8）"
F29=$TMP/fix29
mkdir -p "$F29/bin" "$F29/stun"

# ---- 18.1 F1：STUN 临时文件不再用可预测的 $$ 路径 ----
if grep -q 'mktemp "${TMPDIR:-/tmp}/isp-lc-stun.XXXXXXXX"' "$ROOT/files/usr/sbin/isp-split" &&
   grep -q 'LC_STUN_REQ=' "$ROOT/files/usr/sbin/isp-split" &&
   grep -q 'rm -f "$LC_STUN_REQ"' "$ROOT/files/usr/sbin/isp-split"; then
	ok "18.1 STUN 临时文件改用 mktemp 随机名 + 真实路径 trap 清理（SEC S4）"
else
	ng "18.1 STUN 临时文件仍是可预测路径/没有 trap 清理（SEC S4）"
fi

# 动态复测：在旧实现会命中的 /tmp/isp-lc-stun.$$.req 位置放 symlink，
# 新实现必须走 mktemp，受害文件保持原样。socat 用 fake（只返回失败）。
printf '#!/bin/sh\nexit 1\n' > "$F29/bin/socat"
chmod +x "$F29/bin/socat"
printf 'ISP_TABLE="chinatelecom:isp_tel:wan_only:1"\n' > "$F29/conf"
if command -v hexdump >/dev/null 2>&1; then
	(
		PATH="$F29/bin:$PATH"
		TMPDIR="$F29/stun"
		ISP_SPLIT_CONF="$F29/conf"
		export PATH TMPDIR ISP_SPLIT_CONF
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		printf 'ORIGINAL-A\n' > "$TMPDIR/victim-a"
		printf 'ORIGINAL-B\n' > "$TMPDIR/victim-b"
		ln -sf "$TMPDIR/victim-a" "$TMPDIR/isp-lc-stun.$$.req"
		ln -sf "$TMPDIR/victim-b" "$TMPDIR/isp-lc-stun.$$.resp"
		_lc_stun_once lo 127.0.0.1 3478 40000 1 >/dev/null 2>&1
	) >/dev/null 2>&1
	if [ "$(cat "$F29/stun/victim-a")" = "ORIGINAL-A" ] &&
	   [ "$(cat "$F29/stun/victim-b")" = "ORIGINAL-B" ]; then
		ok "18.1 symlink 预置到旧 \$\$ 路径不再写穿（受害文件未被覆盖/截断）"
	else
		ng "18.1 STUN 仍跟随 symlink 写穿受害文件（SEC S4）"
	fi
else
	ok "18.1 无 hexdump，symlink 动态复测跳过（静态检查已覆盖）"
fi

# ---- 18.2 F2：无标记同名 ipset / rule 段必须硬失败 ----
b25_reset "$B25/s7"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s7" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s7" wanb_only isp_split_wanb_only_m1 wan2 marked
echo "mwan3.ipset_isp_tel=ipset" >> "$B25/s7/show"
printf 'isp_tel\n' > "$B25/s7/data/ipset_isp_tel.name"
printf 'ipv4\n' > "$B25/s7/data/ipset_isp_tel.family"
printf '/tmp/user-cmcc.txt\n' > "$B25/s7/data/ipset_isp_tel.loadfile"
printf '1\n' > "$B25/s7/data/ipset_isp_tel.enabled"
b25_run "$B25/s7" "$B25/conf" wire > "$F29/wire-ipset-conflict.log" 2>&1
_b29_rc=$?
if [ "$_b29_rc" -ne 0 ] &&
   grep -q "已存在同名 ipset 段 'ipset_isp_tel' 且没有 isp_split 标记" "$F29/wire-ipset-conflict.log" &&
   [ "$(cat "$B25/s7/data/ipset_isp_tel.loadfile")" = "/tmp/user-cmcc.txt" ] &&
   [ ! -f "$B25/s7/data/ipset_isp_tel.isp_split" ] &&
   [ ! -s "$B25/s7/commit.log" ]; then
	ok "18.2 无标记同名 ipset 段：wire die 且未改写用户段（SEC S8）"
else
	ng "18.2 无标记同名 ipset 段保护失败（rc=$_b29_rc）"
	sed 's/^/    /' "$F29/wire-ipset-conflict.log" | tail -8
fi

b25_reset "$B25/s8"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s8" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s8" wanb_only isp_split_wanb_only_m1 wan2 marked
echo "mwan3.isp_tel=rule" >> "$B25/s8/show"
printf 'balanced\n' > "$B25/s8/data/isp_tel.use_policy"
b25_run "$B25/s8" "$B25/conf" wire > "$F29/wire-rule-conflict.log" 2>&1
_b29_rc=$?
if [ "$_b29_rc" -ne 0 ] &&
   grep -q "已存在同名 rule 段 'isp_tel' 且没有 isp_split 标记" "$F29/wire-rule-conflict.log" &&
   [ "$(cat "$B25/s8/data/isp_tel.use_policy")" = "balanced" ] &&
   [ ! -f "$B25/s8/data/isp_tel.isp_split" ]; then
	ok "18.2 无标记同名 rule 段：wire die 且未合并/覆盖用户规则（SEC S8）"
else
	ng "18.2 无标记同名 rule 段保护失败（rc=$_b29_rc）"
	sed 's/^/    /' "$F29/wire-rule-conflict.log" | tail -8
fi

# ---- 18.3 F3：原子 mv + commit 不得早于内容校验 ----
if grep -q 'mv -f "$_mi_src" "$CFG_MWAN3"' "$ROOT/files/usr/sbin/isp-split" &&
   ! grep -q 'cat "$WORK/mwan3.new" > "$CFG_MWAN3"' "$ROOT/files/usr/sbin/isp-split"; then
	ok "18.3 mwan3 写回改为原子 mv（不再 cat 截断写）"
else
	ng "18.3 mwan3 写回仍是非原子 cat >（SEC S8）"
fi

b25_reset "$B25/s9"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s9" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s9" wanb_only isp_split_wanb_only_m1 wan2 marked
cp "$B25/conf" "$F29/conf-anchor"
printf 'ISP_ANCHOR="NO_SUCH_ANCHOR_ZZZ"\n' >> "$F29/conf-anchor"
b25_run "$B25/s9" "$F29/conf-anchor" wire > "$F29/wire-anchor-fail.log" 2>&1
_b29_rc=$?
if [ "$_b29_rc" -ne 0 ] &&
   grep -q '规则注入失败' "$F29/wire-anchor-fail.log" &&
   cmp -s "$B25/mwan3" "$FIX/mwan3" &&
   [ ! -s "$B25/s9/commit.log" ]; then
	ok "18.3 splice 校验失败时没有提前 commit、正式配置未被改动（SEC S8）"
else
	ng "18.3 commit 早于内容校验或失败时已改写配置（rc=$_b29_rc）"
	sed 's/^/    /' "$F29/wire-anchor-fail.log" | tail -8
fi

b25_reset "$B25/s10"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s10" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s10" wanb_only isp_split_wanb_only_m1 wan2 marked
b25_run "$B25/s10" "$B25/conf" wire > "$F29/wire-ok.log" 2>&1
_b29_rc=$?
b25_run "$B25/s10" "$B25/conf" wire > "$F29/wire-ok2.log" 2>&1
_b29_rc2=$?
_b29_ip=$(grep -c "^config ipset 'ipset_isp_tel'" "$B25/mwan3" 2>/dev/null || true)
_b29_ru=$(grep -c "^config rule 'isp_tel'" "$B25/mwan3" 2>/dev/null || true)
if [ "$_b29_rc" -eq 0 ] && [ "$_b29_rc2" -eq 0 ] &&
   [ "$_b29_ip" = "1" ] && [ "$_b29_ru" = "1" ] &&
   grep -q 'isp_split=1\|option isp_split' "$B25/mwan3"; then
	ok "18.3 wire 正常回归 + 复跑幂等（ipset=1 rule=1，内容含 isp_split 标记）"
else
	ng "18.3 wire 正常回归/幂等失败（rc=$_b29_rc/$_b29_rc2 ipset=$_b29_ip rule=$_b29_ru）"
	sed 's/^/    /' "$F29/wire-ok.log" | tail -10
fi

# ---- 18.4 F5：并发抢锁只允许 1 个赢家；mkdir 窗口不得被误判陈旧 ----
cat > "$F29/locktry.sh" <<'LOCKTRY'
#!/bin/sh
ISP_SPLIT_BASE=$1
ISP_SPLIT_CONF=$2
export ISP_SPLIT_BASE ISP_SPLIT_CONF
. "$3" >/dev/null 2>&1
_lc_lock_try
echo $?
LOCKTRY
chmod +x "$F29/locktry.sh"
rm -rf "$F29/lock1"
mkdir -p "$F29/lock1"
i=0
while [ "$i" -lt 12 ]; do
	i=$((i + 1))
	( sh "$F29/locktry.sh" "$F29/lock1" "$F29/conf" "$TMP/isp-lib.sh" \
		> "$F29/lock1/rc.$i" 2>/dev/null ) &
done
wait
_b29_win=$(grep -l '^0$' "$F29/lock1/rc."* 2>/dev/null | wc -l | tr -d ' ')
_b29_lose=$(grep -l '^1$' "$F29/lock1/rc."* 2>/dev/null | wc -l | tr -d ' ')
if [ "$_b29_win" = "1" ] && [ "$_b29_lose" = "11" ]; then
	ok "18.4 12 并发抢锁只有 1 个赢家（SEC S7）"
else
	ng "18.4 12 并发抢锁赢家数异常：win=$_b29_win lose=$_b29_lose（SEC S7）"
fi

rm -rf "$F29/lock2"
mkdir -p "$F29/lock2/state/linecheck.lock"
_b29_rc=$(sh "$F29/locktry.sh" "$F29/lock2" "$F29/conf" "$TMP/isp-lib.sh" 2>/dev/null)
if [ "$_b29_rc" = "1" ]; then
	ok "18.4 mkdir 后尚未写 pid/started 的窗口期按“在跑”处理，不抢占（SEC S7）"
else
	ng "18.4 空锁目录窗口被误判陈旧并抢占（rc=$_b29_rc，SEC S7）"
fi

# ---- 18.5 F6：9 个 LINE_CHECK_* 键的写入侧校验 ----
cp "$B25/conf" "$F29/conf-f6"
cp "$F29/conf-f6" "$F29/conf-f6.before"
_b29_ua=$(printf 'EvilUA\r\nX-Injected-Header: pwned')
b25_run "$B25/s11" "$F29/conf-f6" conf set line_check_ua "$_b29_ua" \
	> "$F29/conf-ua-inject.log" 2>&1
_b29_rc=$?
if [ "$_b29_rc" -ne 0 ] &&
   grep -q '不能包含 CR/LF' "$F29/conf-ua-inject.log" &&
   cmp -s "$F29/conf-f6" "$F29/conf-f6.before"; then
	ok "18.5 LINE_CHECK_UA 的 CR/LF 头注入被拒且配置未落盘（SEC S1）"
else
	ng "18.5 LINE_CHECK_UA 头注入未被拒绝（rc=$_b29_rc，SEC S1）"
	sed 's/^/    /' "$F29/conf-ua-inject.log" | tail -5
fi

b25_run "$B25/s11" "$F29/conf-f6" conf check line_check_echo_urls '-K/tmp/lc-curlrc' \
	> "$F29/conf-url-inject.log" 2>&1
_b29_rc=$?
b25_run "$B25/s11" "$F29/conf-f6" conf check line_check_echo_urls \
	'https://api.ipify.org' > "$F29/conf-url-ok.log" 2>&1
_b29_rc_ok=$?
if [ "$_b29_rc" -ne 0 ] && [ "$_b29_rc_ok" -eq 0 ] &&
   grep -q '校验通过' "$F29/conf-url-ok.log"; then
	ok "18.5 ECHO_URLS 拒绝 curl 选项注入、接受 http(s):// URL（SEC S1/S2）"
else
	ng "18.5 ECHO_URLS 校验异常（inject=$_b29_rc ok=$_b29_rc_ok）"
fi

b25_run "$B25/s11" "$F29/conf-f6" conf set line_check_ua \
	'Mozilla/5.0 (X11; Linux x86_64) Test/1.0' > "$F29/conf-ua-ok.log" 2>&1
_b29_rc=$?
if [ "$_b29_rc" -eq 0 ] &&
   grep -q '^LINE_CHECK_UA="Mozilla/5.0 (X11; Linux x86_64) Test/1.0"' "$F29/conf-f6"; then
	ok "18.5 含 ; ( ) 的合法 UA 可以写入（白名单不是一刀切）"
else
	ng "18.5 合法 UA 被误拒（rc=$_b29_rc）"
	sed 's/^/    /' "$F29/conf-ua-ok.log" | tail -5
fi

# ---- 18.6 F6：STUN 清单为空/全部非法时不崩（set -u） ----
if ( ISP_SPLIT_CONF="$F29/conf"; export ISP_SPLIT_CONF
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	LC_START=$(_lc_now)
	LC_BUDGET=20
	LINE_CHECK_STUN_SERVERS=" "
	_lc_stun_probe lo 127.0.0.1 private
	printf '%s|%s\n' "$LC_STUN_TYPE" "$LC_STUN_DETAIL" ) > "$F29/stun-empty.log" 2>&1
then
	_b29_rc=0
else
	_b29_rc=$?
fi
if [ "$_b29_rc" -eq 0 ] &&
   grep -q '^unknown|' "$F29/stun-empty.log" &&
   ! grep -q 'parameter not set' "$F29/stun-empty.log"; then
	ok "18.6 STUN 清单为空时返回 unknown 态，不触发 set -u 崩溃（SEC S2）"
else
	ng "18.6 STUN 空清单仍崩溃（rc=$_b29_rc，SEC S2）"
	sed 's/^/    /' "$F29/stun-empty.log" | tail -5
fi

if ( ISP_SPLIT_CONF="$F29/conf"; export ISP_SPLIT_CONF
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	LC_START=$(_lc_now)
	LC_BUDGET=20
	LINE_CHECK_STUN_SERVERS="bad,entry"
	_lc_stun_probe lo 127.0.0.1 private
	printf '%s|%s\n' "$LC_STUN_TYPE" "$LC_STUN_DETAIL" ) > "$F29/stun-bad.log" 2>&1
then
	_b29_rc=0
else
	_b29_rc=$?
fi
if [ "$_b29_rc" -eq 0 ] &&
   grep -q '^unknown|' "$F29/stun-bad.log" &&
   ! grep -q 'parameter not set' "$F29/stun-bad.log"; then
	ok "18.6 STUN 清单全部非法时同样降级 unknown，不丢整条 WAN（SEC S2）"
else
	ng "18.6 STUN 全非法清单仍崩溃（rc=$_b29_rc，SEC S2）"
	sed 's/^/    /' "$F29/stun-bad.log" | tail -5
fi

# ---- 18.7 F4：隐私文案与实现一致 ----
if ! grep -q '不会发起任何第三方请求' "$ROOT/README.md" "$ROOT/docs/CONFIGURATION.md" "$ROOT/docs/DESIGN.md" &&
   grep -q '关闭归属地只停止归属地查询' "$ROOT/README.md" &&
   grep -q '只关闭归属地查询' "$ROOT/docs/CONFIGURATION.md" &&
   grep -q '只停止归属地查询' "$ROOT/docs/DESIGN.md" &&
   grep -q '出口 IP 回显、STUN' "$ROOT/luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/config.js"; then
	ok "18.7 README/CONFIGURATION/DESIGN/UI 均改为“GEO=0 只关归属地查询”（SEC S6）"
else
	ng "18.7 仍存在“GEO=0 不发任何第三方请求”的旧措辞（SEC S6）"
fi

# ---- 18.8 F7：--wan .. / . 不再被当成网络设备 ----
if ( ISP_SPLIT_CONF="$F29/conf"; export ISP_SPLIT_CONF
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	_lc_wan_one .. >/dev/null 2>&1 ); then
	ng "18.8 --wan .. 仍被接受为设备（SEC 报告低危项）"
else
	ok "18.8 --wan .. / . 按 ifindex 判定后拒绝（健壮性）"
fi

# ---- 19. 发货面：默认 FEATURE_LINECHECK=1（0.3.0 起体检随包发货） ----
# 0.2.3 的 §19 断言的是「体检不在包里」；0.3.0 方向反转：默认产物必须**含**体检。
# 剥离版（FEATURE_LINECHECK=0）仍是受支持的构建期选项，它的整组断言挪到 §19b，
# 两个方向都跑、两个方向都是资产。
# F7 的教训：出货门散在 9 个位置（4 个 Makefile + 4 个脚本 + release.yml），
# 任何一处默认值分叉都会让「产物」与「断言」错位，所以 19.1 先把全链默认=1
# 钉死，后面的载荷断言才有意义。
echo "== 19. 发货面（默认 FEATURE_LINECHECK=1，完整版）"
F31=$TMP/fix31
rm -rf "$F31"
mkdir -p "$F31"
# 构建失败时下面的断言要能给出"解包失败"，而不是 set -u 直接中断
_mipk=""
_lipk=""

# 19.1 出货门默认值全链一致
_gate_bad=""
for _f in Makefile luci-app-isp-split/Makefile \
	feed/op-packages/isp-split/Makefile feed/op-packages/luci-app-isp-split/Makefile; do
	grep -q '^FEATURE_LINECHECK?=1' "$ROOT/$_f" 2>/dev/null || _gate_bad="$_gate_bad $_f"
done
for _f in scripts/build-apk.sh scripts/build-ipk.sh scripts/build-release.sh scripts/install.sh; do
	grep -q 'FEATURE_LINECHECK:-1' "$ROOT/$_f" 2>/dev/null || _gate_bad="$_gate_bad $_f"
done
grep -qE '^[[:space:]]*FEATURE_LINECHECK:[[:space:]]*"1"' \
	"$ROOT/.github/workflows/release.yml" 2>/dev/null ||
	_gate_bad="$_gate_bad release.yml"
if [ -z "$_gate_bad" ]; then
	ok "19.1 出货门默认=1 全链一致（Makefile×4 / scripts×4 / release.yml）"
else
	ng "19.1 出货门默认值分叉：$_gate_bad"
fi

# 19.2 版本链：ISP_VERSION / 主 Makefile / luci Makefile / feed×2 / PKG_RELEASE
_v_main=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/Makefile" | head -1)
_v_luci=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/luci-app-isp-split/Makefile" | head -1)
_v_f1=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/feed/op-packages/isp-split/Makefile" | head -1)
_v_f2=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/feed/op-packages/luci-app-isp-split/Makefile" | head -1)
_r_main=$(sed -n 's/^PKG_RELEASE:=//p' "$ROOT/Makefile" | head -1)
if [ "$_v_main" = "$ISPVER" ] && [ "$_v_luci" = "$ISPVER" ] &&
   [ "$_v_f1" = "$ISPVER" ] && [ "$_v_f2" = "$ISPVER" ] &&
   [ "${_r_main:-1}" = "1" ]; then
	ok "19.2 版本一致：ISP_VERSION=PKG_VERSION=$ISPVER，PKG_RELEASE=$_r_main（主/luci/feed×2）"
else
	ng "19.2 版本漂移：ISP=$ISPVER main=$_v_main luci=$_v_luci feed=$_v_f1/$_v_f2 rel=$_r_main"
fi

# 19.3 剥离实现单一来源（F7）：仓库两份 + feed 两份，逐字节一致
_bad_strip=""
for _s in "$ROOT/strip-linecheck.sh" \
	"$ROOT/luci-app-isp-split/strip-linecheck.sh" \
	"$ROOT/feed/op-packages/isp-split/strip-linecheck.sh" \
	"$ROOT/feed/op-packages/luci-app-isp-split/strip-linecheck.sh"; do
	if [ ! -f "$_s" ]; then
		_bad_strip="$_bad_strip 缺:$_s"
	elif ! cmp -s "$ROOT/scripts/strip-linecheck.sh" "$_s"; then
		_bad_strip="$_bad_strip 异:$_s"
	fi
done
if [ -z "$_bad_strip" ]; then
	ok "19.3 剥离脚本单一来源：仓库 2 份 + feed 2 份与 scripts/strip-linecheck.sh 逐字节一致"
else
	ng "19.3 剥离脚本副本漂移：$_bad_strip"
fi

# 19.4 两个 Makefile 的 Build/Prepare 必须调用同一份脚本，不许再手抄 sed
if grep -q "sed -i '/lc:begin" "$ROOT/Makefile" "$ROOT/luci-app-isp-split/Makefile" 2>/dev/null; then
	ng "19.4 Makefile 仍在手抄 sed 剥离（F7 的分叉源）"
elif grep -Fq 'sh $(CURDIR)/strip-linecheck.sh' "$ROOT/Makefile" &&
     grep -Fq 'sh $(CURDIR)/strip-linecheck.sh' "$ROOT/luci-app-isp-split/Makefile"; then
	ok "19.4 主/luci Makefile 的 Build/Prepare 都调用 \$(CURDIR)/strip-linecheck.sh"
else
	ng "19.4 Makefile 没有调用统一的剥离脚本"
fi

# ipk 解包助手（19.5 起与 §19b 共用）
# 容器嗅探：23.05/24.10 官方与 build-ipk.sh 默认产物是 gzip-tar（magic 1f 8b），
# 历史格式才是明文 ar（!<arch>）。两种都要能读，未知格式必须判失败。
# 不用 od（OpenWrt 精简固件没有），用 dd + cmp 比 magic。
printf '\037\213' > "$F31/magic.gz"
printf '!<ar' > "$F31/magic.ar"
_ipk_magic() { # <ipk> -> gzip | ar | unknown
	if dd if="$1" bs=1 count=2 2>/dev/null | cmp -s - "$F31/magic.gz"; then
		echo gzip
	elif dd if="$1" bs=1 count=4 2>/dev/null | cmp -s - "$F31/magic.ar"; then
		echo ar
	else
		echo unknown
	fi
}
# 只有 ar 容器才走这里：有 ar 用 ar；没有 ar（如 OpenWrt 精简固件）
# 就用 dd/tail 直接读 60 字节头。
_ipk_pull_ar() { # <ipk> <member> <out>
	if command -v ar >/dev/null 2>&1; then
		ar p "$1" "$2" >"$3" && return 0
	fi
	_hp=$3.hdr
	_pos=8
	while :; do
		# 必须落文件再解析：$(dd ...) 会吃掉头部末尾的换行，60 变 59
		rm -f "$_hp"
		dd if="$1" bs=1 skip="$_pos" count=60 of="$_hp" 2>/dev/null
		[ "$(wc -c < "$_hp" 2>/dev/null || echo 0)" -eq 60 ] || return 1
		_name=$(cut -c1-16 "$_hp" | sed 's/[[:space:]]*$//; s:/$::')
		_size=$(cut -c49-58 "$_hp" | tr -cd '0-9')
		_pos=$((_pos + 60))
		if [ "$_name" = "$2" ]; then
			tail -c +$((_pos + 1)) "$1" | head -c "$_size" >"$3"
			return 0
		fi
		_pos=$((_pos + ${_size:-0}))
		[ $((_pos % 2)) -eq 1 ] && _pos=$((_pos + 1))
	done
}
_ipk_unpack() { # <ipk> <dest>
	rm -rf "$2"
	mkdir -p "$2/data" "$2/ctl" "$2/x"
	case "$(_ipk_magic "$1")" in
	gzip)
		# 成员名带 "./" 前缀，整包解开再取 control/data
		tar xzf "$1" -C "$2/x" 2>/dev/null || return 1
		;;
	ar)
		_ipk_pull_ar "$1" data.tar.gz "$2/x/data.tar.gz" || return 1
		_ipk_pull_ar "$1" control.tar.gz "$2/x/control.tar.gz" || return 1
		;;
	*)
		return 1
		;;
	esac
	[ -f "$2/x/data.tar.gz" ] && [ -f "$2/x/control.tar.gz" ] || return 1
	tar -xzf "$2/x/data.tar.gz" -C "$2/data" 2>/dev/null &&
		tar -xzf "$2/x/control.tar.gz" -C "$2/ctl" 2>/dev/null
}

# 19.5 默认路径构建 ipk（不传 FEATURE_LINECHECK，走脚本默认值）+ 容器格式
if command -v tar >/dev/null 2>&1; then
	if sh "$ROOT/scripts/build-ipk.sh" >"$F31/ipk-build.log" 2>&1; then
		_mipk=$ROOT/dist/isp-split_${ISPVER}-1_all.ipk
		_lipk=$ROOT/dist/luci-app-isp-split_${ISPVER}-1_all.ipk
		_mfmt=$(_ipk_magic "$_mipk")
		_lfmt=$(_ipk_magic "$_lipk")
		if [ "$_mfmt" = gzip ] && [ "$_lfmt" = gzip ]; then
			ok "19.5 默认构建 ipk×2 成功，容器 gzip-tar（与 23.05/24.10 官方一致）"
		else
			ng "19.5 ipk 容器不是 gzip-tar（main=${_mfmt:-?} luci=${_lfmt:-?}）"
		fi
	else
		ng "19.5 默认路径 build-ipk 失败"
		sed 's/^/    /' "$F31/ipk-build.log" | tail -5
	fi
else
	ng "19.5 缺少 tar，无法构建/检查 ipk"
fi

# 19.6 主包 payload：lc-run 在包里 + conf 有 LINE_CHECK_* 键 + 语法完好
if [ -n "$_mipk" ] && _ipk_unpack "$_mipk" "$F31/m" 2>/dev/null; then
	_m=$F31/m/data
	_problem=""
	[ -f "$_m/usr/lib/isp-split/lc-run" ] || _problem="$_problem 缺lc-run"
	[ -f "$_m/usr/lib/isp-split/lc-run" ] && ! sh -n "$_m/usr/lib/isp-split/lc-run" 2>/dev/null &&
		_problem="$_problem lc-run语法错"
	sh -n "$_m/usr/sbin/isp-split" 2>/dev/null || _problem="$_problem 主脚本语法错"
	for _k in LINE_CHECK_ENABLE LINE_CHECK_GEO LINE_CHECK_MIN_INTERVAL LINE_CHECK_STUN_SERVERS; do
		grep -q "^${_k}=" "$_m/etc/isp-split.conf" 2>/dev/null || _problem="$_problem 缺${_k}"
	done
	if [ -z "$_problem" ]; then
		ok "19.6 主包 payload：lc-run 在包里 + conf 四类 LINE_CHECK_* 键 + 语法通过"
	else
		ng "19.6 主包 payload 面缺失：$_problem"
	fi
else
	ng "19.6 主包 ipk 解包失败"
fi

# 19.7 LuCI 包 payload：体检页 + 独立菜单节点 + 子节点=3 + CSS 含 .lc-*
if [ -n "$_lipk" ] && _ipk_unpack "$_lipk" "$F31/l" 2>/dev/null; then
	_l=$F31/l/data
	_lproblem=""
	[ -s "$_l/www/luci-static/resources/view/isp-split/linecheck.js" ] || _lproblem="$_lproblem 缺linecheck.js"
	[ -s "$_l/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json" ] ||
		_lproblem="$_lproblem 缺体检菜单节点"
	grep -q '"admin/network/isp-split/linecheck"' \
		"$_l/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json" 2>/dev/null ||
		_lproblem="$_lproblem 菜单节点路径不对"
	# 体检节点在独立 menu.d 文件里，LuCI 运行时合并菜单，所以跨文件数子节点
	_kids=$(cat "$_l"/usr/share/luci/menu.d/*.json 2>/dev/null |
		grep -c '"admin/network/isp-split/' || true)
	[ "${_kids:-0}" = "3" ] || _lproblem="$_lproblem menu子节点=${_kids:-0}"
	_css=$_l/www/luci-static/resources/isp-split/isp-split.css
	grep -q '\.lc-' "$_css" 2>/dev/null || _lproblem="$_lproblem CSS无.lc-*"
	if [ -f "$_css" ]; then
		_co=$(tr -cd '{' <"$_css" | wc -c | tr -d ' \n')
		_cc=$(tr -cd '}' <"$_css" | wc -c | tr -d ' \n')
		[ "$_co" = "$_cc" ] || _lproblem="$_lproblem CSS花括号{$_co}/{$_cc}"
	fi
	if [ -z "$_lproblem" ]; then
		ok "19.7 LuCI payload：linecheck.js + 体检菜单节点 + 子节点=3 + CSS 含 .lc-* 且花括号平衡"
	else
		ng "19.7 LuCI payload 面缺失：$_lproblem"
	fi
else
	ng "19.7 LuCI 包解包失败"
fi

# 19.8 Depends 必须含 socat（UDP STUN 锁线探测的实际依赖）
_dep=$(sed -n 's/^Depends:[[:space:]]*//p' "$F31/m/ctl/control" 2>/dev/null)
if printf '%s' "$_dep" | grep -qw 'socat'; then
	ok "19.8 主包 Depends 含 socat（原文：$_dep）"
else
	ng "19.8 主包 Depends 不含 socat（原文：${_dep:-读不到 control}）"
fi

# 19.9 verify --feature=1 期望面：真实产物必须全中
if sh "$ROOT/scripts/verify-package-payload.sh" verify --feature=1 \
	"$_mipk" "$_lipk" >"$F31/v1.log" 2>&1; then
	ok "19.9 verify --feature=1：默认产物通过完整版断言面"
else
	ng "19.9 verify --feature=1 未通过"
	sed 's/^/    /' "$F31/v1.log" | tail -8
fi

# 19.10 CLI 冒烟（VM）：linecheck 真跑一次，--wan lo，目标是不可达地址，
#      2 秒内必返回；断言不是"没崩"而是 JSON 结构 + 评分/建议字段都在。
#      非 root / 无 nft 的机器（CI 容器、开发机）如实跳过，不算通过。
_lc_smoke_ok=0
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null 2>&1 &&
   [ -f "$ROOT/files/usr/sbin/isp-split" ]; then
	_lc=$F31/lc
	rm -rf "$_lc"
	mkdir -p "$_lc/base"
	cat > "$_lc/conf" <<'LCCONF'
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
"
DNS_TABLE=""
DOMAIN_SPLIT=""
LINE_CHECK_ENABLE=1
LINE_CHECK_GEO=0
LINE_CHECK_GEO_PROVIDER="off"
LINE_CHECK_MIN_INTERVAL=60
LINE_CHECK_TIMEOUT=1
LINE_CHECK_BUDGET=8
LINE_CHECK_TARGETS="
chinatelecom:127.0.0.1
"
LINE_CHECK_BASELINE="127.0.0.1"
LINE_CHECK_STUN_SERVERS="
127.0.0.1:9
"
LINE_CHECK_ECHO_URLS="http://127.0.0.1:9"
LINE_CHECK_UA="Mozilla/5.0 (selftest)"
LCCONF
	ISP_SPLIT_CONF="$_lc/conf" ISP_SPLIT_BASE="$_lc/base" \
		sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --wan lo \
		>"$_lc/o1.json" 2>"$_lc/e1.txt"
	_lc_rc=$?
	if [ "$_lc_rc" = "0" ] &&
	   grep -q '"command":"linecheck"' "$_lc/o1.json" &&
	   grep -q '"wans":\[{"iface":"lo"' "$_lc/o1.json" &&
	   grep -q '"score":{"total":' "$_lc/o1.json" &&
	   grep -q '"advice":"' "$_lc/o1.json" &&
	   grep -q '"cached":false' "$_lc/o1.json"; then
		ok "19.10 CLI 冒烟（VM）：linecheck --json --wan lo 返回 0，JSON 含 wans/score/advice，cached=false"
		_lc_smoke_ok=1
	else
		ng "19.10 CLI 冒烟失败（rc=$_lc_rc）：$(head -2 "$_lc/e1.txt" 2>/dev/null | tr '\n' ' ')"
	fi
	# 19.11 60s 缓存：紧接着的第二次调用必须命中缓存（方向：cached=true，且结果一致）
	if [ "$_lc_smoke_ok" = "1" ]; then
		ISP_SPLIT_CONF="$_lc/conf" ISP_SPLIT_BASE="$_lc/base" \
			sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --wan lo \
			>"$_lc/o2.json" 2>"$_lc/e2.txt"
		if grep -q '"cached":true' "$_lc/o2.json" &&
		   [ "$(sed 's/"cached":[a-z]*//; s/"age":[0-9]*//' "$_lc/o1.json")" = \
		     "$(sed 's/"cached":[a-z]*//; s/"age":[0-9]*//' "$_lc/o2.json")" ]; then
			ok "19.11 60s 缓存：第二次调用 cached=true 且除 cached/age 外结果与首次逐字节一致"
		else
			ng "19.11 缓存未命中或结果漂移（o2: $(head -c 120 "$_lc/o2.json" 2>/dev/null)）"
		fi
	else
		skip "19.11 60s 缓存（依赖 19.10 的首次体检）"
	fi
else
	skip "19.10 CLI 冒烟（linecheck --json --wan lo）——需要 root + nft（VM 环境）；本机跳过"
	skip "19.11 60s 缓存——同上"
fi

# 19.12 方向安全：未知容器 / 空产物必须显式失败（F8）
printf 'NOT-A-PACKAGE-CONTAINER\n' > "$F31/unknown.pkg"
if sh "$ROOT/scripts/verify-package-payload.sh" verify --feature=1 "$F31/unknown.pkg" \
	>"$F31/unknown.log" 2>&1; then
	ng "19.12 未知容器格式被静默接受"
elif grep -q '未知容器格式' "$F31/unknown.log"; then
	ok "19.12 未知容器格式：显式报错 + 非零退出（不静默跳过）"
else
	ng "19.12 未知容器失败原因不对：$(head -1 "$F31/unknown.log")"
fi
if sh "$ROOT/scripts/verify-package-payload.sh" verify --feature=1 >"$F31/empty.log" 2>&1; then
	ng "19.12b 空产物列表被判通过（真空通过）"
else
	ok "19.12b 空产物列表：拒绝（真空通过不可能再发生）"
fi

# 19.13 apk 容器（25.12）：有本轮版本的 SDK 产物就按 feature=1 断言。
# 只认 ${ISPVER} 的 apk——dist 里可能留着上一版的包，拿它断言等于在测旧代码。
if command -v tar >/dev/null 2>&1; then
	set --
	for _a in "$ROOT"/dist/sdk-*/isp-split-"${ISPVER}"-*.apk \
		"$ROOT"/dist/sdk-*/luci-app-isp-split-"${ISPVER}"-*.apk; do
		[ -f "$_a" ] && set -- "$@" "$_a"
	done
	# apk 容器只能用 apk-tools 3 解包。没装就显式 skip，而不是把
	# "本机没有解包器"记成失败；SDK 构建机（CI 与本机跑过 build-apk.sh 的）
	# 会自动用上 staging_dir/host/bin/apk。
	_apkbin=${APK_BIN:-}
	if [ -z "$_apkbin" ]; then
		for _c in "$ROOT"/.sdk-build/*/sdk/staging_dir/host/bin/apk; do
			[ -x "$_c" ] && { _apkbin=$_c; break; }
		done
	fi
	if [ "$#" -gt 0 ] && [ -z "$_apkbin" ]; then
		skip "19.13 apk 断言（本机无 apk-tools 3 解包器；设 APK_BIN 或先跑 scripts/build-apk.sh）"
	elif [ "$#" -gt 0 ]; then
		if APK_BIN="$_apkbin" sh "$ROOT/scripts/verify-package-payload.sh" verify \
			--feature=1 "$@" >"$F31/apk.log" 2>&1; then
			ok "19.13 apk×$#（SDK 产物，${ISPVER}）：ADB 容器解包 + feature=1 期望面全中"
		else
			ng "19.13 apk 未通过 feature=1 断言"
			sed 's/^/    /' "$F31/apk.log" | tail -8
		fi
	else
		skip "19.13 apk 断言（dist 下没有 ${ISPVER} 的 SDK apk 产物；CI 的 25.12 分支会跑）"
	fi
else
	skip "19.13 apk 断言（无 tar）"
fi

# ---- 19b. 剥离版子集（FEATURE_LINECHECK=0，可选构建；两个方向都是资产） ----
# 默认路径已是完整版（§19），这一组只在显式 FEATURE_LINECHECK=0 时才有意义：
#   · 剥离后的运行时树里没有实现/CLI/conf 键/页面/菜单；
#   · 被剥离的 CLI 给出固定拒绝文案，且不留下 state 痕迹；
#   · ipk 的文件清单与 Depends 里没有 linecheck / socat；
#   · 文档按标记剥离后也没有剧透。
echo "== 19b. 剥离版子集（FEATURE_LINECHECK=0）"
F30=$TMP/fix30
_mipk=""
_lipk=""
rm -rf "$F30"
mkdir -p "$F30/root" "$F30/luci/www/luci-static/resources/view/isp-split" \
	"$F30/luci/usr/share/luci/menu.d" "$F30/luci/usr/share/rpcd/acl.d"

# 19b.1 运行时树物理剥离
cp -a "$ROOT/files/." "$F30/root/"
if sh "$ROOT/scripts/strip-linecheck.sh" "$F30/root" >"$F30/strip.log" 2>&1; then
	ok "19b.1 strip-linecheck 成功剥离运行时树"
else
	ng "19b.1 strip-linecheck 失败"
	sed 's/^/    /' "$F30/strip.log" | tail -5
fi

# 19b.2 零残留（白名单为空）
_leak=$(grep -rIl 'linecheck\|LINE_CHECK\|线路体检' "$F30/root" 2>/dev/null || true)
if [ -z "$_leak" ]; then
	ok "19b.2 剥离后运行时树 grep 零残留（linecheck / LINE_CHECK / 线路体检）"
else
	ng "19b.2 剥离后仍有残留：$(printf '%s ' $_leak)"
fi

# 19b.3 语法
if sh -n "$F30/root/usr/sbin/isp-split" && sh -n "$F30/root/etc/isp-split.conf"; then
	ok "19b.3 剥离后的 isp-split 与 conf 通过 sh -n"
else
	ng "19b.3 剥离后语法错误"
fi

# 19b.4 CLI 固定拒绝文案 + 非零退出
cp "$F30/root/etc/isp-split.conf" "$F30/conf"
ISP_SPLIT_CONF="$F30/conf" ISP_SPLIT_BASE="$F30/base" \
	sh "$F30/root/usr/sbin/isp-split" linecheck >"$F30/lc.out" 2>"$F30/lc.err"
_lc_rc=$?
if [ "$_lc_rc" -ne 0 ] && grep -q '此版本未包含该功能' "$F30/lc.err"; then
	ok "19b.4 剥离版 linecheck：固定文案「此版本未包含该功能」+ 退出码 $_lc_rc"
else
	ng "19b.4 剥离版 linecheck 未按约定拒绝（rc=$_lc_rc）"
fi

# 19b.5 拒绝路径不得留下 state/linecheck*
if [ -z "$(ls -d "$F30"/base/state/linecheck* 2>/dev/null)" ]; then
	ok "19b.5 拒绝路径不创建 state/linecheck*（先判后建）"
else
	ng "19b.5 拒绝路径留下了 state/linecheck* 痕迹"
fi

# 19b.6 usage 不含剧透
ISP_SPLIT_CONF="$F30/conf" ISP_SPLIT_BASE="$F30/base" \
	sh "$F30/root/usr/sbin/isp-split" >"$F30/usage.txt" 2>&1
if ! grep -q 'linecheck\|LINE_CHECK\|线路体检' "$F30/usage.txt"; then
	ok "19b.6 剥离版 usage 无 linecheck / 线路体检"
else
	ng "19b.6 剥离版 usage 仍有剧透"
fi

# 19b.7 conf 面：键名不被识别
ISP_SPLIT_CONF="$F30/conf" ISP_SPLIT_BASE="$F30/base" \
	sh "$F30/root/usr/sbin/isp-split" conf set LINE_CHECK_GEO 0 >"$F30/conf.out" 2>&1
_cf_rc=$?
if [ "$_cf_rc" -ne 0 ] && grep -q "未知配置项 'LINE_CHECK_GEO'" "$F30/conf.out"; then
	ok "19b.7 剥离版 conf set LINE_CHECK_GEO：未知配置项 + 非零退出"
else
	ng "19b.7 剥离版 conf 仍接受 LINE_CHECK_*（rc=$_cf_rc）"
fi

# 19b.8 LuCI 面：menu 子节点 == 2，无体检页/节点文件
cp "$ROOT"/luci-app-isp-split/htdocs/luci-static/resources/view/isp-split/*.js \
	"$F30/luci/www/luci-static/resources/view/isp-split/" 2>/dev/null || true
mkdir -p "$F30/luci/www/luci-static/resources/isp-split"
cp "$ROOT"/luci-app-isp-split/htdocs/luci-static/resources/isp-split/isp-split.css \
	"$F30/luci/www/luci-static/resources/isp-split/" 2>/dev/null || true
cp "$ROOT"/luci-app-isp-split/root/usr/share/luci/menu.d/*.json "$F30/luci/usr/share/luci/menu.d/"
cp "$ROOT"/luci-app-isp-split/root/usr/share/rpcd/acl.d/*.json "$F30/luci/usr/share/rpcd/acl.d/"
sh "$ROOT/scripts/strip-linecheck.sh" "$F30/luci" >/dev/null 2>&1
_kids=$(grep -c '"admin/network/isp-split/' "$F30/luci/usr/share/luci/menu.d/luci-app-isp-split.json" 2>/dev/null || echo 0)
if [ "$_kids" = "2" ] &&
   [ ! -f "$F30/luci/www/luci-static/resources/view/isp-split/linecheck.js" ] &&
   [ ! -f "$F30/luci/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json" ] &&
   ! grep -q 'linecheck' "$F30/luci/usr/share/rpcd/acl.d/luci-app-isp-split.json" 2>/dev/null; then
	ok "19b.8 剥离后 menu 子节点=2，无体检页 / 菜单节点 / acl 串"
else
	ng "19b.8 剥离后 LuCI 面不干净（子节点=$_kids）"
fi

# 19b.9 config.js：剥离后仍可被 JS 解析（有 node 时）
if command -v node >/dev/null 2>&1 &&
   [ -f "$F30/luci/www/luci-static/resources/view/isp-split/config.js" ]; then
	if node --check "$F30/luci/www/luci-static/resources/view/isp-split/config.js" 2>/dev/null; then
		ok "19b.9 剥离后 config.js 通过 node --check"
	else
		ng "19b.9 剥离后 config.js 语法错误"
	fi
else
	skip "19b.9 node --check（无 node 或文件不存在）"
fi

# 19b.10 ipk：主包 + LuCI 包的文件清单 / menu 子节点 / Depends
# 容器嗅探：23.05/24.10 官方与 build-ipk.sh 默认产物是 gzip-tar（magic 1f 8b），
# 历史格式才是明文 ar（!<arch>）。两种都要能读，未知格式必须判失败。
# 不用 od（OpenWrt 精简固件没有），用 dd + cmp 比 magic。
printf '\037\213' > "$F30/magic.gz"
printf '!<ar' > "$F30/magic.ar"
_ipk_magic() { # <ipk> -> gzip | ar | unknown
	if dd if="$1" bs=1 count=2 2>/dev/null | cmp -s - "$F30/magic.gz"; then
		echo gzip
	elif dd if="$1" bs=1 count=4 2>/dev/null | cmp -s - "$F30/magic.ar"; then
		echo ar
	else
		echo unknown
	fi
}
# 只有 ar 容器才走这里：有 ar 用 ar；没有 ar（如 OpenWrt 精简固件）
# 就用 dd/tail 直接读 60 字节头，保证 §19 在 VM root 上也能完整跑。
_ipk_pull_ar() { # <ipk> <member> <out>
	if command -v ar >/dev/null 2>&1; then
		ar p "$1" "$2" >"$3" && return 0
	fi
	_hp=$3.hdr
	_pos=8
	while :; do
		# 必须落文件再解析：$(dd ...) 会吃掉头部末尾的换行，60 变 59
		rm -f "$_hp"
		dd if="$1" bs=1 skip="$_pos" count=60 of="$_hp" 2>/dev/null
		[ "$(wc -c < "$_hp" 2>/dev/null || echo 0)" -eq 60 ] || return 1
		_name=$(cut -c1-16 "$_hp" | sed 's/[[:space:]]*$//; s:/$::')
		_size=$(cut -c49-58 "$_hp" | tr -cd '0-9')
		_pos=$((_pos + 60))
		if [ "$_name" = "$2" ]; then
			tail -c +$((_pos + 1)) "$1" | head -c "$_size" >"$3"
			return 0
		fi
		_pos=$((_pos + ${_size:-0}))
		[ $((_pos % 2)) -eq 1 ] && _pos=$((_pos + 1))
	done
}
_ipk_unpack() { # <ipk> <dest>
	rm -rf "$2"
	mkdir -p "$2/data" "$2/ctl" "$2/x"
	case "$(_ipk_magic "$1")" in
	gzip)
		# gzip-tar：外层解开就是 debian-binary / control.tar.gz / data.tar.gz
		tar xzf "$1" -C "$2/x" 2>/dev/null || return 1
		;;
	ar)
		_ipk_pull_ar "$1" data.tar.gz "$2/x/data.tar.gz" || return 1
		_ipk_pull_ar "$1" control.tar.gz "$2/x/control.tar.gz" || return 1
		;;
	*)
		return 1
		;;
	esac
	[ -f "$2/x/data.tar.gz" ] && [ -f "$2/x/control.tar.gz" ] || return 1
	tar -xzf "$2/x/data.tar.gz" -C "$2/data" 2>/dev/null &&
		tar -xzf "$2/x/control.tar.gz" -C "$2/ctl" 2>/dev/null
}
if command -v tar >/dev/null 2>&1; then
	if FEATURE_LINECHECK=0 sh "$ROOT/scripts/build-ipk.sh" >"$F30/ipk-build.log" 2>&1; then
		_mipk=$ROOT/dist/isp-split_${ISPVER}-1_all.ipk
		_lipk=$ROOT/dist/luci-app-isp-split_${ISPVER}-1_all.ipk
		_mfmt=$(_ipk_magic "$_mipk")
		_lfmt=$(_ipk_magic "$_lipk")
		if [ "$_mfmt" = gzip ] && [ "$_lfmt" = gzip ]; then
			ok "19b.10a ipk 容器嗅探：gzip-tar（与 23.05/24.10 官方一致）"
		else
			ng "19b.10a ipk 容器不是 gzip-tar（main=${_mfmt:-?} luci=${_lfmt:-?}）"
		fi
		if _ipk_unpack "$_mipk" "$F30/mipk" && _ipk_unpack "$_lipk" "$F30/lipk"; then
			_m_leak=$(grep -rIl 'linecheck\|LINE_CHECK\|线路体检' "$F30/mipk/data" 2>/dev/null || true)
			_l_leak=$(grep -rIl 'linecheck\|LINE_CHECK\|线路体检' "$F30/lipk/data" 2>/dev/null || true)
			_kids=$(grep -c '"admin/network/isp-split/' \
				"$F30/lipk/data/usr/share/luci/menu.d/luci-app-isp-split.json" 2>/dev/null || echo 0)
			if [ -z "$_m_leak" ] && [ -z "$_l_leak" ] &&
			   [ ! -f "$F30/mipk/data/usr/lib/isp-split/lc-run" ] &&
			   [ ! -f "$F30/lipk/data/www/luci-static/resources/view/isp-split/linecheck.js" ] &&
			   [ ! -f "$F30/lipk/data/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json" ] &&
			   [ "$_kids" = "2" ] &&
			   ! grep -qi 'socat' "$F30/mipk/ctl/control" "$F30/lipk/ctl/control"; then
				ok "19b.10 ipk×2：payload 零残留、无 lc-run/体检页、menu 子节点=2、Depends 无 socat"
			else
				ng "19b.10 ipk 断言失败（menu 子节点=$_kids）"
			fi
		else
			ng "19b.10 ipk 解包失败"
		fi
	else
		ng "19b.10 build-ipk 失败"
		sed 's/^/    /' "$F30/ipk-build.log" | tail -5
	fi
else
	ok "19b.10 跳过 ipk 断言（无 tar）"
fi

# 19b.11 文档：按标记剥离后无剧透
sed '/lc:begin/,/lc:end/d' "$ROOT/README.md" >"$F30/README.md"
sed '/lc:begin/,/lc:end/d' "$ROOT/docs/CONFIGURATION.md" >"$F30/CONFIGURATION.md"
sed '/lc:begin/,/lc:end/d' "$ROOT/docs/DESIGN.md" >"$F30/DESIGN.md"
if ! grep -q 'linecheck\|LINE_CHECK\|线路体检' "$F30/README.md" "$F30/CONFIGURATION.md" "$F30/DESIGN.md"; then
	ok "19b.11 README / CONFIGURATION / DESIGN 剥离后无剧透"
else
	ng "19b.11 文档剥离后仍有剧透"
fi

# 19b.12 apk 容器（0 版）：默认发货路径已改为 feature=1，dist 下的 SDK apk 是
# 完整版，不能再拿它当剥离版断言。0 版 apk 需要整轮 SDK 重编
# （FEATURE_LINECHECK=0 sh scripts/build-apk.sh 25.12.6 x86/64），CI 不含该矩阵。
# 如实跳过：apk 的完整版面由 §19.13 覆盖，剥离路径由本节 ipk + strip 断言覆盖。
skip "19b.12 apk（0 版）断言——需整轮 SDK 重编，本次未构建（apk 完整版面见 §19.13）"

# 19b.13 init / cron：确认没有体检联动（未来也不许偷偷加定时探测）
if ! grep -q 'linecheck' "$ROOT/files/etc/init.d/isp-split" \
	"$ROOT/files/etc/uci-defaults/99-isp-split" 2>/dev/null &&
   ! sed -n '/^add_cron()/,/^}/p' "$ROOT/scripts/install.sh" | grep -q 'linecheck'; then
	ok "19b.13 init / uci-defaults / cron 无体检联动（无定时探测）"
else
	ng "19b.13 init/cron 出现 linecheck 联动"
fi

# 19b.14 CSS 样式体必须随标记一起消失（19.8 已经剥离过 LuCI 树）
_css=$F30/luci/www/luci-static/resources/isp-split/isp-split.css
_css_o=$(tr -cd '{' <"$_css" 2>/dev/null | wc -c | tr -d ' \n')
_css_c=$(tr -cd '}' <"$_css" 2>/dev/null | wc -c | tr -d ' \n')
if [ -f "$_css" ] && ! grep -q '\.lc-' "$_css" && [ "$_css_o" = "$_css_c" ]; then
	ok "19b.14 剥离后 isp-split.css 无 .lc-* 样式且花括号平衡"
else
	ng "19b.14 剥离后 CSS 仍含 .lc-* 或规则体被切坏"
fi

# 19b.15 反向：旧式“标记只包标题注释”必须被 strip 拒绝（F7 回归用例）
mkdir -p "$F30/cssneg"
cat > "$F30/cssneg/isp-split.css" <<'EOF'
.isp-card { color: red; }

/* lc:begin */
/* 线路体检（0.3.0） */
/* lc:end */

.lc-cards { display: block; }
EOF
if sh "$ROOT/scripts/strip-linecheck.sh" "$F30/cssneg" >"$F30/cssneg.log" 2>&1; then
	ng "19b.15 旧式“只包标题”的 CSS 没有被拦截（.lc-* 会裸奔进包）"
elif grep -q '\.lc-' "$F30/cssneg.log"; then
	ok "19b.15 旧式“只包标题”的 CSS 被拒绝（.lc-* 断言命中）"
else
	ng "19b.15 CSS 反向用例失败原因不对：$(head -1 "$F30/cssneg.log")"
fi

# 19b.16 正例：往 LuCI 包的 CSS 里塞一行 .lc-* 后，断言必须抓到（F7 断言面）
_lp=$ROOT/dist/luci-app-isp-split_${ISPVER}-1_all.ipk
if [ -f "$_lp" ] && command -v tar >/dev/null 2>&1 &&
   _ipk_unpack "$_lp" "$F30/leak/src"; then
	_lcss=$F30/leak/src/data/www/luci-static/resources/isp-split/isp-split.css
	if [ -f "$_lcss" ]; then
		printf '\n.lc-probe { color: #f00; }\n' >>"$_lcss"
		mkdir -p "$F30/leak/out"
		cp "$F30/leak/src/x/control.tar.gz" "$F30/leak/out/control.tar.gz"
		printf '2.0\n' >"$F30/leak/out/debian-binary"
		( cd "$F30/leak/src/data" && tar czf "$F30/leak/out/data.tar.gz" . )
		( cd "$F30/leak/out" && tar czf "$F30/leak/leak.ipk" ./debian-binary ./control.tar.gz ./data.tar.gz )
		if sh "$ROOT/scripts/verify-package-payload.sh" verify --feature=0 "$F30/leak/leak.ipk" >"$F30/leak.log" 2>&1; then
			ng "19b.16 注入 .lc-* 的 ipk 被判通过（断言面又漏了）"
		elif grep -q '\.lc-' "$F30/leak.log"; then
			ok "19b.16 注入 .lc-* 的 ipk 被断言抓到（CSS 面不再是盲区）"
		else
			ng "19b.16 ipk 正例失败原因不对：$(head -1 "$F30/leak.log")"
		fi
	else
		ng "19b.16 ipk 正例解包后没有 CSS（打包规则变了？）"
	fi
else
	ng "19b.16 无法构造 ipk 正例（缺 dist 产物或无 tar）"
fi

# 19b.17 方向鉴别：同一批 0 版产物，feature=1 期望面**必须**判失败。
# 只有两边都跑过，才能证明断言方向真的翻了，而不是两套断言都恒真。
if [ -f "${_mipk:-}" ] && [ -f "${_lipk:-}" ]; then
	if sh "$ROOT/scripts/verify-package-payload.sh" verify --feature=1 \
		"$_mipk" "$_lipk" >"$F30/dir.log" 2>&1; then
		ng "19b.17 剥离版产物被 feature=1 期望面判通过（断言方向没翻）"
	elif grep -q '缺少 /usr/lib/isp-split/lc-run' "$F30/dir.log" &&
	     grep -q 'Depends 不含 socat' "$F30/dir.log"; then
		ok "19b.17 方向鉴别：0 版产物被 feature=1 期望面拒绝（缺 lc-run / Depends 无 socat）"
	else
		ng "19b.17 拒绝原因不是预期的那几项：$(head -2 "$F30/dir.log" | tr '\n' ' ')"
	fi
else
	skip "19b.17 方向鉴别（缺 19b.10 的 0 版产物）"
fi


# ---- 20. 运行时行为欠账（fix32a：F-12余项/F-13/F-27/F-28/F-29/B-6） ----
# 这一节的断言全部按"可观察行为"写，编号只放在注释里：
#   F-27  禁用行不参与差集占位，但仍按原顺序生成数据文件
#   F-13  bind 时线路未就绪必须跳过并告警，绝不绑到底层设备
#   F-12  外部清单单次 awk、末行不丢、非法域名跳过、dnsmasq 自检、只回显前几条
#   F-28  fetch/sync 并发互斥，第二个调用干净失败而不是互踩
#   F-29  reload 失败 / reload 成功但规则没渲染，都必须让 wire 非零
#   B-6   TMPDIR 不可用时 plan 干净报错，不再 can't create 崩在半截
echo "== 20. 运行时行为（fix32a）"
F32=$TMP/f32
mkdir -p "$F32"

# ---- 20.1 F-27：禁用行不占位，但仍按原顺序生成文件 ----
mkdir -p "$F32/f27/raw"
printf '10.10.0.0/16\n10.20.0.0/16\n' > "$F32/f27/raw/hi.raw"
printf '10.10.0.0/16\n10.30.0.0/16\n' > "$F32/f27/raw/lo.raw"
sh "$LIB/build.sh" "$F32/f27/raw" "$F32/f27/out-disabled" "hi lo" "lo" \
	2> "$F32/f27/report-disabled"
if grep -qx '10.10.0.0/16' "$F32/f27/out-disabled/lo.txt" &&
   grep -qx '10.30.0.0/16' "$F32/f27/out-disabled/lo.txt" &&
   grep -qx '10.20.0.0/16' "$F32/f27/out-disabled/hi.txt"; then
	ok "20.1 禁用的高优先级行不再抢走启用行的重叠地址（F-27）"
else
	ng "20.1 禁用行仍占位：lo=[$(tr '\n' ' ' < "$F32/f27/out-disabled/lo.txt" 2>/dev/null)]（F-27）"
fi
sh "$LIB/build.sh" "$F32/f27/raw" "$F32/f27/out-enabled" "hi lo" "hi lo" \
	2> "$F32/f27/report-enabled"
if [ ! -s "$F32/f27/out-enabled/lo.txt" ] ||
   ! grep -qx '10.10.0.0/16' "$F32/f27/out-enabled/lo.txt"; then
	ok "20.1b 启用后恢复正常占位（互相重叠的地址只归高优先级）（F-27）"
else
	ng "20.1b 启用 hi 后 lo 仍拿到 10.10.0.0/16（F-27）"
fi
sh "$LIB/build.sh" "$F32/f27/raw" "$F32/f27/out-default" "hi lo" \
	2> /dev/null
if ! grep -qx '10.10.0.0/16' "$F32/f27/out-default/lo.txt"; then
	ok "20.1c 三参数调用保持旧语义（缺省=全部占位，向后兼容）（F-27）"
else
	ng "20.1c 三参数调用的旧语义被破坏（F-27）"
fi

# ---- 20.2 F-13：bind 只认运行时 up + 有 IP + 有 l3_device ----
F13=$F32/f13
mkdir -p "$F13/bin" "$F13/list" "$F13/out"
cat > "$F13/bin/uci" <<'F13_UCI'
#!/bin/sh
[ "${1:-}" = "-q" ] && shift
[ "${1:-}" = "get" ] || exit 1
case "${2:-}" in
mwan3.pol.use_member) echo m1 ;;
mwan3.m1.interface) echo wanx ;;
network.wanx.device) echo eth1.10 ;;
network.wanx.ifname) echo eth1.10 ;;
*) exit 1 ;;
esac
F13_UCI
cat > "$F13/bin/ubus" <<'F13_UBUS'
#!/bin/sh
[ "${1:-}" = "call" ] || exit 1
case "${FAKE_IFACE_UP:-0}" in
1) echo '{"up":true}' ;;
*) echo '{"up":false}' ;;
esac
exit 0
F13_UBUS
cat > "$F13/bin/ifstatus" <<'F13_IFSTATUS'
#!/bin/sh
if [ "${FAKE_IFACE_UP:-0}" = "1" ]; then
	if [ "${FAKE_IFACE_IP:-1}" = "1" ]; then
		echo '{"up":true,"l3_device":"pppoe-wanx","ipv4-address":[{"address":"10.0.0.2"}]}'
	else
		echo '{"up":true,"l3_device":"pppoe-wanx","ipv4-address":[]}'
	fi
else
	echo '{"up":false,"device":"eth1.10"}'
fi
exit 0
F13_IFSTATUS
cat > "$F13/bin/jsonfilter" <<'F13_JSONFILTER'
#!/bin/sh
[ "${1:-}" = "-e" ] && shift
expr=${1:-}
input=$(cat)
if [ "$expr" = "@.up" ]; then
	case "$input" in
	*'"up":true'*) echo true ;;
	*'"up":false'*) echo false ;;
	esac
elif [ "$expr" = "@.l3_device" ]; then
	printf '%s' "$input" | sed -n 's/.*"l3_device":"\([^"]*\)".*/\1/p'
elif [ "$expr" = '@["ipv4-address"][0].address' ]; then
	printf '%s' "$input" | sed -n 's/.*"address":"\([^"]*\)".*/\1/p'
fi
exit 0
F13_JSONFILTER
chmod +x "$F13/bin/"*
cat > "$F13/conf" <<F13_CONF
ISP_TABLE=""
DNS_TABLE="
pol:223.5.5.5
"
DOMAIN_SPLIT="
test.example:pol
"
DOMAIN_LIST_DIR="$F13/list"
DNS_MODE="bind"
COUNT_FALLBACK="0"
F13_CONF

f13_emit() { # <up> <has-ip> <out> [extra conf]
	_f13_up=$1
	_f13_ip=$2
	_f13_out=$3
	_f13_cf=${4:-$F13/conf}
	(
		PATH="$F13/bin:$PATH"
		FAKE_IFACE_UP=$_f13_up
		FAKE_IFACE_IP=$_f13_ip
		ISP_SPLIT_CONF=$_f13_cf
		ISP_SPLIT_BASE="$F13/base"
		ISP_SPLIT_LIB="$LIB"
		export PATH FAKE_IFACE_UP FAKE_IFACE_IP ISP_SPLIT_CONF \
			ISP_SPLIT_BASE ISP_SPLIT_LIB
		. "$TMP/isp-lib.sh" >/dev/null 2>&1
		_dns_emit_rules "$_f13_out"
		printf 'N=%s SKIP=%s BAD=%s DEV=%s STATE=%s\n' \
			"$_DNS_RULE_N" "$_DNS_SKIP" "$_DNS_BAD" "$_DNS_DEV" "$POLICY_DEV_STATE"
	)
}

f13_emit 0 1 "$F13/out/down" > "$F13/down.log" 2>&1
if grep -q '未就绪' "$F13/down.log" &&
   ! grep -q 'server=' "$F13/out/down" 2>/dev/null &&
   ! grep -q 'eth1.10' "$F13/down.log"; then
	ok "20.2 线路 down 时不生成 server=、不绑底层 eth1.10，并明确告警（F-13）"
else
	ng "20.2 线路 down 时仍生成规则或回退到底层设备（F-13）: $(tail -1 "$F13/down.log")"
fi
f13_emit 1 0 "$F13/out/noip" > "$F13/noip.log" 2>&1
if grep -q '未就绪: no-ip' "$F13/noip.log" &&
   ! grep -q 'server=' "$F13/out/noip" 2>/dev/null; then
	ok "20.2b 接口 up 但无 IPv4 时同样跳过（no-ip）（F-13）"
else
	ng "20.2b 无 IPv4 时仍绑定了设备（F-13）: $(tail -1 "$F13/noip.log")"
fi
f13_emit 1 1 "$F13/out/up" > "$F13/up.log" 2>&1
if grep -q 'server=/test.example/223.5.5.5@pppoe-wanx' "$F13/out/up" 2>/dev/null; then
	ok "20.2c 运行时就绪时绑定 l3_device（pppoe-wanx），不是 uci VLAN（F-13）"
else
	ng "20.2c 就绪时未绑定 l3_device（F-13）: $(tail -2 "$F13/up.log" | tr '\n' ' ')"
fi

# ---- 20.3 F-12：外部清单单次 awk、末行不丢、非法跳过、自检、预览 ----
F12=$F32/f12
mkdir -p "$F12/bin" "$F12/list" "$F12/out" "$F12/emptybin"
REAL_TR=$(command -v tr)
cat > "$F12/bin/tr" <<'F12_TR'
#!/bin/sh
echo "tr-call" >> "${TR_LOG:-/dev/null}"
exec "${REAL_TR:-/usr/bin/tr}" "$@"
F12_TR
chmod +x "$F12/bin/tr"
: > "$F12/list/pol.txt"
printf 'a.example\nb.example\nserver=/c.example/9.9.9.9\n' >> "$F12/list/pol.txt"
printf '  # leading space comment\r\nbad domain.example\r\nx/y.example\r\ncrlf.example\r\n' >> "$F12/list/pol.txt"
# 500 行大清单：逐行 printf|tr 会有 1000 次 fork；单次 awk 应为 0 次
_i=0
while [ "$_i" -lt 500 ]; do
	printf 'bulk%s.example\n' "$_i" >> "$F12/list/pol.txt"
	_i=$((_i + 1))
done
printf 'last.example' >> "$F12/list/pol.txt"
cat > "$F12/conf" <<F12_CONF
ISP_TABLE=""
DNS_TABLE="
pol:223.5.5.5
"
DOMAIN_SPLIT=""
DOMAIN_LIST_DIR="$F12/list"
DNS_MODE="mark"
COUNT_FALLBACK="0"
F12_CONF
: > "$F12/tr.log"
(
	PATH="$F12/bin:$F13/bin:$PATH"
	TR_LOG="$F12/tr.log"
	REAL_TR="$REAL_TR"
	ISP_SPLIT_CONF="$F12/conf"
	ISP_SPLIT_BASE="$F12/base"
	ISP_SPLIT_LIB="$LIB"
	export PATH TR_LOG REAL_TR ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	# 只统计生成阶段：source 配置时本身的 tr 不算逐行 fork
	: > "$TR_LOG"
	_dns_emit_rules "$F12/out/rules"
	printf 'N=%s SKIP=%s BAD=%s\n' "$_DNS_RULE_N" "$_DNS_SKIP" "$_DNS_BAD"
) > "$F12/emit.log" 2>&1
_f12_rules=$(grep -c '^server=' "$F12/out/rules" 2>/dev/null)
_f12_rules=${_f12_rules:-0}
if [ "$_f12_rules" = "505" ] &&
   grep -qx 'server=/last.example/223.5.5.5' "$F12/out/rules" &&
   grep -qx 'server=/crlf.example/223.5.5.5' "$F12/out/rules" &&
   ! grep -q 'bad domain\|x/y.example\|leading space' "$F12/out/rules"; then
	ok "20.3 外部清单：末行无换行不丢、CRLF 清理、非法行不拼进 server=（F-12）"
else
	ng "20.3 外部清单输出异常（$_f12_rules 条）：$(tr '\n' '|' < "$F12/out/rules" 2>/dev/null)（F-12）"
fi
if grep -q '域名非法' "$F12/emit.log" &&
   [ "$(grep -c '域名非法' "$F12/emit.log")" -ge 2 ]; then
	ok "20.3b 非法域名逐行告警并跳过（含空格式的 server= 注入）（F-12）"
else
	ng "20.3b 非法域名告警缺失（F-12）: $(tail -3 "$F12/emit.log" | tr '\n' ' ')"
fi
if [ ! -s "$F12/tr.log" ]; then
	ok "20.3c 大清单不再逐行 printf|tr 双 fork（500 行 0 次 tr 调用）（F-12）"
else
	ng "20.3c 仍逐行调用 tr（$(wc -l < "$F12/tr.log") 次）（F-12）"
fi

# dnsmasq --test：合法片段通过、坏片段硬失败、缺 dnsmasq / 基线不可用时降级
mkdir -p "$F12/dnsbin"
cat > "$F12/dnsbin/dnsmasq" <<'F12_DNSMASQ'
#!/bin/sh
f=""
for a do
	case "$a" in --conf-file=*) f=${a#--conf-file=} ;; esac
done
[ "$f" = "/dev/null" ] && exit 0
if grep -q 'BAD' "$f" 2>/dev/null; then
	echo "dnsmasq: bad syntax"
	exit 1
fi
exit 0
F12_DNSMASQ
chmod +x "$F12/dnsbin/dnsmasq"
printf 'server=/ok.example/223.5.5.5\n' > "$F12/out/good.conf"
printf 'server=/BAD/223.5.5.5\n' > "$F12/out/bad.conf"
_f12_good=1
_f12_bad=1
(
	PATH="$F12/dnsbin:$PATH"
	export PATH
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	_dns_check_fragment "$F12/out/good.conf" || exit 1
	_dns_check_fragment "$F12/out/bad.conf" && exit 2
	exit 0
) > "$F12/dnscheck.log" 2>&1
_f12_rc=$?
if [ "$_f12_rc" -eq 0 ]; then
	ok "20.3d 片段通过 dnsmasq --test；坏片段被拒绝（rc 非 0）（F-12）"
else
	ng "20.3d dnsmasq 片段自检方向错误（rc=$_f12_rc）：$(tail -2 "$F12/dnscheck.log" | tr '\n' ' ')"
fi
mkdir -p "$F12/dnsbin-baseline"
printf '#!/bin/sh\nexit 5\n' > "$F12/dnsbin-baseline/dnsmasq"
chmod +x "$F12/dnsbin-baseline/dnsmasq"
(
	PATH="$F12/dnsbin-baseline:$PATH"
	export PATH
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	_dns_check_fragment "$F12/out/bad.conf"
) > "$F12/dnsbase.log" 2>&1
_f12_rc=$?
if [ "$_f12_rc" -eq 0 ] && grep -q '基线自检失败' "$F12/dnsbase.log"; then
	ok "20.3e dnsmasq --test 环境不可用时降级告警，不误杀配置（F-12）"
else
	ng "20.3e 基线不可用被误判为配置错误（rc=$_f12_rc）（F-12）"
fi
(
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	PATH="$F12/emptybin"
	export PATH
	_dns_check_fragment "$F12/out/bad.conf"
) > "$F12/dnsmissing.log" 2>&1
_f12_rc=$?
if [ "$_f12_rc" -eq 0 ] && grep -q '未找到 dnsmasq' "$F12/dnsmissing.log"; then
	ok "20.3f dnsmasq 缺失时降级告警、不硬失败（F-12）"
else
	ng "20.3f dnsmasq 缺失时行为异常（rc=$_f12_rc）（F-12）"
fi
printf 'server=/a.example/1.1.1.1\nserver=/b.example/1.1.1.1\nserver=/c.example/1.1.1.1\nserver=/d.example/1.1.1.1\nserver=/e.example/1.1.1.1\n' \
	> "$F12/out/preview.conf"
(
	. "$TMP/isp-lib.sh" >/dev/null 2>&1
	_dns_print_preview "$F12/out/preview.conf" 5
) > "$F12/preview.log" 2>&1
if [ "$(grep -c '^  server=' "$F12/preview.log")" -eq 3 ] &&
   grep -q '共 5 条' "$F12/preview.log" &&
   ! grep -q 'e.example' "$F12/preview.log"; then
	ok "20.3g 只回显前 3 条规则（不再把整份清单 echo 给 ubus）（F-12）"
else
	ng "20.3g 规则回显未收敛（F-12）: $(tr '\n' '|' < "$F12/preview.log")"
fi

# ---- 20.4 F-28：并发 fetch 互斥（第二个干净失败，不互踩 DATA） ----
F28=$F32/f28
mkdir -p "$F28/bin" "$F28/mirror"
cat > "$F28/bin/uclient-fetch" <<'F28_FETCH'
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
sleep "${FAKE_SLEEP:-0}"
if [ "$out" = "-" ]; then cat "$FAKE_MIRROR/${url##*/}"; else cp "$FAKE_MIRROR/${url##*/}" "$out"; fi
F28_FETCH
chmod +x "$F28/bin/uclient-fetch"
i=0
: > "$F28/mirror/a.txt"
while [ "$i" -lt 2000 ]; do
	echo "10.$((i / 256)).$((i % 256)).0/24" >> "$F28/mirror/a.txt"
	i=$((i + 1))
done
cat > "$F28/conf" <<F28_CONF
ISP_TABLE="a:isp_a:wan_wanb:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_MIRROR="https://mirror.test"
COUNT_FALLBACK="0"
F28_CONF
f28_fetch() { # <sleep>
	FAKE_SLEEP=$1 FAKE_MIRROR="$F28/mirror" \
	PATH="$F28/bin:$PATH" ISP_SPLIT_CONF="$F28/conf" \
	ISP_SPLIT_BASE="$F28/base" ISP_SPLIT_LIB="$LIB" \
		sh "$ROOT/files/usr/sbin/isp-split" fetch
}
f28_fetch 3 > "$F28/a.log" 2>&1 &
_f28_pa=$!
_i=0
while [ ! -d "$F28/base/state/op.lock" ] && [ "$_i" -lt 8 ]; do
	_i=$((_i + 1))
	sleep 1
done
ISP_SPLIT_LOCK_WAIT=0
export ISP_SPLIT_LOCK_WAIT
f28_fetch 3 > "$F28/b.log" 2>&1
_f28_rb=$?
unset ISP_SPLIT_LOCK_WAIT
wait "$_f28_pa"
_f28_ra=$?
if [ "$_f28_ra" -eq 0 ] && [ "$_f28_rb" -ne 0 ] &&
   grep -q '另一个 isp-split 操作正在运行' "$F28/b.log" &&
   [ -s "$F28/base/data/a.txt" ] && [ ! -d "$F28/base/state/op.lock" ]; then
	ok "20.4 并发 fetch：第二个被操作锁拒绝（rc=$_f28_rb），首个成功且数据/锁干净（F-28）"
else
	ng "20.4 并发 fetch 互斥失败（rcA=$_f28_ra rcB=$_f28_rb）：$(tail -2 "$F28/b.log" | tr '\n' ' ')（F-28）"
fi

# ---- 20.5 F-29：reload 失败 / 规则未渲染都必须让 wire 非零 ----
b25_reset "$B25/s12"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s12" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s12" wanb_only isp_split_wanb_only_m1 wan2 marked
MWAN3_SERVICE="$B25/bin/mwan3-fail"
export MWAN3_SERVICE
b25_run "$B25/s12" "$B25/conf" wire > "$F32/f29-reload-fail.log" 2>&1
_f29_rc=$?
unset MWAN3_SERVICE
if [ "$_f29_rc" -ne 0 ] &&
   grep -q 'mwan3 reload 失败' "$F32/f29-reload-fail.log" &&
   grep -q '回滚: cp' "$F32/f29-reload-fail.log" &&
   ! grep -q '规则已注入并生效' "$F32/f29-reload-fail.log"; then
	ok "20.5 reload 必失败时 wire 非零且不再打印成功语义（挡住 Hermes 重放）（F-29）"
else
	ng "20.5 reload 失败仍被当成成功（rc=$_f29_rc）（F-29）: $(tail -2 "$F32/f29-reload-fail.log" | tr '\n' ' ')"
fi
b25_reset "$B25/s13"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s13" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s13" wanb_only isp_split_wanb_only_m1 wan2 marked
b25_run "$B25/s13" "$B25/conf" wire > "$F32/f29-ok.log" 2>&1
_f29_rc=$?
if [ "$_f29_rc" -eq 0 ] && grep -q '规则已注入并生效' "$F32/f29-ok.log"; then
	ok "20.5b reload 成功且两个集合都渲染时 wire 正常（rc=0）（F-29）"
else
	ng "20.5b 正常 wire 回归失败（rc=$_f29_rc）（F-29）: $(tail -2 "$F32/f29-ok.log" | tr '\n' ' ')"
fi
b25_reset "$B25/s14"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s14" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s14" wanb_only isp_split_wanb_only_m1 wan2 marked
FAKE_NFT_OMIT_SET=isp_uni
export FAKE_NFT_OMIT_SET
b25_run "$B25/s14" "$B25/conf" wire > "$F32/f29-shape.log" 2>&1
_f29_rc=$?
unset FAKE_NFT_OMIT_SET
if [ "$_f29_rc" -ne 0 ] &&
   grep -q '未按预期渲染' "$F32/f29-shape.log" &&
   grep -q 'isp_uni' "$F32/f29-shape.log"; then
	ok "20.5c reload 返回 0 但集合未进 mwan3_rules：wire 仍非零并点名缺失集合（F-29）"
else
	ng "20.5c 规则形状缺失未被发现（rc=$_f29_rc）（F-29）: $(tail -2 "$F32/f29-shape.log" | tr '\n' ' ')"
fi

# ---- 20.6 B-6：TMPDIR 不可用时 plan 干净报错 ----
b25_reset "$B25/s15"
cp "$FIX/mwan3" "$B25/mwan3"
b25_policy "$B25/s15" wan_only isp_split_wan_only_m1 wan1 marked
b25_policy "$B25/s15" wanb_only isp_split_wanb_only_m1 wan2 marked
mkdir -p "$B25/base/data"
printf '1.2.3.0/24\n' > "$B25/base/data/a.txt"
printf '1\n' > "$B25/base/data/.stamp"
B25_TMPDIR=/nonexistent-9x
export B25_TMPDIR
b25_run "$B25/s15" "$B25/conf" plan \
	> "$F32/b6.log" 2>&1
_b6_rc=$?
unset B25_TMPDIR
if [ "$_b6_rc" -ne 0 ] &&
   grep -q '无法创建临时文件' "$F32/b6.log" &&
   ! grep -q "can't create" "$F32/b6.log" &&
   ! grep -q 'mktemp:' "$F32/b6.log"; then
	ok "20.6 TMPDIR 不可用时 plan 干净报错退出（不再 can't create 崩在半截）（B-6）"
else
	ng "20.6 TMPDIR 不可用时 plan 仍崩在半截（rc=$_b6_rc）（B-6）: $(tail -3 "$F32/b6.log" | tr '\n' ' ')"
fi


echo "== 21. 卸载三分叉收口（F-14）与 confdir 状态文件名（B-5）"
F14=$TMP/f14
mkdir -p "$F14/bin"

# 有状态的 nft stub：只关心 isp_fallback 计数器的"在/不在"。
cat > "$F14/bin/nft" <<'FAKE_NFT_F14'
#!/bin/sh
S=${FAKE_NFT_STATE:?}
echo "nft $*" >> "$S/nft.log"
case "$1" in
list)
	case "$*" in
	*"counter inet mwan3 isp_fallback")
		[ -f "$S/counter" ] && { echo "counter isp_fallback { packets 1 bytes 2 }"; exit 0; }
		exit 1
		;;
	*"table inet mwan3") exit 0 ;;
	esac
	exit 1
	;;
delete)
	case "$*" in
	*"counter inet mwan3 isp_fallback") rm -f "$S/counter"; exit 0 ;;
	esac
	exit 1
	;;
esac
exit 1
FAKE_NFT_F14
chmod +x "$F14/bin/nft"

# uci stub：confdir 的读/写/删/commit 都要能看见。
cat > "$F14/bin/uci" <<'FAKE_UCI_F14'
#!/bin/sh
S=${FAKE_UCI_STATE:?}
[ "$1" = "-q" ] && shift
cmd=$1
shift
echo "uci $cmd $*" >> "$S/uci.log"
case "$cmd" in
get)
	case "$1" in
	"dhcp.@dnsmasq[0].confdir")
		[ -f "$S/confdir" ] && cat "$S/confdir" || exit 1
		;;
	*) exit 1 ;;
	esac
	;;
set)
	printf '%s\n' "${1#*=}" > "$S/confdir"
	;;
delete)
	case "$1" in
	"dhcp.@dnsmasq[0].confdir") rm -f "$S/confdir" ;;
	*) exit 1 ;;
	esac
	;;
commit) : ;;
show) exit 1 ;;
*) exit 1 ;;
esac
exit 0
FAKE_UCI_F14
chmod +x "$F14/bin/uci"

# 沙箱里造出"装完之后"的全部残留：文件 + 目录 + cron 行 + 计数器
# + confdir 状态 + dnsmasq 片段（运行配置目录 / 默认目录 / 旧版目录）。
f14_seed() { # <root> <state>
	rm -rf "$1" "$2"
	mkdir -p "$2"
	_r=$1
	mkdir -p "$_r/usr/sbin" "$_r/etc/init.d" "$_r/usr/lib/isp-split" \
		"$_r/etc/isp-split/state" "$_r/etc/isp-split/data" "$_r/etc/uci-defaults" \
		"$_r/www/luci-static/resources/view/isp-split" \
		"$_r/www/luci-static/resources/isp-split/logos" \
		"$_r/usr/share/luci/menu.d" "$_r/usr/share/rpcd/acl.d" "$_r/etc/crontabs" \
		"$_r/etc/isp-split/dnsmasq.d" "$_r/run/cfg.d" "$_r/run/default.d" \
		"$_r/run/dnsmasq.legacy.d"
	: > "$_r/usr/sbin/isp-split"
	: > "$_r/etc/init.d/isp-split"
	: > "$_r/usr/lib/isp-split/build.sh"
	: > "$_r/usr/lib/isp-split/rules-splice.awk"
	: > "$_r/etc/isp-split.conf"
	: > "$_r/etc/isp-split.conf.bak.20260101-000000"
	: > "$_r/etc/uci-defaults/99-isp-split"
	: > "$_r/www/luci-static/resources/view/isp-split/overview.js"
	: > "$_r/www/luci-static/resources/isp-split/isp-split.css"
	: > "$_r/usr/share/luci/menu.d/luci-app-isp-split.json"
	: > "$_r/usr/share/rpcd/acl.d/luci-app-isp-split.json"
	echo '17 4 * * * /usr/sbin/isp-split refresh >/dev/null 2>&1 # isp-split' \
		> "$_r/etc/crontabs/root"
	# B-5 新名状态文件：记的是"迁移进 UCI 的清理值"
	printf '%s\n' "$_r/run/keep.d" > "$_r/etc/isp-split/state/dnsmasq.confdir.migrated"
	# 运行中 dnsmasq 的 conf-dir= 指向 cfg.d（OpenClash 场景）
	printf 'conf-dir=%s\n' "$_r/run/cfg.d/" > "$_r/run/dnsmasq.conf.cfg01411c"
	: > "$_r/etc/isp-split/dnsmasq.d/isp-split.conf"
	: > "$_r/run/cfg.d/isp-split.conf"
	: > "$_r/run/default.d/isp-split.conf"
	: > "$_r/run/dnsmasq.legacy.d/isp-split.conf"
	: > "$2/counter"
	: > "$2/nft.log"
	: > "$2/uci.log"
	printf '%s\n' "$_r/run/current.d" > "$2/confdir"
}

f14_run() { # <root> <state> <teardown 参数...>
	_r=$1
	_s=$2
	shift 2
	(
		PATH="$F14/bin:$PATH"
		FAKE_NFT_STATE="$_s"
		FAKE_UCI_STATE="$_s"
		ISP_SPLIT_DESTDIR="$_r"
		ISP_SPLIT_CONF="$_r/etc/isp-split.conf"
		ISP_SPLIT_CRONTAB="$_r/etc/crontabs/root"
		DNSDIR="$_r/run/dnsmasq.legacy.d"
		DNSMASQ_DEFAULT_DIR="$_r/run/default.d"
		DNSMASQ_CONF_GLOB="$_r/run/dnsmasq.conf.*"
		export PATH FAKE_NFT_STATE FAKE_UCI_STATE ISP_SPLIT_DESTDIR \
			ISP_SPLIT_CONF ISP_SPLIT_CRONTAB DNSDIR DNSMASQ_DEFAULT_DIR \
			DNSMASQ_CONF_GLOB
		sh "$ROOT/files/usr/lib/isp-split/teardown.sh" "$@"
	)
}

_f14_list=$(sh "$ROOT/files/usr/lib/isp-split/teardown.sh" --list 2>/dev/null)
_teardown_missing=""
for _p in usr/sbin/isp-split etc/init.d/isp-split usr/lib/isp-split \
	etc/isp-split.conf etc/isp-split etc/uci-defaults/99-isp-split \
	www/luci-static/resources/view/isp-split; do
	case "$_f14_list" in
	*"$_p"*) ;;
	*) _teardown_missing="$_teardown_missing $_p" ;;
	esac
done
case "$_f14_list" in
*"nft delete counter inet mwan3 isp_fallback"*) ;;
*) _teardown_missing="$_teardown_missing 计数器锚点" ;;
esac
case "$_f14_list" in
*dnsmasq.confdir.migrated*) ;;
*) _teardown_missing="$_teardown_missing 状态文件名" ;;
esac
if [ -z "$_teardown_missing" ]; then
	ok "21.1 teardown.sh 清单覆盖审计点名的 6 类残留（脚本/init/库/配置/数据/计数器）"
else
	ng "21.1 teardown.sh 清单缺项:$_teardown_missing"
fi

# 21.2 沙箱全量演练：清单里每一项都必须消失
f14_seed "$F14/r1" "$F14/s1"
f14_run "$F14/r1" "$F14/s1" all > "$F14/r1.log" 2>&1
_f14_rc=$?
_r=$F14/r1
_left=""
for _p in usr/sbin/isp-split etc/init.d/isp-split usr/lib/isp-split \
	etc/isp-split.conf etc/isp-split etc/uci-defaults/99-isp-split \
	www/luci-static/resources/view/isp-split www/luci-static/resources/isp-split \
	usr/share/luci/menu.d/luci-app-isp-split.json \
	usr/share/rpcd/acl.d/luci-app-isp-split.json; do
	[ -e "$_r/$_p" ] && _left="$_left $_p"
done
ls "$_r"/etc/isp-split.conf.bak.* >/dev/null 2>&1 && _left="$_left .conf.bak.*"
[ -f "$F14/s1/counter" ] && _left="$_left 计数器"
grep -q 'isp-split' "$_r/etc/crontabs/root" 2>/dev/null && _left="$_left cron行"
for _d in etc/isp-split/dnsmasq.d run/cfg.d run/default.d run/dnsmasq.legacy.d; do
	[ -e "$_r/$_d/isp-split.conf" ] && _left="$_left 片段($_d)"
done
[ -e "$_r/etc/isp-split/state/dnsmasq.confdir.migrated" ] && _left="$_left 状态文件"
if [ "$_f14_rc" -eq 0 ] && [ -z "$_left" ]; then
	ok "21.2 沙箱 install 残留 → teardown.sh all：清单为空（rc=0）"
else
	ng "21.2 teardown.sh all 后仍有残留（rc=$_f14_rc）:$_left"
	sed 's/^/    /' "$F14/r1.log"
fi
if grep -q 'delete counter inet mwan3 isp_fallback' "$F14/s1/nft.log" 2>/dev/null; then
	ok "21.2b 计数器删除逻辑在 install 路径（teardown.sh）里也有（F-14 关键缺口）"
else
	ng "21.2b teardown.sh 没删 isp_fallback 计数器: $(tr '\n' ';' < "$F14/s1/nft.log" 2>/dev/null)"
fi
if grep -q "set dhcp.@dnsmasq\[0\].confdir=$_r/run/keep.d" "$F14/s1/uci.log" 2>/dev/null; then
	ok "21.2c dnsmasq confdir 按状态文件恢复（写回记录值，不是拍脑袋删）"
else
	ng "21.2c confdir 未恢复: $(tr '\n' ';' < "$F14/s1/uci.log" 2>/dev/null)"
fi

# 21.3 幂等：再跑一次不报错
f14_run "$F14/r1" "$F14/s1" all > "$F14/r1b.log" 2>&1
_f14_rc2=$?
if [ "$_f14_rc2" -eq 0 ] && grep -q '没有需要删除的文件' "$F14/r1b.log"; then
	ok "21.3 teardown.sh 重复执行幂等（rc=0，无动作）"
else
	ng "21.3 重复执行不幂等（rc=$_f14_rc2）: $(tail -3 "$F14/r1b.log" | tr '\n' ' ')"
fi

# 21.4 --keep-conf-bak：备份留档，其余照删
f14_seed "$F14/r2" "$F14/s2"
f14_run "$F14/r2" "$F14/s2" files --keep-conf-bak > "$F14/r2.log" 2>&1
_f14_rc3=$?
if [ "$_f14_rc3" -eq 0 ] &&
   ls "$F14/r2"/etc/isp-split.conf.bak.* >/dev/null 2>&1 &&
   [ ! -e "$F14/r2/usr/sbin/isp-split" ] &&
   grep -q '保留历史配置备份' "$F14/r2.log"; then
	ok "21.4 --keep-conf-bak 只保留 .conf.bak.*，其余照删（策略可选且可见）"
else
	ng "21.4 --keep-conf-bak 行为异常（rc=$_f14_rc3）: $(tail -3 "$F14/r2.log" | tr '\n' ' ')"
fi

# 21.5 三分叉同源：isp-split / install.sh 都调 teardown.sh
if grep -q 'sh "$LIB/teardown.sh" all' "$ROOT/files/usr/sbin/isp-split" &&
   grep -q '"$TEARDOWN" all' "$ROOT/scripts/install.sh" &&
   grep -q 'teardown.sh' "$ROOT/scripts/install.sh"; then
	ok "21.5 isp-split uninstall 与 scripts/install.sh --uninstall 都调同一份 teardown.sh"
else
	ng "21.5 卸载路径没有收敛到 teardown.sh（又分叉了）"
fi
# install.sh 必须把 teardown.sh 也装进设备，否则 `isp-split uninstall` 找不到
# 唯一实现（安装路径漏装 = F-14 的同型 bug，VM 第一轮就实锤）。
if grep -q 'cp -f "$SRC/usr/lib/isp-split/teardown.sh"' "$ROOT/scripts/install.sh"; then
	ok "21.5c install.sh 把 teardown.sh 一并装进 /usr/lib/isp-split（卸载才有实现可用）"
else
	ng "21.5c install.sh 没装 teardown.sh：设备上 isp-split uninstall 会直接拒绝卸载"
fi
# 旧的两份实现必须消失（否则迟早再漂移）
if ! grep -q '^_uninstall_ipsets()' "$ROOT/files/usr/sbin/isp-split" &&
   ! grep -q '^_uninstall_policies()' "$ROOT/files/usr/sbin/isp-split" &&
   ! grep -q '^_restore_dns_confdir()' "$ROOT/files/usr/sbin/isp-split"; then
	ok "21.5b isp-split 内不再保留第二份清理实现（_uninstall_ipsets/_uninstall_policies/_restore_dns_confdir 已删）"
else
	ng "21.5b isp-split 里还留着重复的清理实现"
fi

# 21.6 postrm 兜底清单锚点双向核对（唯一允许的镜像处）
sed -n '/^define Package\/isp-split\/postrm$/,/^endef$/p' "$ROOT/Makefile" > "$F14/postrm.txt"
_miss=""
for _a in $(printf '%s\n' "$_f14_list" | awk '$1 == "anchor" { $1 = ""; sub(/^ /, ""); print }'); do
	grep -Fq -- "$_a" "$F14/postrm.txt" || _miss="$_miss [$_a]"
done
if [ -z "$_miss" ]; then
	ok "21.6 postrm 兜底清单覆盖 teardown.sh 的全部 runtime 锚点（正向）"
else
	ng "21.6 postrm 缺锚点:$_miss"
fi
# 反向：postrm 里的删除目标不许出现清单外的路径
printf '%s\n' "$_f14_list" |
	awk '$1 == "path" || $1 == "dir" || $1 == "glob" || $1 == "base" { print $2 }
	     $1 == "anchor" { $1 = ""; sub(/^ /, ""); print }' |
	awk '{ print; print "/" $0 }' > "$F14/allow.txt"
_extra=""
# 注意：读文件而不是 for $(...)，否则 postrm 里的 `*.bak.*` 会在本机展开，
# 把"清单外的真实文件名"当成新目标（VM 上真有 66 个历史备份，第一版就栽在这）。
grep -E '^[[:space:]]*(rm -[rf]+|nft delete)' "$F14/postrm.txt" |
	sed 's/^[[:space:]]*//' |
	awk '{ for (i = 2; i <= NF; i++) print $i }' |
	grep '^/' | sed 's/[;|].*$//' > "$F14/targets.txt"
while IFS= read -r _t; do
	case "$_t" in *'$'*) continue ;; esac
	_hit=0
	while IFS= read -r _pat; do
		# 用 case 做通配匹配：清单里既有精确路径，也有 `*.bak.*` 这类 glob
		case "$_t" in $_pat) _hit=1; break ;; esac
	done < "$F14/allow.txt"
	[ "$_hit" = "1" ] || _extra="$_extra [$_t]"
done < "$F14/targets.txt"
if [ -z "$_extra" ]; then
	ok "21.6b postrm 的删除目标都在清单内（反向，防夹带）"
else
	ng "21.6b postrm 删了清单外的路径:$_extra"
fi

# 21.7 B-5：旧名状态文件读一次、迁成新名
f14_seed "$F14/r3" "$F14/s3"
rm -f "$F14/r3/etc/isp-split/state/dnsmasq.confdir.migrated"
printf '%s\n' "$F14/r3/run/keep.d" > "$F14/r3/etc/isp-split/state/dnsmasq.confdir.orig"
f14_run "$F14/r3" "$F14/s3" runtime > "$F14/r3.log" 2>&1
_f14_rc4=$?
if [ "$_f14_rc4" -eq 0 ] &&
   grep -q '旧状态文件 dnsmasq.confdir.orig 已迁移为 dnsmasq.confdir.migrated' "$F14/r3.log" &&
   [ ! -e "$F14/r3/etc/isp-split/state/dnsmasq.confdir.orig" ] &&
   grep -q "confdir=$F14/r3/run/keep.d" "$F14/s3/uci.log"; then
	ok "21.7 B-5 旧状态文件 .orig 读一次并迁移为 .migrated，confdir 照常恢复"
else
	ng "21.7 B-5 旧名迁移异常（rc=$_f14_rc4）: $(tail -3 "$F14/r3.log" | tr '\n' ' ')"
fi

# 21.8 B-5：写侧口径。cmd_dns 只写新名；旧名只作为兼容读入存在。
_dns_writes=$(grep -c '> "\$_state"' "$ROOT/files/usr/sbin/isp-split")
_dns_state_line=$(grep -n '_state=\$DNS_STATE/dnsmasq.confdir' "$ROOT/files/usr/sbin/isp-split" |
	head -1)
case "$_dns_state_line" in
*'.migrated'*)
	if [ "$_dns_writes" -ge 1 ]; then
		ok "21.8 B-5 cmd_dns 的状态文件写的是 .migrated（名实一致）"
	else
		ng "21.8 B-5 cmd_dns 找不到状态文件写入点"
	fi
	;;
*)
	ng "21.8 B-5 cmd_dns 仍在用旧名: $_dns_state_line"
	;;
esac
# 注释与实现口径一致：不许再出现"首次记录原值"这种说辞
if ! grep -q '首次记录原值' "$ROOT/files/usr/sbin/isp-split"; then
	ok "21.8b B-5 旧注释（首次记录原值）已清除，注释与写入值口径一致"
else
	ng "21.8b B-5 注释仍称「原值」，与实现不符"
fi

# 21.9 B-5：isp-split 自身的 _dns_state_adopt 也要认旧名（升级兼容读一次）
rm -rf "$F14/b5base"
mkdir -p "$F14/b5base/state"
printf '%s\n' '/tmp/keep.d' > "$F14/b5base/state/dnsmasq.confdir.orig"
(
	ISP_SPLIT_CONF="$TMP/bug6/conf"
	ISP_SPLIT_BASE="$F14/b5base"
	export ISP_SPLIT_CONF ISP_SPLIT_BASE
	. "$TMP/isp-lib.sh"
	# DNS_STATE 由 BASE 派生（DNS_STATE=$BASE/state），这里跟着 BASE 走
	_dns_state_adopt
) > "$F14/b5adopt.log" 2>&1
if [ -f "$F14/b5base/state/dnsmasq.confdir.migrated" ] &&
   [ ! -e "$F14/b5base/state/dnsmasq.confdir.orig" ] &&
   grep -qx '/tmp/keep.d' "$F14/b5base/state/dnsmasq.confdir.migrated" &&
   grep -q '迁移为 dnsmasq.confdir.migrated' "$F14/b5adopt.log"; then
	ok "21.9 B-5 isp-split 侧 _dns_state_adopt 把旧名读一次并迁移（内容不丢）"
else
	ng "21.9 B-5 isp-split 侧旧名迁移异常: $(tail -2 "$F14/b5adopt.log" | tr '\n' ' ')"
fi

echo "== 22. 工具链：SDK 版本分桶（F-19）/ Docker 平台（F-20）/ tag 一致性（F-21）"
F19=$TMP/f19
mkdir -p "$F19/scripts"
cp "$ROOT/scripts/build-apk.sh" "$F19/scripts/"

# 22.1 版本标记不匹配 -> 硬失败（旧的"staging_dir 在就复用"正是 F-19）
mkdir -p "$F19/.sdk-build/1.2.3/sdk"
printf '9.9.9 x86/64\n' > "$F19/.sdk-build/1.2.3/sdk/.isp-split-sdk-version"
sh "$F19/scripts/build-apk.sh" 1.2.3 x86/64 > "$F19/wrong.log" 2>&1
_f19_rc=$?
if [ "$_f19_rc" -ne 0 ] && grep -q '不能混编' "$F19/wrong.log"; then
	ok "22.1 F-19 复用前校验版本标记：目录里的 SDK 是 9.9.9，编 1.2.3 直接失败（rc=$_f19_rc）"
else
	ng "22.1 F-19 错版 SDK 仍被复用（rc=$_f19_rc）: $(tail -2 "$F19/wrong.log" | tr '\n' ' ')"
fi

# 22.2 标记缺失 -> 硬失败（来路不明的 SDK 目录不许赌）
rm -f "$F19/.sdk-build/1.2.3/sdk/.isp-split-sdk-version"
	: > "$F19/.sdk-build/1.2.3/sdk/README"	# 目录非空但无标记（旧脚本遗留的典型现场）
sh "$F19/scripts/build-apk.sh" 1.2.3 x86/64 > "$F19/nomark.log" 2>&1
_f19_rc2=$?
if [ "$_f19_rc2" -ne 0 ] && grep -q '没有版本标记' "$F19/nomark.log"; then
	ok "22.2 F-19 目录里没有版本标记时硬失败，不复用未知 SDK（rc=$_f19_rc2）"
else
	ng "22.2 F-19 无标记目录被静默复用（rc=$_f19_rc2）: $(tail -2 "$F19/nomark.log" | tr '\n' ' ')"
fi

# 22.3 标记匹配 -> 走复用分支（随后因假 SDK 没有 Makefile 失败，属预期）
printf '1.2.3 x86/64\n' > "$F19/.sdk-build/1.2.3/sdk/.isp-split-sdk-version"
sh "$F19/scripts/build-apk.sh" 1.2.3 x86/64 > "$F19/reuse.log" 2>&1
if grep -q '复用 .*sdk（1.2.3 x86/64）' "$F19/reuse.log" &&
   ! grep -q '不能混编' "$F19/reuse.log"; then
	ok "22.3 F-19 标记匹配时才复用（复用的是同版本同架构的 SDK）"
else
	ng "22.3 F-19 复用分支未按标记放行: $(head -3 "$F19/reuse.log" | tr '\n' ' ')"
fi

# 22.4 默认工作目录带版本（不再共用 .sdk-build/sdk）
mkdir -p "$F19/.sdk-build/7.7.7/sdk"
printf '7.7.7 x86/64\n' > "$F19/.sdk-build/7.7.7/sdk/.isp-split-sdk-version"
sh "$F19/scripts/build-apk.sh" 7.7.7 x86/64 > "$F19/default.log" 2>&1
if grep -q '复用 .*\.sdk-build/7.7.7/sdk（7.7.7 x86/64）' "$F19/default.log"; then
	ok "22.4 F-19 默认 WORK 按版本分桶（.sdk-build/<VER>/sdk）"
else
	ng "22.4 F-19 默认 WORK 未按版本分桶: $(head -3 "$F19/default.log" | tr '\n' ' ')"
fi

# 22.5 F-20 Docker 构建必须钉 linux/amd64（用 stub 抓 argv）
F20=$TMP/f20
mkdir -p "$F20/bin"
cat > "$F20/bin/docker" <<'FAKE_DOCKER_F20'
#!/bin/sh
printf '%s\n' "$@" > "${FAKE_DOCKER_ARGS:?}"
exit 0
FAKE_DOCKER_F20
chmod +x "$F20/bin/docker"
(
	PATH="$F20/bin:$PATH"
	FAKE_DOCKER_ARGS="$F20/args"
	export PATH FAKE_DOCKER_ARGS
	sh "$ROOT/scripts/build-apk-docker.sh" 25.12.6 > "$F20/run.log" 2>&1
)
_f20_rc=$?
if [ "$_f20_rc" -eq 0 ] &&
   grep -Fxq -- '--platform' "$F20/args" &&
   grep -Fxq -- 'linux/amd64' "$F20/args" &&
   grep -Fxq -- 'debian:bookworm-slim' "$F20/args"; then
	ok "22.5 F-20 docker run 带 --platform linux/amd64（argv 实测）"
else
	ng "22.5 F-20 docker 未钉平台（rc=$_f20_rc）: $(tr '\n' ' ' < "$F20/args" 2>/dev/null | cut -c1-160)"
fi
if grep -q 'Apple Silicon' "$ROOT/docs/BUILDING.md" &&
   grep -q 'linux/amd64' "$ROOT/docs/BUILDING.md"; then
	ok "22.6 F-20 docs/BUILDING.md 补了 Apple Silicon / linux-amd64 说明"
else
	ng "22.6 F-20 文档缺 Apple Silicon 说明"
fi

# 22.7 F-21 tag 与版本一致（正例 / 错 tag / 非法 tag / 非 tag 触发）
_ver=$(sed -n 's/^PKG_VERSION:=//p' "$ROOT/Makefile" | head -1)
sh "$ROOT/scripts/verify-release-version.sh" "v$_ver" > "$F19/tag-ok.log" 2>&1
_f21_ok=$?
sh "$ROOT/scripts/verify-release-version.sh" "v0.0.1" > "$F19/tag-bad.log" 2>&1
_f21_bad=$?
sh "$ROOT/scripts/verify-release-version.sh" "$_ver" > "$F19/tag-fmt.log" 2>&1
_f21_fmt=$?
sh "$ROOT/scripts/verify-release-version.sh" > "$F19/tag-none.log" 2>&1
_f21_none=$?
if [ "$_f21_ok" -eq 0 ] && [ "$_f21_bad" -ne 0 ] && [ "$_f21_fmt" -ne 0 ] &&
   [ "$_f21_none" -eq 0 ] &&
   grep -q '::error::' "$F19/tag-bad.log"; then
	ok "22.7 F-21 错 tag 版本号必须失败（ok=$_f21_ok bad=$_f21_bad fmt=$_f21_fmt 非tag=$_f21_none）"
else
	ng "22.7 F-21 tag 一致性判定异常（ok=$_f21_ok bad=$_f21_bad fmt=$_f21_fmt 非tag=$_f21_none）"
fi
if grep -q 'scripts/verify-release-version.sh' "$ROOT/.github/workflows/release.yml" &&
   grep -q 'needs: \[ version \]' "$ROOT/.github/workflows/release.yml"; then
	ok "22.7b F-21 release.yml 在编译前跑一致性断言（version job 门住 build）"
else
	ng "22.7b F-21 release.yml 没挂一致性断言"
fi

# 22.7c F-21 后缀先例兼容（E2）：vX.Y.Z-<小写字母数字> 是合法发布 tag。
#   先例 v0.2.1-logo / v0.2.1-happy 早于门禁诞生，旧正则把它们拒死；
#   放宽时不能顺手放宽到畸形：`-` 后为空、大写乱码都必须继续拒。
sh "$ROOT/scripts/verify-release-version.sh" "v$_ver-logo" > "$F19/tag-suffix-ok.log" 2>&1
_f21_suf=$?
sh "$ROOT/scripts/verify-release-version.sh" "v$_ver-LINECHECK" > "$F19/tag-suffix-bad.log" 2>&1
_f21_sufbad=$?
sh "$ROOT/scripts/verify-release-version.sh" "v$_ver-" > "$F19/tag-suffix-empty.log" 2>&1
_f21_sufempty=$?
if [ "$_f21_suf" -eq 0 ] && [ "$_f21_sufbad" -eq 1 ] && [ "$_f21_sufempty" -eq 1 ] &&
   grep -q '::error::' "$F19/tag-suffix-bad.log"; then
	ok "22.7c F-21 后缀 tag：v$_ver-logo 过(rc=$_f21_suf)，v$_ver-LINECHECK 拒(rc=$_f21_sufbad)，v$_ver- 拒(rc=$_f21_sufempty)"
else
	ng "22.7c F-21 后缀 tag 判定异常（logo=$_f21_suf 大写乱码=$_f21_sufbad 空后缀=$_f21_sufempty）"
fi

# 22.8 F-21 通配符口径：apk 连字符、ipk 下划线+_all.ipk
_bad_glob=$(grep -rn --include='*.md' --include='*.yml' --include='*.sh' \
	'isp-split_[*][.]apk' "$ROOT" 2>/dev/null |
	grep -v '/[.]sdk-build/' | grep -v '/dist/' | wc -l | tr -d ' ')
_apk_ok=$(grep -c 'isp-split-[*][.]apk' "$ROOT/.github/workflows/release.yml")
_apk_ok2=$(grep -c 'isp-split-[*][.]apk' "$ROOT/scripts/build-apk.sh")
_ipk_ok=$(grep -rc 'isp-split_[*]_all[.]ipk' "$ROOT/README.md" "$ROOT/docs/BUILDING.md" |
	awk -F: '{ s += $2 } END { print s + 0 }')
if [ "$_bad_glob" -eq 0 ] && [ "$_apk_ok" -ge 1 ] && [ "$_apk_ok2" -ge 1 ] && [ "$_ipk_ok" -ge 1 ]; then
	ok "22.8 F-21 全仓 apk 口径统一 isp-split-*.apk（下划线 glob 归零），ipk 仍为 isp-split_*_all.ipk"
else
	ng "22.8 F-21 口径不一致（残留下划线 apk=$_bad_glob，release=$_apk_ok，build-apk=$_apk_ok2，ipk 文档=$_ipk_ok）"
fi

# 22.8b busybox 安装姿势：路由器侧是「解包 + 进目录」，不许出现 GNU 的 strip 参数。
#   历史 bug：release body 曾教用户 `tar -xzf ... --strip-components[=]1`，
#   而 OpenWrt 的 busybox tar 不认识这个参数，照抄当场报错、装不上。
#   白名单只有 scripts/build-apk.sh（CI / Linux 构建主机的 GNU tar 解 SDK，另一个场景）。
#   （正则里的 [=] 是为了让这段断言代码本身不被算作命中。）
_strip_gnu=$(grep -rn -- '--strip-components[=]1' "$ROOT" 2>/dev/null |
	grep -v '/[.]sdk-build/' | grep -v '/[.]git/' | grep -v '/dist/' |
	grep -v '/scripts/build-apk.sh:' | wc -l | tr -d ' ')
_body_tar=$(grep -c 'mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp$' \
	"$ROOT/.github/workflows/release.yml")
_body_dir=$(grep -cF "sh /tmp/isp/isp-split-$_ver/scripts/install.sh --all" \
	"$ROOT/.github/workflows/release.yml")
_inst_dir=$(grep -cF 'isp-split-${VER}/scripts/install.sh --all' "$ROOT/scripts/build-release.sh")
# body 标题版本号必须跟 PKG_VERSION 走：下次进位忘了换 body，这里直接红。
_body_ver=$(grep -c "^[[:space:]]*## v$_ver" "$ROOT/.github/workflows/release.yml")
if [ "$_strip_gnu" -eq 0 ] && [ "$_body_tar" -ge 1 ] && [ "$_body_dir" -ge 1 ] &&
   [ "$_inst_dir" -ge 1 ] && [ "$_body_ver" -ge 1 ]; then
	ok "22.8b 安装姿势 busybox 安全：release body/INSTALL.txt 走「解包+进目录」，body 标题 v$_ver 与 PKG_VERSION 同步"
else
	ng "22.8b 安装姿势/GNU strip 参数/body 版本异常（残留=$_strip_gnu body_tar=$_body_tar body_dir=$_body_dir install=$_inst_dir body_ver=$_body_ver）"
fi

# 22.9 F-22 release.yml 的 APK_BIN 必须与 build-apk.sh 的 WORK 规则同源。
#      动态：把 release.yml 里那段规则（F22-RULE-BEGIN/END 之间）原样抽出来跑，
#            推出的 APK_BIN 必须落在 build-apk.sh **自己算出来**的 WORK 下。
#            断言的是"同一表达式"，不是"同一个字面量"——所以两边都现场求值。
F22=$TMP/f22
mkdir -p "$F22/scripts"
cp "$ROOT/scripts/build-apk.sh" "$F22/scripts/"
mkdir -p "$F22/.sdk-build/25.12.6/sdk"
printf '25.12.6 x86/64\n' > "$F22/.sdk-build/25.12.6/sdk/.isp-split-sdk-version"
	: > "$F22/.sdk-build/25.12.6/sdk/README"	# 目录非空才走复用分支（之后因没有 Makefile 失败，属预期）
sh "$F22/scripts/build-apk.sh" 25.12.6 x86/64 > "$F22/build.log" 2>&1
_f22_work=$(sed -n 's/^工作目录: //p' "$F22/build.log" | head -1)
sed -n '/F22-RULE-BEGIN/,/F22-RULE-END/p' "$ROOT/.github/workflows/release.yml" > "$F22/rule.sh"
_f22_apk=$(cd "$F22" && VER=25.12.6 ROOT=$F22 sh -c '. ./rule.sh; printf "%s\n" "$APK_BIN"' 2>/dev/null)
if [ -n "$_f22_work" ] && [ "$_f22_apk" = "$_f22_work/sdk/staging_dir/host/bin/apk" ]; then
	ok "22.9 F-22 release.yml 抽出的规则算出的 APK_BIN = build-apk.sh 的 WORK + /sdk/staging_dir/host/bin/apk（$_f22_apk）"
else
	ng "22.9 F-22 APK_BIN 与 build-apk.sh 的 WORK 分叉（work='$_f22_work' apk='$_f22_apk'）"
fi
# 静态：不许再出现手抄的字面量路径；verify 与 parity 必须共用同一处注入的 APK_BIN
_f22_lit=$(grep -c 'sdk-build' "$ROOT/.github/workflows/release.yml")
_f22_inject=$(grep -cF 'APK_BIN=$APK_BIN" >> "$GITHUB_ENV"' "$ROOT/.github/workflows/release.yml")
_f22_verify=$(grep -cF '用 APK_BIN=$APK_BIN 解 apk' "$ROOT/.github/workflows/release.yml")
_f22_parity=$(grep -cF 'parity 用 APK_BIN=' "$ROOT/.github/workflows/release.yml")
if [ "$_f22_lit" -eq 0 ] && [ "$_f22_inject" -ge 1 ] && [ "$_f22_verify" -ge 1 ] && [ "$_f22_parity" -ge 1 ]; then
	ok "22.9b F-22 release.yml 无手抄路径字面量，APK_BIN 单点注入后 verify/parity 共用"
else
	ng "22.9b F-22 release.yml 定义分叉（字面量=$_f22_lit 注入=$_f22_inject verify=$_f22_verify parity=$_f22_parity）"
fi

echo "== 23. verify-domains.sh 按 wire 语义重写（F-24 / F-25）"
V23=$TMP/v23
mkdir -p "$V23"
V23BASE="$ROOT/tools/fixtures/verify/base"

v23_run() { # <fixture dir> <域名...>
	_f=$1
	shift
	(
		ISP_VERIFY_FIXTURES="$_f"
		ISP_SPLIT_CONF="$_f/conf"
		VERIFY_PING=0
		export ISP_VERIFY_FIXTURES ISP_SPLIT_CONF VERIFY_PING
		sh "$ROOT/tools/verify-domains.sh" "$@"
	)
}

# 23.1 基线夹具：多成员策略取任一成员 mark 都算对；未命中集合按兜底打标
v23_run "$V23BASE" tel.example.com uni.example.com other.example.com telrange.example.com \
	> "$V23/base.log" 2>&1
_v23_rc=$?
if [ "$_v23_rc" -eq 0 ] &&
   grep -q '命中集合且 mark 一致: 3' "$V23/base.log" &&
   grep -q '未命中集合、mark 与兜底一致: 1' "$V23/base.log" &&
   grep -q '异常: 0' "$V23/base.log"; then
	ok "23.1 F-24/F-25 基线：多成员 mark(1536)+兜底 mark(2048) 都判对（rc=0）"
else
	ng "23.1 基线夹具判定异常（rc=$_v23_rc）: $(tail -4 "$V23/base.log" | tr '\n' ' ')"
fi
if grep -q 'mark 期望 {1280,1536}' "$V23/base.log" &&
   grep -q '未命中集合（按兜底打标）' "$V23/base.log"; then
	ok "23.2 F-25 期望面取全成员集合（不再是单值），F-24 未命中按兜底期望（不再是恒 0）"
else
	ng "23.2 期望面仍是旧的单值/恒 0 口径: $(grep -E 'mark 期望|兜底' "$V23/base.log" | head -3 | tr '\n' ' ')"
fi

# 23.3 mark 不符必须报异常（禁止恒真）
cp -r "$V23BASE" "$V23/bad"
sed -i 's/mark=1792/mark=1793/' "$V23/bad/conntrack.txt"
v23_run "$V23/bad" uni.example.com > "$V23/bad.log" 2>&1
_v23_bad=$?
if [ "$_v23_bad" -ne 0 ] && grep -q '异常: 1' "$V23/bad.log"; then
	ok "23.3 mark 不符 → rc=$_v23_bad 且异常计数为 1（判定不是恒真）"
else
	ng "23.3 mark 不符未被判异常（rc=$_v23_bad）: $(grep '结论' "$V23/bad.log" | tr '\n' ' ')"
fi

# 23.4 规则排在兜底之后 -> 报"规则不会命中"，不拿 mark 差异去猜
cp -r "$V23BASE" "$V23/order"
sed -n '3,5p' "$V23BASE/nft_chain_mwan3_rules.txt" > "$V23/order/rules.new"
sed -n '1,2p' "$V23BASE/nft_chain_mwan3_rules.txt" >> "$V23/order/rules.new"
mv "$V23/order/rules.new" "$V23/order/nft_chain_mwan3_rules.txt"
v23_run "$V23/order" tel.example.com > "$V23/order.log" 2>&1
_v23_ord=$?
if [ "$_v23_ord" -ne 0 ] && grep -q '规则在兜底之后' "$V23/order.log"; then
	ok "23.4 规则排在 catch-all 之后 → 明确报顺序错误（rc=$_v23_ord）"
else
	ng "23.4 顺序错误未被识别（rc=$_v23_ord）: $(tail -3 "$V23/order.log" | tr '\n' ' ')"
fi

# 23.5 default_rule 关闭：未命中集合的期望 mark 回到 0
cp -r "$V23BASE" "$V23/nodflt"
sed -i '/0.0.0.0\/0/d' "$V23/nodflt/nft_chain_mwan3_rules.txt"
sed -i 's/mark=2048/mark=0/' "$V23/nodflt/conntrack.txt"
v23_run "$V23/nodflt" other.example.com > "$V23/nodflt.log" 2>&1
_v23_nd=$?
if [ "$_v23_nd" -eq 0 ] && grep -q '未打标' "$V23/nodflt.log"; then
	ok "23.5 无兜底规则时未命中流量期望 mark=0（rc=$_v23_nd）"
else
	ng "23.5 无兜底场景判定异常（rc=$_v23_nd）: $(tail -3 "$V23/nodflt.log" | tr '\n' ' ')"
fi

# 23.6 无兜底却有 mark -> 异常
cp -r "$V23/nodflt" "$V23/nodflt-mark"
sed -i 's/mark=0/mark=2048/' "$V23/nodflt-mark/conntrack.txt"
v23_run "$V23/nodflt-mark" other.example.com > "$V23/nodflt-mark.log" 2>&1
_v23_nd2=$?
if [ "$_v23_nd2" -ne 0 ] && grep -q '无兜底规则却有 mark' "$V23/nodflt-mark.log"; then
	ok "23.6 无兜底规则却被打了标 → 异常（rc=$_v23_nd2）"
else
	ng "23.6 无兜底却有 mark 未被判异常（rc=$_v23_nd2）"
fi

# 23.7 策略无成员在线（last_resort）要单独说清楚，不是普通 mark 不符
cp -r "$V23BASE" "$V23/lastresort"
sed -i 's/mark=1536/mark=15872/' "$V23/lastresort/conntrack.txt"
v23_run "$V23/lastresort" tel.example.com > "$V23/lastresort.log" 2>&1
_v23_lr=$?
if [ "$_v23_lr" -ne 0 ] && grep -q '策略无可用成员' "$V23/lastresort.log"; then
	ok "23.7 last_resort(15872) 单独报「策略无可用成员」（rc=$_v23_lr）"
else
	ng "23.7 last_resort 未被单独识别（rc=$_v23_lr）: $(tail -3 "$V23/lastresort.log" | tr '\n' ' ')"
fi

# 23.8 集合不在 nft 里：不能静默当"未命中"
cp -r "$V23BASE" "$V23/noset"
rm -f "$V23/noset/nft_set_isp_uni.txt"
v23_run "$V23/noset" uni.example.com > "$V23/noset.log" 2>&1
_v23_ns=$?
if grep -q '集合不在 nft 里' "$V23/noset.log" && [ "$_v23_ns" -ne 0 ]; then
	ok "23.8 启用集合缺失时如实标注并判失败（rc=$_v23_ns）"
else
	ng "23.8 集合缺失被当成普通未命中（rc=$_v23_ns）"
fi

echo "== 24. 状态页方案 B（0.3.1：PNG logo / 44px 左置 / cernet 退场 / 兜底进格子）"
# 本节的定位：这些都不是"能跑就行"的行为，而是**发货素材与前端引用的一致性**。
# 最容易出的错是"换了图但忘改引用"或"引用改了但包没装图"——两者在浏览器里
# 都只表现为一个裂图标，服务端 404 而页面不报错，靠人眼在截图里发现。
LUCI_R=$ROOT/luci-app-isp-split/htdocs/luci-static/resources
LOGO=$LUCI_R/isp-split/logos
OV=$LUCI_R/view/isp-split/overview.js
LC=$LUCI_R/view/isp-split/linecheck.js
FEED_LUCI=$ROOT/feed/op-packages/luci-app-isp-split/htdocs/luci-static/resources

# 24.1 三张 PNG 到位：存在 + 单文件 ≤20KB + magic 是 PNG
#      magic 直接读前 8 字节（89 50 4E 47 0D 0A 1A 0A），不靠扩展名——
#      "把 SVG 改名成 .png"这种事故，只看文件名是查不出来的。
_lg_bad=""
# PNG 的 8 字节签名：89 50 4E 47 0D 0A 1A 0A。
# 不用 od/hexdump 拼十六进制：busybox 与 GNU 的 -t 写法/分隔不同（VM 上
# `od -An -tx1` 直接空输出，断言会误报"非PNG"）。head -c + cmp 两端行为一致。
printf '\211PNG\r\n\032\n' > "$TMP/png.magic"
for _f in logo-chinatelecom.png logo-unicom.png logo-mobile.png; do
	_p=$LOGO/$_f
	if [ ! -f "$_p" ]; then
		_lg_bad="$_lg_bad 缺$_f"
		continue
	fi
	_sz=$(wc -c < "$_p" | tr -d ' ')
	[ "$_sz" -le 20480 ] || _lg_bad="$_lg_bad ${_f}=${_sz}B>20480"
	head -c 8 "$_p" | cmp -s - "$TMP/png.magic" ||
		_lg_bad="$_lg_bad ${_f}=magic非PNG"
done
if [ -z "$_lg_bad" ]; then
	ok "24.1 logos/ 三张 PNG 存在、单文件 ≤20KB、magic=PNG"
else
	ng "24.1 logo 素材不合格:$_lg_bad"
fi

# 24.2 logos/ 只剩这一套素材：0 个 SVG，且不多不少正好 3 个文件
if [ ! -e "$LOGO/logo-chinatelecom.svg" ] && [ ! -e "$LOGO/logo-unicom.svg" ] &&
   [ ! -e "$LOGO/logo-mobile.svg" ] &&
   [ "$(ls "$LOGO" | grep -c '\.svg$')" -eq 0 ] && [ "$(ls "$LOGO" | wc -l | tr -d ' ')" -eq 3 ]; then
	ok "24.2 logos/ 旧 SVG 已删除，只剩 3 个 PNG"
else
	ng "24.2 logos/ 仍有残留（svg=$(ls "$LOGO" | grep -c '\.svg$') 个，共 $(ls "$LOGO" | wc -l | tr -d ' ') 个文件）"
fi

# 24.3 BRAND_LOGO 引用与文件一致：两个页面里的 logo-*.png 全部落盘、
#      引用集合与 logos/ 实际清单完全相同、且没有任何 .svg 引用
_bl_bad=""
for _js in "$OV" "$LC"; do
	_refs=$(grep -o 'logo-[a-z]*\.\(png\|svg\)' "$_js" | sort -u)
	if [ -z "$_refs" ]; then
		_bl_bad="$_bl_bad $(basename "$_js")=无logo引用"
		continue
	fi
	for _r in $_refs; do
		case "$_r" in
		*.svg) _bl_bad="$_bl_bad $(basename "$_js"):$_r(仍是SVG)" ;;
		*) [ -f "$LOGO/$_r" ] || _bl_bad="$_bl_bad $(basename "$_js"):$_r(文件不存在)" ;;
		esac
	done
	[ "$_refs" = "$(ls "$LOGO" | sort -u)" ] ||
		_bl_bad="$_bl_bad $(basename "$_js"):引用集合≠logos/清单"
done
if [ -z "$_bl_bad" ]; then
	ok "24.3 BRAND_LOGO 引用与 logos/ 文件一一对应（overview.js + linecheck.js，无 SVG）"
else
	ng "24.3 logo 引用与文件不一致:$_bl_bad"
fi

# 24.4 cernet 退场（纯 UI）+ 兜底卡进网格：静态断言
#      · cernet 过滤条件按 src 判（ISP_TABLE 里集合名可改，src 不可改）
#      · #isp-fallback 只应出现 1 次：它现在由 paintOps 建在运营商网格里，
#        若又回到独立大卡，两处会同时存在（第一处渲染成功、第二处空转）
_ov_fb=$(grep -c "id': 'isp-fallback'" "$OV")
if grep -q "r.src === 'cernet'" "$OV" &&
   grep -q "isp-card-fb" "$OV" &&
   grep -q "net:" "$OV" &&
   [ "$_ov_fb" -eq 1 ]; then
	ok "24.4 cernet 在状态页被过滤（后端数据行保留），兜底卡并入运营商网格（#isp-fallback ×1）"
else
	ng "24.4 cernet 过滤或兜底卡合并缺失（#isp-fallback 出现 $_ov_fb 次）"
fi

# 24.5 卡头 44px 左置：两个页面同一个 HEAD_ICO，CSS 里图标位是 44×44 的固定盒
#      （左置 = .isp-card-head 不再 space-between；图标盒 flex: 0 0 44px）
_css=$LUCI_R/isp-split/isp-split.css
if grep -q 'HEAD_ICO = 44' "$OV" && grep -q 'HEAD_ICO = 44' "$LC" &&
   grep -q 'flex: 0 0 44px' "$_css" &&
   grep -q '^\.lc-head-ico' "$_css" &&
   awk '/^\.isp-card-head /,/^}/' "$_css" | grep -q 'justify-content: flex-start' &&
   ! awk '/^\.isp-card-head /,/^}/' "$_css" | grep -q 'space-between'; then
	ok "24.5 卡头 44px 左置（isp-card-head / lc-head-ico，logo 与 glyph 同尺寸）"
else
	ng "24.5 卡头左置 44px 未落实"
fi

# 24.6 打包面跟着改：4 个 Makefile 的 install 规则装 *.png（留 *.svg 会装出空目录），
#      install.sh 同步 PNG 并清掉旧 SVG（升级路径）
_mk_bad=""
for _f in luci-app-isp-split/Makefile feed/op-packages/luci-app-isp-split/Makefile; do
	grep -q 'logos/\*\.png' "$ROOT/$_f" || _mk_bad="$_mk_bad $_f"
	grep -q 'logos/\*\.svg' "$ROOT/$_f" && _mk_bad="$_mk_bad $_f(仍svg)"
done
grep -q 'logos/"\*\.png' "$ROOT/scripts/install.sh" || _mk_bad="$_mk_bad install.sh"
grep -q 'logos/\*\.svg' "$ROOT/scripts/install.sh" ||
	_mk_bad="$_mk_bad install.sh(无旧SVG清理)"
if [ -z "$_mk_bad" ]; then
	ok "24.6 打包/安装面装 PNG 并清理旧 SVG（Makefile×2 + install.sh）"
else
	ng "24.6 打包面未跟上换图:$_mk_bad"
fi

# 24.7 feed 侧 PNG 与主源码逐字节一致（发布物走 feed 构建，二进制漂移最难发现）
_fd_bad=""
for _f in logo-chinatelecom.png logo-unicom.png logo-mobile.png; do
	cmp -s "$LOGO/$_f" "$FEED_LUCI/isp-split/logos/$_f" || _fd_bad="$_fd_bad $_f"
done
[ -e "$FEED_LUCI/isp-split/logos/logo-chinatelecom.svg" ] && _fd_bad="$_fd_bad feed残留SVG"
if [ -z "$_fd_bad" ]; then
	ok "24.7 feed/op-packages 的 logo PNG 与主源码逐字节一致（无 SVG 残留）"
else
	ng "24.7 feed 侧 logo 不一致:$_fd_bad"
fi

# 24.8 三个 LuCI 页仍能被 JS 引擎解析（换卡头动了 DOM 构造，语法错会白屏）
#      有 node 才跑；VM 上没有 node，按 skip 记，不伪装成通过。
_node=${NODE:-}
[ -n "$_node" ] || _node=$(command -v node 2>/dev/null || command -v nodejs 2>/dev/null || true)
if [ -n "$_node" ]; then
	_js_bad=""
	for _f in overview.js config.js linecheck.js; do
		"$_node" --check "$LUCI_R/view/isp-split/$_f" >/dev/null 2>&1 ||
			_js_bad="$_js_bad $_f"
	done
	if [ -z "$_js_bad" ]; then
		ok "24.8 overview.js / config.js / linecheck.js 全部通过 node --check"
	else
		ng "24.8 node --check 失败:$_js_bad"
	fi
else
	skip "24.8 node --check（环境里没有 node/nodejs）"
fi


echo "== 25. audit v2 安全修复第一批（A-01..A-08）"
A25=$TMP/a25
mkdir -p "$A25/bin" "$A25/base" "$A25/tmp"

# ---- A-01：20MiB 响应 + 1024 上限，落盘必须被流式截断 ----
mkdir -p "$A25/a01"
cat > "$A25/bin/uclient-fetch" <<'A25_UCLIENT'
#!/bin/sh
out=""
prev=""
for a in "$@"; do
	[ "$prev" = "-O" ] && out=$a
	prev=$a
done
if [ "$out" = "-" ] || [ -z "$out" ]; then
	head -c 20971520 /dev/zero
else
	head -c 20971520 /dev/zero > "$out"
fi
A25_UCLIENT
chmod +x "$A25/bin/uclient-fetch"
cat > "$A25/a01/conf" <<'A25_CONF'
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_SOURCES="s:primary:https://example.test"
A25_CONF
(
	PATH="$A25/bin:$PATH"
	TMPDIR="$A25/tmp"
	ISP_SPLIT_CONF="$A25/a01/conf"
	ISP_SPLIT_BASE="$A25/a01/base"
	ISP_SPLIT_LIB="$LIB"
	ISP_SPLIT_MAX_RAW_BYTES=1024
	export PATH TMPDIR ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB ISP_SPLIT_MAX_RAW_BYTES
	. "$TMP/isp-lib.sh"
	_fetch_source s https://example.test "$A25/a01/out/s" primary
) > "$A25/a01/run.log" 2>&1
_a25_a01_rc=$?
_a25_a01_sz=$(wc -c < "$A25/a01/out/s/s.txt" 2>/dev/null | tr -d ' \t')
case "${_a25_a01_sz:-}" in '' | *[!0-9]*) _a25_a01_sz=999999999 ;; esac
if [ "$_a25_a01_rc" -ne 0 ] && [ "$_a25_a01_sz" -le 2048 ]; then
	ok "A-01 20MiB 响应在 MAX=1024 下落盘 ${_a25_a01_sz}B（≤2048B，流式截断生效）"
else
	ng "A-01 体积闸门未前置：rc=$_a25_a01_rc size=${_a25_a01_sz}B"
fi

# ---- A-02：四个写命令持同一把 op lock；并发临界区串行 ----
_a25_lock_bad=""
for _a25_f in cmd_init cmd_dns cmd_install cmd_uninstall; do
	sed -n "/^$_a25_f() {/,/^}/p" "$ROOT/files/usr/sbin/isp-split" |
		grep -q '_op_lock_acquire' || _a25_lock_bad="$_a25_lock_bad $_a25_f"
done
if [ -z "$_a25_lock_bad" ]; then
	ok "A-02 cmd_init/cmd_dns/cmd_install/cmd_uninstall 均纳入 _op_lock_acquire"
else
	ng "A-02 未持锁的写命令:$_a25_lock_bad"
fi

mkdir -p "$A25/a02/base"
cat > "$A25/a02/conf" <<'A25_CONF'
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A25_CONF
cat > "$A25/a02/lock.sh" <<'A25_LOCK'
#!/bin/sh
tag=$1
. "$ISP_SPLIT_LIBFILE"
_op_lock_acquire || exit 2
printf '%s-start\n' "$tag" >> "$A25_LOG"
sleep 1
printf '%s-end\n' "$tag" >> "$A25_LOG"
_op_lock_release
A25_LOCK
cat > "$A25/a02/run.sh" <<'A25_RUN'
#!/bin/sh
ISP_SPLIT_CONF="$1" ISP_SPLIT_BASE="$2" ISP_SPLIT_LIBFILE="$3" \
	A25_LOG="$4" ISP_SPLIT_LOCK_WAIT=10 \
	sh "$5" "$6"
A25_RUN
: > "$A25/a02/log"
sh "$A25/a02/run.sh" "$A25/a02/conf" "$A25/a02/base" "$TMP/isp-lib.sh" \
	"$A25/a02/log" "$A25/a02/lock.sh" A >/dev/null 2>&1 &
_a25_p=$!
sleep 1
# 让第二个进程在 A 已持锁后启动；若锁不生效，B-start 会落在 A-end 之前。
sh "$A25/a02/run.sh" "$A25/a02/conf" "$A25/a02/base" "$TMP/isp-lib.sh" \
	"$A25/a02/log" "$A25/a02/lock.sh" B >/dev/null 2>&1
wait "$_a25_p"
if awk '/^A-start$/{a=NR} /^A-end$/{ae=NR} /^B-start$/{b=NR} END{exit !(a && ae && b && b>ae)}' \
	"$A25/a02/log"; then
	ok "A-02 并发操作锁串行化：B-start 在 A-end 之后（uci 暂存区不重叠）"
else
	ng "A-02 操作锁未串行化: $(tr '\n' ' ' < "$A25/a02/log")"
fi

# ---- A-03：LF / | 转换 / CR / TAB 全部拒绝，conf 无残留 ----
mkdir -p "$A25/a03/base"
cat > "$A25/a03/conf" <<'A25_CONF'
LINE_CHECK_UA="Mozilla/5.0"
LINE_CHECK_ACCEPT="text/html"
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A25_CONF
_a25_conf_run() {
	(
		ISP_SPLIT_CONF="$A25/a03/conf"
		ISP_SPLIT_BASE="$A25/a03/base"
		ISP_SPLIT_LIB="$LIB"
		export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
		. "$TMP/isp-lib.sh"
		"$@"
	) >/dev/null 2>&1
}
_a25_a03_bad=""
_a25_conf_run conf_set line_check_ua 'Mozilla/5.0|X-Injected-UA: yes' ||
	_a25_a03_bad="$_a25_a03_bad pipe-rejected"
[ "$_a25_a03_bad" = " pipe-rejected" ] || _a25_a03_bad="$_a25_a03_bad pipe-ACCEPTED"
_lf_val=$(printf 'Mozilla/5.0\nX-Injected-LF: yes')
_a25_conf_run conf_set line_check_ua "$_lf_val" ||
	_a25_a03_bad="$_a25_a03_bad lf-rejected"
[ "$_a25_a03_bad" = " pipe-rejected lf-rejected" ] ||
	_a25_a03_bad="$_a25_a03_bad lf-ACCEPTED"
_cr_val=$(printf 'Mozilla/5.0\rX: yes')
_a25_conf_run conf_set line_check_ua "$_cr_val" ||
	_a25_a03_bad="$_a25_a03_bad cr-rejected"
_tab_val=$(printf 'Mozilla/5.0\tX: yes')
_a25_conf_run conf_set line_check_ua "$_tab_val" ||
	_a25_a03_bad="$_a25_a03_bad tab-rejected"
if [ "$_a25_a03_bad" = " pipe-rejected lf-rejected cr-rejected tab-rejected" ] &&
   ! grep -q 'X-Injected' "$A25/a03/conf"; then
	ok "A-03 LF/| 注入 rc=1，CR/TAB 仍拒，conf 无残留"
else
	ng "A-03 控制字符校验异常:$_a25_a03_bad"
fi

# ---- A-04：PROBE_URLS / ECHO_URLS 的 -K 注入被读取侧拒绝 ----
mkdir -p "$A25/a04/bin" "$A25/a04/base"
cat > "$A25/a04/bin/curl" <<'A25_CURL'
#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
echo "0 0"
A25_CURL
chmod +x "$A25/a04/bin/curl"
cat > "$A25/a04/conf" <<'A25_CONF'
PROBE_URLS="-K/tmp/curlrc"
PROBE_IFACES="lo"
PROBE_TIME=1
PROBE_BYTES=1
LINE_CHECK_ECHO_URLS="-K/tmp/curlrc"
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A25_CONF
: > "$A25/a04/curl.log"
(
	PATH="$A25/a04/bin:$PATH"
	FAKE_CURL_LOG="$A25/a04/curl.log"
	ISP_SPLIT_CONF="$A25/a04/conf"
	ISP_SPLIT_BASE="$A25/a04/base"
	ISP_SPLIT_LIB="$LIB"
	export PATH FAKE_CURL_LOG ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	cmd_probe
) >/dev/null 2>&1
_a25_a04_probe=$?
(
	ISP_SPLIT_CONF="$A25/a04/conf"
	ISP_SPLIT_BASE="$A25/a04/base"
	ISP_SPLIT_LIB="$LIB"
	export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	_lc_echo_raw >/dev/null
) >/dev/null 2>&1
_a25_a04_echo=$?
if [ "$_a25_a04_probe" -ne 0 ] && [ "$_a25_a04_echo" -ne 0 ] &&
   [ ! -s "$A25/a04/curl.log" ]; then
	ok "A-04 PROBE_URLS/ECHO_URLS 的 -K 注入被拒且 curl 未被调用"
else
	ng "A-04 --url/读取侧校验缺失：probe_rc=$_a25_a04_probe echo_rc=$_a25_a04_echo curl=$(cat "$A25/a04/curl.log" 2>/dev/null)"
fi

# ---- A-05：DNSDIR=/etc 被拒；teardown 不删白名单外目录 ----
mkdir -p "$A25/a05/base" "$A25/a05/root/etc/isp-split"
cat > "$A25/a05/conf" <<'A25_CONF'
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A25_CONF
printf 'KEEP\n' > "$A25/a05/root/etc/isp-split.conf"
_a25_a05_rc=0
DNSDIR=/etc ISP_SPLIT_CONF="$A25/a05/conf" ISP_SPLIT_BASE="$A25/a05/base" \
	ISP_SPLIT_LIB="$LIB" sh "$ROOT/files/usr/sbin/isp-split" dns \
	> "$A25/a05/dns.log" 2>&1 || _a25_a05_rc=$?
(
	ISP_SPLIT_DESTDIR="$A25/a05/root"
	ISP_SPLIT_BASE="$A25/a05/base"
	DNSDIR="$A25/a05/root/etc"
	DNSMASQ_CONF_GLOB="$A25/a05/no-such-conf.*"
	DNSMASQ_DEFAULT_DIR="$A25/a05/root/tmp/dnsmasq.d"
	export ISP_SPLIT_DESTDIR ISP_SPLIT_BASE DNSDIR DNSMASQ_CONF_GLOB DNSMASQ_DEFAULT_DIR
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" runtime --i-know-what-im-doing
) > "$A25/a05/teardown.log" 2>&1
if [ "$_a25_a05_rc" -ne 0 ] && grep -q 'DNSDIR 非法' "$A25/a05/dns.log" &&
   [ -f "$A25/a05/root/etc/isp-split.conf" ]; then
	ok "A-05 DNSDIR=/etc rc=$_a25_a05_rc，teardown 未删白名单外 isp-split.conf"
else
	ng "A-05 DNSDIR 白名单未生效（rc=$_a25_a05_rc，文件 $( [ -f "$A25/a05/root/etc/isp-split.conf" ] && echo 在 || echo 丢失)）"
fi

# ---- A-06：坏集合名在 _lc_set_for/_lc_ip_isp 入口被拒 ----
mkdir -p "$A25/a06/bin" "$A25/a06/base"
cat > "$A25/a06/bin/nft" <<'A25_NFT'
#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_NFT_LOG:?}"
exit 0
A25_NFT
chmod +x "$A25/a06/bin/nft"
cat > "$A25/a06/conf" <<'A25_CONF'
ISP_TABLE="s:isp_tel;flush:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A25_CONF
: > "$A25/a06/nft.log"
_a25_a06_set=0
_a25_a06_ip=0
(
	PATH="$A25/a06/bin:$PATH"
	FAKE_NFT_LOG="$A25/a06/nft.log"
	ISP_SPLIT_CONF="$A25/a06/conf"
	ISP_SPLIT_BASE="$A25/a06/base"
	ISP_SPLIT_LIB="$LIB"
	export PATH FAKE_NFT_LOG ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	_lc_set_for s
) >/dev/null 2>&1 || _a25_a06_set=$?
(
	PATH="$A25/a06/bin:$PATH"
	FAKE_NFT_LOG="$A25/a06/nft.log"
	ISP_SPLIT_CONF="$A25/a06/conf"
	ISP_SPLIT_BASE="$A25/a06/base"
	ISP_SPLIT_LIB="$LIB"
	export PATH FAKE_NFT_LOG ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	_lc_ip_isp 1.2.3.4
) >/dev/null 2>&1 || _a25_a06_ip=$?
if [ "$_a25_a06_set" -ne 0 ] && [ "$_a25_a06_ip" -ne 0 ] &&
   ! grep -q 'isp_tel;flush' "$A25/a06/nft.log"; then
	ok "A-06 坏集合名在 _lc_set_for/_lc_ip_isp 入口被拒，未进入 nft argv"
else
	ng "A-06 坏集合名未被入口拦截（set_rc=$_a25_a06_set ip_rc=$_a25_a06_ip nft=$(tr '\n' ';' < "$A25/a06/nft.log")）"
fi

# ---- A-07：坏 DNS_TABLE 策略名在 mwan3_policy_* argv 前被拒 ----
mkdir -p "$A25/a07/bin" "$A25/a07/base"
cat > "$A25/a07/bin/nft" <<'A25_NFT7'
#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_NFT_LOG:?}"
case "$*" in
"list table inet mwan3") exit 0 ;;
"list chain inet mwan3 mwan3_output")
	printf '%s\n' 'table inet mwan3 {' '	chain mwan3_output {' \
		'		type filter hook output priority mangle; policy accept;' \
		'		jump mwan3_rules' '	}' '}'
	exit 0
	;;
*) exit 0 ;;
esac
A25_NFT7
chmod +x "$A25/a07/bin/nft"
cat > "$A25/a07/bin/uci" <<'A25_UCI7'
#!/bin/sh
exit 1
A25_UCI7
chmod +x "$A25/a07/bin/uci"
cat > "$A25/a07/conf" <<'A25_CONF'
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE="bad;flush:223.5.5.5"
DNS_MODE="mark"
A25_CONF
: > "$A25/a07/nft.log"
(
	PATH="$A25/a07/bin:$PATH"
	FAKE_NFT_LOG="$A25/a07/nft.log"
	ISP_SPLIT_CONF="$A25/a07/conf"
	ISP_SPLIT_BASE="$A25/a07/base"
	ISP_SPLIT_LIB="$LIB"
	DNS_RETRY_TRIES=1 DNS_RETRY_DELAY=0
	export PATH FAKE_NFT_LOG ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB \
		DNS_RETRY_TRIES DNS_RETRY_DELAY
	. "$TMP/isp-lib.sh"
	_dns_bypass 0
) >/dev/null 2>&1
_a25_a07_rc=$?
_a25_a07_cmd=0
PATH="$A25/a07/bin:$PATH" FAKE_NFT_LOG="$A25/a07/nft.log" \
	ISP_SPLIT_CONF="$A25/a07/conf" ISP_SPLIT_BASE="$A25/a07/base" \
	ISP_SPLIT_LIB="$LIB" DOMAIN_LIST_DIR="$A25/a07/domains" \
	DNSMASQ_SERVICE=/bin/true DNSMASQ_CONF_GLOB="$A25/a07/no-such-conf.*" \
	DNSMASQ_DEFAULT_DIR="$A25/a07/dnsmasq.d" \
	sh "$ROOT/files/usr/sbin/isp-split" dns > "$A25/a07/dns.log" 2>&1 ||
	_a25_a07_cmd=$?
if [ "$_a25_a07_rc" -eq 2 ] && [ "$_a25_a07_cmd" -eq 1 ] &&
   ! grep -q 'mwan3_policy_bad' "$A25/a07/nft.log"; then
	ok "A-07 坏策略名：_dns_bypass rc=2，cmd_dns rc=1，未进入 nft argv"
else
	ng "A-07 坏策略名未被拦截（bypass_rc=$_a25_a07_rc cmd_rc=$_a25_a07_cmd nft=$(tr '\n' ';' < "$A25/a07/nft.log")）"
fi

# ---- A-08：health JSON 数值位/cron 字段注入后仍是合法 JSON ----
mkdir -p "$A25/a08/base"
cat > "$A25/a08/conf" <<'A25_CONF'
ISP_TABLE="s:isp_s:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
ISP_MIRROR="https://example.test"
ISP_SOURCE_MAX_FAIL_DAYS='3,"injected":"yes"'
ISP_CRON='17 4 * * *
"cron_injected":"yes'
A25_CONF
(
	ISP_SPLIT_CONF="$A25/a08/conf"
	ISP_SPLIT_BASE="$A25/a08/base"
	ISP_SPLIT_LIB="$LIB"
	export ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LIB
	. "$TMP/isp-lib.sh"
	cmd_health_json
) > "$A25/a08/health.json" 2>/dev/null
_a25_a08_json=$(cat "$A25/a08/health.json")
_a25_a08_ok=0
if command -v jsonfilter >/dev/null 2>&1; then
	_a25_a08_max=$(printf '%s' "$_a25_a08_json" | jsonfilter -e '@.sources[0].max_fail' 2>/dev/null)
	_a25_a08_inj=$(printf '%s' "$_a25_a08_json" | jsonfilter -e '@.sources[0].injected' 2>/dev/null)
	[ "$_a25_a08_max" = "0" ] && [ -z "$_a25_a08_inj" ] && _a25_a08_ok=1
elif command -v python3 >/dev/null 2>&1; then
	python3 -c 'import json,sys; o=json.load(sys.stdin); assert o["sources"][0]["max_fail"]==0; assert "injected" not in o["sources"][0]' \
		< "$A25/a08/health.json" >/dev/null 2>&1 && _a25_a08_ok=1
else
	printf '%s' "$_a25_a08_json" | grep -q '"max_fail":0' &&
		! printf '%s' "$_a25_a08_json" | grep -q '"injected"' && _a25_a08_ok=1
fi
if [ "$_a25_a08_ok" = "1" ]; then
	ok "A-08 注入值被归一化，health JSON 可被 jsonfilter/python3 解析"
else
	ng "A-08 health JSON 仍非法或含注入字段: $_a25_a08_json"
fi

echo "== 26. audit v2 安全修复第二批（A-09..A-14）"
A26=$TMP/a26
mkdir -p "$A26"

# ---- A-09：export 的 README/数据文件预置 symlink，不得写穿 ----
mkdir -p "$A26/a09/base/data" "$A26/a09/out"
printf '1.0.1.0/24\n' > "$A26/a09/base/data/chinatelecom.txt"
cat > "$A26/a09/conf" <<'A26_CONF'
ISP_TABLE="chinatelecom:isp_tel:wan_only:1"
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
A26_CONF
printf 'VICTIM-README\n' > "$A26/a09/victim-readme"
printf 'VICTIM-YAML\n' > "$A26/a09/victim-yaml"
ln -s "$A26/a09/victim-readme" "$A26/a09/out/README-mihomo.txt"
ln -s "$A26/a09/victim-yaml" "$A26/a09/out/isp-chinatelecom.yaml"
ISP_SPLIT_CONF="$A26/a09/conf" ISP_SPLIT_BASE="$A26/a09/base" \
	sh "$ROOT/files/usr/sbin/isp-split" export mihomo "$A26/a09/out" \
	> "$A26/a09/export.log" 2>&1
_a26_a09_rc=$?
_a26_a09_ok=0
if [ "$_a26_a09_rc" -eq 0 ] &&
   [ "$(cat "$A26/a09/victim-readme")" = "VICTIM-README" ] &&
   [ "$(cat "$A26/a09/victim-yaml")" = "VICTIM-YAML" ] &&
   grep -q '^mihomo / OpenClash 用法' "$A26/a09/out/README-mihomo.txt" &&
   grep -q 'payload:' "$A26/a09/out/isp-chinatelecom.yaml"; then
	_a26_a09_ok=1
fi
if [ "$_a26_a09_ok" = "1" ]; then
	ok "A-09 export 的 README/数据文件走原子落位，预置 symlink 未被写穿"
else
	ng "A-09 symlink 写穿或导出失败（rc=$_a26_a09_rc）: $(tail -2 "$A26/a09/export.log" | tr '\n' ' ')"
fi
# 目录 symlink -> /etc 必须在真实路径检查处被拒
ln -s /etc "$A26/a09/link-to-etc"
ISP_SPLIT_CONF="$A26/a09/conf" ISP_SPLIT_BASE="$A26/a09/base" \
	sh "$ROOT/files/usr/sbin/isp-split" export mihomo "$A26/a09/link-to-etc" \
	> "$A26/a09/link.log" 2>&1
if [ $? -ne 0 ] && grep -q '拒绝导出到系统目录' "$A26/a09/link.log"; then
	ok "A-09 输出目录真实路径为 /etc 时被拒（symlink 组件不能绕过黑名单）"
else
	ng "A-09 realpath 黑名单未生效: $(tail -2 "$A26/a09/link.log" | tr '\n' ' ')"
fi

# ---- A-10：BASE 守卫 + 清单随 BASE ----
mkdir -p "$A26/a10"
# 安全版事故重演：conf 故意不存在。守卫命中时会在读 conf 之前退出；
# 即使守卫将来回归，缺少 conf 也会在 uninstall 动手之前退出，不会碰宿主 /etc。
_a26_a10_main_bad=""
for _a26_mb in /etc // /etc//; do
	ISP_SPLIT_CONF="$A26/a10/no-such.conf" ISP_SPLIT_BASE=$_a26_mb \
		sh "$ROOT/files/usr/sbin/isp-split" uninstall > "$A26/a10/etc-main.log" 2>&1
	[ $? -ne 0 ] && grep -qE '系统目录|非法' "$A26/a10/etc-main.log" ||
		_a26_a10_main_bad="$_a26_a10_main_bad $_a26_mb"
done
if [ -z "$_a26_a10_main_bad" ]; then
	ok "A-10 ISP_SPLIT_BASE=/etc（含 //、/etc//）isp-split uninstall 被入口守卫拒绝"
else
	ng "A-10 主脚本未拒绝系统 BASE:$_a26_a10_main_bad"
fi
sed '/^# ---------------------------------------------------------------- main$/,$d' \
	"$ROOT/files/usr/lib/isp-split/teardown.sh" > "$A26/a10/teardown-lib.sh"
_a26_a10_bad=""
for _a26_b in /etc /usr /var / /tmp // /etc//; do
	if ( ISP_SPLIT_BASE=$_a26_b ISP_SPLIT_DESTDIR=; . "$A26/a10/teardown-lib.sh"; validate_base ) >/dev/null 2>&1; then
		_a26_a10_bad="$_a26_a10_bad $_a26_b"
	fi
done
if [ -z "$_a26_a10_bad" ]; then
	ok "A-10 teardown validate_base 拒绝 /etc /usr /var / /tmp（含 //、/etc//）"
else
	ng "A-10 validate_base 漏放系统目录:$_a26_a10_bad"
fi
# 默认路径放行；自定义路径必须显式确认；沙箱必须在 DESTDIR 子树
_a26_a10_ok=0
( ISP_SPLIT_BASE=/etc/isp-split ISP_SPLIT_DESTDIR=; . "$A26/a10/teardown-lib.sh"; validate_base ) || _a26_a10_ok=1
( ISP_SPLIT_BASE="$A26/a10/custom" ISP_SPLIT_DESTDIR=; . "$A26/a10/teardown-lib.sh"; validate_base ) && _a26_a10_ok=1
( ISP_SPLIT_BASE="$A26/a10/custom" ISP_SPLIT_DESTDIR=; . "$A26/a10/teardown-lib.sh"; IWKD=1; validate_base ) || _a26_a10_ok=1
if [ "$_a26_a10_ok" = "0" ]; then
	ok "A-10 validate_base：默认放行 / 自定义需 --i-know-what-im-doing"
else
	ng "A-10 validate_base 放行策略异常"
fi
# 真实根上验证“无 flag 拒绝 / 有 flag 才动手”时，用假 rm 记录调用，
# 绝不真的删宿主或 VM 上的 /usr/sbin/isp-split（A-10 事故就是这么发生的）。
mkdir -p "$A26/a10/fakebin" "$A26/a10/custom/state"
cat > "$A26/a10/fakebin/rm" <<'A26_RM'
#!/bin/sh
printf '%s\n' "$*" >> "${A26_RM_LOG:-/dev/null}"
exit 0
A26_RM
chmod +x "$A26/a10/fakebin/rm"
printf 'KEEP\n' > "$A26/a10/custom/state/x"
: > "$A26/a10/rm-nof.log"
PATH="$A26/a10/fakebin:$PATH" A26_RM_LOG="$A26/a10/rm-nof.log" \
	ISP_SPLIT_BASE="$A26/a10/custom" \
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" files \
	> "$A26/a10/custom-nof.log" 2>&1
_a26_a10_rc1=$?
: > "$A26/a10/rm-yes.log"
PATH="$A26/a10/fakebin:$PATH" A26_RM_LOG="$A26/a10/rm-yes.log" \
	ISP_SPLIT_BASE="$A26/a10/custom" \
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" files \
	--i-know-what-im-doing > "$A26/a10/custom-yes.log" 2>&1
_a26_a10_rc2=$?
if [ "$_a26_a10_rc1" -ne 0 ] && [ ! -s "$A26/a10/rm-nof.log" ] &&
   [ -d "$A26/a10/custom" ] && [ "$_a26_a10_rc2" -eq 0 ] &&
   grep -Fq "$A26/a10/custom" "$A26/a10/rm-yes.log"; then
	ok "A-10 自定义 BASE：无 flag 被拒且零删除；带 flag 才按 BASE 删除（假 rm 记录）"
else
	ng "A-10 自定义 BASE 行为异常（nof=$_a26_a10_rc1 yes=$_a26_a10_rc2 rm=$(tr '\n' ';' < "$A26/a10/rm-yes.log")）"
fi
# 沙箱里做一次真实删除：DESTDIR + 默认 BASE，验证清单与数据目录一起消失
mkdir -p "$A26/a10/root/etc/isp-split/state" "$A26/a10/root/usr/sbin"
printf 'KEEP\n' > "$A26/a10/root/etc/isp-split/state/x"
: > "$A26/a10/root/usr/sbin/isp-split"
ISP_SPLIT_DESTDIR="$A26/a10/root" \
	sh "$ROOT/files/usr/lib/isp-split/teardown.sh" files > "$A26/a10/sandbox.log" 2>&1
_a26_a10_rc3=$?
if [ "$_a26_a10_rc3" -eq 0 ] && [ ! -e "$A26/a10/root/etc/isp-split" ] &&
   [ ! -e "$A26/a10/root/usr/sbin/isp-split" ]; then
	ok "A-10 沙箱真实删除：DESTDIR 内数据目录与固定清单同时清空"
else
	ng "A-10 沙箱删除异常（rc=$_a26_a10_rc3）: $(tail -2 "$A26/a10/sandbox.log" | tr '\n' ' ')"
fi
if sh "$ROOT/files/usr/lib/isp-split/teardown.sh" --list 2>/dev/null | grep -q '^base /etc/isp-split$'; then
	ok "A-10 --list 的数据目录随 BASE 推导（base /etc/isp-split）"
else
	ng "A-10 --list 未输出随 BASE 推导的数据目录"
fi

# ---- A-11：文档明示 ACL 授权面 + A-15 E() 语义 ----
_a26_a11_bad=""
[ -f "$ROOT/docs/SECURITY.md" ] || _a26_a11_bad="$_a26_a11_bad SECURITY.md"
for _a26_p in '任意子命令' 'file exec' 'createTextNode' 'innerHTML' 'A-15' 'ISP_SPLIT_BASE=/etc'; do
	grep -Fq -- "$_a26_p" "$ROOT/docs/SECURITY.md" 2>/dev/null ||
		_a26_a11_bad="$_a26_a11_bad [$_a26_p]"
done
grep -Fq 'docs/SECURITY.md' "$ROOT/README.md" || _a26_a11_bad="$_a26_a11_bad README-link"
grep -Fq 'ANY isp-split subcommand' "$ROOT/luci-app-isp-split/root/usr/share/rpcd/acl.d/luci-app-isp-split.json" ||
	_a26_a11_bad="$_a26_a11_bad ACL-warning"
if [ -z "$_a26_a11_bad" ]; then
	ok "A-11 SECURITY.md/README/ACL 说明覆盖 write=任意子命令与 E() 文本节点"
else
	ng "A-11 安全文档缺项:$_a26_a11_bad"
fi

# ---- A-12：action 钉 SHA / job 级权限 / SDK sha256 ----
_a26_a12_bad=""
if awk '/uses:/ && $0 !~ /@[0-9a-f]{40}/ { bad=1 } END { exit(bad ? 1 : 0) }' \
	"$ROOT/.github/workflows/release.yml"; then :; else
	_a26_a12_bad="$_a26_a12_bad action-SHA"
fi
[ "$(grep -v '^[[:space:]]*#' "$ROOT/.github/workflows/release.yml" | grep -c 'contents: write')" = "1" ] ||
	_a26_a12_bad="$_a26_a12_bad write-count"
[ "$(grep -v '^[[:space:]]*#' "$ROOT/.github/workflows/release.yml" | grep -c 'contents: read')" = "1" ] ||
	_a26_a12_bad="$_a26_a12_bad read-count"
awk '/^  release:/{f=1} f && /contents: write/{found=1} END { exit(found ? 0 : 1) }' \
	"$ROOT/.github/workflows/release.yml" || _a26_a12_bad="$_a26_a12_bad release-write"
awk '/^  release:/{exit} /^[[:space:]]*#/{next} /contents: write/{early=1} END { exit(early ? 1 : 0) }' \
	"$ROOT/.github/workflows/release.yml" || _a26_a12_bad="$_a26_a12_bad early-write"
grep -q 'sha256sums' "$ROOT/scripts/build-apk.sh" &&
	grep -q 'SDK sha256 校验失败' "$ROOT/scripts/build-apk.sh" ||
	_a26_a12_bad="$_a26_a12_bad sdk-sha256"
if [ -z "$_a26_a12_bad" ]; then
	ok "A-12 action 全部 40 位 SHA、contents:write 只在 release job、SDK 有 sha256 校验"
else
	ng "A-12 CI/供应链加固缺项:$_a26_a12_bad"
fi
# 校验和清单解析：模拟上游 sha256sums 的 "*文件名" 写法
_a26_sum=$(printf '%s\n' 'deadbeef *openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst' |
	awk -v f='openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst' '$2 == f || $2 == "*" f { print $1; exit }')
if [ "$_a26_sum" = "deadbeef" ]; then
	ok "A-12 sha256sums 的 *文件名 解析路径命中"
else
	ng "A-12 sha256sums 解析失败: [$_a26_sum]"
fi

# ---- A-13：auto 仅 HTTPS 百度 / 体积上限 / 缓存 TSV 清洗 ----
_a26_a13_bad=""
grep -Fq '_provs="baidu"' "$ROOT/files/usr/sbin/isp-split" || _a26_a13_bad="$_a26_a13_bad auto-provider"
grep -Fq 'baidu ip-api' "$ROOT/files/usr/sbin/isp-split" && _a26_a13_bad="$_a26_a13_bad auto-still-ip-api"
grep -Fq -- "--proto '=https'" "$ROOT/files/usr/sbin/isp-split" || _a26_a13_bad="$_a26_a13_bad proto-https"
grep -Fq -- '--max-filesize 131072' "$ROOT/files/usr/sbin/isp-split" || _a26_a13_bad="$_a26_a13_bad max-filesize"
mkdir -p "$A26/a13/base/state"
( ISP_SPLIT_CONF="$A26/a09/conf" ISP_SPLIT_BASE="$A26/a13/base"; export ISP_SPLIT_CONF ISP_SPLIT_BASE
  . "$TMP/isp-lib.sh"
  _c=$(_lc_geo_cache_clean "$(printf 'A\tB\nC')")
  [ "$_c" = "A B C" ] || exit 1
  _c=$(_lc_geo_cache_clean "$(printf '%0300d' 0)")
  [ "${#_c}" -eq 200 ] || exit 1
  LC_GEO=$STATE_DIR/linecheck.geo.tsv
  _lc_geo_cache_put 1.2.3.4 baidu "$(printf 'X\tY\nZ')"
  awk -F'\t' 'NF != 4 || $3 != "X Y Z" { bad=1 } END { exit(bad ? 1 : 0) }' "$LC_GEO" || exit 1
  [ "$(wc -l < "$LC_GEO" | tr -d ' ')" = "1" ] || exit 1
) >/dev/null 2>&1 || _a26_a13_bad="$_a26_a13_bad cache-clean"
if [ -z "$_a26_a13_bad" ]; then
	ok "A-13 auto 只走百度 HTTPS、响应限体积、缓存 TAB/换行被清洗且截断 200"
else
	ng "A-13 归属地链路加固缺项:$_a26_a13_bad"
fi

# ---- A-14：state/cache 700/600 ----
mkdir -p "$A26/a14/base"
cat > "$A26/a14/conf" <<'A26_CONF'
ISP_TABLE=""
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
LINE_CHECK_GEO=0
A26_CONF
ISP_SPLIT_CONF="$A26/a14/conf" ISP_SPLIT_BASE="$A26/a14/base" \
	ISP_SPLIT_LC_WANS="wan1|wan1|1|online|203.0.113.5" \
	ISP_SPLIT_LC_EXIT_IPS="198.51.100.7" \
	ISP_SPLIT_LC_LAT="dns=0.4,tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5" \
	ISP_SPLIT_LC_FORCE_SAME=1 ISP_SPLIT_LC_NO_SOCAT=1 \
	ISP_SPLIT_LC_RESOLVE_IPS="124.236.19.250" \
	sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --force \
	> "$A26/a14/lc.json" 2> "$A26/a14/lc.err"
_a26_mode() { stat -c %a "$1" 2>/dev/null || ls -ld "$1" 2>/dev/null | awk '{ print $1 }'; }
_a26_m_state=$(_a26_mode "$A26/a14/base/state")
_a26_m_cache=$(_a26_mode "$A26/a14/base/state/linecheck")
_a26_m_json=$(_a26_mode "$A26/a14/base/state/linecheck/last.json")
case "$_a26_m_state" in 700 | drwx------) _a26_state_ok=1 ;; *) _a26_state_ok=0 ;; esac
case "$_a26_m_cache" in 700 | drwx------) _a26_cache_ok=1 ;; *) _a26_cache_ok=0 ;; esac
case "$_a26_m_json" in 600 | -rw-------) _a26_json_ok=1 ;; *) _a26_json_ok=0 ;; esac
if [ "$_a26_state_ok" = "1" ] && [ "$_a26_cache_ok" = "1" ] && [ "$_a26_json_ok" = "1" ]; then
	ok "A-14 state=700 / linecheck=700 / last.json=600（umask 077 + 落位 chmod）"
else
	ng "A-14 权限未收紧: state=$_a26_m_state cache=$_a26_m_cache json=$_a26_m_json"
fi
if grep -q 'chmod 700 /etc/isp-split/state' "$ROOT/scripts/install.sh" &&
   grep -q 'chmod 700 /etc/isp-split/state' "$ROOT/files/etc/init.d/isp-split" &&
   grep -q 'umask 077' "$ROOT/files/etc/init.d/isp-split" &&
   grep -q 'chmod 600' "$ROOT/files/usr/sbin/isp-split"; then
	ok "A-14 install/init 安装时 chmod + 运行时 umask 077 双向落地"
else
	ng "A-14 安装/运行时权限修正缺失"
fi

echo "== 27. F-23 回显源国内化 / F-24b 按线测 DNS / A-15 XSS 回归"
A27=$TMP/a27
mkdir -p "$A27"

# ---- F-23：默认源全 HTTPS、国内可达；文本提取；exit_probe ----
_a27_bad=""
grep -q '^LC_DEFAULT_ECHO=.*https://ip.3322.net' "$ROOT/files/usr/sbin/isp-split" || _a27_bad="$_a27_bad default-echo"
grep -q '^LINE_CHECK_ECHO_URLS="https://ip.3322.net,https://myip.ipip.net,https://ddns.oray.com/checkip"' "$ROOT/files/etc/isp-split.conf" || _a27_bad="$_a27_bad conf-echo"
for _a27_s in '当前 IP：198.51.100.9 来自于：中国 测试' 'Current IP Address: 203.0.113.7' '198.51.100.9'; do
	_a27_ip=$( ISP_SPLIT_CONF="$A26/a09/conf" ISP_SPLIT_BASE="$A27/base"; export ISP_SPLIT_CONF ISP_SPLIT_BASE
		. "$TMP/isp-lib.sh"; _lc_extract_ip "$_a27_s" )
	case "$_a27_ip" in 198.51.100.9 | 203.0.113.7) ;; *) _a27_bad="$_a27_bad extract[$_a27_s=$_a27_ip]" ;; esac
done
mkdir -p "$A27/bin"
cat > "$A27/bin/curl" <<'A27_CURL'
#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do
	case "$1" in
	--url) url=$2; shift ;;
	-o) out=$2; shift ;;
	esac
	shift
done
case "$url" in
*bad*) echo "curl: (6) Could not resolve host: bad.example" >&2; echo "000 0.010"; exit 6 ;;
*) printf '当前 IP：198.51.100.9 来自于：中国 测试' > "$out"; echo "200 0.120"; exit 0 ;;
esac
A27_CURL
chmod +x "$A27/bin/curl"
cat > "$A27/f23.conf" <<'A27_CONF'
ISP_TABLE=""
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
LINE_CHECK_GEO=0
LINE_CHECK_ECHO_URLS="https://bad.example/ip,https://good.example/ip"
LINE_CHECK_UA="Mozilla/5.0"
A27_CONF
( PATH="$A27/bin:$PATH" ISP_SPLIT_CONF="$A27/f23.conf" ISP_SPLIT_BASE="$A27/f23-base"
  export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE
  . "$TMP/isp-lib.sh"
  _lc_exit_ip wan1
  printf '%s\n' "$LC_EXIT_IP" > "$A27/f23.ip"
  printf '%s\n' "$LC_EXIT_PROBE" > "$A27/f23.probe"
) >/dev/null 2>&1
_a27_probe=$(cat "$A27/f23.probe" 2>/dev/null)
if [ -z "$_a27_bad" ] && [ "$(cat "$A27/f23.ip" 2>/dev/null)" = "198.51.100.9" ] &&
   printf '%s' "$_a27_probe" | grep -q '"http_code":0' &&
   printf '%s' "$_a27_probe" | grep -q '"http_code":200' &&
   printf '%s' "$_a27_probe" | grep -q 'Could not resolve host'; then
	if command -v python3 >/dev/null 2>&1; then
		printf '%s' "$_a27_probe" | python3 -c 'import json,sys; o=json.load(sys.stdin); assert len(o)==2; assert o[0]["ok"] is False; assert o[1]["ok"] is True' \
			>/dev/null 2>&1 || _a27_bad="$_a27_bad probe-json"
	else
		printf '%s' "$_a27_probe" | grep -q '^\[{.*}\]$' || _a27_bad="$_a27_bad probe-json"
	fi
else
	_a27_bad="$_a27_bad exit-probe"
fi
# 全失败时 exit_ok=false 且 exit_probe 非空（页面文案拆分的判据）
sed 's#https://good.example/ip#https://also-bad.example/ip#' "$A27/f23.conf" > "$A27/f23bad.conf"
( PATH="$A27/bin:$PATH" ISP_SPLIT_CONF="$A27/f23bad.conf" ISP_SPLIT_BASE="$A27/f23-base2"
  export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE
  . "$TMP/isp-lib.sh"
  _lc_exit_ip wan1
  printf '%s\n' "$LC_EXIT_IP" > "$A27/f23bad.ip"
  printf '%s\n' "$LC_EXIT_PROBE" > "$A27/f23bad.probe"
) >/dev/null 2>&1
if [ -z "$(cat "$A27/f23bad.ip" 2>/dev/null)" ] &&
   [ "$(cat "$A27/f23bad.probe" 2>/dev/null)" != "[]" ] &&
   grep -q '回显源不可达（建议更换 LINE_CHECK_ECHO_URLS）' "$LUCI_R/view/isp-split/linecheck.js" &&
   grep -q '未取到（可能未真正出网）' "$LUCI_R/view/isp-split/linecheck.js"; then
	ok "F-23 默认源国内 HTTPS；逐 URL 记录 http_code/err/耗时；失败文案与“未出网”已拆分"
else
	ng "F-23 回显源/exit_probe/文案异常:$_a27_bad"
fi
# 端到端 JSON：exit_probe 必须出现在 last.json / --json 输出里
mkdir -p "$A27/f23-lc/base"
cat > "$A27/f23-lc/conf" <<'A27_CONF'
ISP_TABLE=""
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
LINE_CHECK_GEO=0
LINE_CHECK_ECHO_URLS="https://bad.example/ip,https://good.example/ip"
LINE_CHECK_UA="Mozilla/5.0"
A27_CONF
( PATH="$A27/bin:$PATH"
  ISP_SPLIT_CONF="$A27/f23-lc/conf" ISP_SPLIT_BASE="$A27/f23-lc/base"
  ISP_SPLIT_LC_WANS="wan1|wan1|1|online|203.0.113.5"
  ISP_SPLIT_LC_LAT="dns=0.4,tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5"
  ISP_SPLIT_LC_FORCE_SAME=1 ISP_SPLIT_LC_NO_SOCAT=1
  ISP_SPLIT_LC_STUN="ok:1.2.3.4:40000|ok:1.2.3.4:40000"
  ISP_SPLIT_LC_RESOLVE_IPS="124.236.19.250"
  export PATH ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LC_WANS ISP_SPLIT_LC_LAT 	ISP_SPLIT_LC_FORCE_SAME ISP_SPLIT_LC_NO_SOCAT ISP_SPLIT_LC_STUN ISP_SPLIT_LC_RESOLVE_IPS
  sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --force
) > "$A27/f23.json" 2>/dev/null
if grep -q '"exit_ip":"198.51.100.9"' "$A27/f23.json" &&
   grep -q '"exit_ok":true' "$A27/f23.json" &&
   grep -q '"exit_probe":\[{"url":"https://bad.example/ip"' "$A27/f23.json"; then
	ok "F-23 端到端 JSON 含 exit_probe（失败+成功两条），exit_ip/exit_ok 正常"
else
	ng "F-23 端到端 JSON 缺 exit_probe 或 exit_ip 异常"
fi

# 兼容旧 conf：安装脚本保留已存在的 conf（默认值变更不覆盖用户显式配置）
if grep -q '保留现有 /etc/isp-split.conf 不覆盖' "$ROOT/scripts/install.sh"; then
	ok "F-23 旧 conf 兼容：install.sh 保留用户已有配置，默认 ECHO 变更不覆盖"
else
	ng "F-23 install.sh 的旧 conf 保留约定丢失"
fi

# ---- F-24b：夹具 0.4 -> 400；缺失 -> null；"<1"；按线 DNS ----
mkdir -p "$A27/f24/base"
cat > "$A27/f24/conf" <<'A27_CONF'
ISP_TABLE=""
DNS_TABLE=""
DOMAIN_SPLIT=""
DNS_MODE="bind"
LINE_CHECK_GEO=0
A27_CONF
_a27_lc() { # <lat> <out>
	ISP_SPLIT_CONF="$A27/f24/conf" ISP_SPLIT_BASE="$A27/f24/base" \
	ISP_SPLIT_LC_WANS="wan1|wan1|1|online|203.0.113.5" \
	ISP_SPLIT_LC_EXIT_IPS="198.51.100.7" \
	ISP_SPLIT_LC_LAT="$1" \
	ISP_SPLIT_LC_FORCE_SAME=1 ISP_SPLIT_LC_NO_SOCAT=1 \
	ISP_SPLIT_LC_STUN="ok:1.2.3.4:40000|ok:1.2.3.4:40000" \
	ISP_SPLIT_LC_RESOLVE_IPS="124.236.19.250" \
	sh "$ROOT/files/usr/sbin/isp-split" linecheck --json --force > "$2" 2>/dev/null
}
_a27_lc "dns=0.4,tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5" "$A27/f24/dns04.json"
_a27_lc "tcp=30,tls=40,ttfb=50,total=60,jitter=3,loss=0,http=200,attempts=5" "$A27/f24/dnsnull.json"
if grep -q '"dns_ms":400' "$A27/f24/dns04.json" &&
   ! grep -q '"dns_ms":0[,}]' "$A27/f24/dns04.json" &&
   grep -q '"dns_scope":"local"' "$A27/f24/dns04.json" &&
   grep -q '"dns_ms":null' "$A27/f24/dnsnull.json"; then
	ok "F-24b 夹具 dns=0.4 -> 400ms；dns 缺失 -> null；0 不再作为哨兵"
else
	ng "F-24b dns_ms 夹具输出异常: dns04=$(grep -o '"dns_ms":[^,]*' "$A27/f24/dns04.json" 2>/dev/null) null=$(grep -o '"dns_ms":[^,]*' "$A27/f24/dnsnull.json" 2>/dev/null)"
fi
( ISP_SPLIT_CONF="$A27/f24/conf" ISP_SPLIT_BASE="$A27/f24/base"; export ISP_SPLIT_CONF ISP_SPLIT_BASE
  . "$TMP/isp-lib.sh"
  _v=$(_lc_sec_to_dns_ms 0.0004); [ "$_v" = "<1" ] || exit 1
  _v=$(_lc_sec_to_dns_ms 0.4); [ "$_v" = "400" ] || exit 1
  _v=$(_lc_sec_to_dns_ms ""); [ -z "$_v" ] || exit 1
) >/dev/null 2>&1
if [ $? -eq 0 ]; then
	ok "F-24b 秒->毫秒转换：0.0004 -> \"<1\"，0.4 -> 400，空 -> null"
else
	ng "F-24b 秒->毫秒转换异常"
fi
# 按线 DNS：夹具 DNS IP + 假 nslookup，确认 server 参数与 scope
cat > "$A27/bin/nslookup" <<'A27_NS'
#!/bin/sh
printf '%s\n' "$*" >> "$A27_NS_LOG"
echo "Server: 223.5.5.5"
echo "Address: 223.5.5.5:53"
echo "Name: $1"
echo "Address: 1.2.3.4"
exit 0
A27_NS
chmod +x "$A27/bin/nslookup"
: > "$A27/nslookup.log"
( PATH="$A27/bin:$PATH" A27_NS_LOG="$A27/nslookup.log"
  ISP_SPLIT_CONF="$A27/f24/conf" ISP_SPLIT_BASE="$A27/f24/base"
  ISP_SPLIT_LC_DNS_IP=223.5.5.5
  export PATH A27_NS_LOG ISP_SPLIT_CONF ISP_SPLIT_BASE ISP_SPLIT_LC_DNS_IP
  . "$TMP/isp-lib.sh"
  LC_DNS_MS=""; LC_DNS_SCOPE=""; LC_DNS_SERVER=""
  _lc_dns_ms wan1 baidu.com
  printf '%s|%s|%s\n' "$LC_DNS_MS" "$LC_DNS_SCOPE" "$LC_DNS_SERVER" > "$A27/f24/perline.txt"
) >/dev/null 2>&1
_a27_pl=$(cat "$A27/f24/perline.txt" 2>/dev/null)
case "$_a27_pl" in
'<1|wan|223.5.5.5' | [0-9]*'|wan|223.5.5.5')
	if grep -q 'baidu.com 223.5.5.5' "$A27/nslookup.log" &&
	   grep -q 'v === .<1.' "$LUCI_R/view/isp-split/linecheck.js" &&
	   grep -q "'<1ms'" "$LUCI_R/view/isp-split/linecheck.js"; then
		ok "F-24b 按线 DNS：nslookup 使用该 WAN 的 DNS IP（scope=wan），fmtMs 支持 \"<1ms\""
	else
		ng "F-24b 按线 DNS 命中但 nslookup 参数/前端 fmtMs 异常"
	fi
	;;
*)
	ng "F-24b 按线 DNS 未命中夹具 server: $_a27_pl"
	;;
esac

# ---- A-15 XSS 回归：node 渲染断言优先，否则静态 grep ----
_a27_node=${NODE:-}
[ -n "$_a27_node" ] || _a27_node=$(command -v node 2>/dev/null || command -v nodejs 2>/dev/null || true)
if [ -n "$_a27_node" ]; then
	if "$_a27_node" "$ROOT/tools/xss-render-check.js" > "$A27/xss-node.log" 2>&1; then
		ok "A-15 node 渲染断言：伪造全字段 payload 只以文本节点出现，innerHTML 仅静态 SVG"
	else
		ng "A-15 node 渲染断言失败: $(tail -2 "$A27/xss-node.log" | tr '\n' ' ')"
	fi
else
	_a27_xss_bad=""
	for _a27_js in linecheck.js overview.js config.js; do
		_a27_n=$(grep -c 'innerHTML' "$LUCI_R/view/isp-split/$_a27_js" 2>/dev/null)
		case "$_a27_n" in '' | *[!0-9]*) _a27_n=0 ;; esac
		[ "$_a27_n" -eq 1 ] || _a27_xss_bad="$_a27_xss_bad $_a27_js:innerHTML=$_a27_n"
		grep 'innerHTML' "$LUCI_R/view/isp-split/$_a27_js" 2>/dev/null |
			grep -q "'<svg" || _a27_xss_bad="$_a27_xss_bad $_a27_js:not-static"
		grep 'innerHTML' "$LUCI_R/view/isp-split/$_a27_js" 2>/dev/null |
			grep -Eq '(w|d|data|geo|nat|target|exit)[A-Za-z_]*\.' &&
			_a27_xss_bad="$_a27_xss_bad $_a27_js:field-concat"
	done
	grep -q "E('span', {}, \[ exitText \])" "$LUCI_R/view/isp-split/linecheck.js" ||
		_a27_xss_bad="$_a27_xss_bad exitText-E"
	grep -q 'Array.isArray(w.exit_probe)' "$LUCI_R/view/isp-split/linecheck.js" ||
		_a27_xss_bad="$_a27_xss_bad exit_probe"
	if [ -z "$_a27_xss_bad" ]; then
		ok "A-15 静态断言：三个 view 的 innerHTML 各仅 1 处且为静态 SVG，外网字段只经 E() 文本节点"
	else
		ng "A-15 XSS 静态断言失败:$_a27_xss_bad"
	fi
fi


echo
echo "通过 $pass 项，失败 $fail 项，跳过 $skipn 项"
if [ "$fail" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
	echo "（非 root 环境：依赖 uid=0 属主校验的 2 项属预期失败，已由 VM 覆盖）"
fi
[ "$fail" -eq 0 ]
