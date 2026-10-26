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
	if [ "$_n" -eq 4 ]; then
		ok "mwan3 重建竞态下 4 条 DNS 旁路规则全部恢复"
	else
		ng "mwan3 重建后 DNS 规则数异常: $_n（期望 4）"
	fi
else
	ng "mwan3 重建竞态下 DNS 旁路恢复失败"
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

echo "== 5. conf set 失败退出码"
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

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
