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

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
