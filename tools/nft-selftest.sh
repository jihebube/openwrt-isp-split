#!/bin/sh
# nft-selftest.sh —— 在任意 Linux（Debian / OpenWrt / 容器）上实测 isp-split 的 nft 数据加载
#
# 只做一件事：把 1.3 万条运营商 CIDR 真正灌进一张**独立临时表**，
# 验证批处理不会被整批拒绝、测量加载耗时，然后删表收工。
# 全程不碰 inet mwan3，也不需要 mwan3、uci、ubus。
#
# 用法（在仓库根目录）：
#   sudo sh tools/nft-selftest.sh
#   sudo sh tools/nft-selftest.sh --keep     # 保留临时表以便检查
#
# 依赖：nft、awk、sort、curl 或 wget
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIB=$ROOT/files/usr/lib/isp-split
WORK=${TMPDIR:-/tmp}/isp-split-nft-selftest.$$
TABLE=isptest
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# 与 isp-split.conf 默认优先级保持一致；改这里会改变归属
PRIORITY="chinatelecom unicom_cnc cmcc cernet chinabtn gwbn othernet hk mo tw"

cleanup() {
	[ "$KEEP" = "1" ] || nft delete table inet "$TABLE" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

say() { printf '[nft-selftest] %s\n' "$*"; }
die() { printf '[nft-selftest] 错误: %s\n' "$*" >&2; exit 1; }

# ---- 前置检查 ----
command -v nft >/dev/null 2>&1 || die "未找到 nft（Debian: apt install nftables）"
command -v awk >/dev/null 2>&1 || die "未找到 awk"
nft list tables >/dev/null 2>&1 || die "没有 nftables 权限，请用 root 运行"
[ "$(id -u)" = "0" ] || say "警告：非 root 运行，nft 可能失败"

say "awk 实现: $(readlink -f "$(command -v awk)" 2>/dev/null || command -v awk)"
say "nft 版本: $(nft --version 2>/dev/null | head -1)"

mkdir -p "$WORK/raw" "$WORK/out"

# ---- 1. 下载 ----
for isp in $PRIORITY; do
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -m 30 -o "$WORK/raw/$isp.raw" "https://ispip.clang.cn/$isp.txt" ||
			die "$isp 下载失败"
	else
		wget -q -T 30 -O "$WORK/raw/$isp.raw" "https://ispip.clang.cn/$isp.txt" ||
			die "$isp 下载失败"
	fi
done
say "下载完成：$(cat "$WORK/raw"/*.raw | wc -l) 行原始数据"

# ---- 2. 构建（归一化 + 互斥化）----
say "构建集合…"
ISP_SPLIT_LIB=$LIB sh "$LIB/build.sh" "$WORK/raw" "$WORK/out" "$PRIORITY" 2>"$WORK/report"
cat "$WORK/report"

# ---- 3. 生成批处理（独立表）----
BATCH=$WORK/batch.nft
{
	echo "add table inet $TABLE"
	for isp in $PRIORITY; do
		f=$WORK/out/$isp.txt
		[ -s "$f" ] || continue
		set=$(echo "$isp" | sed 's/chinabtn/tietong/;s/othernet/other/;s/chinatelecom/tel/;s/unicom_cnc/uni/')
		echo "add set inet $TABLE isp_$set { type ipv4_addr; flags interval; auto-merge; counter; }"
		awk -v tbl="$TABLE" -v s="isp_$set" '
			{
				buf = (buf == "") ? $1 : buf ", " $1
				n++
				if (n % 400 == 0) { printf "add element inet %s %s { %s }\n", tbl, s, buf; buf = "" }
			}
			END { if (buf != "") printf "add element inet %s %s { %s }\n", tbl, s, buf }
		' "$f"
	done
} > "$BATCH"

say "批处理: $(wc -l < "$BATCH") 条语句，$(du -h "$BATCH" | cut -f1)"

# ---- 4. 干跑校验 ----
if nft -c -f "$BATCH" 2>"$WORK/check.err"; then
	say "✓ 干跑校验通过（nft -c，未提交）"
else
	say "✗ 干跑校验失败："
	cat "$WORK/check.err" >&2
	exit 1
fi

# ---- 5. 实弹加载 ----
nft delete table inet "$TABLE" 2>/dev/null || true
T0=$(date +%s)
nft -f "$BATCH" || die "实弹加载失败"
T1=$(date +%s)

# ---- 6. 结果 ----
# 注意：interval 集合的 nft list set 输出是区间格式（a-b），不是 CIDR，
#       且 auto-merge 会把相邻网段合并，所以内核元素数会少于输入 CIDR 数。
count_elements() {
	nft list set inet "$1" "$2" 2>/dev/null | awk '
		{
			line = $0
			# 用 index() 而不是正则匹配花括号：
			# busybox awk 的 ERE 会拒绝 \{，报 "Invalid contents of {}" 并整段退出。
			if (!inb && index(line, "elements = {")) {
				inb = 1
				line = substr(line, index(line, "elements = {") + 12)
			}
			if (inb) {
				q = index(line, "}")
				if (q) {
					end = 1
					line = substr(line, 1, q - 1)
				}
				if (line ~ /[0-9]/)
					seen = 1
				c += gsub(/,/, ",", line)
				if (end)
					inb = 0
			}
		}
		END { printf "%d\n", (seen ? c + 1 : 0) }'
}

echo
printf '%-14s %10s %10s\n' "集合" "输入CIDR" "内核元素"
TOTAL=0
TOTALC=0
for isp in $PRIORITY; do
	set=$(echo "$isp" | sed 's/chinabtn/tietong/;s/othernet/other/;s/chinatelecom/tel/;s/unicom_cnc/uni/')
	n=$(count_elements "$TABLE" "isp_$set")
	c=$(wc -l < "$WORK/out/$isp.txt" 2>/dev/null | tr -d ' ')
	printf '%-14s %10s %10s\n' "isp_$set" "${c:-0}" "$n"
	TOTAL=$((TOTAL + n))
	TOTALC=$((TOTALC + ${c:-0}))
done
echo "----------------------------------------------"
printf '%-14s %10s %10s\n' "合计" "$TOTALC" "$TOTAL"
say "加载耗时 $((T1 - T0)) 秒（元素数少于 CIDR 数是 auto-merge 合并所致，正常）"

# 内存占用（interval set 用 rbtree，很省）
say "内核 slab 参考: $(grep -m1 '^Slab:' /proc/meminfo 2>/dev/null || echo '不可用')"

if [ "$KEEP" = "1" ]; then
	say "已保留表 inet $TABLE，检查完请手动删除：nft delete table inet $TABLE"
else
	nft delete table inet "$TABLE"
	say "临时表已删除，系统恢复原状"
fi

echo
say "结论：$TOTAL 条 CIDR 可被 nftables 一次性接受，不存在整批被拒风险。"
