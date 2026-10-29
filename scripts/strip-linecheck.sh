#!/bin/sh
# 构建期剥离线路体检（FEATURE_LINECHECK=0）。
#
# 用法：sh scripts/strip-linecheck.sh <staging-root>
#
# 源文件里用成对标记包住 feature 专属内容（shell/conf/js 用 `lc:begin` /
# `lc:end` 注释，Markdown 用 `<!-- lc:begin -->` / `<!-- lc:end -->`）。
# 本脚本把标记区间整段物理删除，再删掉只在 feature=1 时才安装的文件。
# 最后做一次“零残留”断言：产物里不得再出现 linecheck / LINE_CHECK / 线路体检。
#
# 这不是运行时开关：删掉的内容不会进入包、不会进入安装目录，也不存在
# 一个环境变量或 UCI 键能把它打开。
set -eu

ROOT=${1:-}
[ -n "$ROOT" ] || { echo "用法: sh scripts/strip-linecheck.sh <staging-root>" >&2; exit 1; }
[ -d "$ROOT" ] || { echo "目录不存在: $ROOT" >&2; exit 1; }

del_blocks() {
	_f=$1
	grep -Iq 'lc:begin' "$_f" 2>/dev/null || return 0
	_tmp=$_f.lcstrip.$$
	sed '/lc:begin/,/lc:end/d' "$_f" > "$_tmp" || { rm -f "$_tmp"; return 1; }
	# 保留原权限位（isp-split 必须仍可执行）
	chmod --reference="$_f" "$_tmp" 2>/dev/null || chmod 644 "$_tmp"
	mv -f "$_tmp" "$_f"
}

# 1) 文本文件里的标记区
find "$ROOT" -type f | while IFS= read -r f; do
	del_blocks "$f"
done

# 2) feature=1 专属文件
find "$ROOT" -type f \
	\( -name 'linecheck.js' -o -name 'lc-run' -o -name 'luci-app-isp-split-linecheck.json' \) \
	-exec rm -f {} +

# 3) 空目录顺手收掉（LuCI view 目录只有 linecheck.js 时）
find "$ROOT" -type d -empty -delete 2>/dev/null || true

# 4) 零残留断言（白名单为空）
_leak=$(grep -rIl 'linecheck\|LINE_CHECK\|线路体检' "$ROOT" 2>/dev/null || true)
if [ -n "$_leak" ]; then
	echo "剥离失败，以下文件仍有 linecheck 残留：" >&2
	printf '%s\n' "$_leak" | sed 's/^/  /' >&2
	exit 1
fi

# 5) 语法自检（脚本仍能被 shell 解析）
_main=$ROOT/usr/sbin/isp-split
if [ -f "$_main" ]; then
	sh -n "$_main" || { echo "剥离后 isp-split 语法错误" >&2; exit 1; }
fi
_conf=$ROOT/etc/isp-split.conf
if [ -f "$_conf" ]; then
	sh -n "$_conf" || { echo "剥离后 isp-split.conf 语法错误" >&2; exit 1; }
fi

echo "已剥离线路体检: $ROOT"
