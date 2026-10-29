#!/bin/sh
# tag ↔ 版本号一致性断言（F-21）
#
# 为什么需要：CI 由 `push tag v*` 触发，但产物里的版本号只来自 PKG_VERSION。
# 打 tag 时忘了改 Makefile（或反过来改了版本号却没打 tag）不会有任何报错，
# 结果是 Release 页写着 v0.3.0、里面的包却自报 0.2.3——0.2.3 那次就差点这么发。
#
# 用法：
#   sh scripts/verify-release-version.sh v0.3.1-logo  # CI（tag 触发）与本地演练
#   sh scripts/verify-release-version.sh            # 非 tag 触发：跳过（rc=0）
#
# 校验项（任何一项不符即 rc=1，CI 里由 ::error:: 标注）：
#   1. tag 形如 vX.Y.Z，或 vX.Y.Z-<小写字母数字后缀>
#      （先例兼容：v0.2.1-logo / v0.2.1-happy 早于本门禁诞生。后缀只是发布批次
#       标记 —— 换装版 / 彩蛋版，不改变版本语义，比对时剥掉取主版本。
#       畸形后缀一律拒：`-` 后为空（v0.3.1-）、大写或杂字符（v0.3.1-LINECHECK）、
#       多段（v0.3.1-a-b）、带点或横线续段都不认。）
#   2. tag 的主版本（剥掉后缀）== v<主 Makefile PKG_VERSION>
#   3. files/usr/sbin/isp-split 的 ISP_VERSION == PKG_VERSION
#      （`isp-split --version` 与包版本不能各说各话）
#   4. luci-app-isp-split/Makefile 的 PKG_VERSION / PKG_RELEASE 与主包一致
#   5. feed 壳的两个 Makefile（sync-feed.sh 会同步）版本与主包一致
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:-}

_err() { echo "::error::$*" >&2; exit 1; }

if [ -z "$TAG" ]; then
	echo "非 tag 触发：跳过 tag↔版本一致性断言（F-21）"
	exit 0
fi

ver_of() { # <file> <key>
	sed -n "s/^$2:=//p" "$1" | head -1 | tr -d '\r'
}

VER=$(ver_of "$ROOT/Makefile" PKG_VERSION)
REL=$(ver_of "$ROOT/Makefile" PKG_RELEASE)
[ -n "$VER" ] || _err "读不到 Makefile 的 PKG_VERSION"
[ -n "$REL" ] || _err "读不到 Makefile 的 PKG_RELEASE"

# 后缀正则刻意收紧：- 后必须至少一个小写字母/数字，只允许一段。
# 放行大写或多段会让 v0.3.1-LINECHECK、v0.3.1-a-b 这类"看起来像版本号"的
# 乱码混进 Release 列表（tag 一旦推出就删不干净），所以这里宁可拒。
_TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?$'
case "$TAG" in
v*) ;;
*) _err "tag '$TAG' 不是 vX.Y.Z 或 vX.Y.Z-<小写字母数字后缀> 形式（F-21）" ;;
esac
printf '%s' "$TAG" | grep -Eq "$_TAG_RE" ||
	_err "tag '$TAG' 不是 vX.Y.Z 或 vX.Y.Z-<小写字母数字后缀> 形式（后缀不许为空/大写/多段；F-21）"

# 剥掉后缀取主版本再比：v0.3.1-logo 与 v0.3.1 是同一个版本号，
# 后缀不参与版本比较（否则换装版 / 彩蛋版永远过不了这一关）。
BASE=${TAG%%-*}
WANT="v$VER"
[ "$BASE" = "$WANT" ] ||
	_err "tag '$TAG' 的主版本 '$BASE' 与 Makefile PKG_VERSION '$VER' 不一致（应为 $WANT）：先改版本号或改 tag，不允许错版发车"

ISPV=$(sed -n 's/^ISP_VERSION="\([^"]*\)"/\1/p' "$ROOT/files/usr/sbin/isp-split" | head -1 | tr -d '\r')
[ -n "$ISPV" ] || _err "读不到 files/usr/sbin/isp-split 的 ISP_VERSION"
[ "$ISPV" = "$VER" ] ||
	_err "ISP_VERSION '$ISPV' 与 PKG_VERSION '$VER' 不一致（--version 会自报错版本）"

LVER=$(ver_of "$ROOT/luci-app-isp-split/Makefile" PKG_VERSION)
LREL=$(ver_of "$ROOT/luci-app-isp-split/Makefile" PKG_RELEASE)
[ "$LVER" = "$VER" ] || _err "luci-app-isp-split PKG_VERSION '$LVER' 与主包 '$VER' 不一致"
[ "$LREL" = "$REL" ] || _err "luci-app-isp-split PKG_RELEASE '$LREL' 与主包 '$REL' 不一致"

for _feed in "$ROOT/feed/op-packages/isp-split/Makefile" \
	"$ROOT/feed/op-packages/luci-app-isp-split/Makefile"; do
	[ -f "$_feed" ] || continue
	_fv=$(ver_of "$_feed" PKG_VERSION)
	[ "$_fv" = "$VER" ] ||
		_err "feed 壳 ${_feed#$ROOT/} 的 PKG_VERSION '$_fv' 与主包 '$VER' 不一致（跑 tools/sync-feed.sh）"
done

echo "tag↔版本一致：tag=$TAG PKG_VERSION=$VER PKG_RELEASE=$REL ISP_VERSION=$ISPV"
