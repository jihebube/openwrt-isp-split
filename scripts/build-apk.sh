#!/bin/sh
# 用 OpenWrt SDK 编译本项目的包
#
#   25.12+ 的 SDK 产出 .apk；24.10 及以下的 SDK 产出 .ipk
#
# 用法：
#   sh scripts/build-apk.sh                     # 25.12.6 / x86-64
#   sh scripts/build-apk.sh 24.10.4 x86/64      # 指定版本与架构
#   OWRT_WORK=/tmp/sdkbuild sh scripts/build-apk.sh   # 自定义工作目录
#
# 产物在 dist/sdk-<版本>/ 下。
# 需要 Linux x86_64（SDK 是 Linux 程序）+ zstd + curl + make + perl 基础环境。
set -eu

VER=${1:-25.12.6}
ARCH=${2:-x86/64}
# 出货门：0 = 构建期剥离线路体检（0.2.3），1 = 完整功能（0.3.0+）。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-0}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${OWRT_WORK:-$ROOT/.sdk-build}
OUT=$ROOT/dist/sdk-$VER

BASE=https://downloads.openwrt.org/releases/$VER/targets/$ARCH

echo "== SDK 构建: $VER / $ARCH =="

mkdir -p "$WORK" "$OUT"

# 1) 下载并解压 SDK（只做一次）
if [ ! -x "$WORK/sdk/staging_dir" ] && [ ! -d "$WORK/sdk/toolchain" ]; then
	FILE=$(curl -fsSL "$BASE/" | grep -oE 'openwrt-sdk-[^"<]*Linux-x86_64\.tar\.(zst|xz)' | head -1)
	[ -n "$FILE" ] || { echo "在 $BASE 找不到 SDK，确认版本号与架构" >&2; exit 1; }
	echo "下载 $FILE"
	curl -fsSL -o "$WORK/sdk.tar" "$BASE/$FILE"
	mkdir -p "$WORK/sdk"
	case "$FILE" in
	*.zst) tar --zstd -xf "$WORK/sdk.tar" -C "$WORK/sdk" --strip-components=1 ;;
	*)     tar -xf "$WORK/sdk.tar" -C "$WORK/sdk" --strip-components=1 ;;
	esac
	echo "SDK 已解压到 $WORK/sdk"
fi
cd "$WORK/sdk"

# 2) 放入软件包（仓库根目录即包目录）
# Build/Prepare 调 $(CURDIR)/strip-linecheck.sh：包目录必须自带这份脚本，
# 所以主包这里显式复制（LuCI 包目录本来就整目录带过去）。
rm -rf package/isp-split package/luci-app-isp-split
mkdir -p package/isp-split
cp -r "$ROOT"/Makefile "$ROOT"/files "$ROOT"/strip-linecheck.sh package/isp-split/
mkdir -p package/luci-app-isp-split
cp -r "$ROOT"/luci-app-isp-split/. package/luci-app-isp-split/

# 3) feeds（解析依赖用）
if [ ! -d feeds/packages ]; then
	echo "更新 feeds（首次较慢）"
	./scripts/feeds update -a >/dev/null 2>&1 || echo "警告：feeds update 失败，依赖可能解析不了"
fi
if [ ! -L feeds/packages/net/mwan3 ] && [ ! -d feeds/packages/net/mwan3 ]; then
	./scripts/feeds install -a >/dev/null 2>&1 || true
fi

# 4) 构建
make defconfig >/dev/null
echo "编译 isp-split"
make FEATURE_LINECHECK="$FEATURE_LINECHECK" package/isp-split/compile V=s

echo "编译 luci-app-isp-split（若因 luci-base 版本差异失败，可忽略）"
make FEATURE_LINECHECK="$FEATURE_LINECHECK" package/luci-app-isp-split/compile V=s || echo "  跳过（依赖版本不匹配不影响主包）"

# 5) 收集产物
find bin/packages -type f \( -name 'isp-split*.apk' -o -name 'isp-split*.ipk' \
	-o -name 'luci-app-isp-split*.apk' -o -name 'luci-app-isp-split*.ipk' \) \
	-exec cp -v {} "$OUT/" \;

echo
echo "== 产物 =="
ls -lh "$OUT"
echo
echo "安装（25.12/apk 系）："
echo "  apk add --no-network --allow-untrusted $OUT/isp-split_*.apk"
