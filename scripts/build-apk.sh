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
# 出货门：1 = 完整功能（默认，0.3.0 起线路体检随包发货）；
#         0 = 显式构建剥离版（小闪存 / 特殊渠道）。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-1}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# F-19：工作目录必须按 SDK 版本分桶。
# 旧实现是固定的 $ROOT/.sdk-build，25.12 与 24.10 共用同一个 sdk/ 目录，
# 而复用条件是"staging_dir/toolchain 在就跳过下载"——先编 25.12 再编 24.10
# 时，24.10 会拿 25.12 的 toolchain/feeds 编译，产出看着成功、实际是错版包
# （CI 每次干净环境，本地才会踩）。
# 现在默认目录带 $VER，并且复用前校验版本标记文件；显式 OWRT_WORK 指向
# 别的版本时硬失败，绝不静默复用。
WORK=${OWRT_WORK:-$ROOT/.sdk-build/$VER}
OUT=$ROOT/dist/sdk-$VER
# 标记文件记录"这个 sdk/ 是哪一版、哪个架构解出来的"。
SDK_MARK_NAME=.isp-split-sdk-version
SDK_MARK=$WORK/sdk/$SDK_MARK_NAME
SDK_ID="$VER $ARCH"

BASE=https://downloads.openwrt.org/releases/$VER/targets/$ARCH

echo "== SDK 构建: $VER / $ARCH =="

mkdir -p "$WORK" "$OUT"

# 1) 下载并解压 SDK（每个版本目录只做一次）
# F-19：复用条件从"staging_dir/toolchain 存在"改成"版本标记匹配"。
# 标记缺失说明这个目录是旧脚本留下的、或者不是本脚本解出来的——无法
# 确认版本就硬失败，让用户删掉目录重来，而不是赌一把编出错版包。
if [ -d "$WORK/sdk" ] && [ -n "$(ls -A "$WORK/sdk" 2>/dev/null)" ]; then
	if [ ! -f "$SDK_MARK" ]; then
		echo "错误：$WORK/sdk 已存在但没有版本标记 $SDK_MARK_NAME，无法确认是哪一版 SDK。" >&2
		echo "      删除 $WORK 后重跑，或改用 OWRT_WORK=<空目录>。不要复用来路不明的 SDK 目录。" >&2
		exit 1
	fi
	_mark=$(cat "$SDK_MARK" 2>/dev/null | tr -d '\r')
	if [ "$_mark" != "$SDK_ID" ]; then
		echo "错误：$WORK 里的 SDK 是 '$_mark'，本次要编 '$SDK_ID'。" >&2
		echo "      同一工作目录不能混编两个版本/架构（F-19）。默认目录已按版本分桶：" >&2
		echo "      去掉 OWRT_WORK 直接跑，或指向另一个空目录。" >&2
		exit 1
	fi
	echo "复用 $WORK/sdk（$_mark）"
else
	FILE=$(curl -fsSL "$BASE/" | grep -oE 'openwrt-sdk-[^"<]*Linux-x86_64\.tar\.(zst|xz)' | head -1)
	[ -n "$FILE" ] || { echo "在 $BASE 找不到 SDK，确认版本号与架构" >&2; exit 1; }
	echo "下载 $FILE"

	# A-12：SDK 是随后会被执行的构建工具链，不能只靠 TLS。OpenWrt 的
	# target 目录同时发布 sha256sums（与 SDK 同源）；先取清单、再下载、
	# 最后逐字节核对。清单缺失或哈希不匹配都硬失败，绝不“校验不了就跳过”。
	SUMS=$(curl -fsSL "$BASE/sha256sums") || {
		echo "无法下载 SDK 校验清单: $BASE/sha256sums" >&2
		exit 1
	}
	WANT=$(printf '%s\n' "$SUMS" | awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1; exit }')
	[ -n "$WANT" ] || {
		echo "校验清单里没有 $FILE（上游未发布或文件名变了），拒绝无校验构建" >&2
		exit 1
	}
	curl -fsSL -o "$WORK/sdk.tar" "$BASE/$FILE"
	command -v sha256sum >/dev/null 2>&1 || {
		echo "缺少 sha256sum，无法校验 SDK" >&2
		exit 1
	}
	GOT=$(sha256sum "$WORK/sdk.tar" | awk '{ print $1 }')
	if [ "$GOT" != "$WANT" ]; then
		echo "SDK sha256 校验失败: 期望 $WANT，实际 $GOT（$FILE）" >&2
		rm -f "$WORK/sdk.tar"
		exit 1
	fi
	echo "SDK sha256 校验通过: $WANT"
	mkdir -p "$WORK/sdk"
	# 这里是**构建主机**（CI / Linux x86_64，GNU tar）解 SDK 包，--strip-components
	# 合法也必须用；路由器侧用户装源码包的姿势（busybox tar 不支持该参数）在
	# release body 与 INSTALL.txt 里，两边各说各的场景，别互相抄。
	case "$FILE" in
	*.zst) tar --zstd -xf "$WORK/sdk.tar" -C "$WORK/sdk" --strip-components=1 ;;
	*)     tar -xf "$WORK/sdk.tar" -C "$WORK/sdk" --strip-components=1 ;;
	esac
	# 标记写在解压完成之后：中途失败不会留下"看起来可用"的半套 SDK。
	printf '%s\n' "$SDK_ID" > "$SDK_MARK" || { echo "无法写入 $SDK_MARK" >&2; exit 1; }
	echo "SDK 已解压到 $WORK/sdk（$SDK_ID）"
fi
echo "工作目录: $WORK"
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
# F-21：两种包名的通配符口径不同，照抄会 glob 不到文件：
#   apk = isp-split-<版本>-r<发布号>.apk（连字符，apk 3 的命名规则）
#   ipk = isp-split_<版本>-<发布号>_all.ipk（下划线）
# 按实际产物给命令：24.10 SDK 只产 ipk，不该提示 apk add。
if ls "$OUT"/*.apk >/dev/null 2>&1; then
	echo "安装（25.12/apk 系）："
	echo "  apk add --no-network --allow-untrusted $OUT/isp-split-*.apk"
fi
if ls "$OUT"/*.ipk >/dev/null 2>&1; then
	echo "安装（≤24.10/opkg 系）："
	echo "  opkg install $OUT/isp-split_*_all.ipk"
fi
