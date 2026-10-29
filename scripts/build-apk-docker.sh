#!/bin/sh
# 在 Docker 里跑 SDK 构建 —— 给 Mac / Windows / 没有 Linux 环境的人
#
# 用法：
#   sh scripts/build-apk-docker.sh                 # 默认 25.12.6
#   sh scripts/build-apk-docker.sh 24.10.4         # 编 opkg/ipk 版
#
# 产物同样落在 dist/sdk-<版本>/。
# 第一次运行会拉镜像 + 装 SDK 依赖（约 3-5 分钟，联网）。
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
VER=${1:-25.12.6}

command -v docker >/dev/null 2>&1 || {
	echo "未安装 docker。没有 Docker 就得用原生 Linux 跑 scripts/build-apk.sh" >&2
	exit 1
}

echo "== Docker SDK 构建: $VER =="
echo "仓库挂载: $REPO -> /repo"
echo

# debian:bookworm 里装齐 OpenWrt SDK 的宿主依赖后，复用同一个构建脚本。
# 这保证了"本地 Linux 构建"与"Docker 构建"走的是完全相同的代码路径。
#
# F-20：显式钉住 linux/amd64。OpenWrt SDK 只有 Linux x86_64 版本，SDK 里的
# toolchain 也是 x86_64 二进制。Apple Silicon（arm64）上 docker 默认拉
# linux/arm64 镜像，容器里跑的是 arm64 的 debian，SDK 的 gcc/make 全部
# "cannot execute binary file"，报错埋在几百行编译日志里；即使靠 QEMU
# 兜住，构建也会慢到不可用。钉住平台后走 Rosetta/QEMU 模拟，行为与 x86 主机一致。
docker run --rm \
	--platform linux/amd64 \
	-e SDK_VER="$VER" \
	-v "$REPO":/repo \
	-w /repo \
	debian:bookworm-slim \
	bash -ec '
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
		build-essential flex bison gawk gettext git \
		libncurses-dev libssl-dev python3 rsync unzip \
		zlib1g-dev file wget curl zstd ca-certificates xz-utils \
		perl python3-distutils >/dev/null
	# 平台没钉住时这里会以 "Exec format error" 炸掉：先把结论说清楚。
	case "$(uname -m)" in
	x86_64 | amd64) ;;
	*)
		echo "错误：容器架构是 $(uname -m)，OpenWrt SDK 需要 linux/amd64（F-20）" >&2
		exit 1
		;;
	esac
	echo "== 依赖就绪，开始 SDK 构建 =="
	sh scripts/build-apk.sh "$SDK_VER" x86/64
	'

echo
echo "产物在 $REPO/dist/sdk-$VER/"
