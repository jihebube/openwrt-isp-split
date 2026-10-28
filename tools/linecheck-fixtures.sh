#!/bin/sh
# 线路体检 STUN fixture 生成器（离线、无网络、无 Python）
#
# 用法：sh tools/linecheck-fixtures.sh [输出目录]
# 默认输出到 ./linecheck-fixtures
#
# 生成内容（全部是 20 字节 Binding Request 的响应）：
#   stun-32.bin       最小合法响应：XOR-MAPPED-ADDRESS，32 字节
#   stun-84.bin       含 XOR-MAPPED + MAPPED + SOFTWARE 的 84 字节响应
#   stun-timeout.bin  空文件（socat -T 超时的真实产物）
#   stun-bad-magic.bin   magic cookie 错误
#   stun-bad-txid.bin    transaction id 与请求不一致
#   stun-bad-type.bin    Binding Error Response（0x0103），不是成功响应
#   stun-short.bin       截断到 30 字节（属性越界）
#   stun-bad-len.bin     头部长度大于实际报文
#
# 期望值（合法 fixture）：
#   121.20.198.57 44653   （河北联通，报告 §2.2 的实测样本）
#
# 这些文件同时被 tools/selftest.sh 和 VM 回归使用；不依赖 hexdump -R / xxd。

set -u
OUT=${1:-./linecheck-fixtures}
mkdir -p "$OUT" || { echo "无法创建 $OUT" >&2; exit 1; }

# hex 字符串 -> 二进制（busybox printf 八进制；fold/read 都是 busybox 自带）
hex2bin() {
	_hex=$1
	_out=$2
	: >"$_out" || return 1
	# 不用 fold：部分 busybox 精简固件（含测试 VM）没有 fold。
	# cut 是 busybox 自带，逐字节转八进制交给 printf。
	_i=1
	_n=${#_hex}
	while [ "$_i" -le "$_n" ]; do
		_b=$(printf '%s' "$_hex" | cut -c"$_i"-$((_i + 1)))
		printf "\\$(printf '%03o' "$((0x$_b))")" >>"$_out"
		_i=$((_i + 2))
	done
}

# 32 字节：type=0101 len=000c magic=2112a442 txid=1122...cc
# XOR-MAPPED: 00 20 00 08 00 01 8f 7f 58 06 62 7b
#   port 0x8f7f ^ 0x2112 = 44653；ip 58.06.62.7b ^ 21.12.a4.42 = 121.20.198.57
H32=0101000c2112a442112233445566778899aabbcc0020000800018f7f5806627b

# 84 字节：20 头 + 12 XOR-MAPPED + 12 MAPPED + 36 SOFTWARE(32B) + 4 空属性
# 消息长度 = 84 - 20 = 64 = 0x0040
H84=010100402112a442112233445566778899aabbcc0020000800018f7f5806627b000100080001ae6d7914c639802200206c696e65636865636b2d666978747572652d736f6674776172652d303030303180220000

hex2bin "$H32" "$OUT/stun-32.bin"
hex2bin "$H84" "$OUT/stun-84.bin"
: >"$OUT/stun-timeout.bin"

# magic cookie 改坏（偏移 4..7 = 00000000）
hex2bin 0101000c00000000112233445566778899aabbcc0020000800018f7f5806627b "$OUT/stun-bad-magic.bin"

# txid 与请求（1122...cc）不一致
hex2bin 0101000c2112a442ffeeddccbbaa9988776655440020000800018f7f5806627b "$OUT/stun-bad-txid.bin"

# 0x0103 Binding Error Response，不是 0x0101 Success
hex2bin 0103000c2112a442112233445566778899aabbcc0020000800018f7f5806627b "$OUT/stun-bad-type.bin"

# 截断：30 字节，属性声明 8 字节但只剩 2 字节
hex2bin 0101000c2112a442112233445566778899aabbcc0020000800018f7f58 "$OUT/stun-short.bin"

# 头部长度 0x0040，实际只有 32 字节
hex2bin 010100402112a442112233445566778899aabbcc0020000800018f7f5806627b "$OUT/stun-bad-len.bin"

cat >"$OUT/expected.txt" <<'EXP'
# fixture	expected
stun-32.bin	121.20.198.57 44653
stun-84.bin	121.20.198.57 44653
stun-timeout.bin	FAIL
stun-bad-magic.bin	FAIL
stun-bad-txid.bin	FAIL
stun-bad-type.bin	FAIL
stun-short.bin	FAIL
stun-bad-len.bin	FAIL
EXP

echo "已生成 fixture：$OUT"
ls -l "$OUT" | sed 's/^/  /'
