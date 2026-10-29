#!/bin/sh
# 产物 payload 断言：容器嗅探 + 双向期望面 + 两条构建路径恒等。
#
# 用法：
#   sh scripts/verify-package-payload.sh verify --feature=1 <pkg>...   # 0.3.0 发货面
#   sh scripts/verify-package-payload.sh verify --feature=0 <pkg>...   # 剥离版
#   sh scripts/verify-package-payload.sh parity <pkgA> <pkgB>
#
# 期望面必须显式给出（不设默认值）：0.3.0 把断言方向从「零残留」翻成「必须有」，
# 留一个默认值就会在发版时悄悄沿用旧方向，等于没断言。
#   --feature=1：linecheck 子命令可调用、lc-run 在包里、linecheck.js + 菜单节点
#                安装、CSS 含 .lc-*、conf 有 LINE_CHECK_* 键、Depends 含 socat；
#   --feature=0：反向——grep 零残留、CSS 无 .lc-*（0.2.3 的剥离资产，保留可跑）。
#
# 支持的容器（按 magic 嗅探，不看扩展名）：
#   · gzip-tar ipk（1f 8b）：23.05/24.10 官方与 scripts/build-ipk.sh 默认产物
#   · 明文 ar ipk（21 3c 61 72，"!<ar"）：历史格式，build-ipk.sh 的 ar 回退
#   · ADB 容器 apk（41 44 42 64，"ADBd"）：25.12 起 apk-tools 3.x 的产物
#
# 未知格式必须显式失败——绝不静默跳过。CI 的 25.12 job 只产 .apk，旧断言
# 循环 glob 的是 out/*.ipk，于是循环空转、假通过（F8）。
#
# apk 解包用 apk-tools 3.x 的 `apk extract`：CI 里就是刚编译用的那个 SDK 的
# staging_dir/host/bin/apk（build-apk.sh 已下载）。找不到工具就报错，不降级为
# “跳过”。ipk 用 tar/ar，纯 shell 即可。
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "$*" >&2; exit 1; }

WORK=$(mktemp -d 2>/dev/null) || WORK=$(mktemp -d /tmp/verify-pkg.XXXXXX) ||
	die "无法创建临时目录"
trap 'rm -rf "$WORK"' EXIT
printf '\037\213' >"$WORK/m.gz"
printf '!<ar' >"$WORK/m.ar"
printf 'ADBd' >"$WORK/m.adb"

mkdtemp() {
	mktemp -d 2>/dev/null || mktemp -d /tmp/verify-pkg.XXXXXX ||
		die "无法创建临时目录"
}

magic_id() { # <pkg> -> gzip | ar | apk | unknown
	# 不用 od（OpenWrt 精简 busybox 没有 od applet），dd + cmp 比前缀
	if dd if="$1" bs=1 count=2 2>/dev/null | cmp -s - "$WORK/m.gz"; then
		echo gzip
	elif dd if="$1" bs=1 count=4 2>/dev/null | cmp -s - "$WORK/m.ar"; then
		echo ar
	elif dd if="$1" bs=1 count=4 2>/dev/null | cmp -s - "$WORK/m.adb"; then
		echo apk
	else
		echo unknown
	fi
}

apk_bin() {
	if [ -n "${APK_BIN:-}" ]; then
		[ -x "$APK_BIN" ] || die "APK_BIN 指向的文件不可执行: $APK_BIN"
		printf '%s\n' "$APK_BIN"
		return 0
	fi
	if command -v apk >/dev/null 2>&1; then
		command -v apk
		return 0
	fi
	for _c in \
		"${OWRT_WORK:-$ROOT/.sdk-build}/sdk/staging_dir/host/bin/apk" \
		"$ROOT/.sdk-build/sdk/staging_dir/host/bin/apk"; do
		if [ -x "$_c" ]; then
			printf '%s\n' "$_c"
			return 0
		fi
	done
	return 1
}

# ar 容器里取成员：有 ar 用 ar，没有就用 60 字节头 + dd 直接读
ar_member() { # <ar> <member> <out>
	if command -v ar >/dev/null 2>&1; then
		ar p "$1" "$2" >"$3" 2>/dev/null && [ -s "$3" ] && return 0
	fi
	_pos=8
	_hdr=$3.hdr
	while :; do
		rm -f "$_hdr"
		dd if="$1" bs=1 skip="$_pos" count=60 of="$_hdr" 2>/dev/null
		[ "$(wc -c <"$_hdr" 2>/dev/null || echo 0)" -eq 60 ] || return 1
		_name=$(cut -c1-16 "$_hdr" | sed 's/[[:space:]]*$//; s:/$::')
		_size=$(cut -c49-58 "$_hdr" | tr -cd '0-9')
		_pos=$((_pos + 60))
		if [ "$_name" = "$2" ]; then
			tail -c +$((_pos + 1)) "$1" | head -c "$_size" >"$3"
			rm -f "$_hdr"
			[ -s "$3" ] && return 0
			return 1
		fi
		_pos=$((_pos + ${_size:-0}))
		[ $((_pos % 2)) -eq 1 ] && _pos=$((_pos + 1))
	done
}

extract_payload() { # <pkg> <dest>
	_pkg=$1
	_dest=$2
	[ -f "$_pkg" ] || die "产物不存在: $_pkg"
	_kind=$(magic_id "$_pkg")
	rm -rf "$_dest"
	mkdir -p "$_dest"
	case "$_kind" in
	gzip)
		# gzip-tar：外层解开就是 debian-binary / control.tar.gz / data.tar.gz
		_x=$_dest.outer
		rm -rf "$_x"
		mkdir -p "$_x"
		tar xzf "$_pkg" -C "$_x" || die "$_pkg: gzip-tar 外层解包失败"
		[ -f "$_x/data.tar.gz" ] ||
			die "$_pkg: gzip-tar 外层没有 data.tar.gz（成员: $(tar tzf "$_pkg" 2>/dev/null | tr '\n' ' '))"
		tar xzf "$_x/data.tar.gz" -C "$_dest" || die "$_pkg: data.tar.gz 解包失败"
		rm -rf "$_x"
		;;
	ar)
		# 明文 ar：!<ar
		_x=$_dest.outer
		rm -rf "$_x"
		mkdir -p "$_x"
		ar_member "$_pkg" data.tar.gz "$_x/data.tar.gz" ||
			die "$_pkg: ar 容器里取不到 data.tar.gz"
		tar xzf "$_x/data.tar.gz" -C "$_dest" || die "$_pkg: data.tar.gz 解包失败"
		rm -rf "$_x"
		;;
	apk)
		# ADB 容器：apk-tools 3.x。没有工具就硬失败，不静默跳过。
		_apk=$(apk_bin) || die "$_pkg: 是 ADB 容器（apk），但找不到 apk-tools 3.x 解包工具；请设置 APK_BIN=/path/to/apk（SDK 的 staging_dir/host/bin/apk）"
		_log=$_dest.apk-extract.log
		if "$_apk" extract --allow-untrusted --destination "$_dest" "$_pkg" >"$_log" 2>&1; then
			:
		else
			# 老一点的 3.x 没有 --destination，退回“进目录再 extract”
			rm -rf "$_dest"
			mkdir -p "$_dest"
			( cd "$_dest" && "$_apk" extract --allow-untrusted "$_pkg" ) >"$_log" 2>&1 || {
				cat "$_log" >&2
				rm -f "$_log"
				die "$_pkg: apk extract 失败（apk-tools 版本或容器损坏）"
			}
		fi
		rm -f "$_log"
		;;
	*)
		_head=$(dd if="$_pkg" bs=1 count=4 2>/dev/null | tr -cd '[:print:]')
		die "$_pkg: 未知容器格式（magic=$_head），拒绝静默跳过"
		;;
	esac
	# 空 payload 也是假通过：至少要有一个文件被解出来
	[ -n "$(find "$_dest" -type f | head -1)" ] ||
		die "$_pkg: 解包后 payload 为空（容器格式或解包通路不对）"
}

assert_clean() { # <pkg> <payload-dir>
	_pkg=$1
	_payload=$2
	_leak=$(grep -rIl 'linecheck\|LINE_CHECK\|线路体检' "$_payload" 2>/dev/null || true)
	if [ -n "$_leak" ]; then
		echo "::error::$_pkg 仍含 linecheck 残留：" >&2
		printf '%s\n' "$_leak" | sed 's/^/  /' >&2
		return 1
	fi
	# `.lc-*` 样式类不含 linecheck 字样，字符串断言抓不到——F7 的泄漏面。
	_cssleak=$(find "$_payload" -type f -name '*.css' -exec grep -l '\.lc-' {} + 2>/dev/null || true)
	if [ -n "$_cssleak" ]; then
		echo "::error::$_pkg 的 CSS 仍含 .lc-* 样式（体检样式没被标记包住/没剥离）：" >&2
		printf '%s\n' "$_cssleak" | sed 's/^/  /' >&2
		return 1
	fi
	return 0
}

# 包的 Depends 原文（三个容器各走各的读法；读不到就返回 1，不静默算过）
pkg_depends() { # <pkg>
	_kind=$(magic_id "$1")
	_w=$(mkdtemp)
	case "$_kind" in
	gzip)
		# 成员名带 "./" 前缀（与官方产物一致），按名提取会被 tar 拒；
		# 整包解开后再取 control.tar.gz。
		mkdir -p "$_w/outer" "$_w/ctl"
		tar xzf "$1" -C "$_w/outer" 2>/dev/null || { rm -rf "$_w"; return 1; }
		[ -f "$_w/outer/control.tar.gz" ] || { rm -rf "$_w"; return 1; }
		tar xzf "$_w/outer/control.tar.gz" -C "$_w/ctl" 2>/dev/null || { rm -rf "$_w"; return 1; }
		[ -f "$_w/ctl/control" ] || { rm -rf "$_w"; return 1; }
		sed -n 's/^Depends:[[:space:]]*//p' "$_w/ctl/control"
		;;
	ar)
		ar_member "$1" control.tar.gz "$_w/control.tar.gz" || { rm -rf "$_w"; return 1; }
		mkdir -p "$_w/ctl"
		tar xzf "$_w/control.tar.gz" -C "$_w/ctl" 2>/dev/null || { rm -rf "$_w"; return 1; }
		sed -n 's/^Depends:[[:space:]]*//p' "$_w/ctl/control"
		;;
	apk)
		_apk=$(apk_bin) || { rm -rf "$_w"; return 1; }
		"$_apk" adbdump "$1" 2>/dev/null >"$_w/adbdump" || { rm -rf "$_w"; return 1; }
		sed -n '/^  depends:/,/^  [a-z]/p' "$_w/adbdump"
		;;
	*)
		rm -rf "$_w"
		return 1
		;;
	esac
	rm -rf "$_w"
}

# feature=1 期望面：0.3.0 的产物**必须**含体检。
# 这是 0 版「零残留」的镜像：同一批断言反过来证明体检真的在包里。
assert_feature1() { # <pkg> <payload-dir>
	_pkg=$1
	_payload=$2
	_bad=0
	_main=$_payload/usr/sbin/isp-split
	_views=$_payload/www/luci-static/resources/view/isp-split
	_conf=$_payload/etc/isp-split.conf
	_has_main=0
	[ -f "$_main" ] && _has_main=1
	_has_luci=0
	[ -d "$_views" ] && _has_luci=1
	if [ "$_has_main" = 0 ] && [ "$_has_luci" = 0 ]; then
		echo "::error::$_pkg：payload 里既没有 usr/sbin/isp-split 也没有 LuCI 视图目录" >&2
		return 1
	fi

	if [ "$_has_main" = 1 ]; then
		# 1) 主脚本语法完好（标记区不能被切坏）
		if ! sh -n "$_main" 2>/dev/null; then
			echo "::error::$_pkg：usr/sbin/isp-split 语法错误（sh -n 失败）" >&2
			_bad=1
		fi
		# 2) linecheck 子命令真的可调用：在临时 conf/base 上跑 usage 与 conf 写面
		_t=$(mkdtemp)
		mkdir -p "$_t/base"
		if [ -f "$_conf" ]; then cp "$_conf" "$_t/conf"; else : >"$_t/conf"; fi
		ISP_SPLIT_CONF="$_t/conf" ISP_SPLIT_BASE="$_t/base" \
			sh "$_main" >"$_t/usage" 2>&1 || true
		if ! grep -q 'linecheck' "$_t/usage"; then
			echo "::error::$_pkg：usage 里没有 linecheck 子命令（体检没进 CLI 面）" >&2
			_bad=1
		fi
		# conf 键必须被识别：与 19.7 的剥离版断言是同一个命令、相反方向
		if ISP_SPLIT_CONF="$_t/conf" ISP_SPLIT_BASE="$_t/base" \
			sh "$_main" conf set LINE_CHECK_GEO 0 >"$_t/confset" 2>&1 &&
			grep -q '^LINE_CHECK_GEO="0"' "$_t/conf"; then
			:
		else
			echo "::error::$_pkg：conf set LINE_CHECK_GEO 不被接受（conf 键面缺失）：" >&2
			sed 's/^/  /' "$_t/confset" >&2
			_bad=1
		fi
		rm -rf "$_t"
		# 3) 后台探测引擎入口 lc-run 必须在包里
		if [ ! -f "$_payload/usr/lib/isp-split/lc-run" ]; then
			echo "::error::$_pkg：缺少 /usr/lib/isp-split/lc-run（--background 探测引擎）" >&2
			_bad=1
		elif ! sh -n "$_payload/usr/lib/isp-split/lc-run" 2>/dev/null; then
			echo "::error::$_pkg：usr/lib/isp-split/lc-run 语法错误" >&2
			_bad=1
		fi
		# 4) conf 必须有 LINE_CHECK_* 键（四项核心键，缺一项就说明标记区没进包）
		for _k in LINE_CHECK_ENABLE LINE_CHECK_GEO LINE_CHECK_MIN_INTERVAL LINE_CHECK_STUN_SERVERS; do
			if ! grep -q "^${_k}=" "$_conf" 2>/dev/null; then
				echo "::error::$_pkg：/etc/isp-split.conf 缺少 ${_k}=" >&2
				_bad=1
			fi
		done
		# 5) Depends 必须含 socat（UDP STUN 锁线探测的实际依赖）
		_kind=$(magic_id "$_pkg")
		_dep=$(pkg_depends "$_pkg") || {
			echo "::error::$_pkg：读不到包的 Depends（容器 $_kind）" >&2
			_bad=1
			_dep=""
		}
		if [ -n "$_dep" ] && ! printf '%s\n' "$_dep" | grep -qw 'socat'; then
			echo "::error::$_pkg：Depends 不含 socat（实际：$(printf '%s' "$_dep" | tr '\n' ' ')）" >&2
			_bad=1
		fi
	fi

	if [ "$_has_luci" = 1 ]; then
		# 6) 体检页与独立菜单节点必须安装
		if [ ! -s "$_views/linecheck.js" ]; then
			echo "::error::$_pkg：缺少 view/isp-split/linecheck.js（体检卡片页）" >&2
			_bad=1
		fi
		_menu=$_payload/usr/share/luci/menu.d/luci-app-isp-split.json
		_lmenu=$_payload/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json
		if [ ! -s "$_lmenu" ] || ! grep -q '"admin/network/isp-split/linecheck"' "$_lmenu"; then
			echo "::error::$_pkg：缺少线路体检菜单节点 luci-app-isp-split-linecheck.json" >&2
			_bad=1
		fi
		# 7) 菜单子节点 = 3（状态 / 配置 / 线路体检）。
		#    体检节点在独立文件里，LuCI 运行时会合并 menu.d，所以跨文件数。
		_kids=$(cat "$_payload"/usr/share/luci/menu.d/*.json 2>/dev/null |
			grep -c '"admin/network/isp-split/' || true)
		if [ "${_kids:-0}" != "3" ]; then
			echo "::error::$_pkg：menu 子节点=${_kids:-0}（完整版应为 3：状态/配置/线路体检）" >&2
			_bad=1
		fi
		# 8) CSS 必须实际带体检样式类（与 0 版「无 .lc-*」相反的断言）
		_css=$(find "$_payload" -type f -name '*.css' -exec grep -l '\.lc-' {} + 2>/dev/null || true)
		if [ -z "$_css" ]; then
			echo "::error::$_pkg：CSS 里没有 .lc-* 样式（体检卡片页会无样式）" >&2
			_bad=1
		fi
		# 9) 线检页 JS 语法（有 node 才查；没有就跳过，不假装通过）
		if command -v node >/dev/null 2>&1 && [ -s "$_views/linecheck.js" ]; then
			if ! node --check "$_views/linecheck.js" 2>/dev/null; then
				echo "::error::$_pkg：linecheck.js 语法错误（node --check 失败）" >&2
				_bad=1
			fi
		fi
	fi

	return "$_bad"
}

cmd_verify() {
	# 方向必须显式给出：默认值会让断言面在发版时悄悄反向（F7/F8 的教训）。
	_feature=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--feature=0 | --feature=1) _feature=${1#--feature=} ;;
		*) break ;;
		esac
		shift
	done
	[ -n "$_feature" ] ||
		die "verify 必须显式指定期望面：--feature=0（剥离版零残留）或 --feature=1（完整版含体检）"
	[ "$#" -gt 0 ] || die "verify：没有给任何产物（空列表=真空通过，拒绝）"
	_checked=0
	_bad=0
	for p in "$@"; do
		[ -f "$p" ] || die "verify：产物不存在: $p（glob 没展开？）"
		d=$(mkdtemp)
		if extract_payload "$p" "$d/payload"; then
			if [ "$_feature" = "1" ]; then
				if assert_feature1 "$p" "$d/payload"; then
					echo "[ok] $p（$(magic_id "$p") 容器，payload $(find "$d/payload" -type f | wc -l | tr -d ' ') 个文件，feature=1 期望面全中）"
				else
					_bad=1
				fi
			else
				if assert_clean "$p" "$d/payload"; then
					echo "[ok] $p（$(magic_id "$p") 容器，payload $(find "$d/payload" -type f | wc -l | tr -d ' ') 个文件，零残留）"
				else
					_bad=1
				fi
			fi
		else
			_bad=1
		fi
		rm -rf "$d"
		_checked=$((_checked + 1))
	done
	[ "$_checked" -gt 0 ] || die "verify：实际检查了 0 个产物（真空通过，拒绝）"
	[ "$_bad" -eq 0 ] || die "verify：有产物未通过 feature=$_feature 断言"
	echo "verify（feature=$_feature）：$_checked 个产物全部通过"
}

cmd_parity() {
	[ "$#" -eq 2 ] || die "parity：需要两个产物（本地路径产物 / SDK 路径产物）"
	command -v diff >/dev/null 2>&1 || die "parity：缺少 diff 命令（CI 上一定有；VM 精简 busybox 没这个 applet）"
	a=$1
	b=$2
	da=$(mkdtemp)
	db=$(mkdtemp)
	extract_payload "$a" "$da/payload"
	extract_payload "$b" "$db/payload"
	# apk 安装时会写自己的数据库目录；它不属于包 payload，两边都不该比。
	rm -rf "$da/payload/lib/apk" "$db/payload/lib/apk"
	# 删空目录：apk 侧可能留下只有 lib/apk 的空 lib/，内容比较不该被它绊倒
	find "$da/payload" -type d -empty -delete 2>/dev/null || true
	find "$db/payload" -type d -empty -delete 2>/dev/null || true
	# 空目录（如 etc/isp-split/data）两边都可能存在，diff -r 会比对目录结构
	if diff -r "$da/payload" "$db/payload" >"$da/diff.txt" 2>&1; then
		echo "[ok] payload 恒等: $a == $b（$(find "$da/payload" -type f | wc -l | tr -d ' ') 个文件）"
		rm -rf "$da" "$db"
	else
		echo "::error::两条构建路径的 payload 不一致：" >&2
		echo "  A=$a" >&2
		echo "  B=$b" >&2
		sed 's/^/  /' "$da/diff.txt" >&2
		rm -rf "$da" "$db"
		exit 1
	fi
}

cmd=${1:-}
[ -n "$cmd" ] || die "用法: sh scripts/verify-package-payload.sh verify --feature=0|1 <pkg>... | parity <pkgA> <pkgB>"
shift || true
case "$cmd" in
verify) cmd_verify "$@" ;;
parity) cmd_parity "$@" ;;
*) die "未知子命令: $cmd（verify|parity）" ;;
esac
