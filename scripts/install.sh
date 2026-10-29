#!/bin/sh
# 通用安装脚本 —— 适用于任何 OpenWrt，尤其是 25.12+ 的 apk 系固件
#
# 为什么需要它：
#   OpenWrt 25.12 起包管理器从 opkg 换成 apk-tools 3.x，包格式是带签名段的
#   私有容器，无法像 .ipk 那样手工拼装。没有 SDK 编译环境时，直接用这个脚本
#   复制文件即可，效果与装包一致。
#
# 用法（在解压后的仓库目录，或仅上传 files/ 目录亦可）：
#   sh scripts/install.sh            安装（不启用定时任务）
#   sh scripts/install.sh --cron     安装并启用每日自动更新
#   sh scripts/install.sh --uninstall 卸载（调用 isp-split uninstall）
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$ROOT/files
# 出货门，与 Makefile / build-ipk.sh 同义：1 = 完整功能（默认），0 = 构建期剥离。
FEATURE_LINECHECK=${FEATURE_LINECHECK:-1}
case "$FEATURE_LINECHECK" in 0|1) ;; *) echo "FEATURE_LINECHECK 只能是 0 或 1" >&2; exit 1 ;; esac
LUCI_SRC=$ROOT/luci-app-isp-split
STAGE=""

say() { printf '[install] %s\n' "$*"; }
die() { printf '[install] 错误: %s\n' "$*" >&2; exit 1; }

cleanup_stage() {
	if [ -n "${STAGE:-}" ]; then rm -rf "$STAGE"; fi
	return 0
}
trap cleanup_stage EXIT

[ "$(id -u)" = "0" ] || die "需要 root 权限"
[ -d "$SRC" ] || die "找不到 $SRC，请在仓库根目录运行"

if [ "${1:-}" = "--uninstall" ]; then
	# F-14：卸载清理只有一份实现——files/usr/lib/isp-split/teardown.sh
	# （与 `isp-split uninstall`、包 postrm 同源）。旧版本这里只删 LuCI 资源，
	# 于是 rc=0 而 /usr/sbin/isp-split、/etc/init.d/isp-split、/usr/lib/isp-split/、
	# /etc/isp-split.conf、isp_fallback 计数器、.conf.bak.* 全留着。
	shift
	KEEP_BAK=0
	for arg in "$@"; do
		case "$arg" in
		--keep-conf-bak) KEEP_BAK=1 ;;
		*) say "卸载时忽略未知参数: $arg" ;;
		esac
	done
	# 先走已装版本的卸载（它内部也调 teardown.sh，且会用 rules-splice 摘掉
	# mwan3 规则块——那一步需要 /usr/lib/isp-split/rules-splice.awk）。
	if [ -x /usr/sbin/isp-split ]; then
		/usr/sbin/isp-split uninstall ||
			say "警告：isp-split uninstall 非零退出，继续用 teardown.sh 兜底清理"
	else
		say "isp-split 未安装或不可执行，直接用 teardown.sh 清理"
	fi
	# 再无条件跑一遍：幂等，且二进制缺失/损坏/版本不符时也能清干净。
	TEARDOWN=$SRC/usr/lib/isp-split/teardown.sh
	[ -f "$TEARDOWN" ] || TEARDOWN=/usr/lib/isp-split/teardown.sh
	[ -f "$TEARDOWN" ] || die "找不到 teardown.sh（仓库树不完整？）"
	if [ "$KEEP_BAK" = "1" ]; then
		sh "$TEARDOWN" all --keep-conf-bak || die "teardown.sh 执行失败，卸载不完整"
	else
		sh "$TEARDOWN" all || die "teardown.sh 执行失败，卸载不完整"
	fi
	say "已卸载（脚本、配置、LuCI 页面、计数器、dnsmasq confdir 状态全部清理）"
	exit 0
fi

# 前置检查
[ -f /etc/openwrt_release ] || say "警告：这不像 OpenWrt，继续但可能有问题"
command -v nft >/dev/null 2>&1 || die "缺少 nft"

# mwan3 必须是 nftables 版（Kwrt 源叫 mwan3-nft，官方 feed 的 mwan3 是 iptables 版）
# apk list -I 的输出是 "mwan3-3.6.12-r1 ..."（连字符接版本），
# opkg 是 "mwan3 - 3.6.x"，所以只按前缀匹配
if ! apk list -I 2>/dev/null | grep -q "^mwan3" &&
   ! opkg list-installed 2>/dev/null | grep -q "^mwan3"; then
	die "未检测到 mwan3 / mwan3-nft。需要 nftables 版 mwan3（>= 3.6.0）：
     Kwrt:  apk add mwan3-nft
     上游:  https://github.com/dl12345/mwan3"
fi
if grep -q render_config_ipsets /lib/mwan3/mwan3.sh 2>/dev/null; then
	say "mwan3 为 nftables 版 ✓"
else
	die "检测到 iptables 版 mwan3 —— 本项目需要 nftables 版（>= 3.6.0）"
fi
if ! nft list table inet mwan3 >/dev/null 2>&1; then
	say "警告：table inet mwan3 不存在"
	say "      说明 mwan3-nft 未运行或装的是 iptables 版，本项目无法工作"
	say "      检查: grep -c render_config_ipsets /lib/mwan3/mwan3.sh   （需 >=1）"
fi

# 备份已有配置
if [ -f /etc/isp-split.conf ]; then
	BAK=/etc/isp-split.conf.bak.$(date +%Y%m%d-%H%M%S)
	cp -f /etc/isp-split.conf "$BAK"
	say "已备份原配置到 $BAK（保留你的 ISP_TABLE 设置前请先比对）"
	KEEP_CONF=1
fi

# 复制文件。FEATURE_LINECHECK=0 时先在临时目录里做一次构建期剥离，
# 再从剥离后的树安装——安装目录里不会出现可被重新打开的实现。
if [ "$FEATURE_LINECHECK" != "1" ]; then
	if grep -q 'lc:begin' "$SRC/usr/sbin/isp-split" 2>/dev/null; then
		[ -f "$ROOT/scripts/strip-linecheck.sh" ] ||
			die "缺少 scripts/strip-linecheck.sh，无法剥离（或改用 FEATURE_LINECHECK=1）"
		STAGE=$(mktemp -d 2>/dev/null) || STAGE=$(mktemp -d /tmp/isp-split-stage.XXXXXX) || die "无法创建临时目录"
		mkdir -p "$STAGE/files"
		cp -a "$SRC/." "$STAGE/files/"
		sh "$ROOT/scripts/strip-linecheck.sh" "$STAGE/files" >/dev/null
		SRC=$STAGE/files
	fi
	# 只暂存真正会被安装的两棵树。包目录里还有 Makefile / strip-linecheck.sh，
	# 它们含有 `lc:begin` 与 `linecheck` 字样，整目录复制会被自己的断言误杀。
	if [ -d "$LUCI_SRC" ] &&
	   grep -rIq 'lc:begin' "$LUCI_SRC/htdocs" "$LUCI_SRC/root" 2>/dev/null; then
		[ -n "${STAGE:-}" ] || STAGE=$(mktemp -d 2>/dev/null) ||
			STAGE=$(mktemp -d /tmp/isp-split-stage.XXXXXX) || die "无法创建临时目录"
		mkdir -p "$STAGE/luci"
		cp -a "$LUCI_SRC/htdocs" "$LUCI_SRC/root" "$STAGE/luci/"
		sh "$ROOT/scripts/strip-linecheck.sh" "$STAGE/luci" >/dev/null
		LUCI_SRC=$STAGE/luci
	fi
fi
mkdir -p /usr/sbin /usr/lib/isp-split /etc/init.d /etc/isp-split/data
cp -f "$SRC/usr/sbin/isp-split" /usr/sbin/isp-split
cp -f "$SRC/usr/lib/isp-split/"*.awk "$SRC/usr/lib/isp-split/build.sh" /usr/lib/isp-split/
# F-14：卸载清理的唯一实现必须跟着装进设备——`isp-split uninstall` 靠它，
# 缺了这一份就只能退回"各写一份清单"的老路（install 路径当时正是漏装它）。
cp -f "$SRC/usr/lib/isp-split/teardown.sh" /usr/lib/isp-split/teardown.sh
if [ -f "$SRC/usr/lib/isp-split/lc-run" ]; then
	cp -f "$SRC/usr/lib/isp-split/lc-run" /usr/lib/isp-split/
fi
cp -f "$SRC/etc/init.d/isp-split" /etc/init.d/isp-split
chmod 755 /usr/sbin/isp-split /etc/init.d/isp-split /usr/lib/isp-split/build.sh \
	/usr/lib/isp-split/teardown.sh
if [ "$FEATURE_LINECHECK" != "1" ]; then
	# 升级残留：旧功能版留下的引擎入口与缓存目录不能留在 0 版设备上。
	rm -f /usr/lib/isp-split/lc-run
	rm -rf /etc/isp-split/state/linecheck*
fi

# 配置文件：已存在则不覆盖，避免冲掉用户的 ISP_TABLE
if [ "${KEEP_CONF:-0}" = "1" ]; then
	say "保留现有 /etc/isp-split.conf 不覆盖"
	say "  新版默认值可参考 $SRC/etc/isp-split.conf（注意 cmcc 默认已改为 wanb_only）"
else
	cp -f "$SRC/etc/isp-split.conf" /etc/isp-split.conf
	say "已写入 /etc/isp-split.conf"
fi

/etc/init.d/isp-split enable >/dev/null 2>&1 || true

# ---- 可选组件：LuCI 页面 ----
install_luci() {
	L=$LUCI_SRC
	[ -d "$L" ] || { say "找不到 $L，跳过 LuCI"; return 0; }
	mkdir -p /www/luci-static/resources/view/isp-split /usr/share/luci/menu.d /usr/share/rpcd/acl.d
	mkdir -p /www/luci-static/resources/isp-split/logos
	cp -f "$L/htdocs/luci-static/resources/isp-split/"*.css \
		/www/luci-static/resources/isp-split/ 2>/dev/null || true
	cp -f "$L/htdocs/luci-static/resources/isp-split/logos/"*.svg \
		/www/luci-static/resources/isp-split/logos/ 2>/dev/null || true
	cp -f "$L/htdocs/luci-static/resources/view/isp-split/overview.js" \
		"$L/htdocs/luci-static/resources/view/isp-split/config.js" \
		/www/luci-static/resources/view/isp-split/
	if [ "$FEATURE_LINECHECK" = "1" ]; then
		cp -f "$L/htdocs/luci-static/resources/view/isp-split/linecheck.js" \
			/www/luci-static/resources/view/isp-split/linecheck.js
		cp -f "$L/root/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json" \
			/usr/share/luci/menu.d/ 2>/dev/null || true
	else
		# 升级残留：0 版安装必须把旧版装的体检页/菜单节点删掉
		rm -f /www/luci-static/resources/view/isp-split/linecheck.js
		rm -f /usr/share/luci/menu.d/luci-app-isp-split-linecheck.json
	fi
	cp -f "$L/root/usr/share/luci/menu.d/luci-app-isp-split.json" /usr/share/luci/menu.d/
	cp -f "$L/root/usr/share/rpcd/acl.d/luci-app-isp-split.json" /usr/share/rpcd/acl.d/
	# 权限归一化：cp -f 会继承源文件权限位。工作区里若被改成 0600，
	# 装到设备上 uhttpd 读不了 → 静态资源 403、页面裸奔（0.3.0 实测踩到）。
	chmod 644 /www/luci-static/resources/isp-split/*.css 2>/dev/null || true
	chmod 644 /www/luci-static/resources/isp-split/logos/*.svg 2>/dev/null || true
	chmod 644 /www/luci-static/resources/view/isp-split/*.js 2>/dev/null || true
	chmod 644 /usr/share/luci/menu.d/luci-app-isp-split*.json 2>/dev/null || true
	chmod 644 /usr/share/rpcd/acl.d/luci-app-isp-split.json 2>/dev/null || true
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache* 2>/dev/null
	# 只重启 rpcd（ACL 生效所需）。uhttpd 不必重启——
	# 静态文件与 menu.d 都是按请求读取的，重启反而会造成短暂无法访问。
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	say "LuCI 页面已安装：网络 → 运营商分流"
}

remove_luci() {
	rm -f /www/luci-static/resources/view/isp-split/*.js
	rmdir /www/luci-static/resources/view/isp-split 2>/dev/null || true
	rm -f /usr/share/luci/menu.d/luci-app-isp-split.json
	rm -f /usr/share/luci/menu.d/luci-app-isp-split-linecheck.json
	rm -f /usr/share/rpcd/acl.d/luci-app-isp-split.json
	rm -f /usr/lib/isp-split/lc-run
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache* 2>/dev/null
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	say "LuCI 页面已移除"
}

add_cron() {
	mkdir -p /etc/crontabs
	touch /etc/crontabs/root
	# 不要用固定的 /tmp/.ispcron：/tmp 世界可写，低权用户可以先把这个名字
	# 做成指向任意文件的符号链接，root 的两次重定向就会写穿过去
	# （详见 isp-split 主脚本里 _cron_rewrite 的说明）。
	# mktemp 用 O_EXCL 建文件，抢不到名字；临时文件放在 /etc 下，
	# 与目标同文件系统，rename 才是原子的。
	_cron_tmp=$(mktemp /etc/.isp-split-cron.XXXXXX) || die "无法创建 crontab 临时文件"
	grep -v 'isp-split' /etc/crontabs/root > "$_cron_tmp" 2>/dev/null || true
	echo "17 4 * * * /usr/sbin/isp-split refresh >/dev/null 2>&1 # isp-split" >> "$_cron_tmp"
	mv -f "$_cron_tmp" /etc/crontabs/root || { rm -f "$_cron_tmp"; die "无法更新 crontab"; }
	/etc/init.d/cron restart >/dev/null 2>&1 || true
	say "已启用每日 04:17 自动更新数据（refresh，不改 mwan3 配置）"
}

for arg in "$@"; do
	case "$arg" in
	--cron) add_cron ;;
	--luci) install_luci ;;
	--all) add_cron; install_luci ;;
	esac
done

say "安装完成。建议顺序："
echo "  1) isp-split plan      只读预演"
echo "  2) isp-split check     nft 干跑校验"
echo "  3) isp-split selftest  独立表实弹加载"
echo "  4) isp-split sync      正式生效"
echo "  5) isp-split verify    核对规则渲染"
