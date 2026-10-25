#!/bin/sh
# vm-fakewan.sh —— 在 OpenWrt 测试 VM 里伪造两条上游线路，供 mwan3 + isp-split 测试
#
# 为什么用 dummy 而不是加虚拟网卡：
#   1. 不需要改虚拟机管理器的网络配置
#   2. 不需要额外的 NAT 网络，完全离线可控
#   3. 可以随时把某条线 up/down，测试 mwan3 的故障切换
#
# 用法：
#   sh vm-fakewan.sh setup      建立 dummy 线路 + mwan3 接口/成员/策略
#   sh vm-fakewan.sh status     查看当前状态
#   sh vm-fakewan.sh down wan1  模拟某条线路掉线
#   sh vm-fakewan.sh up wan1    恢复
#   sh vm-fakewan.sh teardown   全部拆除
#
# 拓扑（运营商侧放在独立 netns 里，避免同网段双接口打乱路由）：
#
#   主命名空间                        netns ispnet
#   wan1  10.99.1.2/24  <--veth-->  isp1  10.99.1.1/24    模拟电信线
#   wan2  10.99.2.2/24  <--veth-->  isp2  10.99.2.1/24    模拟联通线
#
# 为什么用 veth + netns 而不是 dummy：
#   dummy 两端在同一命名空间且同网段，内核路由会和对方地址冲突，
#   ping 不通 -> mwan3 健康检查失败 -> 接口被判 offline -> 策略 0%，
#   分流规则虽然渲染出来了却永远不会命中。
#   veth 对配上独立 netns 后探测真的有回应，两条线稳定 online。
set -eu

say() { printf '[fakewan] %s\n' "$*"; }
die() { printf '[fakewan] 错误: %s\n' "$*" >&2; exit 1; }

need_openwrt() {
	[ -f /etc/openwrt_release ] || die "这不像 OpenWrt 环境"
	command -v uci >/dev/null 2>&1 || die "缺少 uci"
}

# ---------------------------------------------------------------- 设备层

ISPNS=ispnet

create_devs() {
	ip netns list 2>/dev/null | grep -qx "$ISPNS" || ip netns add "$ISPNS"
	ip netns exec "$ISPNS" ip link set lo up 2>/dev/null || true

	n=0
	for w in wan1 wan2; do
		n=$((n + 1))
		i="isp$n"
		base="10.99.$n"

		ip link show "$w" >/dev/null 2>&1 && ip link del "$w" || true
		ip link add "$w" type veth peer name "$i"
		ip link set "$i" netns "$ISPNS"
		ip link set "$w" up
		ip addr replace "$base.2/24" dev "$w"

		ip netns exec "$ISPNS" ip link set "$i" up
		ip netns exec "$ISPNS" ip addr replace "$base.1/24" dev "$i"
	done
	say "veth 双线路已建立（运营商侧在 netns $ISPNS 内）"
}

destroy_devs() {
	for w in wan1 wan2; do
		ip link show "$w" >/dev/null 2>&1 && ip link del "$w" || true
	done
	ip netns del "$ISPNS" 2>/dev/null || true
	say "veth 双线路已删除"
}

destroy_devs() {
	for l in wan1 wan2 isp0; do
		ip link show "$l" >/dev/null 2>&1 && ip link del "$l" || true
	done
	say "dummy 设备已删除"
}

# 开机重建（dummy 设备重启后会消失，网络可能在它之前就起来了）
install_boot_hook() {
	cat > /etc/init.d/fakewan <<'EOF'
#!/bin/sh /etc/rc.common
# 测试用：在 network 启动前重建 veth 双线路与运营商侧 netns
START=15

start() {
	ip netns list 2>/dev/null | grep -qx ispnet || ip netns add ispnet
	ip netns exec ispnet ip link set lo up 2>/dev/null || true
	n=0
	for w in wan1 wan2; do
		n=$((n + 1))
		base="10.99.$n"
		ip link show "$w" >/dev/null 2>&1 || ip link add "$w" type veth peer name "isp$n"
		ip link set "isp$n" netns ispnet 2>/dev/null || true
		ip link set "$w" up
		ip addr replace "$base.2/24" dev "$w"
		ip netns exec ispnet ip link set "isp$n" up 2>/dev/null || true
		ip netns exec ispnet ip addr replace "$base.1/24" dev "isp$n" 2>/dev/null || true
	done
}

stop() { :; }
EOF
	chmod +x /etc/init.d/fakewan
	/etc/init.d/fakewan enable >/dev/null 2>&1 || true
	say "开机重建钩子已安装（/etc/init.d/fakewan）"
}

remove_boot_hook() {
	/etc/init.d/fakewan disable >/dev/null 2>&1 || true
	/etc/init.d/fakewan stop >/dev/null 2>&1 || true
	rm -f /etc/init.d/fakewan
	say "开机重建钩子已移除"
}

# ---------------------------------------------------------------- netifd 接口

create_ifaces() {
	uci -q delete network.wan1 || true
	uci set network.wan1=interface
	uci set network.wan1.proto='static'
	uci set network.wan1.device='wan1'
	uci set network.wan1.ipaddr='10.99.1.2'
	uci set network.wan1.netmask='255.255.255.0'
	uci set network.wan1.gateway='10.99.1.1'
	# metric 让 lan 的默认路由优先，否则伪 WAN 会抢走默认路由让整机断网
	uci set network.wan1.metric='100'

	uci -q delete network.wan2 || true
	uci set network.wan2=interface
	uci set network.wan2.proto='static'
	uci set network.wan2.device='wan2'
	uci set network.wan2.ipaddr='10.99.2.2'
	uci set network.wan2.netmask='255.255.255.0'
	uci set network.wan2.gateway='10.99.2.1'
	uci set network.wan2.metric='101'

	uci commit network
	say "netifd 接口 wan1/wan2 已创建"
}

delete_ifaces() {
	uci -q delete network.wan1 || true
	uci -q delete network.wan2 || true
	uci commit network
}

# ---------------------------------------------------------------- mwan3

create_mwan3() {
	# 接口都配 track_ip，探测运营商侧 netns 里的对端地址
	_n=0
	for i in wan1 wan2; do
		_n=$((_n + 1))
		uci -q delete mwan3.$i || true
		uci set mwan3.$i=interface
		uci set mwan3.$i.enabled='1'
		uci set mwan3.$i.family='ipv4'
		uci set mwan3.$i.initial_state='online'
		# 探测运营商侧 netns 里的对端地址，健康检查才真正有响应
		uci add_list mwan3.$i.track_ip="10.99.$_n.1"
		uci set mwan3.$i.track_method='ping'
	done

	# 成员（权重 1，确保两条线都会参与）
	uci -q delete mwan3.wan_m1_w3 || true
	uci set mwan3.wan_m1_w3=member
	uci set mwan3.wan_m1_w3.interface='wan1'
	uci set mwan3.wan_m1_w3.metric='1'
	uci set mwan3.wan_m1_w3.weight='3'

	uci -q delete mwan3.wanb_m1_w2 || true
	uci set mwan3.wanb_m1_w2=member
	uci set mwan3.wanb_m1_w2.interface='wan2'
	uci set mwan3.wanb_m1_w2.metric='1'
	uci set mwan3.wanb_m1_w2.weight='2'

	# 策略：名字与 isp-split.conf 的默认值对齐
	uci -q delete mwan3.wan_only || true
	uci set mwan3.wan_only=policy
	uci add_list mwan3.wan_only.use_member='wan_m1_w3'

	uci -q delete mwan3.wanb_only || true
	uci set mwan3.wanb_only=policy
	uci add_list mwan3.wanb_only.use_member='wanb_m1_w2'

	uci -q delete mwan3.balanced || true
	uci set mwan3.balanced=policy
	uci add_list mwan3.balanced.use_member='wan_m1_w3'
	uci add_list mwan3.balanced.use_member='wanb_m1_w2'

	uci commit mwan3
	say "mwan3 接口/成员/策略已创建（wan_only / wanb_only / balanced）"
}

delete_mwan3() {
	for s in wan1 wan2 wan_m1_w3 wanb_m1_w2 wan_only wanb_only balanced; do
		uci -q delete mwan3.$s || true
	done
	uci commit mwan3
}

# ---------------------------------------------------------------- 命令

cmd_setup() {
	need_openwrt
	install_boot_hook
	create_devs
	create_ifaces
	create_mwan3
	/etc/init.d/network reload
	sleep 2

	# network reload 不会重装 lan 的默认路由（只有 restart 才会），
	# 而 restart 会掐断 br-lan、导致远程 SSH 掉线。
	# 这里非破坏性地补一条，保证测试机始终有出口。
	if ! ip route show default 2>/dev/null | grep -q "dev br-lan"; then
		_gw=$(uci -q get network.lan.gateway)
		_dev=$(uci -q get network.lan.device)
		if [ -n "$_gw" ] && [ -n "$_dev" ]; then
			ip route replace default via "$_gw" dev "$_dev" metric 0
			say "已补 lan 默认路由 via $_gw dev $_dev"
		fi
	fi

	/etc/init.d/mwan3 restart
	sleep 2
	say "完成。用 sh vm-fakewan.sh status 检查"
}

cmd_status() {
	echo "== 设备"
	ip -br addr show isp0 2>/dev/null || echo "  isp0 不存在"
	ip -br addr show wan1 2>/dev/null || echo "  wan1 不存在"
	ip -br addr show wan2 2>/dev/null || echo "  wan2 不存在"
	echo
	echo "== mwan3 接口状态"
	mwan3 status 2>/dev/null || echo "  mwan3 status 不可用"
	echo
	echo "== 路由表 1/2（mwan3 为每条线建的）"
	ip route show table 1 2>/dev/null | sed 's/^/  t1: /' || echo "  table 1 空"
	ip route show table 2 2>/dev/null | sed 's/^/  t2: /' || echo "  table 2 空"
}

cmd_down() {
	l=${1:-}
	[ -n "$l" ] || die "用法: vm-fakewan.sh down <wan1|wan2>"
	ip link set "$l" down
	say "$l 已下线（模拟断线）"
}

cmd_up() {
	l=${1:-}
	[ -n "$l" ] || die "用法: vm-fakewan.sh up <wan1|wan2>"
	ip link set "$l" up
	say "$l 已恢复"
}

cmd_teardown() {
	need_openwrt
	delete_mwan3
	delete_ifaces
	remove_boot_hook
	destroy_devs
	/etc/init.d/network reload 2>/dev/null || true
	/etc/init.d/mwan3 restart 2>/dev/null || true
	say "已全部拆除"
}

case "${1:-}" in
setup) cmd_setup ;;
status) cmd_status ;;
down) cmd_down "${2:-}" ;;
up) cmd_up "${2:-}" ;;
teardown) cmd_teardown ;;
*)
	cat <<EOF
用法: sh vm-fakewan.sh <命令>

  setup       建立 dummy 双线路 + mwan3 接口/成员/策略
  status      查看设备、mwan3 状态、路由表
  down <wan>  模拟某条线掉线
  up <wan>    恢复
  teardown    全部拆除
EOF
	exit 1
	;;
esac
