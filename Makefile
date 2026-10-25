include $(TOPDIR)/rules.mk

PKG_NAME:=isp-split
PKG_VERSION:=0.1.1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/isp-split
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=ISP-aware policy routing for mwan3 (nftables)
# 注意：这里故意不写 +mwan3 依赖。
#   官方 feed 的 mwan3 是 iptables 版（2.12.5），写 +mwan3 会错误地拉进它；
#   Kwrt 源里 nft 版的包名是 mwan3-nft，与其他源命名不一致。
#   nftables 版 mwan3 是硬性前提，由 install.sh 与 router-preflight 检查，
#   并在 description 里说明。
  DEPENDS:=+nftables +curl
  PKGARCH:=all
endef

define Package/isp-split/description
  Route traffic by the ISP that owns the destination address.
  Builds mutually exclusive nftables sets from daily-updated
  Chinese ISP CIDR data and wires them into mwan3-nft rules.

  REQUIRES the nftables port of mwan3 (>= 3.6.0):
    - Kwrt:  apk add mwan3-nft        (软件源里自带)
    - 上游:  用 https://github.com/dl12345/mwan3 替换官方 feed 的
             iptables 版 mwan3 (2.12.5)，或从 Release 下载
endef

define Build/Compile
endef

define Package/isp-split/conffiles
/etc/isp-split.conf
endef

# 显式指定权限，不依赖源文件的权限位——固件里脚本不可执行会很难查
define Package/isp-split/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib/isp-split
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/isp-split/data

	$(INSTALL_BIN) ./files/usr/sbin/isp-split $(1)/usr/sbin/isp-split
	$(INSTALL_BIN) ./files/etc/init.d/isp-split $(1)/etc/init.d/isp-split
	$(INSTALL_BIN) ./files/usr/lib/isp-split/build.sh $(1)/usr/lib/isp-split/build.sh
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-isp-split $(1)/etc/uci-defaults/99-isp-split

	$(INSTALL_DATA) ./files/usr/lib/isp-split/cidr2range.awk $(1)/usr/lib/isp-split/cidr2range.awk
	$(INSTALL_DATA) ./files/usr/lib/isp-split/merge.awk $(1)/usr/lib/isp-split/merge.awk
	$(INSTALL_DATA) ./files/usr/lib/isp-split/exclude.awk $(1)/usr/lib/isp-split/exclude.awk
	$(INSTALL_DATA) ./files/usr/lib/isp-split/range2cidr.awk $(1)/usr/lib/isp-split/range2cidr.awk
	$(INSTALL_DATA) ./files/usr/lib/isp-split/rules-splice.awk $(1)/usr/lib/isp-split/rules-splice.awk
	$(INSTALL_DATA) ./files/usr/lib/isp-split/badcidr.awk $(1)/usr/lib/isp-split/badcidr.awk
	$(INSTALL_CONF) ./files/etc/isp-split.conf $(1)/etc/isp-split.conf
endef

$(eval $(call BuildPackage,isp-split))
