include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-isp-split
PKG_VERSION:=0.2.3
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

# 与主包同一个构建期开关：0.2.3 出货默认 0，LuCI 的体检页/菜单节点不进包。
FEATURE_LINECHECK?=0

define Package/luci-app-isp-split
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for ISP-aware policy routing
  DEPENDS:=+isp-split +luci-base
  PKGARCH:=all
endef

define Package/luci-app-isp-split/description
  LuCI page for isp-split: shows per-ISP element counts and hit
  counters, and offers one-click sync, data refresh, and config
  editing (wire/apply/dns).
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./htdocs $(PKG_BUILD_DIR)/htdocs
	$(CP) ./root $(PKG_BUILD_DIR)/root
	if [ "$(FEATURE_LINECHECK)" != "1" ]; then \
		sed -i '/lc:begin/,/lc:end/d' $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/config.js; \
		rm -f $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/linecheck.js; \
		rm -f $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json; \
	fi
endef

define Build/Compile
endef

define Package/luci-app-isp-split/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/isp-split
	$(INSTALL_DIR) $(1)/www/luci-static/resources/isp-split
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/isp-split/isp-split.css \
		$(1)/www/luci-static/resources/isp-split/isp-split.css
	$(INSTALL_DIR) $(1)/www/luci-static/resources/isp-split/logos
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/isp-split/logos/*.svg \
		$(1)/www/luci-static/resources/isp-split/logos/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/overview.js \
		$(1)/www/luci-static/resources/view/isp-split/overview.js
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/config.js \
		$(1)/www/luci-static/resources/view/isp-split/config.js
	if [ -f $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/linecheck.js ]; then \
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/isp-split/linecheck.js \
			$(1)/www/luci-static/resources/view/isp-split/linecheck.js; \
	fi
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-isp-split.json \
		$(1)/usr/share/luci/menu.d/luci-app-isp-split.json
	if [ -f $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json ]; then \
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json \
			$(1)/usr/share/luci/menu.d/luci-app-isp-split-linecheck.json; \
	fi
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/rpcd/acl.d/luci-app-isp-split.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-isp-split.json
endef

define Package/luci-app-isp-split/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache* 2>/dev/null
/etc/init.d/rpcd restart >/dev/null 2>&1
exit 0
endef

$(eval $(call BuildPackage,luci-app-isp-split))
