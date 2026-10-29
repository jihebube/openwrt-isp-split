# FIX33C — v0.3.2-full 发布装配

- **仓库/基线**：`openwrt-isp-split` @ `5b648ae`（fix33B 已验收）
- **版本**：`0.3.1` → `0.3.2`（`PKG_RELEASE:=1` 不变）
- **纪律**：未 push、未 tag、未操作 GitHub、未触碰生产 `192.168.10.1`

## 改动

1. **C1 版本全链**
   - `files/usr/sbin/isp-split`：`ISP_VERSION="0.3.2"`
   - 主 / luci / feed×2 四个 Makefile：`PKG_VERSION:=0.3.2`、`PKG_RELEASE:=1`
   - 跑 `sh tools/sync-feed.sh`（V5），feed 壳代码与主源码逐字节一致
2. **C2 release.yml**
   - `generate_release_notes: false`、`FEATURE_LINECHECK: "1"`、版本门禁均未动
   - body 逐字替换为「v0.3.2-full 扫雷更新」，安装路径同步为 `isp-split-0.3.2`
3. **C3 本地验证**
   - `sh scripts/verify-release-version.sh v0.3.2-full` → rc=0
   - 本机 selftest：**274 / 5 / 6**，与 fix33B 本机基线同集合；19.2 版本断言绿
   - VM（192.168.12.1，root）selftest：**281 / 0 / 4**，19.2 版本断言绿

## 关键输出

```text
tag↔版本一致：tag=v0.3.2-full PKG_VERSION=0.3.2 PKG_RELEASE=1 ISP_VERSION=0.3.2

feed 壳已同步 (PKG_VERSION=0.3.2)，运行时代码逐字节一致

✓ 19.2 版本一致：ISP_VERSION=PKG_VERSION=0.3.2，PKG_RELEASE=1（主/luci/feed×2）
通过 281 项，失败 0 项，跳过 4 项
```

## 交付

单个 commit：`chore: v0.3.2-full 发布装配——版本进位 + 扫雷 body`。后续 push/tag 由 Hermes 接手。