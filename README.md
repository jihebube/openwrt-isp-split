# openwrt-isp-split

按**目标 IP 归属的运营商**做 mwan3 分流。为 mwan3-nft（原生 nftables 版）设计，用 nftables 集合承载上万条国内运营商网段，每日自动跟进。

```
电信网段  ->  wan1（电信线）
联通网段  ->  wan2（联通线）
移动网段  ->  可指定线路
其余      ->  落到既有兜底规则
```

## 特性

- **运营商网段自动维护**：每日拉取 10 类运营商 IP 段（约 1.3 万条），互斥化后写入 mwan3 的 nftables 集合，无需手工维护
- **原子更新不断流**：单次 `nft -f` 事务完成集合替换，不重启 mwan3、不重建规则链
- **多线路 DNS**：域名按线路绑定 DNS 出接口，让 CDN 返回本运营商节点（bind / mark 两种模式）
- **与代理共存**：只处理直连流量，OpenClash / sing-box 的代理流量不受影响
- **LuCI 界面**：状态页（命中计数 / 流量 / 策略）+ 配置页（策略映射 / DNS / 域名分流）
- **安全设计**：三级只读预检、stage 灰度、改动前自动备份、卸载零残留

## 环境要求

- OpenWrt 23.05+（firewall4 / 纯 nftables）；在 OpenWrt 25.12.6 (x86_64) 完整验证
- **nftables 版 mwan3 3.6.0+**：Kwrt 源内的 `mwan3-nft` 即为所需版本；上游官方源的 `mwan3` 是 iptables 版，不兼容
- `nftables`、`curl`；LuCI 页面为可选组件

## 快速开始

```sh
# 1. 安装（二选一）
sh scripts/install.sh --all                       # 从源码目录安装
apk add --allow-untrusted ./isp-split_*.apk       # 或安装 Release 中的 apk 包

# 2. 预检与生效（前两步只读）
isp-split plan      # 预演：将要做哪些改动
isp-split check     # nft 干跑校验
isp-split sync      # 拉取数据并生效
isp-split verify    # 核对规则渲染

# 3. 查看分流效果
isp-split status    # 各集合命中计数与流量
```

卸载：`sh scripts/install.sh --uninstall` 或 `isp-split uninstall`，配置完全还原。

## 工作原理

```
准备：ispip.clang.cn -> 区间化合并 -> 按优先级差集（互斥化）-> 最小 CIDR -> nftables 集合
运行：包进入 -> ip daddr @isp_tel 命中 -> jump mwan3 策略链打标 -> ip rule 选表 -> 出对应 WAN
```

- 每个连接只有首包经过规则链，后续包由 conntrack 恢复标记，稳态开销接近零
- 代理流量在更早的优先级已被标记（如 OpenClash 的 `0x162`），与本工具的掩码判断天然互斥
- 完整设计说明见 [docs/DESIGN.md](docs/DESIGN.md)

## 常用命令

| 命令 | 作用 | 改动 |
|---|---|---|
| `plan` / `check` / `selftest` | 三级预检（预演 / 干跑 / 独立表实弹） | 无 |
| `fetch` / `rollback` | 拉取 / 回滚数据 | 数据 |
| `wire` | 把集合与规则写入 mwan3 配置 | mwan3 |
| `apply` | 把数据原子刷入 nftables 集合 | nft |
| `refresh` | fetch + apply（日常定时任务） | nft |
| `sync` | fetch + wire + apply（首次部署） | 全部 |
| `dns` | 生成多线路 DNS 配置 | dnsmasq |
| `status` / `verify` / `probe` | 状态 / 渲染核对 / 分线测速 | 无 |
| `export` | 导出给 mihomo / sing-box | 无 |
| `stage` / `enable` | 灰度：先注入不渲染，确认后启用 | mwan3 |
| `uninstall` | 卸载并完全还原 | 全部 |

## 配置

主配置在 `/etc/isp-split.conf`，核心是三段：

```sh
# 运营商 -> 策略映射（第三列为 mwan3 中的 policy 名，第四列 1 启用 / 0 停用）
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
"

# 每条线路的 DNS 与需要钉到线路的域名后缀
DNS_TABLE="wan_only:223.5.5.5 wanb_only:119.29.29.29"
DOMAIN_SPLIT="bilivideo.com:wanb_only"
```

生效方式：策略映射改动执行 `isp-split wire && isp-split apply`；DNS 改动执行 `isp-split dns`；也可在 LuCI 配置页操作。完整字段说明见 [docs/CONFIGURATION.md](docs/CONFIGURATION.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | 配置详解：策略映射、多线路 DNS、域名分流、兜底行为 |
| [docs/BUILDING.md](docs/BUILDING.md) | 构建：ipk（零依赖）、apk（Docker / 原生 SDK）、CI、发布 |
| [docs/FIRMWARE.md](docs/FIRMWARE.md) | 编译进自编译固件（buildroot / ImageBuilder） |
| [docs/DESIGN.md](docs/DESIGN.md) | 设计与原理：数据管线、与代理共存、与商业方案对比 |

## 已知限制

1. 只处理直连流量；代理流量的出口由代理自身决定
2. CDN 调度依赖 DNS 解析路径，国内域名应走本地 dnsmasq 而非代理远程解析
3. 数据来自 APNIC/WHOIS 派生，个别骨干段归类有误差
4. 稳态性能开销接近零；每日一次全量加载约 800 ms（x86_64）
5. `wire` 直接写 `/etc/config/mwan3`（文本级插入），在 LuCI 保存过 mwan3 后需重跑一次
6. 更新源的 IP 可能落在某个集合里，该线路故障时 `fetch` 会失败
7. 启用 `othernet` 集合会把公共 DNS 一并分走，该线路故障时导致解析失败（默认关闭）
8. mwan3 原生的「域名 -> nftset」需要 dnsmasq-full（`no-nftset` 的基础镜像不支持）；本工具的多线路 DNS 不受此限制

## 路线图

- [ ] IPv6 支持
- [ ] LuCI 内集成 `probe` 分线测速与自动纠偏
- [ ] 多格式域名清单导出（smartdns / AdGuard Home）

## 许可

[MIT](LICENSE)。运营商数据来自 [ispip.clang.cn](https://ispip.clang.cn)（数据源自 APNIC 等公开记录），使用时请保留来源说明。mwan3-nft 基于 [dl12345/mwan3](https://github.com/dl12345/mwan3)。
