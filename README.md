# openwrt-isp-split

按**目标 IP 归属的运营商**做 mwan3 分流。为 mwan3-nft（原生 nftables 版）设计，用 nftables 集合承载上万条国内运营商网段，每日自动跟进。

```
电信网段  ->  wan1（电信线）
联通网段  ->  wan2（联通线）
移动网段  ->  由你决定（默认给电信，因为大量移动 PCDN 在电信侧更快）
其余      ->  落到你自己的兜底规则
```

## 快速开始

前提：mwan3 必须是 **nftables 版**（Kwrt 源里的 `mwan3-nft` 就是；上游官方源的是 iptables 版，不能用）。

```sh
# 安装（Kwrt 25.12+ / OpenWrt 25.12+）
wget -O /tmp/isp.tgz "$(cd "$(dirname "$0")" && echo)/isp-split.tar.gz"
mkdir -p /tmp/isp && tar -xzf /tmp/isp.tgz -C /tmp/isp --strip-components=1
sh /tmp/isp/scripts/install.sh --all

# 上线（前两步只读，先看清楚再动手）
isp-split plan      # 只读预演：会改什么
isp-split check     # nft 干跑校验
isp-split sync      # 生效
isp-split verify    # 核对规则渲染
```

不放心就分步来：`stage` 先把规则写进配置但不渲染，确认健康后 `enable`；卸载 `sh scripts/install.sh --uninstall`，配置完全还原。

| 文档 | 内容 |
|---|---|
| [docs/BUILDING.md](docs/BUILDING.md) | 自己打 ipk / apk / 让 CI 编译 |
| [docs/build-into-firmware.md](docs/build-into-firmware.md) | 编译进自编译固件 |
| [docs/distribute.md](docs/distribute.md) | 分发渠道与做法 |
| [docs/why-ikuai.md](docs/why-ikuai.md) | 为什么爱快分流更准，本项目补了什么 |

---

## 为什么需要它

双线（或多线）环境里，mwan3 的常规玩法是"按端口分流"——比如 `tcp dport 443` 统一走某一条线。这在 CDN 时代基本是错的：

同一个视频站点，播放地址可能落在电信、联通、移动三个不同的 CDN 上。实测中同一目标在两条线上的速度差可以到 **100 倍以上**（不是夸张，见下）。

| 实测目标 | 电信 | 联通 | 正确出口 |
|---|---|---|---|
| 联通自有 CDN `cn-*-cu-*` | 7.5 MB/s | **18-24 MB/s** | 联通 |
| 某 PCDN 节点 `*mcdn*:8082` | **12-22 MB/s** | 0.04-1 MB/s | 电信 |
| 移动 CDN `39.134.x` | 72 ms | **22 ms** | 联通 |
| 电信 CDN `150.138.x` | **22 ms** | 62 ms | 电信 |

而 `443 端口统一走联通` 这种规则会让上表第二行直接掉进 0.04 MB/s。真正的判据不是端口，而是**目标 IP 属于哪个运营商**。

## 和已有方案的区别

| 项目 | 数据源 | 载体 | 现状 |
|---|---|---|---|
| [owmwpprt](https://github.com/larsonzh/owmwpprt) | ispip.clang.cn | ipset + iptables | 2025-04 停更，作者注明"mwan3 不支持 nfset，建议 22.03 及以前使用" |
| [china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | APNIC + BGP | 纯数据 | 仅提供数据，分 8 类 |
| [ikuai-bypass](https://github.com/joyanhui/ikuai-bypass) | 多种 | 爱快专用 | 不适用 OpenWrt |
| **本项目** | ispip.clang.cn | **mwan3-nft 原生 nftset** | 适配 firewall4 固件（23.05+ / 24.10 / 25.x） |

三个具体差异：

1. **用原生 nft 集合，不依赖 ipset。** mwan3-nft 3.6 起支持 `config ipset`（实际是 nftables 地址集合）与 `loadfile`，因此不需要 dnsmasq 的 ipset 支持，也不需要 `iptables-nft` 兼容层。
2. **做了集合互斥化。** 上游数据里各运营商的网段是**有重叠**的（例如电信与联通之间有 494 处重叠）。如果直接把每个运营商的列表塞进各自的集合、再加一组规则，同一个 IP 归属谁就变成"规则先后决定的隐性行为"。本项目按优先级做区间差集，让每个 IP 只属于一个集合 —— 见 [原理](#原理)。
3. **更新是原子的、不断流的。** 每日更新通过单次 `nft -f` 事务完成（`flush set` + `add element`），不重启 mwan3、不重建规则链，已有连接不中断。

> 另外：商业方案如爱快（iKuai）的分流效果普遍更准，原因不在算法，而在它把 **DNS 层**也纳入了分流决策。详细拆解与我们的差距分析见 **[docs/why-ikuai.md](docs/why-ikuai.md)**。

## 它不做什么

- **不管代理流量。** OpenClash / mihomo 的 TPROXY 标记在 `ip rule` 里优先级更早，代理流量根本不经过 mwan3。本项目只影响**直连**流量。
- **不做域名分流。** 域名级覆盖请用 mwan3 自身的 `config ipset` + `list domain`（由 dnsmasq 填充）。两者可以共存：把域名集合的规则放在运营商规则**之前**即可。
- **不改 mwan3 的核心配置。** 只新增 `config ipset` 和 `config rule` 节，并在你指定的位置插入规则；卸载时完全还原。

## 原理

```
入站流量
   |
   v
mwan3_rules 链（first-match，命中即停）
   |
   +-- ① 按设备/IP 的规则          （你原有的，优先级最高）
   +-- ② 按域名的集合规则          （可选，用 dnsmasq 填充 nftset）
   +-- ③ 本工具注入的运营商规则     <-- 这里
   +-- ④ 按端口的规则 / 兜底规则    （你原有的）
```

### 数据管线

```
ispip.clang.cn/<运营商>.txt
   |  cidr2range.awk          CIDR -> [起始, 结束] 整数区间
   |  sort -n + merge.awk     区间合并
   |  exclude.awk             按优先级做区间差集（互斥化）
   |  range2cidr.awk          区间 -> 最小 CIDR 集合
   v
/etc/isp-split/data/<运营商>.txt  ->  mwan3 的 loadfile
```

以 2026-10 的实际数据为例（`chinatelecom > unicom_cnc > cmcc > cernet > ...` 为优先级）：

| 运营商 | 原始条目 | 互斥化后 | 覆盖地址数 |
|---|---:|---:|---:|
| chinatelecom | 1790 | 1790 | 128,757,760 |
| unicom_cnc | 1368 | **1001** | 70,538,752 |
| cmcc | 319 | **166** | 40,518,400 |
| cernet | 90 | 87 | 17,221,120 |
| othernet | 2071 | 1914 | 28,473,344 |
| hk | 7367 | 7245 | 19,743,744 |
| tw | 1128 | 1113 | 33,220,096 |

互斥化让"归属"变成数据本身的属性，而不是规则顺序的副作用。

## 依赖

- OpenWrt **23.05 及以上**（firewall4 / 纯 nftables），实测于上游 OpenWrt 25.12.6
- **nftables 版 mwan3 3.6.0+**，需要其 `config ipset` 支持
  - **Kwrt 源里直接有 `mwan3-nft`**，`apk add mwan3-nft` 即可，无需任何替换
  - **上游官方 feed 的 mwan3 是 iptables 版（2.12.5）**，不支持本项目；自编译固件时需用
    [dl12345/mwan3](https://github.com/dl12345/mwan3) 替换（见 docs/build-into-firmware.md）
  - 检查：`grep -c "render_config_ipsets" /lib/mwan3/mwan3.sh`，结果 ≥1 才可用
- `nft`、`awk`、`sort`（busybox 自带的即可）
- `curl`（仅 `probe` 命令需要）

## 安装

```sh
# 1. 把 files/ 下的内容放到路由器对应位置
scp -r files/* root@192.168.1.1:/

chmod +x /usr/sbin/isp-split /etc/init.d/isp-split /usr/lib/isp-split/build.sh

# 2. 先看预演，什么都不改
isp-split plan

# 3. 确认无误后执行
isp-split sync

# 4. 注册每日更新与开机自动应用
isp-split install
```

`sync` 会依次做：下载数据 → 构建互斥集合 → 在 mwan3 中创建集合与规则 → 原子刷入 nftables → 重载 mwan3。

### 自动更新

`install` / `install.sh --cron` 会写一条 cron：

```sh
17 4 * * * /usr/sbin/isp-split refresh
```

**用 `refresh` 而不是 `sync`**：日常只需要更新数据（`fetch` + `apply`），不需要每天重写 mwan3 配置再 reload mwan3——那会带来无谓的规则重载抖动。`wire` 只在改映射关系时才需要。

前提是 cron 服务在运行：

```sh
/etc/init.d/cron status || /etc/init.d/cron enable && /etc/init.d/cron start
```

## 配置

编辑 `/etc/isp-split.conf`。核心是 `ISP_TABLE`：

```
<源文件名>:<集合名>:<mwan3策略>:<是否启用>
```

```sh
ISP_TABLE="
chinatelecom:isp_tel:wan_only:1
unicom_cnc:isp_uni:wanb_only:1
cmcc:isp_cmcc:wan_only:1
cernet:isp_cernet:wan_only:0
"
```

- **顺序即优先级**：排前面的优先占有重叠地址
- **集合名**同时是 mwan3 规则名，必须 ≤15 字符，且不能以 `mwan3_` 开头
- **策略名**必须是 mwan3 里已存在的策略（`uci show mwan3 | grep policy`）；`wire` 会校验，不存在会直接报错而不是静默失败

改完执行 `isp-split sync`。

### 决策移动/教育网走哪条线

不要凭感觉，用 `probe` 两条线各测一遍：

```sh
isp-split probe
```

它会对同一个 URL 分别绑定 `pppoe-wan1` / `pppoe-wan2` 测速，输出速率和建连耗时。把这几个结果和你实际会踩到的场景（视频站、网盘、游戏更新）对照，再决定 `ISP_TABLE` 里的策略。

## 命令

| 命令 | 作用 | 是否改动配置 |
|---|---|---|
| `plan` | 预演，打印将要做的全部动作 | 否（只读） |
| `fetch` | 下载并重建数据 | 否（仅写 `/etc/isp-split/data`） |
| `apply` | 原子刷入 nft 集合 | 仅运行时集合 |
| `wire` | 创建 mwan3 集合与规则并插入 | 是 |
| `refresh` | fetch + apply（只更新数据，不动 mwan3 配置） | 是（仅 nft） |
| `sync` | fetch + wire + apply | 是 |
| `status` | 条目数、命中包数、流量（`--json` 给 LuCI 用） | 否 |
| `probe` | 分线测速 | 否 |
| `dns` | 生成多线路 DNS 配置（域名按线路选 DNS） | 是（dnsmasq）|
| `conf` | 读写配置：`conf get` / `conf set <项> <值>`（LuCI 用） | 是（配置） |
| `export` | 导出给代理侧用：`export mihomo\|singbox\|text <目录>` | 否 |
| `rollback` | 回滚上一份数据 | 仅集合 |
| `install` / `uninstall` | 注册/移除定时任务与自启 | 是 |

`status` 输出示例：

```
集合             来源         条目       命中包       流量  策略
isp_tel          chinatelecom  1790      1842302   12.4GiB  wan_only
isp_uni          unicom_cnc    1001       933120    6.8GiB  wanb_only
```

## 安全设计

- **`plan` 是纯只读预演**，可以先跑一遍看要改什么
- **改配置前自动备份**：`/etc/isp-split/work/mwan3.bak`
- **注入后做解析校验**，uci 解析不了就放弃修改，原配置不动
- **数据更新失败不覆盖现有数据**：下载条目数异常、构建产物为空都会中止
- **nft 更新是单事务**，失败则线上规则完全不变
- **历史快照保留 3 份**，可用 `rollback` 回退

## 打包与安装

> **第三方构建指南**：克隆仓库后怎么自己打 ipk / apk / 编固件，全部步骤见
> **[docs/BUILDING.md](docs/BUILDING.md)**。一句话：ipk 零依赖本地就能打；
> apk 用 Docker 跑 `scripts/build-apk-docker.sh`；fork 后打 tag 由 CI 代编。

三条路径，按你的固件版本选：

| 固件 | 包管理器 | 推荐方式 |
|---|---|---|
| OpenWrt ≤ 24.10（含 opkg 系衍生固件） | opkg | `.ipk` 包 |
| **OpenWrt 25.12+（含 Kwrt 25.12）** | **apk-tools 3.x** | **`scripts/install.sh`** 或 SDK 编译 |
| 任意版本 | — | `scripts/install.sh` 最通用 |

### 方式一：`.ipk`（opkg 系）

```sh
sh scripts/build-ipk.sh      # 产物在 dist/
opkg install dist/isp-split_0.1.0-1_all.ipk
```

`.ipk` 是 `ar` 归档，成员为 `debian-binary` / `control.tar.gz` / `data.tar.gz`。脚本已处理一个平台坑：**BSD ar（macOS）不加 `-S` 会把非目标文件的成员整个丢掉**，只留下 `__.SYMDEF` 空壳，所以必须 `ar rcS`。

### 方式二：`scripts/install.sh`（25.12 / apk 系，最通用）

```sh
sh scripts/install.sh            # 安装
sh scripts/install.sh --cron     # 安装 + 每日 04:17 自动更新
sh scripts/install.sh --uninstall
```

它会保留已有的 `/etc/isp-split.conf`（先备份），避免冲掉你的 `ISP_TABLE` 设置。

**为什么 25.12 不能手工造 apk** —— 三项实测，逐条排除：

| 测试 | 结果 |
|---|---|
| 官方 `.apk` 的魔数 | `ADBd`，是 apk v3 的 **ADB 容器格式，不是 tar** |
| `apk mkpkg` 子命令 | **不存在**（apk 3.0.5 未编译该功能，路由器自身无法打包） |
| 手工构造 v2 格式包（tar.gz + `.PKGINFO`） | **`ERROR: v2 package format error`**，apk 3 不再接受 v2 |

所以 apk 只有一条产出路径：**OpenWrt SDK 编译**。

```sh
W=~/owrt-sdk && mkdir -p $W && cd $W
wget https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/openwrt-sdk-25.12.6-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst
mkdir sdk && tar --zstd -xf *.tar.zst -C sdk --strip-components=1
cd sdk
./scripts/feeds update -a && ./scripts/feeds install -a   # 解析 mwan3 等依赖
mkdir -p package/isp-split && cp -r /path/to/repo/{Makefile,files} package/isp-split/
make defconfig && make package/isp-split/compile V=s
# 产物在 bin/packages/x86_64/base/isp-split_*.apk
```

装的时候：`apk add --allow-untrusted ./isp-split_*.apk`（无签名，必须加 `--allow-untrusted`；若 `apk add` 会先联网拉索引，可加 `--no-network`）。

注意 SDK 是 **Linux x86_64** 的，macOS 上跑不了；需要一台 Linux 机器或 Docker。

### 方式三：OpenWrt SDK 编译（可产出原生 apk）

这也是**唯一**能产出 `.apk` 的方式。CI 配置已备好（`.github/workflows/release.yml`），打 tag 即自动编译并建 Release，使用者只需下载。

### 编译进固件

想把 isp-split 直接打进自编译固件（而不是装成单独的包），见 **[docs/build-into-firmware.md](docs/build-into-firmware.md)**。

⚠️ 有一个容易忽略的前提：**官方 feed 里的 mwan3 是 iptables 版**，编译固件时必须先替换成 nftables 版，否则镜像里带的 mwan3 与本项目不兼容。

### 分发

产物怎么发给别人、有哪些渠道、各自的门槛与坑，见 **[docs/distribute.md](docs/distribute.md)**。

快速版：

```sh
sh scripts/build-release.sh          # tar.gz + ipk + SHA256SUMS
gh release create v0.1.0 dist/*      # 发布
```



```sh
# 用对应版本的 SDK
make package/isp-split/compile V=s
```

仓库根目录已有 `Makefile`（`DEPENDS:=+mwan3 +nftables +curl`，`PKGARCH:=all`）。

## 多线路 DNS

只按目标 IP 纠线路，治标不治本：

```
走联通线 + 电信 DNS  ->  CDN 返回电信节点  ->  跨网，慢 100 倍
```

真正要解决的是**让查询从对应线路发出**，这样 CDN 才会把本运营商的节点给你。这也是商业方案（爱快）分流更准的核心原因，见 [docs/why-ikuai.md](docs/why-ikuai.md)。

### 用法

```sh
# /etc/isp-split.conf
DNS_TABLE="wan_only:223.5.5.5 wanb_only:119.29.29.29"
DOMAIN_SPLIT="bilivideo.com:wanb_only bilibili.com:wanb_only"

isp-split dns
```

生成到 `/etc/isp-split/dnsmasq.d/isp-split.conf`：

```
server=/bilivideo.com/119.29.29.29@wan2
server=/bilibili.com/119.29.29.29@wan2
```

`@wan2` 是 dnsmasq 的出接口绑定（`SO_BINDTODEVICE`），强制这个后缀的查询走 wan2。

同时在 `inet mwan3 mwan3_output` 链顶部插入旁路：

```
ip daddr 119.29.29.29 udp dport 53 counter return
```

**这一步不能省**：路由器自身发出的 DNS 会经过 mwan3 的 `route output` 钩子，不旁路的话会被按目标 IP 重新打标，把你刚绑好的线路又抢走。

### 两种出线方式：bind 与 mark

`DNS_MODE` 决定"查询怎么被送上指定线路"：

| 模式 | 实现 | 依赖 | 适用 |
|---|---|---|---|
| `bind` | `server=/域名/IP@接口` | dnsmasq 的 `SO_BINDTODEVICE` | 纯 dnsmasq 环境 |
| `mark` | `server=/域名/IP` + nft 给发往该 DNS 的 53 端口 `jump` 对应策略 | **不依赖 `@接口`** | OpenClash 接管 DNS、或解析器不是 dnsmasq |

`mark` 模式实测：向 `223.5.5.5` 查询 → mark `1280` → wan1 电信；向 `119.29.29.29` 查询 → mark `1536` → wan2 联通。它只看目标 IP，不关心查询是谁发出的，所以在 OpenClash 接管 DNS 的环境下更抗干扰。

> **注意**：无论哪种模式，生成的文件仍是 dnsmasq 语法（`server=/...`）。换 smartdns 之类的解析器需要改成 `nameserver /域名/组` 格式 —— 这部分仍是 dnsmasq 绑定。真正与解析器无关的只有 `mark` 的打标逻辑。

### 匹配优先级（与 OpenClash 共存的关键）

实测确认：**dnsmasq 按最长域名后缀匹配，与配置书写顺序无关**。

```
server=/#/127.0.0.1#7874          # OpenClash 装进来的通配转发
server=/bilivideo.com/119.29.29.29@wan2   # 本工具生成
```

`bilivideo.com` 的查询会命中后者，**不会被通配规则抢走**。实测：写一条通配 + 一条绑定到无出口线路的特定规则，通配域名正常解析，特定域名解析失败 —— 特定规则胜出。

### 旁路规则的持久化

`mwan3_output` 链是 mwan3 自己重建的，我们插进去的 `return` 会随 mwan3 重启消失（实测：重启后从 4 条变 0 条）。所以 `/etc/init.d/isp-split` 在开机时会重放一次 `isp-split dns`（幂等），实测能恢复到 4 条。

**手工重启过 mwan3 之后，记得也跑一次 `isp-split dns`**，或用 `/etc/init.d/isp-split start`。

### 兼容外部域名清单

`/etc/isp-split/domains/<策略>.txt`，每行一个域名；也兼容 [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 `server=/domain/1.2.3.4` 格式（只取域名，DNS 替换为该线路配置的值）。

### 验证方式

在双假线路测试机上：`www.baidu.com` 正常解析，而 `www.bilibili.com` 解析失败（它被绑到没有出口的 wan2）。同一次 dnsmasq、同样的客户端，只有被绑定的域名失败 —— 反向证明接口绑定真的生效。

## 与 OpenClash / sing-box 共存

### 与 OpenClash：互不干扰，但只管直连

两者都动 fwmark，好在**恰好不冲突**，实测确认：

| 组件 | nft hook 优先级 | 标记 |
|---|---|---|
| OpenClash | `prerouting priority mangle`（-150） | `0x162` |
| mwan3（含本工具） | `prerouting priority mangle + 1`（-149） | `0x3F00` 掩码 |

OpenClash 先执行并打上 `0x162`。mwan3 的规则判断条件是 `meta mark & 0x3f00 == 0`，而 `0x162 & 0x3F00 = 0x100 ≠ 0` —— 于是 mwan3 认为「这个包已标记过」直接跳过。

**结论**：代理流量永远不经过 isp-split，isp-split 只影响直连流量。这是设计使然，不是缺陷——但也意味着「翻墙后的出口」不由本工具决定。

### DNS 层是唯一会"打架"的地方

OpenClash 通常会在 dnsmasq 里装一条 `server=/#/127.0.0.1#7874`，把所有查询转给它自己。看上去会覆盖我们的配置，**但不会**——dnsmasq 按最长后缀匹配，我们的 `server=/bilivideo.com/...@wan2` 更具体，优先命中（已实测）。

实际效果：**列进 `DOMAIN_SPLIT` 的域名会绕过 OpenClash 的 DNS，拿到真实 IP 并走国内线。** 对国内 CDN 这正是想要的。

⚠️ **fake-ip 模式下要注意**：这些域名拿不到 fake-ip，也就不会被代理。如果某个域名你既想走代理、又想用某条线的 DNS 解析，这两件事本质冲突，必须二选一。放行给代理的域名就不要写进 `DOMAIN_SPLIT`。

### 与 mihomo / OpenClash / sing-box：共享同一份数据

想在代理侧也按运营商分流，把数据导出成它们的 rule-set 格式：

```sh
isp-split export mihomo  /etc/openclash/rule_provider
isp-split export singbox /etc/sing-box/ruleset
isp-split export text    /tmp/plain
```

输出（以 chinatelecom 为例）：

```yaml
# mihomo rule-provider：behavior=ipcidr, format=yaml
payload:
  - 1.48.0.0/15
  - 1.50.0.0/16
```

```json
// sing-box rule_set：type=local, format=source
[
"1.48.0.0/15",
"1.50.0.0/16"
]
```

导出目录里还会附一份 `README-mihomo.txt` / `README-singbox.txt`，含可直接抄的配置片段。

导出的是**全部 10 个运营商集合**（不只是启用的那些），因为在代理侧你可能想用不同的映射关系。



## LuCI 界面

`luci-app-isp-split/` 在「网络 → 运营商分流」下提供两个页面。

### 状态

- 每个运营商集合的**条目数、命中包数、流量、当前策略**（10 秒自动刷新）
- 按钮：预演（只读）、nft 校验、实弹自检、同步生效、核对规则
- 命令输出直接显示在页面下方，无需 SSH

### 配置

| 能配什么 | 说明 |
|---|---|
| **运营商 → 策略** | 10 个运营商各一行：下拉选策略（`wan_only` / `wanb_only` / `balanced`）+ 启用勾选 |
| **多线路 DNS** | 出线方式（bind / mark）+ 每条线使用的 DNS 地址 |
| **域名分流** | 一个文本框，每行 `域名后缀:策略` |
| **保存** | 「仅保存」或「保存并生效」（后者连跑 `wire` + `apply` + `dns`） |

配置页**不直接改文件**，而是调用 `isp-split conf set <项> <值>`，由 shell 侧完成校验与写入：

- 策略名必须在 mwan3 里真实存在，否则拒绝
- 启用位只能是 0/1
- DNS 必须是 IPv4 地址
- 写前自动备份，写后 `sh -n` 校验语法，不合法自动回滚

数据通过 `isp-split status --json` 与 `isp-split conf get`（TSV）提供，LuCI 走 `ubus call file exec`，权限由 `acl.d` 控制。

安装：

```sh
sh scripts/install.sh --luci      # 只装界面
sh scripts/install.sh --all       # 界面 + 每日自动更新
```

用 SDK 编译的话，`luci-app-isp-split/` 目录里有独立 `Makefile`（`DEPENDS:=+isp-split +luci-base`）。

## 性能与健壮性

在 OpenWrt 25.12.6 / x86_64 虚拟机上实测：

| 项目 | 数值 |
|---|---|
| 全量 13417 条 CIDR（10 个集合）加载 | 约 **800 ms**，内核合并为 10278 个元素 |
| 4 个启用集合（约 2300 元素）内核内存 | **344 kB**（约 150 字节/元素） |
| 连续 3 次 `wire`+`apply` | 元素数与规则数完全不变（幂等） |
| 数据文件含非法行 | `nft -c` 整批拒绝且不提交，并定位到具体行号 |
| 策略名不存在 | `wire` 明确报错并中止，不写坏配置 |

非法数据的定位效果：

```
---- 数据文件自检 ----
  /etc/isp-split/data/chinatelecom.txt:
    1791: 999.999.999.999/33
    1792: garbage line here
```

## 未命中任何运营商集合的流量

这是最该讲清楚的一件事：**本工具不会丢包，也不会把不认识的流量乱扔。** 落点分三层：

| 情况 | 去哪 |
|---|---|
| 命中某个**已启用**的集合 | 走该集合配置的策略（wan_only / wanb_only / balanced） |
| 未命中任何启用集合 | 本工具**不打标**，交还给 mwan3 |
| ↳ 若 mwan3 的 `default_rule_v4` 已启用 | 按你的默认策略分配（推荐这样配） |
| ↳ 若未启用 | `mark=0`，走系统默认路由（通常是拨号抢到的那条线，不均衡） |

`isp-split status` 会主动检测最后一种情况并提示。

### 什么情况会"漏掉"

- **海外 IP** —— 不在任何一份国内运营商列表里
- **未启用的运营商** —— 如 `othernet`（华为云/IDC/公共 DNS）、`gwbn`、`hk/mo/tw`
- **云厂商自有 AS** —— 华为云、部分腾讯云/阿里云段，不属于三大运营商

### 怎么减少漏网

1. 启用更多集合（`cernet` 已默认开启，覆盖清华/中科大镜像站）
2. 启用 mwan3 的 `default_rule_v4`，让漏网流量也参与分配
3. 用 `tools/verify-domains.sh` 查自己的常用站点是否被覆盖 —— 输出里标 `-（落兜底）` 的就是没覆盖的

## 已知限制

1. **代理流量不受影响。** 见上文「与 OpenClash / sing-box 共存」。
2. **DNS 决定成败。** 若国内域名走了代理的远程 DNS 解析，拿到的 CDN IP 是远端视角的，可能不是对你本地最优的节点。国内域名应走本地 dnsmasq。
3. **数据准确性有上限。** 上游数据基于 APNIC/BGP，个别骨干节点或代播地址可能归类不准。它解决的是 95% 的问题，剩下的靠域名级覆盖兜底。
4. **切换出口会切断现有连接所属的路径。** 集合更新只增删差量，正常情况下不影响长连接；但若某 IP 对应的运营商发生变更，该 IP 上的连接需要重连。
5. **`wire` 会直接写 `/etc/config/mwan3`（文本级插入）。** 这样做的原因是 mwan3 严格按配置顺序渲染规则链，而 `uci add` 只能追加到末尾。副作用：如果你之后在 LuCI 里保存 mwan3 配置，uci 会用内存缓存覆盖文件，需重新执行一次 `isp-split wire`。
6. **更新数据时，更新源自己的 IP 也可能落进某个集合。** 极端情况下（该集合映射的线路恰好不可用、且策略里没有可用备份成员）`fetch` 会失败。生产环境正常双线时不会遇到；若遇到，先 `/etc/init.d/mwan3 stop` 再 `fetch`，然后 `start`。这也提醒一句：**给策略配一个备份成员**，别让单成员策略在故障时把自身流量也黑洞掉。
7. **启用 `othernet` 会把 DNS 服务器本身也分走。** `othernet` 是"三大运营商之外"的集合，华为云、各类 IDC、以及**公共 DNS（223.5.5.5 / 119.29.29.29）**都可能落在里面。启用后路由器自己的 DNS 查询会被分到那条线，那条线若不可用，**整个域名解析直接挂掉**——实测启用后 `nslookup` 全部返回空，`isp-split fetch` 也随之失败（`223.5.5.5` 的 mark 实测被打成 1536）。启用前请确认 DNS 不在该集合内，或给策略配好备份成员。因此 `othernet` 默认关闭。
8. **域名→nftset 需要 dnsmasq-full。** 基础镜像的 dnsmasq 常带 `no-nftset` 编译选项（实测 2.93 就是），此时 mwan3 原生支持的 `list domain` 不生效。`isp-split dns` 走的是 `server=/域名/IP@接口`，属于核心功能，不受此限制。

## 卸载

```sh
isp-split uninstall
```

会移除定时任务、删除本工具创建的 `config ipset` 与规则节、还原 mwan3 配置、删除数据目录。建议卸载后核对一次 `uci show mwan3`。

## 自检

不联网、不需要路由器即可跑完整回归：

```sh
sh tools/selftest.sh
```

覆盖：集合互不相交、优先级正确、被完全覆盖的集合被清空、规则插入位置正确、重复注入幂等、卸载后配置完全还原。

### 多域名 / 多节点 / 多运营商实网验证

```sh
sh tools/verify-domains.sh                    # 内置 13 个域名
sh tools/verify-domains.sh www.jd.com a.com   # 自选域名
MAXIPS=5 sh tools/verify-domains.sh           # 每域名最多取 5 个节点
sh tools/verify-domains.sh 1.2.3.4            # 也可直接给 IP
```

验证的不变量：**IP 归属集合 → 该集合配置的策略 → 实际 conntrack mark 三者一致**；未命中任何启用集合的 IP 应不打标（mark=0）。任一不一致则以非 0 退出，适合塞进 CI 或上机后自检。


## 验证记录

在 OpenWrt 25.12.6 (x86/64) + mwan3-nft 3.6.12-r1 上完成过一轮完整验证，虚拟机内用 veth + netns 伪造双线路（电信/联通各一条）。

| 验证项 | 结果 |
|---|---|
| 数据管线（busybox awk + sort） | 13417 条，与 Python 参考实现逐项一致 |
| `nft -c` 干跑校验 | 通过，12 条语句 |
| 实弹加载到独立表 | 2957 条 CIDR → auto-merge 后 2229 个内核元素，0 秒 |
| 集合持久化 | 重启后 mwan3 按 `loadfile` 自动重建，规则无需干预 |
| 规则渲染 | `ip daddr @isp_tel ... jump mwan3_policy_wan_only` 等 3 条正确内联 |
| **端到端分流** | 见下表 |
| `uninstall` | mwan3 配置 0 条残留、规则链 0 条、集合 0 个、数据目录已删 |

端到端实测（发出 ICMP 后读 conntrack 的 mark）：

| 目标 IP | 归属运营商 | conntrack mark | 命中策略 | 出口 |
|---|---|---|---|---|
| `1.48.0.1` | 电信 | 1280 (0x500) | `wan_only` | wan1 |
| `27.0.160.1` | 移动 | 1536 (0x600) | `wanb_only` | wan2 |
| `1.1.8.1` | 联通 | 1536 (0x600) | `wanb_only` | wan2 |

三个目标分别命中电信集合、移动集合、联通集合 —— 集合归属与策略映射都符合预期。

### 真实域名验证

拿真实 CDN 域名解析出的节点 IP 做归属判定（`nft get element`），再实测其 mark：

| 域名 | 解析 IP | 命中集合 | 实测 mark | 出口 |
|---|---|---|---|---|
| `upos-sz-mirrorcos.bilivideo.com` | 101.69.99.80 | `isp_uni` | 1536 | wan2 联通 |
| `dl.steam.clngaa.com` | 150.138.143.164 | `isp_tel` | 1280 | wan1 电信 |
| `files.steam.nsclouds.cn` | 39.134.188.33 | `isp_cmcc` | 1536 | wan2 联通 |
| `www.baidu.com` | 124.237.178.35 | `isp_tel` | 1280 | wan1 电信 |
| `mirrors.huaweicloud.com` | 123.249.118.101 | 未命中 | 0 | 兜底规则 |

两个值得注意的结论：

1. **移动段默认给联通**。Steam 的移动 CDN `39.134.x` 实测联通 22ms / 电信 72ms，联通明显更好，而 Steam 下载又是典型大流量场景。这个默认值已写进 `isp-split.conf`，并在注释里说明了 B 站 PCDN 的例外情况。
2. **华为云落在 `othernet`**（自家 AS，不属于三大运营商）。想让它走联通，把 `othernet` 启用并映射到 `wanb_only` 即可 —— 但**注意随后 DNS 可能一起被分走**，见「已知限制」第 7 条。

### 多运营商交叉验证（13 域名 / 22 节点）

用 `tools/verify-domains.sh` 跑的一轮完整结果，覆盖电信、联通、移动、教育网四条线：

| 域名 | 节点 | 命中集合 | mark | 出口 |
|---|---|---|---|---|
| www.baidu.com / www.qq.com / www.jd.com / www.taobao.com | 多个 | `isp_tel` | 1280 | wan1 电信 |
| mirrors.aliyun.com / mirrors.tencent.com | 多个 | `isp_tel` | 1280 | wan1 电信 |
| upos-sz-mirrorcos.bilivideo.com | 27.221.52.164 | `isp_uni` | 1536 | wan2 联通 |
| files.steam.nsclouds.cn | 39.134.188.33/36 | `isp_cmcc` | 1536 | wan2 联通 |
| mirrors.tuna.tsinghua.edu.cn | 101.6.15.130 | `isp_cernet` | 1280 | wan1 电信 |
| mirrors.ustc.edu.cn | 202.38.95.110 / 202.141.160.110 | `isp_cernet` / `isp_tel` | 1280 | wan1 电信 |
| mirrors.huaweicloud.com | 124.70.61.162 等 | 未命中（othernet 关闭） | 0 | 兜底 |
| github.com | 20.205.243.166 | 未命中（海外） | 0 | 兜底 |

汇总：**22 个 IP，19 个命中集合且 mark 一致，3 个正确落兜底，异常 0。**

两个值得注意的现象：

- **同一个域名解析出多个节点，可能分属不同运营商。** `mirrors.ustc.edu.cn` 一个节点是教育网、另一个是电信 —— 因为两条线最终都映射到 `wan_only`，所以结果一致；但换成不同映射就会分到两条线。这正是「按目标 IP 而不是按域名分流」的价值。
- **Steam CDN 节点每次解析可能不同**（`dl.steam.clngaa.com` 两次分别命中 `150.138.143.x` 和 `113.240.64.x`），但都稳定落在 `isp_tel`，说明集合判定不依赖具体节点。



验证过程中发现并修复的 busybox 兼容问题（都已写进代码注释）：

1. **`sort -n` 对大数不排序** —— 改用零填充定宽，让字典序等价于数值序。
2. **awk 的 ERE 拒绝 `\{`** —— 报 `Invalid contents of {}` 并让整段脚本静默退出，改用 `index()` 做字符串匹配。
3. **interval 集合的 `nft list set` 输出是区间格式**（`a-b`）而非 CIDR —— 用 `/前缀` 正则统计元素数会恒为 0，改为按逗号分隔解析。
4. **`uci -q delete` 删除不存在的节返回非 0** —— 在 `set -e` 脚本里会中断，需 `|| true`。



## 不建虚拟机也能验证

上真机之前不需要虚拟机，也不需要碰 mwan3。按风险从低到高四级推进：

### 第 0 级：离线回归（只读，Mac/Linux 均可）

```sh
sh tools/selftest.sh
```

### 第 1 级：只读预演（在路由器上，不改任何配置）

```sh
isp-split plan
```

能确认：mwan3 里策略名是否存在、集合是否已存在、规则会插到哪一位、注入后的完整匹配顺序。

### 第 2 级：nft 干跑校验（在路由器上，不提交）

```sh
isp-split check
```

`nft -c` 会完整解析并检查整份批处理语句，但不提交。专门用来捕获「一条元素非法导致整批被拒」这类失败——它对 mwan3 是灾难性的，因为 nft 的 batch 是原子的，一条错所有规则都不生效。

### 第 3 级：实弹自检（在路由器上，用独立临时表）

```sh
isp-split selftest
```

在**独立表 `inet isptest`** 里真跑一遍 1.3 万条元素，测量加载耗时，然后删表。`inet mwan3` 全程不受影响。

如果没有路由器 handy，任意一台 Linux 都能跑同样的测试（只需要 `nft`，不需要 mwan3 / uci / ubus）：

```sh
sudo sh tools/nft-selftest.sh
```

### 上真机前：只读预检

真机上有五个必须满足的前提（mwan3 是 nft 版、策略名齐全、数据源可达、锚点存在、dnsmasq 能力），装之前先跑一遍：

```sh
sh tools/router-preflight.sh
```

**全程只读**：不改配置、不写文件、不重启任何服务。输出逐项 ✓/✗，退出码 0 才继续部署。

### 上线：两阶段启用（dark launch）

```sh
isp-split sync     # 只下载数据 + 建立集合，规则尚未参与匹配
isp-split stage    # 注入规则但 enabled=0 —— mwan3 会完全跳过它们
isp-split enable   # 确认 mwan3 健康后真正启用
isp-split verify   # 检查规则链渲染结果
```

`stage` 的意义：即使我们写的配置有问题，也只表现为「这些新规则不生效」，**不可能波及你原有的分流规则**。确认 `nft list chain inet mwan3 mwan3_rules` 非空、`mwan3 status` 正常之后，再 `enable`。

### 还有什么必须真机验证

mwan3 的规则渲染结果、以及分流后的实际速度。前者已由 `stage`/`verify` 把风险压到最低，后者只能在真实双线下用 `isp-split probe` 观察。

### 想彻底隔离地测：开一台 OpenWrt VM


要点：版本必须 ≥ 25.12（mwan3-nft 的硬要求）、镜像变体与 UEFI/BIOS 必须配对、**网卡绝对不能桥接到家里的 LAN**（OpenWrt 自带的 dnsmasq 会和主路由抢 DHCP）。


## 数据来源

运营商 IP 段来自 [苍狼山庄 ISPIP](https://ispip.clang.cn/)，由 APNIC 数据每日更新整理。

**本项目不在仓库中分发任何第三方数据**，安装后由路由器自行拉取。上游声明数据"可用于大多数应用，但请勿用于关键任务或需要绝对准确性的系统"，请自行评估。

## 路线图

- [x] 数据管线（互斥化）+ 离线自检
- [x] mwan3 nft 集合注入与规则定位
- [x] 原子更新、历史回滚、只读预演
- [ ] IPv6 支持（上游有 `_ipv6` 系列文件）
- [x] **多线路 DNS**：`isp-split dns` 按线路绑定 DNS 出接口，让 CDN 返回本运营商节点
- [ ] 域名组配置入口：利用 mwan3 原生 `domain` + nftset 做到"域名级钉线路"
- [x] LuCI 页面：集合状态、命中计数、一键预演/校验/自检/生效
- [ ] LuCI 页内接入 probe（分线测速结果图表）
- [ ] 实测反馈闭环：对关键域名分线定期测速，自动纠正运营商规则的例外
- [x] 打包：`.ipk` 构建脚本、通用 `install.sh`、`luci-app-isp-split`
- [ ] 原生 apk 包（25.12+ 需 SDK 编译，无法手工拼装）

## 许可

[MIT](LICENSE) —— 可以随便用、改、商用、二次分发，只要保留版权声明。

- 脚本本体：MIT（`LICENSE` 文件）
- IP 段数据：来自 [ispip.clang.cn](https://ispip.clang.cn)（其数据源自 APNIC 等公开 WHOIS/BGP 记录），使用时请保留对数据来源的说明

## 致谢

- mwan3-nft：[dl12345/mwan3](https://github.com/dl12345/mwan3)
- 运营商数据：[ispip.clang.cn](https://ispip.clang.cn)
