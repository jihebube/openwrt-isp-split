# 兜底计数器增量归因（BUG-21 收尾）

本文回答一个具体问题：

> 静默 20 秒兜底计数涨 136/117；NAS 跑 20 次 `nslookup @223.5.5.5` 的 20 秒
> 涨 297。多出来的约 160 包真的来自 DNS 吗？

结论：**不是**。按已装规则（`th dport != 53 th sport != 53`），DNS 对这个
计数器的贡献是 **0**；即使把 DNS 的排除条件全删掉，20 次 nslookup 的物理
上限也只有 **80 包**（每次 4 包）。观测到的 8 包/次查询 = 2 × 物理上限，
不可能是 DNS 包。计数器行为是对的，问题在"这个数字到底在数什么"。

---

## 1. 一次 nslookup 到底发多少包（实测）

被测客户端是 Synology NAS（Debian 12，`bind9-dnsutils 9.18.33`，
`resolv.conf` 里有 `search lan`、`options single-request`）。用 strace 数
系统调用：

```
strace -f -e trace=%network nslookup bing.com 223.5.5.5
  2 × connect(..., sin_port=htons(53), 223.5.5.5)   # 两个 socket（A 一个、AAAA 一个）
  1 × sendmmsg(fd13, 26 字节)                       # A 查询
  1 × sendmmsg(fd14, 26 字节)                       # AAAA 查询
  2 × recvmsg                                       # 两个响应（AAAA 是空答案）
```

所以一次 `nslookup`：

| 项 | 数量 |
|---|---|
| 查询包 | 2（A + AAAA） |
| 响应包 | 2 |
| 合计 | **4 包** |
| conntrack 流 | **2 条**（两个 socket，源端口不同） |
| 搜索域扩展 | 无（`bing.com` 含点，ndots=1，直接按绝对名查） |
| 重传 | 无（两次查询都拿到响应） |

20 次 nslookup = 40 查询 + 40 响应 = **80 包**、40 条流。这就是 DNS 在这
20 秒里能贡献的全部包数——**每个包都带 53 端口**。

## 2. 为什么 DNS 到不了兜底计数器

`mwan3_prerouting` 挂在 `priority mangle + 1`，也就是 **-149**；conntrack 的
DNAT/un-SNAT 在 **-100**。所以 mwan3 看到的是"还没做地址转换"的包，WAN 回来
的响应此刻目的地址仍是路由器自己的 WAN 地址。响应包要走到 `mwan3_rules`
里的兜底计数规则，必须同时躲过下面三道门，而**任意一道命中就会提前离开**：

| 门 | 规则（mwan3 3.6 nft） | 对 DNS 响应的效果 |
|---|---|---|
| 1. conntrack 标记 | `meta mark & 0x3f00 == 0 ct mark & 0x3f00 vmap { … }` | 查询首包在出向时已把 ct mark 打成 `0x200/0x600`，响应直接 vmap 到策略链 |
| 2. 入接口打标 | `... jump mwan3_ifaces_in` → `iifname "wan2" ... meta mark set ... | 0x600` | WAN 入向包按 `iifname` 打标，随后 `meta mark & 0x3f00 == 0 jump mwan3_rules` 不再命中 |
| 3. connected / local | `... jump mwan3_connected`、`fib daddr type local return` | 响应此刻目的地址还是路由器 WAN 地址，属于 connected 网段 → `mark | 0x3f00; return` |

再加第四道：兜底规则自身带 `th sport != 53`。

### VM 实测（OpenWrt 25.12.6 / nft 1.1.6 / mwan3 3.6）

在隔离测试 VM 上搭了同构拓扑：客户端 netns — br-lan — VM（mwan3 wan1/wan2，isp-split 四个集合）—
上游 netns 里的 DNS 服务器 `223.5.5.5:53`。在 `mwan3_rules` 链首插探针
计数器（`p_rules_all` / `p_rules_q53` / `p_rules_r53`），在
`mwan3_prerouting` 的每个"提前离开"点插位置探针（`t1..t6`）。

| 场景（20 次 nslookup / 40 条流） | 进 `mwan3_rules` 的查询包 | 进 `mwan3_rules` 的响应包 | 兜底增量 |
|---|---:|---:|---:|
| DNS 服务器 IP 在集合里（生产同构） | 40（= 流数） | **0** | **0** |
| DNS 服务器 IP 不在任何集合 | 60 | **0** | **0** |
| 把 `mwan3_iface_in_wan2` 清空 | 60 | **0**（被 connected 拦下） | 0 |
| 再删 `fib daddr type local return`、并把测试网段移出 `mwan3_connected_v4`（10 次 nslookup） | 30 | 30 | 0（双侧 53 排除生效） |
| 同上，但把规则换成"不排除 DNS"的单条规则 | 30 | 30 | **60**（1 包 1 计） |

> VM 客户端是 busybox `nslookup`（AAAA 会多一次重试），所以"查询包"比
> NAS 上的 bind9（严格 2 包/次）多；有意义的是一列对一列的比例，不是绝对值。

位置探针证明响应的实际去向：

```
t1 (ifaces_in 前)      +10
t2 (fib local 前)      +10
t3 (custom 前)         +0      ← 在 fib daddr type local return 处返回
```

也就是说：**响应包在健康 mwan3 里根本走不到兜底计数规则**。上一轮
（FIX21/FIX22）"响应包被计入"的复现，是在 netns 里手工把测试网段从
`mwan3_connected_v4` 移掉、并绕开 `mwan3_ifaces_in` 造出来的，不是生产
路径。`th sport != 53` 因此是**防御性**的（mwan3 被改坏、WAN 未纳管时才
兜底），不是这次 +160 的原因。

## 3. 上限论证

把上面两张表合起来：

- 20 次 nslookup 在线上只有 **80 个带 53 端口的包**；
- 兜底计数规则**只统计两侧都不是 53 的包**；
- 极端假设"排除条件被删掉"，计数上限也就是 80。

观测增量 ≈ **160**，正好是上限的 2 倍。所以：

> 至少一半的增量在物理上不可能是 DNS 包。

## 4. 那 160 是什么？按可能性排序

| # | 可能 | 为什么像 / 怎么判 |
|---|---|---|
| 1 | **测量口径重复计数**：同一批包被两个计数点各数一遍（两个 hook、两个接口 rx+tx、把 `status` 里"命中包"列和"兜底"行相加、或 `nft` 与 `conntrack` 混着看） | 8 = 2 × 4，正好是"每次 nslookup 4 包 × 2 个计数点"。用 `tools/count-attrib.sh` 只读对账即可排除 |
| 2 | **同期 LAN 其他流量**：兜底计数器数的是"未命中任何集合的新连接"，静默窗口本身就有 117~136 的抖动（±16%）。一台手机刷视频时的 QUIC 短连接可以轻松贡献 8 条/秒 | 交替做 3 次静默 + 3 次 DNS 轮，看 DNS 轮是否**稳定**高出一截；再看 `count-attrib.sh` 给出的 DNS 实际包数 |
| 3 | **生产装的不是当前形状**：`status` 的提示被忽略、或升级后没跑 `apply`。此时 DNS 查询会进兜底（2 包/次），响应仍进不来 | `nft list chain inet mwan3 mwan3_rules \| grep isp_fallback`，或看 `status` 有没有"形状不符"提示 |
| 4 | DNS 客户端有重传/搜索域扩展，线上包数比 4 包/次多 | 用 `count-attrib.sh` 直接读 `nf_conntrack` 的实测包数，不用估 |

反过来，"计数器把 DNS 算进去了"这一条可以排除：见第 3 节。

## 5. 生产上怎么一分钟定性（只读）

```sh
# 把仓库里的 tools/count-attrib.sh 传到路由器（或直接在仓库目录里跑）
sh tools/count-attrib.sh 20 223.5.5.5
# 采样窗口内，在 NAS 上跑你的 DNS 轮
```

它同时取三个只读口径：

1. `isp_fallback` 计数器增量；
2. 窗口内 DNS 流**实际走过的包数**（读 `/proc/net/nf_conntrack`，双向合计，
   这是 DNS 能贡献的物理上界）；
3. DNS 流的 conntrack mark（判断 mwan3 有没有把它们匹配进集合）。

判定：

| 观测 | 结论 |
|---|---|
| Δ兜底 = 0 | 计数器正确，DNS 没被计入；外部看到的增量不是这个计数器 |
| 0 < Δ兜底 ≤ DNS 实际包数 | 增量可以由 DNS 解释 → 排除条件没生效，`isp-split apply` 重建 |
| Δ兜底 > DNS 实际包数 | 至少 `Δ兜底 - DNS包数` 不可能是 DNS → 按第 4 节 1/2 两条查 |

工具全程只读：只 `nft list`、只读 `/proc`，不插入/删除任何规则。

再做一组对照（同样 20 秒，不跑 DNS）各 3 次，比较两组的中位数：
静默组和 DNS 组如果没有稳定差异，就说明这 160 是噪声或同期其他流量。

## 6. VM 复现步骤

```sh
# 1) 客户端 netns 挂到 br-lan（模拟 NAS）
ip netns add cli
ip link add lancli type veth peer name cli0
ip link set cli0 netns cli && ip link set lancli master br-lan && ip link set lancli up
ip netns exec cli ip link set cli0 up
ip netns exec cli ip addr add 192.168.50.50/24 dev cli0
ip netns exec cli ip route add default via 192.168.50.1

# 2) 上游 netns 里起一个 223.5.5.5:53 的 DNS
ip netns exec ispnet ip addr add 223.5.5.5/32 dev isp2
ip route replace 223.5.5.5/32 via 10.99.2.1 table 6
ip netns exec ispnet dnsmasq --no-daemon --port=53 --listen-address=223.5.5.5 \
    --bind-interfaces --no-resolv --no-hosts --local=/bing.com/ \
    --address=/bing.com/93.184.216.34 --log-queries --log-facility=/tmp/dnsq.log &

# 3) 探针（只读计数，不改 mwan3 语义）
nft add counter inet probe c_q;  nft add counter inet probe c_r
nft add rule inet probe pre ip saddr 192.168.50.50 ip daddr 223.5.5.5 udp dport 53 counter name c_q
nft add rule inet probe pre ip saddr 223.5.5.5 udp sport 53 counter name c_r

# 4) 跑一轮，读增量
i=0; while [ $i -lt 20 ]; do ip netns exec cli nslookup bing.com 223.5.5.5 >/dev/null; i=$((i+1)); done
nft list counter inet probe c_q   # 期望 40
nft list counter inet probe c_r   # 期望 40
nft list counter inet mwan3 isp_fallback   # 期望不变
```

想复现"响应也被计入"的极端场景，需要同时拆掉三道门（`mwan3_ifaces_in`
清空、删掉 `fib daddr type local return`、把 `mwan3_connected_v4` 里的
测试网段移掉）——这本身就说明该路径在生产上不可达。

## 7. 本次改动的口径修正

`COUNT_FALLBACK` 的语义是"未命中任何集合的新连接数"，`status` 也是这么
写的。但旧规则只带 `meta mark & 0x3f00 == 0`，它只保证"包进来时没打标"，
不保证这条连接后面会拿到 conntrack 标记。如果 `default_rule_v4` 被
`enabled=0` 关掉（`status` 会提示这种情况），未命中集合的流就完全没有
标记，同一连接的**每个包**都会重新走一遍 `mwan3_rules`：

```
VM 实测：一条未打标的 ICMP 流 ping 5 次
  旧形状（无 ct state new）  → 兜底 +5（按包）
  新形状（ct state new）     → 兜底 +1（按连接）
```

所以这一版给两条规则都加了 `ct state new`。这样"兜底 / 时长"才等价于
"未命中集合的新连接速率"，也才和 DNS 的"每次 2 条流"能直接对账。
