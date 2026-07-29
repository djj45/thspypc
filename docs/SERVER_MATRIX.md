# 行情服务器域名、权限与用途

本文记录 thspypc 已观察到的服务器拓扑。8901 行情域名来自 HTTP 鉴权响应中的
`M_hqdns`，具体 IP 由 DNS 动态解析，不能把某次解析结果写死为长期配置。
9601 REALORDER 是例外：官方配置提供固定 seed，并可缓存服务端选择的物理节点。

更新时间：2026-07-29。

## 结论：`stock_list` 请求哪种服务器

`stock_list()` 走 **MAIN A 股基础行情连接**：

1. 通过 `auth.10jqka.com.cn:80` 完成 HTTP 鉴权并取得 passport；
2. 从 passport 的 `M_hqdns` 中选择 `ifindhq.123ths.com:8901`；
3. 使用普通登录身份建立 `ConnectionRole.MAIN`；
4. 在这条已登录的 MAIN 连接上发送一个 `DataType=[5],[55]` 请求；
5. 从服务器返回的 `hd3.1` 全量代码表中解码股票代码。

它**不走** `shlv2.123ths.com` 或 `szlv2.123ths.com`，也不要求
`L2_MARKET_ACCESS`。2026-07-29 活网验证时，MAIN 实际连接
`8.134.123.179:8901`；该 IP 属于当时的 `ifindhq.123ths.com` DNS 集合，
一次请求返回 26,499 条代码记录。

最小请求的文本负载为：

```text
DataType=[5],[55]
CodeList=16();17();19();20();144();145();146();147();150();151();
DateTime=0
pageid=5716
```

编码后的 FDF envelope 为 146 字节，线上发送时追加一个换行，共 147 字节。
逐段、逐帧 A/B 已确认旧 `stock_list_replay.bin` 中另外 153 帧均不需要。

同一请求也曾在一个 `shlv2` IP（`122.9.202.190`）上返回全量表。这只说明
该 L2 实例兼容这类代码表查询，不改变生产路由：基础股票列表应复用 MAIN，
不应为它额外申请 L2 权限或占用沪市 L2 连接。

## 已实现的连接角色

| 连接角色 | 地址 | 登录身份 / 初始化 | 权限要求 | 已验证用途 |
|---|---|---|---|---|
| HTTP 鉴权 | `auth.10jqka.com.cn:80` | HTTP 三步鉴权 | 有效账号、密码或扫码凭据 | 获取 passport、signature、`M_hqdns` |
| MAIN | `ifindhq.123ths.com:8901` | 普通登录；`VerifyCode=0` 后发送标准 MAIN init，不发送 `__manual` L2 init | `BASIC_QUOTE`；不是 L2 专用 | `stock_list`、热门/排序列表、批量行情、基础分时、K 线、名称增量等 MAIN 请求 |
| SH_L2 | `shlv2.123ths.com:8901` | `__manual` 登录；init `MarketCode=16;144;` | Level2 账号，且 `L2_MARKET_ACCESS` 已有成功证据；具体功能还分别受 `L2_TIMELINE`、`L2_AUCTION`、`L2_SNAPSHOT_PUSH`、`L2_HISTORY_TIMELINE` 控制 | 沪市主板/科创板 L2 分时、竞价、快照推送、历史分时 |
| SZ_L2 | `szlv2.123ths.com:8901` | `__manual` 登录；init `MarketCode=32;` | 同 SH_L2 | 深市 L2 分时、竞价、快照推送、历史分时 |
| REALORDER | 固定 seed/default `106.14.65.90:9601`；官方客户端可缓存动态首选物理节点 | 独立 9601 登录 | `REALORDER`；这是独立能力，不能仅由“是否 Level2 账号”推断 | `qurealorder` 历史异动、`subrealorder` 实时异动订阅、`pushrealorder` 接收 |

权限判断采用“业务成功证据优先”原则。域名出现在 `M_hqdns`、TCP 能连通或登录
成功，都不等于某个具体业务已获授权；超时、RST 也不能单独证明账号无权限。

## 当前 passport 下发的其他行情域名

2026-07-29 当前账号的 `M_hqdns` 原文包含以下路由。下表中的“市场/通道标识”
忠实记录服务端字段；除已实现角色外，项目尚未完成业务级验证，因此不把域名前缀或
市场码直接当成权限结论。

| 域名 | 端口 | `M_hqdns` 市场/通道标识 | 当前判断 | thspypc 状态 |
|---|---:|---|---|---|
| `shlv2.123ths.com` | 8901 | `16;144` | 沪市 L2，已验证 | 已实现，要求 L2 能力 |
| `szlv2.123ths.com` | 8901 | `32` | 深市 L2，已验证 | 已实现，要求 L2 能力 |
| `fu4.123ths.com` | 8901 | `96;128;88;URS;UCT;UNX;UCX;UME;216;48` | 多市场/板块/订阅路由；确切业务权限未完成验证 | 未作为 MAIN 或 L2 路由 |
| `hkus.123ths.com` | 8901 | `176;112` 和 `168;184;200` | 域名指向港股组；具体品种和账号权限未验证 | 未实现 |
| `ifindhq.123ths.com` | 8901 | `232;120;104;56` | 尽管公告字段不是沪深 16/32，活网已验证它承担本项目 A 股 MAIN 请求 | 已实现为唯一 MAIN DNS 域名 |
| `fu2.123ths.com` | 8901 | `64;80;UGF;UZC;UDE` | 多市场路由；确切用途和权限未验证 | 未实现 |
| `euhq.123ths.com` | 8901 | `160` | 域名表明欧洲行情组；业务和权限未验证 | 未实现 |
| `fu6.123ths.com` | 8601 | `UZX` | 独立 8601 通道；用途和权限未验证 | 未实现 |
| `usotc.123ths.com` | 8901 | `UNS;UHI` | 域名表明美股 OTC 组；业务和权限未验证 | 未实现 |

注意：`M_hqdns` 中域名后的标识是服务端路由元数据，不是完整的权限声明。例如
`ifindhq` 公告的标识不含 16/32，但它已连续响应沪深 MAIN 查询。因此，新增市场支持
必须用真实请求/响应验证，不能只按名称或市场码猜测。

## 路由约束

- MAIN 只从 `ifindhq` 解析 IP。把 `fu4`、`hkus`、`euhq` 等 IP 混入 MAIN，
  可能登录成功，但已观察到沪深基础行情请求超时。
- 沪深 L2 必须分服。`shlv2` 与 `szlv2` 的 DNS IP 集合当前完全不重叠；
  沪票连 `shlv2` 并 init `16;144`，深票连 `szlv2` 并 init `32`。
- MAIN 必须完成自己的标准 init；不要把 `__manual` L2 init 发到 MAIN。
- REALORDER 是独立端口和独立能力，不复用 MAIN/L2 的功能权限判断。
  `106.14.65.90:9601` 是可直接连接的固定 seed/default，不保证永远是客户端
  缓存的首选物理节点；不能把 `otqs` 或 `wdcs/hxstats` 的 9601 节点混入该角色。
- DNS 结果会轮换。文档中的 IP 只作为某次活网证据，运行时始终应解析 passport
  下发的域名。
