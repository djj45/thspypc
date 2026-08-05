# 看盘主界面抓包交接 2026-08-05

## 背景

2026-08-04 ~ 2026-08-05 对同花顺 PC 客户端「看盘主界面」做了多轮抓包，
对照 thspypc 现有实现，确认了**真实客户端的 pageid/period/route 体系与代码假设的差异**，
并发现了若干未实现协议。本文档记录抓包结论、与 `PROTOCOL_AND_IMPLEMENTATION_GUIDE.md`
的逐项对比、以及据此要做的实现修正。

抓包工具：`tests/capture_kanpan.py`（含「已知协议识别器」，本次抓包后据此迭代修正了
识别器的两处误报：① route 是会话内动态实例号、不该按固定集合判未知；② 9601 纯文本帧
按 `method=` 归类而非「无 pageid 新协议」）。

## 抓包文件清单（captures_live/）

| 文件 | 账号 | 大小 | 说明 |
|---|---|---|---|
| `kanpan_20260804_235612.pcap` | **Level2** | 2.9MB | 看盘界面全流量（板块/分时/盘口/短线精灵翻页）；首次发现 9601 statscalc/calcext |
| `kanpan_20260805_000650.pcap` | **Level2** | 216KB | 点 3 只股票的分时/日K/盘口；发现 pageid=1334 + 未知 period 7169/7173/7174/4096 |
| `kanpan_20260805_001523.pcap` | **Level2** | 597KB | 进入分时/日K界面（浙江荣泰 603118）；确认 1334 做分时、4214/4417 做 L2 增强 |
| `kanpan_20260805_003410.pcap` | **普通** | 1.4MB | 普通账号分时/日K/盘口；确认普通账号用 9354/9355/1335（与代码一致） |
| `kanpan_20260805_003548.pcap` | **普通** | 1.6MB | 普通账号板块加载；确认 392 + route 0x0039/0x0139（与代码一致） |

## 结论速览

### 1. pageid 体系：Level2 与普通账号路径不同，代码的 9354/9355 是普通账号路径

**这是最重要的结论。** 同花顺客户端按账号类型走完全不同的 pageid：

| 业务 | 普通账号（代码现状，抓包确认✅） | Level2 账号（抓包真实，代码不一致❌） |
|---|---|---|
| 当日分时 | `9354` period=8192 route=0x010A | `1334` period=8192 route=0x0133/0x0033 |
| 日K线 | `9355` period=16384 route=0x0001/0x013B | `1334` period=16384 route=0x0100/0x0033 |
| 历史分时 | `9355` period=8192 route=0x005D | `4417` period=16384/8192（L2通道） |
| 列表行情/盘口快照 | `1335` period=0 多种route | `1334` period=0 多种route |
| 五档盘口 | `1335` DataType=24,25,30,31 | `1334` DataType=13,18,24,25... |
| 早盘竞价 | `9354`/`9355` period=7176/6144 | `1334` period=7176 route=0x01FC |
| 尾盘竞价 | `9354`/`9355` period=7424 | `1334` period=7424 route=0x0100 |
| 板块列表 | `392` route=0x0039/0x0139 | `1334` route=0x002B/0x012B（8901） |
| L2增强分时 | —（普通账号无） | `4214` period=8192 route=0x0201 |
| L2增强历史/K线 | — | `4417` period=16384/8192 |

**要点**：
- thspypc 代码里的 `9354`(分时)/`9355`(K线/历史) 是**普通账号在 MAIN 通道上验证可用的 pageid**，
  抓包确认真实客户端普通账号确实用这两个值——**代码正确，不要改普通账号路径**。
- Level2 账号在真实客户端里**不用 9354/9355**，而是统一用 `1334`（走 L2 连接 stream）做
  分时/K线/盘口/竞价，再用 `4214/4417` 做 L2 增强。thspypc 当前让 Level2 也走 9354/9355，
  虽然服务器能返回数据（pageid 不严格校验），但与真实客户端不一致。
- `1334` 在普通账号是**排行榜**（stock_list，DataType=199112），在 Level2 账号是**通用看盘请求**
  pageid——同一个数字在不同账号下语义不同，这是同花顺的设计。

### 2. 盘口区新 period（Level2，pageid=4214/4417，未实现）

抓包发现 Level2 账号在盘口/逐笔区用了 4 个 thspypc 未实现的 period：

| period | pageid | DataType | 推断业务 | 状态 |
|---|---|---|---|---|
| **7169** | 4214 | 10,12,13 | 逐笔成交回放（全天逐笔） | ❌ 路线图缺口。注意真实 pageid 是 **4214**，不是 HANDOFF_SUPERORDER 推测的 4260 |
| **7173** | 4417 | 10 | 逐笔委托？（待确认） | ❌ 完全未知 |
| **7174** | 4214 | 10 | 逐笔相关（待确认） | ❌ 完全未知 |
| **4096** | 4417 | 7,49,12,18,75,10 | 分笔 tick（个股，类比指数分笔） | ❌ 未实现 |

> 这组协议复杂（逐笔回放单帧 440KB+），本轮**暂不实现**，仅记录。

### 3. 9601 板块统计协议（statscalc/calcext，✅ 已实现 2026-08-05）

真实客户端的板块列表除 8901 的 392/1334 请求外，还走 9601 的**纯文本计算协议**。
两者共享帧封装 ``\x09`` + ``\n`` 分隔 GBK key=value 文本 + ``\x00``（请求/响应
同构，无二进制子帧头）：

| method | 节点 | 请求格式 | 返回 | 用途 |
|---|---|---|---|---|
| `statscalc` | 独立统计节点 `8.132.233.77:9601`（不在 DNS/passport） | `instid= method=statscalc market=48, codelist=48(881101,...) datatype=330342 dataclass=intervalcalc interval=0-0 rightstype=forward period=0 datetime=0(0-0) rettype=hdfile` | hd1.0 表（每码 24B：code8+pad8+date4LE+value4float） | 板块批量统计（涨跌幅/涨速/资金流聚合计算） |
| `calcext` | REALORDER 节点 `106.14.65.90:9601`（与 qurealorder 共享） | `instid= method=calcext codelist=33(003017,) datatype=199359 rightstype=forward rettype=json` | JSON `{"data":[{"3":<market>,"4":"<code>","199359":<value>}]}` | 单板块/个股扩展计算 |

实测数据：
- `statscalc` `dataclass=updownlimit datatype=330326,330328` → 涨跌停统计
- `calcext` 对单只股票（如 003017/003018）请求 `datatype=199359 rettype=json`
- 端口：全部 9601（与短线精灵同端口，但走独立 instid 流）
- thspypc 的 `board_quotes` 走 8901 fu4 通道（pageid 392/5716），是另一套协议，功能可达但路径不同

**thspypc 实现**（2026-08-05）：
- `features/board_stats_protocol.py`：请求构造（`build_statscalc_query` /
  `build_calcext_query`，字段顺序逐字节对齐抓包）+ 响应解析
  （`parse_statscalc_response` / `parse_calcext_response`，record_len 由 payload
  计算不写死 24）。
- `services/board_stats.py` `BoardStatsService`：statscalc 走
  `ConnectionRole.BOARD_STATS`（独立统计节点，懒连接 + 心跳），calcext 走
  `ConnectionRole.REALORDER`（复用 9601 socket，门控用 `Capability.REALORDER`
  与短线精灵一致，REALORDER 能力证据在首次 9601 建连时懒建立）。
- 公开 API：`board_stats_interval` / `board_stats_updownlimit` / `board_calcext`。
  statscalc 节点不可达时优雅降级返回空列表（可降级 `board_quotes`），不影响 calcext。
- 节点 IP 用 `THSPYPC_STATSCALC_HOST` 环境变量覆盖。

**活网验证结论**（2026-08-05）：
- ✅ statscalc：`board_stats_interval(["881121"])` 返回 `{code:0881121, date:20160127, value:-3.19}`，hd1.0 解析正确。
- ✅ calcext：`board_calcext("600030", 17)` 返回流通市值 `4054 亿`，JSON 解析正确。
- ⚠ **statscalc 是低频计算协议**：抓包确认真实客户端请求间隔 **~9 秒**（服务端区间聚合
  计算耗时）。连续高频调用（如循环批量查）会被服务端限流/丢弃导致超时。正确用法是
  低频轮询（≥10s 间隔），不要像行情查询那样连续发。首次请求还需预留建连时间
  （PC login 到独立统计节点 ~15s）。
- calcext 与 qurealorder 共享 REALORDER socket，无此限流问题，可连续调用。

**与 8901 board_quotes 的区别**：statscalc 是**服务端计算型**（`dataclass=intervalcalc` 让
服务器做区间聚合），8901 board_quotes 只取预存字段。两者可互补、交叉验证。

### 4. 短线精灵翻页（qurealorder）：基本对齐，3 处差异

抓包（Level2 账号，勾选 4 类异动：大笔买入/卖出、打开涨停/跌停）对照 thspypc `build_qurealorder_query`：

| 参数 | thspypc 代码 | 真实客户端 | 对齐 |
|---|---|---|---|
| `method=qurealorder` / `reqtype=4` / `rettype=hqfile` | ✅ | ✅ | ✅ |
| `maxcount` | 写死 `80` | **80 / 120 / 1000 三种**（见下） | ⚠️ 需改成按市场可选 |
| `datatype` | `DXJL_DATATYPE`（4类） | 4类（与勾选一致）| ✅ 本次勾选对齐 |
| `accept_ziptype=snappy` | ❌ 未发 | ✅ **46/46 帧全发** | ⚠️ 需补 |
| 响应压缩 | — | **实测未压缩**（明文 hq1.0，record_count=80 record_len=45，数据区可见明文代码 300750） | ✅ 不修也能用 |

**maxcount 三种值的含义**（实测 market 分布）：

| maxcount | 适用 market | 含义 |
|---|---|---|
| **80** | 16(沪)/32(深)/151(北交所)/48(板块) | 个股市场标准每页条数（异动多） |
| **120** | 151(北交所)/16/32/48 | 北交所等异动较少市场的翻页条数 |
| **1000** | 48(板块)/16(沪首批) | 板块异动少，一次拉满；或首批全量加载 |

> 同花顺客户端按市场/场景动态选 maxcount；thspypc 写死 80 在个股市场可用，但板块/北交所
> 场景分页不合理。`accept_ziptype=snappy` 盘后小响应未压缩，盘中大响应可能压缩（待验证）。

## 与 PROTOCOL_AND_IMPLEMENTATION_GUIDE.md 的逐项对比

### 第 6 节「业务请求速查总表」需修订

文档现表（普通账号为主）抓包确认✅，但**缺少 Level2 账号的 pageid 对照**。补充：

| 业务 | 文档现状（普通） | Level2 真实（抓包新增） |
|---|---|---|
| 当日分时 | 9354 period=8192 | **1334** period=8192 route=0x0133/0x0033（+4214 L2增强） |
| 日K | 9355 period=16384 | **1334** period=16384 route=0x0100/0x0033 |
| 历史分时 | 9355 period=8192 | **4417** period=16384/8192（L2通道） |
| 五档盘口 | 1335 DataType=24,25... | **1334** DataType=13,18,24,25... |
| 早盘竞价 | 9354 period=7176 | **1334** period=7176 route=0x01FC |
| 尾盘竞价 | 9354 period=7424 | **1334** period=7424 route=0x0100 |
| 板块列表 | 392 route=0x0039 | **1334** route=0x002B/0x012B |

### 第 12 节「K线」补充

文档说 K线「始终走 MAIN，pageid=9355」——这只对**普通账号**成立。Level2 账号真实客户端用：
- `pageid=1334` period=16384 route=0x0100（普通日K，走L2连接）
- `pageid=4417` period=16384 route=0x0100/0x0157（L2增强日K，带大单字段 207/206/205...）
- `pageid=4214` period=16384 route=0x0100（L2通道日K，DataType=13,407）

### 新增「盘口逐笔协议」小节（待实现）

| period | pageid | DataType | 业务 | 参考 |
|---|---|---|---|---|
| 7169 | 4214 | 10,12,13 | 逐笔成交回放 | HANDOFF_SUPERORDER_20260726（pageid 需更正为4214） |
| 7173 | 4417 | 10 | 逐笔委托？（待确认） | — |
| 7174 | 4214 | 10 | 逐笔相关（待确认） | — |
| 4096 | 4417 | 7,49,12,18,75,10 | 分笔 tick | 类比指数分笔 period=4096 |

## 本轮实现修正（已确认要做）

### A. 短线精灵：补 accept_ziptype=snappy + maxcount 参数化

**文件**：`src/thspypc/features/realorder_protocol.py`

1. `build_qurealorder_query` 增加参数 `accept_ziptype: str = "snappy"`，文本末尾在
   `rettype=hqfile` 前插入 `accept_ziptype=snappy\n`（对齐真实客户端 46/46 帧）。
2. `maxcount` 从写死 80 改为参数（默认仍 80，保持兼容），并在 docstring 写明三种值的含义。
3. `services/realorder.py` 的 `dxjl_page` 透传 maxcount（已有参数，确认默认值与文档一致）。

> 实测响应未压缩（明文 hq1.0），所以 `accept_ziptype=snappy` 不影响解析，仅对齐请求形态。
> 解析器无需改。

### B. Level2 pageid 对齐 1334（已实现，2026-08-05）

经抓包确认并实现：
- **普通账号**（9354/9355/1335）路径与真实客户端一致，**保持不变**。
- **Level2 账号**的分时/K线/当日竞价主体 pageid 从 4214 改为 **1334**（DataType/route 不变），
  对齐真实客户端。关键改动：

| 业务 | 文件 | 改动 |
|---|---|---|
| 分时（当日） | `features/timeline_protocol.py` `build_timeline_l2_query` | 新增 `pageid` 参数（默认4214向后兼容）；`services/timeline.py` `build_timeline_request` L2 分支传 `pageid=1334` |
| 日K/周K/分钟K | `features/kline_protocol.py` | 新增 `build_kline_l2_query`（pageid=1334, route=0x0100）；`build_kline_query` 新增 `route` 参数 |
| K线服务层 | `services/kline.py` | 新增 profile 判断：Level2 走 L2 连接(SH_L2/SZ_L2)+1334，普通走 MAIN+9355 |
| K线门面 | `_client/service_facade.py` | 按 profile 选 capability（BASIC_QUOTE / L2_TIMELINE） |
| 当日开盘竞价 | `features/auction_protocol.py` `build_auction_query` | pageid 4214→1334，route 0x01FC 不变 |
| 当日尾盘竞价 | `features/auction_protocol.py` `build_l2_closing_auction_query` | 当日 pageid 4214→1334；历史保持 4417 |

**关键确认**：1334 分时请求的 DataType 仍含 dt223-230 大单字段（抓包帧15/96 确认），
改 pageid **不丢失 L2 大单曲线**。解析器全部不依赖 pageid（靠 flag/record_size 区分），无需改。

**不改的部分**（有 fixture 背书或功能可用）：
- 历史分时 `build_history_timeline_query`（4417，有 fixture）
- 历史竞价 `build_l2_history_auction_query`（4417，抓包确认）
- 盘口十档 `build_depth_ten_query`（4214，有 fixture `req_000938_4214_ten.bin`）
- 盘口五档 `build_depth_quote_query`（1333，走 MAIN，功能可用）

> ⚠️ 待活网验证：1334 路径虽对齐了请求形态，但响应是否仍为 flag=0x00B4（L2表）需 Level2 账号
> 活网确认。若响应 flag 变化，需调整解析器。测试已全部更新（388 passed）。

### C. 盘口新协议（7169/7173/4096）：本轮不实现

逐笔回放协议复杂（单帧 440KB+，变长字段，HANDOFF_SUPERORDER 的 fmt 子标记 22/34 未破译），
且 HANDOFF_SUPERORDER 推测的 pageid=4260 与本次抓包（pageid=4214 period=7169）不符，需
重新逆向。本轮仅记录，留作后续 P2-R&D。

请求形态已确认（2026-08-05 抓包 `kanpan_20260805_010356`）：

```
# 逐笔成交回放
CodeList=33(000938,); DataType=10,12,13, DateTime=7169(-27-0) pageid=4214  route=0x02FC
# 逐笔委托
CodeList=33(000938,); DataType=10, DateTime=7173(-1-0) pageid=4214  route=0x02FC
```

### D. 竞价 trade_date 默认值修复（盘后超时根因）

**问题**：`closing_auction()` / `auction()` 不传 `trade_date` 时原用 `date.today()`，
盘后/非交易日请求"当日"竞价导致超时（当日无数据）。2026-08-05 抓包确认同花顺客户端
盘后查竞价用的是**最近交易日**（8/4）的显式时间戳（`7424(1785826620-1785826800)`
= 8/4 14:57-15:00），而非"今天"。

**修复**：`auction_protocol.py` 新增 `resolve_trade_date(value)`：
- `None` → 最近已收盘交易日（周末回退；工作日 15:00 前回退到前一交易日）
- 显式日期 → 原样返回
- 三处 `trade_date or datetime.now().date()` 和 `build_auction_query` 的 `0-0` 默认
  全部替换

**活网验证（盘后 2026-08-05）**：

| 接口 | 修复前 | 修复后 |
|---|---|---|
| `closing_auction()` 不传日期 | ⏱ 超时 | ✅ 21 tick（8/4 14:57-15:00） |
| `auction()` 不传日期 | ✅（`0-0` 服务器自决） | ✅ 68 tick（8/4 09:15-09:24） |

### E. 1334 改动活网验证结论

Level2 账号（2026-08-05 盘后）全部通过：

| 接口 | pageid | 结果 |
|---|---|---|
| 分时 timeline | 1334 | ✅ 241 点 + L2 大单字段 dt227/229（不丢失） |
| 日K kline | 1334 + SH_L2/SZ_L2 | ✅ 11 根（新 L2 路径打通） |
| 周K kline | 1334 | ✅ 6 根 |
| 当日竞价 auction | 1334 | ✅ 68 tick |
| 当日尾盘 closing_auction | 1334 | ✅ 21 tick（修 trade_date 后） |
| 历史尾盘（4417 未改） | 4417 | ✅ 21 tick |

**关键确认**：1334 分时请求的 DataType 仍含 dt223-230 大单字段，改 pageid 不丢失
L2 大单曲线；响应仍为 flag=0x00B4 的 L2 表，解析器无需改。

### F. 看盘界面指数实时推送（✅ 已实现 2026-08-05）

盘中抓包（``captures_live/kanpan_push_20260805_132347.pcap`` +
``index_push_20260805_140642.pcapng``）发现看盘界面有一类 ``09 7b d0 0f`` 头的
实时推送帧（之前归在"其他"里），是 pageid=5716 subreal 订阅的服务端推送。

**五大指数全局推送**：客户端启动时一次性注册（pageid=5716 + PushField=16:241;32:241
+ subreal URS/UCT/UNX/UCX/UME），服务端持续推送指数点位。

**字段解码**（4 字节 LE THS-float，深市/沪市字段顺序一致，起点偏移不同；北证50
紧凑帧用相对代码偏移，与分时响应交叉验证逐字节确认）：

| 字段 | 深市(399xxx) | 沪市(1Axxxx) | 北证(899050) |
|---|---|---|---|
| dt6 昨收 | off=48 | off=39 | — |
| dt7 开盘 | off=52 | off=43 | — |
| 最高 | off=56 | off=47 | — |
| 最低 | off=60 | off=51 | — |
| dt10 最新 | off=64 | off=55 | code+6 |
| dt19 成交额 | off=76 | off=63 | code+14 |

**活网验证**（2026-08-05 盘中）：399001=14129/+1.76%、1A0001=3872/+1.32%、
1B0680=1928/+4.72%、899050=1114。

**实现**：``features/index_push_protocol.py`` 的 ``parse_index_push``，支持三套
布局（深市/沪市/北证），9 个测试（含真实帧）全通过。

### G. 北证50 分时解析兼容（✅ 已修复 2026-08-05）

北证50（899050）当日分时返回 ``flag=0x0046`` hd3.1 表（230 点，无 dt40），现有
``parse_timeline_response`` 拒绝（只接受指数 flag 0x3E/0x86/0x9E + dt40，或个股
record_count==241）导致超时。**这不是权限问题，是解析器兼容问题**。

修复：``timeline_protocol.py`` 个股分时路径放宽 record_count（200-242）+ shell
市场标记扩展（0x11/0x12/0x13/0x21/0x25）。

## 抓包方法学补充（给 capture_kanpan.py 的后续维护）

本次抓包迭代修正了识别器两处设计错误，已写入 `tests/capture_kanpan.py`：

1. **route 不是协议常量**：route 是会话内动态分配的「页面组件实例号」，同一业务每次连接
   route 不同（如分时 route 在不同 stream 是 0x0133/0x0033/0x013C）。识别器原先按固定
   `KNOWN_ROUTES` 集合判「未知route」造成海量误报。修正：仅对「未知 pageid/协议」才提示
   route，已知业务不判 route。

2. **9601 纯文本帧按 method= 归类**：statscalc/calcext/qurealorder 等是 `\x09` + `instid=`/`method=`
   纯文本帧，不走 pageid 体系。识别器原先归「无pageid新协议」，修正为按 `method=` 关键词
   分类（statscalc→板块统计、calcext→板块扩展、qurealorder→短线精灵历史）。
