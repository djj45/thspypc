# 同花顺 PC 版功能复刻路线图（缺口对照表）

> 对照同花顺 Windows PC 免费版（hexin），盘点 `thspypc` 的实现现状与缺口，
> 作为后续补全的优先级依据。本文档随实现进度更新。
>
> 最近能力盘点：2026-07-29。

## 口径说明

- **目标**：基本复刻**同花顺 PC 免费版**的核心行情功能，不是手机版、不是通达信。
- **大单/资金流口径**：PC 版分时图只有一条「大单金额」曲线（主力净额=主动买额−主动卖额），
  **不分**超大单/大单/中单/小单（那是手机版/通达信的口径）。因此个股层面的资金流
  在 PC 版复刻目标里**已达标**，无需按四档拆分。

---

## ✅ 已实现（核心行情 + 自选股）

| 模块 | 方法 | 完成度 | 备注 |
|------|------|--------|------|
| 登录（账密） | `connect` | ✅ 完整 | HTTP 三步鉴权 + 8901 login |
| 二维码扫码登录 | `connect_with_qrcode` | ✅ 完整 | 终端二维码 + 手机扫码 |
| 凭证缓存登录 | `connect_cached` | ✅ 完整 | 30 天免扫码，自适应失效 |
| 设备指纹 | `generate_imei` / `generate_mac64` | ✅ 完整 | 已逆向，无需抓包 |
| 个股列表行情 | `list_quotes` | ✅ 完整 | hd1.0/hd3.1 解码链 |
| 个股五档盘口 | `depth_quote` | ✅ API 已完成 | 买卖各五档 + 涨跌停封单额；不是 Level2 十档 |
| K线（日/周/月/5分/15分/30分/60分） | `kline` | ✅ 完整 | 连接复用 + 坏 IP 黑名单 |
| 当日分时（普通/L2） | `timeline` | ✅ 完整 | 普通 9354；L2 4214 |
| 历史分时（普通） | `history_timeline` | ✅ 完整 | MAIN 9355，基础价量额 241 点 |
| 早盘集合竞价 | `auction` | ✅ 完整 | 普通 current/history + L2 |
| 尾盘集合竞价 | `closing_auction` | ✅ 完整 | 普通 MAIN 9354/9355、L2 当日 4214 已验证；L2 历史 4417 沪深两市均端到端打通。沪市 3 秒/tick（≈61 点）、深市 9 秒/tick（≈20-21 点），同一 `build_l2_closing_auction_query` + 解析器无市场分支。深市需连 szlv2 节点（DNS `szlv2.123ths.com`）。早期"深市 ServerCost 拒绝"是探测脚本收帧 bug（误把短确认帧当结果），非协议差异。详见 HANDOFF §7.6。 |
| 完整日内序列 | `intraday` | ✅ 完整 | 早盘竞价 + 盘中 + 尾盘竞价 |
| 全市场代码表 | `stock_list` / `stock_list_cached` | ✅ 完整 | ~7400 条，自然日缓存 |
| 排行榜/涨跌幅榜 | `stock_list_hot` | ✅ 部分 | 按排序字段排，无成交量/成交额榜 |
| 全市场快照 | `market_snapshot` / `market_snapshot_with_quotes` | ✅ 完整 | 沪市 hfd1.0 + 全市场混合方案 |
| 自定义板块/自选股 CRUD | `list_groups`/`add_group`/`add_stock` 等 | ✅ 完整 | 门面委托 `BlockManager` |
| 问财动态选股 | `query_dynamic_plate` | ✅ 完整 | 选股表达式成分股查询 |
| 短线精灵（异动）历史 | `dxjl_latest` / `dxjl_history` | ✅ 完整 | 9601 qurealorder；普通账号基础 23 类，Level2 全选 53 类 |
| 短线精灵实时推送 | `subscribe_realtime` / `receive_pushes` | ✅ 完整 | 盘中 ~500-800 帧/分钟 |
| 个股逐 tick 推送 | `snapshot_subscribe` | ✅ 完整 | pageid=4214 实时快照 |
| 心跳保活 | 自动（`_start_heartbeat`） | ✅ 完整 | 8901 每 3s / 9601 每 30s |

> 普通账号冷启动抓包已验证 MAIN 登录及上述基础行情；Level2 专属字段仍按独立
> capability 路由，不因 MAIN 可用而开放。

### 分时附带的大单金额曲线（PC 版口径，已实现）

| 方法 | 大单字段 | 说明 |
|------|---------|------|
| `timeline`（当日） | dt227-dt230 | 主力净额曲线，对应 hexin 分时图「大单金额」第二条曲线（实测 000938 末根 −4.31 亿 vs app −4.32 亿） |
| `history_timeline`（历史） | dt201-230 | 26 个 level2 字段，含大单金额双线 |

---

## ⚠️ 部分实现

| 模块 | 方法 | 现状 | 缺什么 |
|------|------|------|--------|
| 历史分时（Level2） | `history_timeline` | ✅ 已接入沪深分服的 Level2 passport + 标准行情登录壳 + L2 init；0x0082 个股表固定 92 字节记录，241 点 × 23 字段（dt1/10/13/19/22/23/54/201-230）全部可解 | 无（2026-07-31 修复外层正规化长匹配 off-by-one 后，原「强状态省略型」结论撤销） |
| 排行榜 | `stock_list_hot` | 涨幅/涨速/换手/量比/主力净流入/竞价等排序榜 | 不支持成交量/成交额榜（这两个走别的协议） |

---

## ❌ 缺口（离"基本复刻 PC 版"还差的）

### 1. 系统板块（行业/概念板块）— 最大缺口

PC 版左侧导航的核心功能，当前 `blocks.py` 只覆盖**自定义**板块/自选股，**完全不含**系统板块。

> **2026-08-01 决策**：数据源**全程以抓包同花顺 Windows 客户端的数据形式为准**
> （8901 协议），**不用 `basic.10jqka.com.cn` 网页接口兜底**。本地
> `BlockUpdate/block_*.ini` + `industry.ini`（block_hq 缓存域）已完成逆向解析
> （`thspypc.features.system_blocks` / `SystemBlocksService`），作为**离线
> oracle**：校验抓包解析结果、提供稳定 ID 与名称/成分股真值，但查询路径
> 必须以抓包还原的 8901 协议落地。

| 子能力 | 状态 | 说明 |
|--------|------|------|
| 申万一/二/三级行业板块列表 | ❌ | 无 |
| 同花顺行业板块列表（881xxx 指数） | 🔄 协议已还原 | 本地 oracle 已有 881xxx→名称/成分股（~90 个）；8901 请求/响应已离线验证（0x130 表），活网通道验证待解（见下） |
| 概念板块列表（半导体/人工智能/新能源…） | 🔄 协议已还原 | 板块指数统一 market=48（885xxx 概念指数）；同一 0x130 请求形态 |
| 按板块查成分股 | 🔄 协议已还原 | 0x64 表已离线验证；`query_dynamic_plate("半导体")` 仍是问财实时选股，非系统板块语义 |
| 板块行情（指数/涨跌幅排行） | 🔄 已接线 | `client.board_quotes()`（0x130 板块行情：代码+GBK 名称+OHLC） |
| 板块指数分时（当日/历史） | 🔄 已接线 | `client.board_timeline()`（0x42 表，242 点/日，packed-date 游标） |
| 板块集合竞价 | 🔄 已接线 | `client.board_auction()`（0x32 表：unix 秒+撮合价+累计量） |
| 板块资金流 | ❌ | 无（依赖系统板块能力） |

> 抓包流程与样本要求见
> `docs/handoffs/HANDOFF_SYSTEM_BLOCKS_CAPTURE_20260801.md`；抓包脚本：
> `tests/capture_system_blocks.py`（板块发现/成分股/板块指数分时历史/盘中实时）。
> `blocks.py` 中无相关常量或代码，独立模块已开始落地。

#### 2026-08-01 第二轮：板块通道建连已落地（活网验证待解）

**专用板块通道 = fu4.123ths.com 市场组**（2026-08-01 抓包铁证）：板块行情/
分时/竞价/成分股必须走 fu4 服务器（``MarketCode=96;128;88;216;48;``、subreal
通道 URS/UCT/UNX/UCX/UME），**不能在 MAIN/ifindhq 连接上重放**——MAIN 上
原样重放引导帧服务器只回 CodeListSize=0。L2/普通账号 pcap 的板块通道 IP
（106.15.249.238 / 122.9.78.232）均属 ``fu4.123ths.com`` DNS 解析结果。

已落地：

- `LoginIdentity.BOARD`：板块通道 login 壳按账号 profile 分支——Level2 无
  UserName/Password（suffix=计算 check+09，抓包 ``aa 09``）；普通账号
  ``UserName=__manual``（``\r\n\n`` 分隔，suffix 固定 ``5e 07``）。
- `features/system_blocks_protocol.py` 引导 builders：subreal 注册（pageid
  L2=5716 / 普通=392，5/7 通道）→ pageid 注册 → MarketCode init →
  qureal-init×10（instid 0xE0000/0x290000 起、步长 0x20000）→ ``[5],[55]``
  分类表 → StockNameVer（L2 双子帧 / 普通 upstockname）。subreal、分类表、
  普通 StockNameVer 与抓包**逐字节一致**（离线回归 `tests/test_board_channel.py`）。
- `resolve_fu4_hosts()`：从 passport M_hqdns 解析 fu4 组 IP（与 MAIN/shlv2
  分组隔离）。
- `ConnectionRole.BOARD` + `ConnectionFactory` + `client._board_sock`：
  `_open_board_channel()` 完成 login（fu4 轮换 IP + 并发登录）→ 引导 →
  排空，`sync_service_connections` 收编；`disconnect()` 一并关闭。
- `BoardService` 改走 `ConnectionRole.BOARD`（不再用 MAIN）；
  THSClient 门面新增 `board_quotes` / `board_timeline` / `board_auction` /
  `board_constituents`。
- 活网验证脚本：`tests/verify_board_online.py`（四接口，`--env normal` 换账号）。

**活网验证待解（2026-08-01 晚间复核）**：冷却数小时、各种身份/时序/捆绑组合
均失败，fu4 侧会话拒绝已确认（帧内容逐字节核对无差异）：

- 双账号 MAIN 行情正常（如 `timeline("000938")` 仍 241 点）——账号未全局受限。
- fu4 login 各种身份均可 VerifyCode=0（L2 账号三种壳全 0；普通账号
  `__manual`/无用户名间歇 `PromptText=-6`、`thsuser` 通过——已为
  `_open_board_channel` 加 **BOARD→STANDARD→MANUAL 登录壳降级链**）。
- 但 login 后发送任意引导帧（subreal/pageid/MKT_INIT/qureal/[5],[55]/
  StockNameVer），服务器要么零响应、要么多帧突发时先回孤立 `\n` 再 FIN；
  抓包旧票据 + 原样帧 + 原时序的「完美重放」同样失败。
- 并发捆绑（main/shlv2/szlv2/fu4 四通道独立新票据同时登录，四者全
  VerifyCode=0）后 fu4 引导仍被 FIN（probe: `tests/_probe_board_bundle_fresh.py`）。

判定：fu4 侧对该账号/设备存在**会话级拒绝**（今日大量 fu4 login 探测触发，
与 HANDOFF 记载的 Passport64 复用保护同族；MAIN 通道不受影响）。需等待更
长冷却（建议隔天），或先在真实 hexin 客户端里重新打开板块页刷新会话状态
后重跑 `tests/verify_board_online.py`。协议侧已无未覆盖变量（登录壳、引导
帧、时序、会话捆绑均已逐项复刻）。

### 2. Level2 深度行情与逐笔数据

| 子能力 | 状态 | 说明 |
|--------|------|------|
| 五档买卖盘 | ✅ 已实现 | `depth_quote` 门面 + `build_depth_quote_query` / `parse_depth_quote_response` |
| 十档买卖盘 | ❌ | 当前已确认字段只覆盖买卖各五档，不能按“十档”宣称 |
| 逐笔成交/委托（Level2） | ❌ | L2 账号有权限，但未实现 |

> 五档盘口已经完成；后续十档、逐笔成交和逐笔委托需要重新抓取并确认独立
> DataType/pageid、权限失败表现及推送频率。

### 3. 资金流向（个股层面已达标，剩余历史/排名）

| 子能力 | 状态 | 说明 |
|--------|------|------|
| 个股大单金额分时（主力净额曲线，PC 口径） | ✅ 已实现 | `timeline`/`history_timeline` 的 dt227-230 |
| 个股资金流明细（超大/大/中/小单四档拆分） | — 不需要 | PC 版不分四档，本就不是复刻目标 |
| 个股资金流历史/排名 | ❌ | 缺 |
| 板块资金流 | ❌ | 依赖系统板块能力 |

### 4. 龙虎榜

| 子能力 | 状态 | 说明 |
|--------|------|------|
| 龙虎榜（lxhb/lhb） | ❌ | 无（注意：`dxjl_*` 是异动精灵，不是龙虎榜） |

### 5. F10 / 基本面

| 子能力 |状态 | 说明 |
|--------|------|------|
| 公司资料 / 股本结构 / 股东 | ❌ | 无 |
| 分红送配 | ❌ | 无 |
| 财务指标 / 财报 | ❌ | 无 |
| 公告 / 研报 / 限售解禁 | ❌ | 无 |

> F10 多走 HTTP 接口而非 8901 协议，与行情 TCP 协议栈相对独立。

### 6. 分时成交明细（逐笔成交回放）

| 子能力 | 状态 | 说明 |
|--------|------|------|
| 分时成交明细（成交回放/分笔） | ❌ | 当前分时是聚合后的逐点数据，非逐笔成交 |

---

## 📊 执行优先级

按"复刻同花顺常用功能"的性价比和重要性排序：

| 优先级 | 模块 | 理由 |
|--------|------|------|
| ✅ P-1 | **8901 请求串行化 + `MarketSession`** | 已完成第一阶段，防止业务查询与心跳串帧 |
| 🔴 P0 | **个股历史分时强状态 codec** | ✅ 已撤销：2026-07-31 确认是外层正规化移植 bug（长匹配 off-by-one），修复后 241 点 × 23 字段全解 |
| 🔴 P0 | **系统板块只读 MVP** | 🔄 抓包逆向中：板块发现/成分股/板块指数（历史+盘中实时）全程以客户端抓包为准；本地 block_hq 缓存作 oracle；不捆绑资金流 |
| 🟡 P1 | **系统板块行情/排名/资金流** | 建立在只读板块实体和成分股能力上 |
| 🟡 P1 | **个股资金流历史/排名** | 个股主力净额曲线已有，补历史/排名即完整 |
| 🟢 P2 | **龙虎榜** | 重要但非每日必用 |
| 🟢 P2-R&D | **十档/逐笔成交/委托（L2）** | 先做协议与权限调研，再承诺稳定 API |
| ⚪ P3 | **F10/基本面** | 独立 HTTP 服务域，不放进 8901 行情会话 |

### 最近执行顺序

1. 完成 8901 同步请求会话和并发保护（已完成）。
2. 用五档盘口作为第一条纵向切片验证门面/API/测试路径（已完成）。
3. 攻克个股历史分时强状态省略记录，移除随机变体重请求。
4. 系统板块只读 MVP：抓包客户端 → 逆向 8901 请求/响应 → 板块列表/成分股/板块指数
   （历史 + 盘中实时）；本地 block_hq 缓存作 oracle 校验。
5. 在板块实体之上增加行情、排名及资金流。

## 验收口径

功能状态按以下阶段推进，不能以单次活网成功直接标记“完整”：

`协议已识别 → 离线样本通过 → 公开 API 完成 → 多股票/多交易日活网验证 → 稳定`

新增路线图项目时至少记录：

- 数据来源（8901 / 4214 / 9601 / HTTP / 本地缓存）；
- 前置依赖和账号权限；
- 已保存的离线样本及对应测试；
- 公开 API 与无数据、超时、协议不支持的返回语义；
- 多市场、多股票、多交易日的验收范围。

---

## 维护说明

- 实现某项缺口后，把对应行从「缺口」移到「已实现」或更新「部分实现」。
- 优先级表可随实际情况调整，但保持"性价比 = 重要性 / 实现成本"的排序逻辑。
- 生成此表的代码盘点依据：`client.py`（全部 public 方法）、`blocks.py`（确认无系统板块能力）、
  `protocol.py`（build_*/parse_* 函数清单）。
