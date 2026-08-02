# 系统板块 P0：抓包驱动逆向交接（2026-08-01）

## 结论与决策

- **不用 `basic.10jqka.com.cn` 网页接口兜底**。系统板块只读 MVP（板块发现、
  稳定 ID、成分股）与板块指数（历史 + 盘中实时）**全程以抓包同花顺 Windows
  客户端（hexin.exe）的 8901 数据形式为准**。
- 本机 hexin 安装：`D:\同花顺软件\同花顺`；抓包工具：
  `D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark`。

## 已落地的本地 block_hq 缓存 oracle

`src/thspypc/features/system_blocks.py` + `src/thspypc/services/system_blocks.py`
已完成本地缓存逆向解析（离线、无网络），用途是**校验抓包结果 / 提供稳定 ID 与
名称/成分股真值**，不是查询路径：

| 文件 | 内容 | 实测规模（2026-07-29 缓存） |
|------|------|------|
| `BlockUpdate/block_2B.ini` | 概念板块：十六进制 block_id→名称 + 成分股（`17:688981,-105:920045` 格式，基金类另有 `1(36):184*` 前缀通配） | ~390 个概念 |
| `industry.ini` | 同花顺行业：`881xxx` 板块指数代码→名称 + 成分股（无市场码，按代码前缀推断 17/33/-105） | ~90 个行业 |
| `BlockUpdate/block_tree.ini` | 板块树：根 `[@10001]` → 分类根（`2B`=概念、`47`=地域、`7`=港股…）→ 分组/叶子；叶子标记 `536871426/536871427` | 根 30+ 分类 |
| `BlockUpdate/block_47.ini` 等 | 地域/港股/基金/指标股等分类 | — |

公开门面（`THSClient`）：

- `client.system_blocks`（`SystemBlocksService`）
- `client.system_block_categories()`
- `client.list_system_blocks(category=None)`
- `client.get_system_block_constituents(block_id)`（如 `881121` / `C024`）

稳定 ID 约定：行业 `881xxx`（与 `q.10jqka.com.cn/thshy/detail/code/881xxx/`
同源）；概念/地域等为十六进制 block_id（如 `C024`=BC电池）。**概念板块在
8901 中的实际代码（885xxx？301xxx？）待抓包确认**。

## 抓包脚本与流程

### 1. 系统板块四段流程（P0 主攻）

`tests/capture_system_blocks.py`（默认 240s，`--analyze-only` 可离线分析已有 pcap）：

| 阶段 | 客户端操作 | 目标抓取 |
|------|-----------|---------|
| A 板块发现 | 左侧导航【板块】→ 行业/概念列表，滚动 | 板块指数列表请求（pageid/代码域） |
| B 成分股 | 点进【半导体】→ 成分股列表，滚动；再点 1-2 个概念板块 | 成分股查询请求（分页/SortBegin？） |
| C 板块指数 | 半导体 881121 分时图 → 按 ← 翻 2026-07-23 / 2026-06-30 | 板块指数分时/历史（DateTime=8192 日期区间） |
| D 盘中实时 | 回板块列表停 60s | 实时刷新（订阅 4214？/轮询？） |

分析输出：pageid 分布、含板块代码（881/885/301-309 前缀）的请求明细、
响应解码（列表/分时/K线复用现有 parser）、按 代码×pageid dump 原始响应帧到
`captures_live/system_blocks_<code>_<pageid>_<ts>.bin`。

### 2. 历史分时两日补抓（小尾巴）

`tests/capture_history_timeline_dates.py`（默认 180s）：000938 分时图按 ← 翻到
2026-07-23 与 2026-06-30；分析按 `DateTime=8192(bar_start-bar_end)` 还原日期，
解码 241 点并 dump `captures_live/history_000938_20260630_<ts>.bin` /
`history_000938_20260723_<ts>.bin`。样本放入 captures_live 后，
`test_history_timeline_response.py::test_captured_history_dump_dates_four_day_regression`
自动纳入四日期离线回归。

### 3. dt54 哨兵字段

当前实现：`0xFFFFFFFF` 哨兵 → `decode_ths_float` 映射 0.0（`codecs/numeric.py`）。
抓包脚本会对每个 241 点响应做**原始 u32 扫描**（按 bar_index 定位行首，读
字段表 dt54 列），打印 `raw_u32=0xFFFFFFFF decoded=0.0` 的对应关系，用于确认
哨兵出现规律（哪些点位/哪类股票为哨兵，是否恒为 0xFFFFFFFF）。

## 逆向还原后的落地路径（对齐 ARCHITECTURE 纵向切片）

1. 保存并标注最小请求/响应样本（本轮 dump）；
2. `features/system_blocks_protocol.py`：纯函数 builder/parser（8901，不碰
   `basic.10jqka.com.cn`）；
3. 离线回归：dump 样本 + 本地 oracle 双校验（成分股逐条、板块指数逐点）；
4. `services/` 接入 `THSClient` 门面；明确无数据/超时/权限语义；
5. 多板块、多市场、历史+实时活网验证；
6. 更新 `docs/plans/FEATURE_GAP_ROADMAP.md`。

## 待办

- [x] 用户抓包：000938 06-30/07-23 历史分时（普通 9355 + L2 4417 双通道）
- [x] 四日期离线回归：05-13/05-14（旧样本）+ 06-30/07-23（新 L2 样本，241 点）
- [x] dt54 哨兵确认：L2 0x0082 真实数据该列全为 0xFFFFFFFF，`decode_ths_float`
      映射 0.0 正确（首末行原始 u32 已打印验证）
- [ ] 用户抓包：系统板块四段流程（A-D）
- [ ] 逆向：板块发现请求（列表 pageid、板块指数代码域）
- [ ] 逆向：成分股查询（页式/SortBegin 绑定）
- [ ] 逆向：板块指数分时/历史与股票分时是否同一请求形态（881xxx 当代码发；
      已见 9354/9355 带 881xxx/885xxx/886xxx 代码列表的请求样本）
- [ ] 逆向：盘中实时（4214 订阅 vs 列表轮询）

## 2026-08-01 第二轮：板块协议已逆向（双账号抓包）

板块指数统一 **market=48**；账号只影响 pageid（Level2: 5716/1341/6000/6002；
普通: 392/4180/4181）。请求形态为双子帧（前缀 CodeList+pageid + 查询
DataType/DateTime/LackTime/pageid），历史分时用 packed-date 游标。

响应表型（hd3.1 + BitRLE 位面，已离线解码验证）：

| 表型 | 行宽 | 字段 | 内容 |
|------|------|------|------|
| 0x130 | 344B | dt5(16B 代码)、dt55(20B GBK 名称)、dt6/7/8/9/10/13/19…（dt5/dt6 出现两次，取首次） | 板块行情列表 |
| 0x64 | 95B | dt5(7B 代码)、dt215…dt66 21 字段 | 板块成分股行情 |
| 0x42 | 28B | dt1/10/13/19/22/23/40 | 板块指数分时（242 点/日） |
| 0x32 | 12B | dt1(unix 秒)/10/49 | 板块集合竞价 |

已落地：

- `src/thspypc/features/system_blocks_protocol.py`：builders（列表/分时/竞价/
  成分股，双 pageid 家族）+ parsers（0x130/0x64/0x42/0x32）。
- `src/thspypc/services/system_blocks.py`：`BoardService`（待板块通道接线）。
- `tests/test_system_blocks_protocol.py`：9 项离线回归（样本
  `captures_live/_board_*.bin` + `_board_req_*.bin`）。
- 双账号抓包原始样本已存 `captures_live/system_blocks_20260801_*.pcap`。

**活网接线遗留**：板块查询必须在**专用板块通道**（独立 8901 连接）上执行，
引导序列为 subreal 注册（URS/UCT/UNX/UCX/UME）+ ``MarketCode=96;128;88;216;48;``
（含 MarketDate/StockLinkVer）+ ``DataType=[5],[55]`` 分类表 + StockNameVer。
实测在 MAIN 连接上重放抓包原样请求，服务器只回 CodeListSize=0/无数据。
下一步：为 BoardService 实现板块通道建连（复用 8901 login），接线后做活网
验证（板块行情/分时/竞价/成分股四接口）。

## 2026-08-01 附加结论（历史分时协议修正）

0. **双账号活网验证通过**（`tests/verify_accounts_241_auction.py`）：
   L2 账号（.env）与普通账号（.env.normal）对 2026-06-30/07-23 均正确下发
   **历史分时 241 点**（bar 132627038/132575838，packed-date 与抓包一致）+ 早盘
   竞价（07-23: 68 tick 09:15:00-09:24:57；06-30: 65 tick）+ 尾盘竞价（07-23:
   21 tick 14:57:00-15:00:00；06-30: 19 tick），两账号逐值一致。

1. **DateTime 游标编码修正**：历史分时（L2 4417 与普通 9355）的
   `DateTime=8192(bar_start-bar_end)` 使用 **packed-date 编码**
   `(year-1900)<<9 | month<<5 | day) × 2048 + 606`。旧 ordinal 公式
   只在 05-13/14、07-24 等日期巧合一致；07-23 实测
   `132627038 = packed(07-23)`（ordinal 会误标 07-26）。铁证：4417 响应
   241 行数据与普通通道逐值一致（07-23: dt10 45.57→42.45、06-30: 26.0→28.86）。
   `build_history_timeline_query` 已改为内部调用 `date_to_normal_timeline_bar`；
   `date_to_timeline_bar`（ordinal）仅保留给竞价 4417 上下文预热兼容。
   竞价预热同批修正为 `packed(trade_date)`（07-24 与旧值巧合相同，钉死测试不变）。
2. **9355 稀疏响应 = 分时窗口未放大的请求模式（route 0x7A）**：客户端分时
   窗口较小时走 ``0x7A`` 路由，服务端只下发部分分钟（实测 07-23 201/241、
   06-30 185/241，行乱序分段、多张 0x42 表）；**窗口放大后走 ``0x6C`` 路由，
   服务端回全量 241 点**（2026-08-01 12:03 普通账号放大窗口抓包证实，两次
   请求文本完全一致、仅子帧路由不同）。L2（4417）历史分时恒为全量 241 点。
   缺失分钟在 L2 全量数据中都有真实值（价格在变化），是降采样下发，不是
   客户端缺分钟。解析器已支持 0x7A 稀疏格式（多表合并 + 乱序锚定，
   `_history_timeline_row_anchors` 全块搜索、合并去重、普通表阈值 120 行）；
   `build_normal_history_timeline_query` 走 0x6C 全量，无需改动。
3. **L2 4417 历史分时响应完整 241 点**，且响应体含两张表：0x007E（基准
   399002/1A0002，22 字段无 dt54）+ 0x0082（目标股，23 字段含 dt54）。
   样本：`captures_live/history_000938_20260630_115059.bin`（33,164B）、
   `history_000938_20260723_115059.bin`（43,888B）；普通账号全量样本：
   `history_000938_20260630_120342.bin`（4,960B）、
   `history_000938_20260723_120342.bin`（5,830B）。均已纳入四日期回归。

> 抓包注意事项（已写进 `capture_history_timeline_dates.py` 用法）：
> **先把分时窗口放大/最大化**再抓包，否则走 0x7A 稀疏模式只有部分分钟。

## 2026-08-02 补充：板块列表请求形态漂移（08-01 跨机抓包实证）

### 现象与修复

`system_blocks_protocol.py` 里板块列表行情请求此前用的形态在 **2026-08-01
另一台电脑的抓包**中即可找到（用户提供的 `system_blocks_20260801_132439.pcap`）：
`system_blocks_20260801_132439.pcap` stream 2 帧 f1413（t≈4.72s）重组后与
`captures_live/_board_req_list_392.bin` **逐字节一致**。2026-08-02 起服务端
对该形态**静默不回复**（跨机重放 0x0139 请求实测无数据）。对照
08-02 真实客户端请求帧（`tests/fixtures/board/list_req_392.bin`，逐字节
一致），列表查询路由已改变：

| 字段 | 08-01 跨机抓包真值 | 08-02 抓包真值 |
|---|---|---|
| 普通账号（392）前缀/查询路由 | 0x0039 / 0x0139 | 0x006C / 0x016C |
| L2（5716）前缀/查询路由 | 0x0052 / 0x0152 | 同左 |
| 查询子帧字节 17（history flag） | 0x00（同路由另有 0x20 变体） | 0x00 |
| LackTime | 0,0,0,0,0,0,0,0 | 0,0,0,0,0,0,0,0 |
| 列表请求 seq | 0x00B4（普通）/ 0x0069（L2） | 0x01C4（普通）/ 0x0068（L2） |
| 查询子帧文本 | 3691B（513 码全量 universe） | 3691B（完全相同） |
| 前缀可见码数 | 36 | 51 |
| 列表请求的直接响应 | 0x20/0x1c/0x22 紧凑表 | 0x20/0x1c/0x22 紧凑表（513 行，无名称列） |

> 字节级证据（2026-08-02 复核跨机 pcap）：
> - `_board_req_list_392.bin`（4016B）与 `system_blocks_20260801_132439.pcap`
>   中 0x0139 请求帧重组后逐字节一致：前缀 route=0x0039（
>   `CodeList=48(36 码); pageid=392`）、查询 route=0x0139、seq=0x00B4、
>   字节 17=0x00；查询文本 `DataType=48,592890,10,6,66`、LackTime 全 0。
> - L2 版：`system_blocks_20260801_132302.pcap` 帧 f1780，route 0x0052/0x0152、
>   seq=0x0069，与 `_board_req_list_5716.bin` 一致。
> - `0x130` 是 hd3.1 **响应表 flag**（344B/行、72 字段），不是请求 opcode。
>   它在 08-01 抓包中确实被服务端周期推送，但不是 f1413/pageid=392 列表请求的
>   直接响应；`_board_quote_0x130.bin` 可解出 17 行（881101 种植业与林业 …
>   881124 消费电子）。

### 0x130 的实际触发链（2026-08-02 复核）

逐帧把 0x130 中的代码集合与前序请求对齐后，触发点是**打开板块详情页后的相关
行业/概念板块批量行情**：

1. f1413（t=4.723s）是 pageid=392 的旧列表请求；f1477（t=4.816s）立即返回
   0x20/0x1c 紧凑表，此时没有 0x130。
2. t=15.046s 打开板块 `886068` 详情页（pageid=4180）；t=15.260s 发出
   route=0x0048/0x0148、`DataType=19,10,66` 的 29 码相关板块查询。
3. t=16.329s 起出现可解码的 0x130 周期推送；首批 30 行恰好等于上述 29 码
   加当前板块 `886068`。
4. t=22.576s 切到 `886090`（pageid=4181）后，客户端分别查询 18 个行业板块
   （`DataType=592890`）和 18 个概念板块（`DataType=19,10,66`）；随后两类
   0x130 均返回 19 行，即“18 个相关板块 + 当前板块 `886090`”。

因此，旧抓包中的 0x130 应归因于板块详情页的相关板块组件及其周期刷新，而不是
pageid=392 全量板块列表请求。抓包初始化还携带非零 `StockLinkVer`（20260731）
和 `StockNameVer name_88_*`，证明**无需删除本地 `BlockUpdate/*.ini` 或
`industry.ini` 才能触发 0x130**；删除缓存只会引入配置重下载这一额外变量。

已修复：`build_board_list_query` 逐字节对齐 08-02 抓包（新增
`universe_codes`：前缀=可见页、查询=完整 513 码 universe）；`board_quotes`
显式传码路径改用 `parse_board_full_quote_response` 解析紧凑表。回归样本：
`tests/fixtures/board/list_req_392.bin`（真实客户端请求帧，逐字节一致）。
查询文本与 08-01 旧形态完全相同，差异仅在路由/seq/前缀可见码数。

### 结论与证据边界

- 08-01 跨机抓包证明 0x0039/0x0139 列表形态当时被正常受理并返回紧凑表；
  0x130 则由稍后的板块详情相关板块查询触发，两条因果链不能合并。
- 08-02 抓包观察到客户端改发 0x006C/0x016C，且旧 0x0139 跨机重放无数据。
  这足以确认**发送侧应迁移到新路由**，但仅凭现有一份 08-01 原始 pcap 和
  08-02 请求 fixture，尚不能完全排除服务端下发配置、页面组件状态或客户端
  配置差异；“纯服务端协议变化、与客户端无关”不应写成已闭环事实。
- 旧解析器 `parse_board_quote_response`（0x130 名称表）保留作兼容；发送侧
  统一走 08-02 形态。

### 分时 / 历史日K / 竞价（08-01 中午实现）08-02 离线复核

用 2026-08-02 本机抓包样本对 8 月 1 日中午写好的三个解析器做了离线对拍：

| 功能 | 响应解析 | 08-02 请求形态（本机客户端真值） |
|---|---|---|
| 集合竞价 0x32 | ✅ 正确：21 tick（09:15:15→09:25），dt10/dt49 正常 | pageid=6000，route 0x01FC，h17=0x1C，LackTime 全 0，单查询子帧（旧实现：6002/4181、route 0x0112、h17=0x20、LackTime=0,3、双子帧） |
| 历史日K 16384 | ✅ 正确：0x42 日K 表（字段 [1,7,8,9,11,19,13]，dt1=YYYYMMDD，596 根 2024-02-19→2026-07-31）经 `parse_kline_hd3_response` 解码 | pageid=6002/6000，route 0x0160/0x0100，h17=0x00/0x40，LackTime=0,3/0,0，文本含 `ReqFuquan=Q`；**目前没有独立 board K builder（仅 `KLINE_DAY_PERIOD` 常量）** |
| 板块分时 0x42 | ⚠️ 08-02 抓包中**没有**分时字段集 [1,10,13,19,22,23,40] 的 0x42 表（0x42 全被日K 占用），无法离线复核 242 点；已给解析器加字段集守卫，避免把日K 表误当分时 | pageid=6000/5716 图表上下文，route 0x017D/0x015A，h17=0x00，DataType=272,271,…（与旧实现 6002/4181、[13,19,40,10,23,22,6] 不同） |

结论：解析器层面竞价/日K 与 08-02 服务端数据兼容；但**分时/日K/竞价的
请求字节与 08-02 本机客户端形态同样存在漂移**（同类问题），是否已不兼容
取决于 08-01 那台电脑的版本——按上文“待办”先跨机验证，再决定是否把三个
builder 也按 08-02 形态改写。
