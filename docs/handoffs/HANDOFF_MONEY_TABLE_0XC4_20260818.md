# HANDOFF: 0xc4 金额表逆向（主力净额/DDE/总市值直查）+ web 左栏交互对齐同花顺

日期：2026-08-18（盘后）
状态：已完成并活网验证，已接入 `/api/quotes_ext` 与 web 左栏
语料：`captures_live/stocklist_page_20260818_185944.pcapng`（同花顺客户端 A股列表页抓包）

## 1. 背景与结论

同花顺客户端在 A股列表页（pageid=1334）对**显式代码子集**发送含
`592890/592888` 等扩展 DataType 的请求，服务器返回 hd3.1 变体 **0xc4
"金额表"**——一张 30 字段的完整行情行（价格类 + 主力净额 dt250 + DDE 主力
dt248 + 总市值 dt202 等）。本次完成全链路逆向：

- **请求格式**：`CodeList=<market>(code,code,…)`（按市场分组）+ 抓包原文
  29 个 DataType + `DateTime=0(0-0)` + `LackTime=0,…` + `pageid=1334`
  （`MONEY_QUOTE_DATATYPE`，features/quote_protocol.py）
- **编码**（codecs/hd.py）：
  - 大批量（≥3 行）：hd3.1 魔数，dc 高 8 位=0x01 标志，字段表后
    **64 字节前导 + 标准 BitRLE 流**（BE32 明文长度在前导末尾）
  - 小批量（2 行）：hd1.0 魔数但同 dc 标志，**60 字节前导 + 未压缩明文
    记录**；末行末字节偶发缺失（与十档盘口同型怪癖，解码器补零）
- **字段表真实布局**：4 字节项 = `byte0=dt, byte1=fmt, byte3=width`
  （此前 LE16 读法在标准字段上恰好同样成立）
- **fmt 0x79/0x7B = 与 0x70 相同的 THS 定点浮点**（bit31 除法位 + 3 位
  指数 + 符号位 + 27 位尾数）

## 2. 已活网验证的字段语义

| 字段 | fmt | 含义 | 验证方式 |
|---|---|---|---|
| dt250 | 0x7B | 主力净额（元） | 量级与 dt248 交叉一致；负值=净流出 |
| dt248 | 0x7B | DDE 主力（亿） | 与 `/api/dde_rank`（592888）逐码一致：600601/688693/000001/002953/300561 全对 |
| dt202 | 0x79 | 总市值（元） | 茅台 1.62 万亿、农行 9293 亿、平安 2144 亿——真实量级全对 |
| dt13×dt10 | 0x70 | 成交额（表内无 dt19） | 与 1335 基础表 dt19 口径一致 |
| dt5/dt7/dt10/dt17/dt48/dt66/dt6… | 0x70/0x20 | 与既有列表含义相同 | 688077 等样本与基础表一致 |
| dt200×2、dt126、dt131、dt87 | 0x79/0x7B | 未完全定位（疑似流通市值/换手类） | 待需要时对照 |

两个 dt200 重复字段：解析器输出 `dt200` / `dt200#2`（第二个起加后缀）。

## 3. 边界行为（实测）

- **单代码请求服务器不应答**（超时）：facade 凑批时加填充码
  （`money_filler`，结果按请求 codes 过滤，填充码不外泄）
- **已退市代码被服务器省略**（600068 葛洲坝）：按缺失处理
- **北交所 920xxx 可用**（920087 主力 +1.9 亿实测）
- 尝试在 DataType 里追加 265260(封单)/19(成交额) 服务器接受但**表格结构
  改变导致错位**——不扩展；封单额仍走排序榜 sort_by=265260（dt44）
- 性能：40 码 0.02s；web 可视窗口（~33 码）跨 3 市场基础+资金两路 0.17s

## 4. 接入链路

- `stock_quote_fields`（facade）：每批两路请求（1335 基础表 + 1334 金额表）
  合并；资金路失败仅告警不影响基础列
- `derive_list_quote_fields`：新增 `main_inflow/dde_main/market_cap` 透传，
  `amount` 增加 dt13×dt10 回退
- `/api/quotes_ext` 响应行新增三个字段；web 左栏主力净额列全面切到
  dt250 真值，主力排行 DDE 值亿→元归一显示

## 5. 同日其他协议发现/修复

1. **`sort_by=592890` 排序响应今日回 dt44（封单额）值**而非 dt250——
   服务端行为变化（排序序仍像主力）。前端不再采信该排序值，主力列改
   0xc4 直查。`sort_by=265260` 的 dt44 正常。
2. **`sort_dir=A`（升序）首次活网实测可用**（此前文档标注"推测，未实测"）。
3. **list_quotes MAIN 僵死自愈**：收盘后长时间空闲的 MAIN 连接 TCP 探活
   "活着"但服务端不再应答（流不同步），原实现吞掉 ProtocolError 返回空、
   永不恢复。现在空结果/OSError 时 `connect_main()` 全新鉴权重连后重试
   一次（>20s 必走新 Passport，符合 AGENTS.md 登录规则）。
4. **dde_rank 加一次重试**：页面刷新时 ranked 全量 + quotes_ext 资金请求
   与 dde_rank 在同一对 L2 连接上并发竞争偶发超时，重试即恢复。

## 6. web 左栏交互（对齐同花顺客户端）

- 滚轮虚拟滚动全量列表（全市场 5300+ 行一次拉全，L2 SortCount 放大
  单请求 ~0.1s；DOM 只渲染可视窗口 ±8 行）
- 可视窗口代码增量请求 quotes_ext（对齐客户端"显式代码子集批量刷新"）
- 表头点击排序：全市场=服务端排序键（含升/降序切换），其余面板=本地
  排序（空值恒排末尾）；成交额列无服务端键不可点
- 列宽拖拽（表头右缘把手，localStorage 持久化）
- 面板宽度拖拽（左栏↔中栏、左栏内部两列两条分隔条）+ 变窄自动隐藏
  尾列（代码/名称恒显）；全部持久化（ths.layout.leftW / ths.layout.col1 /
  ths.cols.stock / ths.cols.board）

## 7. 相关文件

- 编解码：`src/thspypc/codecs/hd.py`（c4 分支 + fmt 0x79/0x7B + 重复 dt）
- 协议：`src/thspypc/features/quote_protocol.py`（MONEY_QUOTE_DATATYPE、derive）
- facade：`src/thspypc/_client/service_facade.py`（双路合并、自愈、dde 重试）
- 单测：`tests/test_hd_c4_codec.py`（两张捕获帧 fixture 内嵌 base64）
- 诊断脚本（可复跑）：`tests/analyze_hd3_variants.py`（变体扫描）、
  `tests/diag_money_fields_live.py`（活网直查）、
  `tests/crack_c4_floats.py`（raw↔真值对照）、
  `tests/verify_c4_and_extract_request.py`（DDE 交叉验证+请求提取）

## 8. 遗留

- dt200×2/dt126/dt131 语义未定位（可从板块/个股横向对照入手）
- 封单额列只在"封单"排序时由排序榜填值（与客户端行为一致）
- 0xc4 请求在非 L2 账号（MAIN 通道）的行为未验证
