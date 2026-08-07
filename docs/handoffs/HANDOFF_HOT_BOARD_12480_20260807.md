# 热点板块（94 页面）pageid=12480 协议实现交接 2026-08-07

## 背景

2026-08-07 晚盘对同花顺 PC 客户端「94 热点板块」页面做了多轮双账号抓包
（列表/排序/分时/日K 全流程），逆向并**完整实现**了该页面的协议：
pageid=12480，与现有板块协议（392/5716）同通道同构，响应是标准 hd3.1 表。
**本轮已全部落地并通过活网验证**（普通账号），无遗留盘中项。

## 抓包文件清单（captures_live/）

| 文件 | 账号 | 说明 |
|---|---|---|
| `kanpan_20260807_224017.pcap` | **Level2** | 94 页面全流程（列表→成分股→分时→日K→竞价） |
| `kanpan_20260807_225319.pcap` | **普通** | 同上；含 0x0a 外层压缩响应 |
| `kanpan_20260807_231038.pcap` | **普通** | 表头排序操作（涨幅/1分钟涨速/主力金额/涨停数/涨家数/跌家数） |

## 协议结论

### 1. pageid=12480（双账号一致），复用板块通道

94 热点板块请求文本 ``CodeList=…\r\nDataType=…\r\nDateTime=…\r\nLackTime=…\r\npageid=12480``，
与板块列表（392/5716）**共用同一批 fu4 板块通道连接**，仅组件路由不同：

| 账号 | 板块路由 | 成分股路由 | 与板块列表关系 |
|---|---|---|---|
| 普通 | `0x003A`/`0x013A` | `0x003B`/`0x013B` | 与 392 旧路由 0x0039 相邻 |
| Level2 | `0x0053`/`0x0153` | `0x0054`/`0x0154` | 与 5716 路由 0x0052 相邻 |

route 是会话内动态组件实例号（同页面还见 0x0100/0x01FC/0x053A/0x00DE 等），
服务端按 pageid+DataType 路由，固定基础 route 即可。

### 2. 响应格式：标准 hd3.1（`hd\x93/hd\x84/hd\x89` 是 0x0a 压缩误报）

`capture_kanpan.py` 曾把 `hd\x93/hd\x84/hd\x89` 标为「新响应格式」，逐帧
验证后确认是**误报**：这些是 `cmd=0x0a` 8901 外层压缩帧里未压缩透传的明文
段，用 `normalize_8901_response()` 解压后即标准 ``hd3.1\x00`` 表。解析侧
零新工作。

### 3. 板块详情表 0x40/72B 字段（885927 CRO概念 实测锚定）

详情请求（`DataType=271,13,3252,48,19,3251,90,3250,39,10,275,38,6,45,66`）
的响应含 0x40/72B 表。885927 行与 94 页面 UI 逐项一致：

| dt | 解码值 | 94 页面 UI | 语义 |
|---|---|---|---|
| dt5 | `885927` | CRO概念 | 板块代码（16B） |
| dt6 / dt10 | 897.798 / 970.032 | 昨收 / 最新 | 昨收 / 最新 |
| 涨幅 | (970.032/897.798-1)=+8.05% | +8.05% | 客户端本地计算 |
| **dt15** | **8.0** | **涨停数 8** | 涨停数 |
| **dt38** | **73.0** | **涨家数 73** | 涨家数 |
| **dt39** | **3.0** | **跌家数 3** | 跌家数 |
| **dt48** | -0.003 | 4分钟涨速 -0.00% | 4分钟涨速 |
| dt55 | "CRO" | CRO概念 | 名称（分类表） |

注意：普通账号详情表 0x40 的字段比 0x38/64B 多 dt6/dt45（昨收+1 字段）；
L2 账号另见 0x118/215B 大表（dt180/179/178 等，本轮未接入，见下）。

### 4. 表头排序：SortType=Sort + SortBy=<列>，响应字段 = dt5 + dt<SortBy>

点击板块表头即发 `subtype=0x000f` Sort 请求：
```
CodeList=48(<全部板块>);\r\n
DataType=<SortBy>,\r\n
SortType=Sort\r\nSortBy=<SortBy>\r\nSortDir=D\r\nSortAppend=YC\r\n
SortBegin=0\r\nSortCount=26\r\nFuncPeriod=0\r\nDateTime=0(0-0)\r\n
LackTime=0,0,0,0,0,0,0,0\r\npageid=12480
```
响应为 `method=sort` + `indexname=<SortBy>:<语义名>;...` 文本 + hd3.1 表
（dt5 代码 + **dt<SortBy>** 排序字段值）。**SortBy 值即响应第二字段的 dt
编号**，实测映射：

| SortBy | 响应字段 | 语义名 | 94 页面列 |
|---|---|---|---|
| 199112 | dt200 | ZHANGDIEFU | 涨幅（默认排序） |
| 527527 | dt167 | onerise | 1分钟涨速 |
| 592890 | dt250 | bigtrademoneynow | 主力净流入 |
| 271 | dt15 | — | 涨停数 |
| 38 | dt38 | — | 涨家数 |
| 39 | dt39 | — | 跌家数 |
| 48 | dt48 | — | 4分钟涨速 |

排序响应自带每行该列数值：SortBy=199112 时 885927=8.05（涨幅%）、
SortBy=592890 时 885338=408.64亿（主力元）、SortBy=527527 时 885971=0.09
（1分钟涨速%）。

**关键结论**：主力净流入（dt250）与 1分钟涨速（dt167）**只出现在排序响应
里**（`dt<SortBy>` 列），不在 0x40 详情表——因此这两列必须走 sort 请求
获取，不能从详情表拿。

## 实现清单

- `src/thspypc/features/system_blocks_protocol.py`：
  - `PAGEID_BOARD_HOT=12480`、`HOT_BOARD_ROUTE_NORMAL/L2`（0x003A/0x0053）、
    `HOT_STOCK_ROUTE_NORMAL/L2`（0x003B/0x0054）
  - `HOT_BOARD_DATATYPE`（详情字段集）、`HOT_SORT_BY_*`（7 个排序列）
  - `HOT_DETAIL_*_DT`（dt15/dt38/dt39/dt48 语义）
  - `build_board_hot_query()`（复用 `build_board_query` + `route_base`）
  - `build_board_hot_sort_query()`（subtype=0x000f Sort 请求）
  - `parse_board_hot_detail_response()`（0x40/72B 表 → code/pre_close/price/
    chg_pct/limit_up/up_count/down_count/speed_4m）
  - `parse_board_hot_sort_response()`（method=sort + dt5 + dt<SortBy> →
    code/value）
- `src/thspypc/services/system_blocks.py`：`BoardService.hot_boards()`
  （详情，`codes=None` 时详情+527527 全量合并）、`hot_boards_sorted()`
- `src/thspypc/_client/service_facade.py`：`hot_boards()` / `hot_boards_sorted()`
  门面
- `tests/test_system_blocks_protocol.py`：6 项离线回归（普通/L2 路由族、
  参数透传、Sort 请求形态、0x40 表 885927 锚点、sort 响应 dt<SortBy>）
- `tests/capture_kanpan.py`：`KNOWN_PAGEIDS` 加 12480
- `tests/verify_hot_board_online.py`：活网冒烟（详情 + 三列排序）
- fixtures：`tests/fixtures/board/hot_detail_resp_0x40_949.bin`、
  `hot_sort_resp_271_1348.bin`

## 活网验证（2026-08-08，双账号交叉验证）

验证脚本 `tests/verify_hot_board_online.py --env .env|.env.normal`：

- **Level2 账号**（`.env` mx_722141944，`_is_level2()`=True → 0x0053 路由）：
  `hot_boards` 详情 0x40 表字段齐全（涨停/涨家/跌家/4分钟涨速），
  三列排序（涨幅/主力/涨停数）返回正常 ✅
- **普通账号**（`.env.normal` mx_6euk93lwi → 0x003A 路由）：结果与
  Level2 **逐项一致** ✅
- 885927 CRO概念 双账号均：chg=+8.05%、涨停=8、涨家=73、跌家=3、
  4分钟涨速=-0.003 —— 与 94 页面 UI 一致 ✅

**重要结论**：Level2 账号的板块详情请求（0x0053 路由 + DataType=271,...）
服务端同样返回 0x40/72B 表（与普通账号一致）。0x118/215B 大表只出现在
**成分股行情**请求（DataType=7,14,157,...，板块个股列表），不是板块列表
请求的响应——交接文档遗留项据此修正。

## 遗留项（下轮，非阻塞）

1. **板块个股列表**（94 页面点板块后的成分股）走 `HOT_STOCK_ROUTE`
   （0x003B/0x013B、0x0054/0x0154），CodeList 用股票市场码 17/22/33/151；
   已确认请求形态存在，未单独封装 `hot_constituents`。Level2 成分股行情
   响应为 0x118/215B 大表（dt180/179/178 等增强字段）。
2. 竞价涨幅（开盘价/昨收 间接计算）与封单额、竞价金额（已实现表头同款
   间接计算）无需协议改动，客户端本地计算。
