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
6. 更新 `FEATURE_GAP_ROADMAP.md`。

## 待办

- [ ] 用户抓包：系统板块四段流程（A-D）
- [ ] 用户抓包：000938 06-30/07-23 历史分时（+可选 600519）
- [ ] 逆向：板块发现请求（列表 pageid、板块指数代码域）
- [ ] 逆向：成分股查询（页式/SortBegin 绑定）
- [ ] 逆向：板块指数分时/历史与股票分时是否同一请求形态（881xxx 当代码发）
- [ ] 逆向：盘中实时（4214 订阅 vs 列表轮询）
- [ ] dt54 哨兵规律确认并写死测试
