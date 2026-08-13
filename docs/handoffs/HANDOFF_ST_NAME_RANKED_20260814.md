# 股票名称源补全 / ST 市场码 / 全市场排序榜修复（2026-08-14）

> 本次会话把 Level2 账号下「深市/ST 名称缺失」「排序榜缺深市」「竞价额/封单额切换慢」
> 三组问题一次收口。核心是纠正两个长期错误假设：ST 走独立服务器、排序榜要拆沪深。

## 核心结论

| 问题 | 根因 | 修复 |
|---|---|---|
| 沪市 ST 股（600525 等）行情/名称异常 | ST 不是独立服务器，是**市场码 22**（沪风险警示板）；深市 ST 无独立码，仍 33 | `st_market()` 仅 17→22；`_market_for_code` 按名称前缀判 ST |
| Level2 深市/沪深名称只下了 3/8 组 | 8 个名称组此前全用 STANDARD 登录身份，shlv2/szlv2/fu4/fu2/usotc 登录失败 | 每组按域名用正确 LoginIdentity（main/shlv2→standard，szlv2→manual，其余→l2） |
| 全市场代码表缺深市（00/30x） | Level2 的深市代码表在 szlv2（market 32/33），MAIN 全量表只回沪系 | `full_list` 在 SZ_L2 上再取一次 `CodeList=32();33();` 并合并；沪 ST 表另查 market 22 |
| 竞价额/封单额榜只有沪市 | 排序查询漏了 market 33 | `ranked()` 改为 MAIN 单请求 `CodeList=17();22();33();151();` |
| 涨幅榜显示超大百分比（+884720000.00%） | 排序响应百分比字段存 ×1e8（涨幅% = dt200 / 1e8） | 前端 RankPanel 对 pct 类字段 ÷1e8 |
| 切换排序键 ~1.2s | `useData` 的 delayMs 在每次 deps 变化都重新延迟 | 延迟只首次挂载生效 |

## 1. ST 市场码（活网验证）

沪市 ST → market **22**（独立风险警示板）；深市 ST → **33**（无独立市场）。
不是换服务器，同一 shlv2/main:8901，改 `CodeList=22(code)`。

- 600525 ST长园 → 22，dt10=5.05 ✅
- 600745 *ST闻泰 → 22，dt10=17.43 ✅
- 002759 ST天际 → 33，dt10=19.48 ✅

`src/thspypc/features/stock_name_protocol.py` 的 `is_st_name()` / `st_market()`；
`client._market_for_code()` 里 `base = 17 if code.startswith('6') else 33`，ST 沪再 `st_market(17)=22`。

## 2. Level2 名称下载的登录身份

`download_all_stock_names` 按组登录时，各域名身份不同（抓包字节级确认）：

| 域名 | 登录身份 |
|---|---|
| main / shlv2 | standard（thsuser/thsuser） |
| szlv2 | manual（__manual/__manual） |
| fu4 / hkus / ifindhq / fu2 / usotc | l2（7 字段壳，无 UserName/Password） |

映射在 `stock_name_bootstrap.NAME_GROUP_LOGIN_IDENTITY`，下载函数签名改成
`login_body_factory(group_key)`。修复后名称 34796 → 119985，沪深全齐。

## 3. 全量代码表的深市 / 沪 ST 补全

MAIN 的 `DataType=[5],[55]` 全量表对 Level2 只回沪系市场（16/17/19/20/144-151），
26356 行、0 个 00/30x。深市表要：

- SZ_L2（szlv2）上发 `CodeList=32();33();` → 单帧 3274 行，覆盖全部深市 A 股；
- 沪 ST 表在 MAIN 上另查 `CodeList=22();` → 84 只沪 ST。

见 `stock_list.full_list()` 的三段合并（MAIN 常规 + MAIN 22 + SZ_L2 32/33），
`FULL_STOCK_LIST_SZ_MARKETS` / `FULL_STOCK_LIST_ST_MARKETS` 常量。
结果 26356 → 29714 行。

## 4. 排序榜：MAIN 单请求即可全市场

2026-08-14 抓包 `seal_sort_20260814_012844.pcap` 确认真实客户端拆沪深两个服务器发：

- 沪 `8.134.98.163:8901`：`CodeList=17();22();151();` + SortBy + SortCount=29；
- 深 `122.9.205.228:8901`：`CodeList=33();` + SortBy + SortCount=29。

但活网验证 MAIN **单请求** `CodeList=17();22();33();151();` 即返回沪深京全市场
（SortTotal=5217，服务端全局排序，top 300862/601991/000887 交错正确，深市涨停数与
单查 SZ_L2 一致）。故 `ranked()` 收敛为单请求，不拆沪深、不本地合并，比拆分流更快
（~155ms，4 次翻页 vs 拆分的 8 次串行 + SZ_L2 偶发重新鉴权）。

SortCount 用 59（客户端用 29，但我们 count=200 时 59/页翻页更少）。

## 5. 排序值缩放（前端显示）

排序响应的 dt 字段：

- 涨幅 dt200 = 涨幅% × 1e8（比值实测 10^8，精确）；涨速 dt48 同 ×1e8 处理（盘中待核）；
- 竞价金额 dt150 / 封单额 dt44 / 主力 dt250 = 原始元，不缩放。

前端 RankPanel 对 pct 类 ÷1e8；金额类走 fmtAmt。公共 `fmtPct` 不能动（HotBoardsPanel 传的是已缩放小数）。

## 6. 前端 useData 延迟

`delayMs` 原在每次 deps 变化都重新延迟，切排序键白等 1s。改为 `firstRunRef` 只在
首次挂载延迟，之后立即发请求。

## 关键文件

- src/thspypc/features/stock_name_protocol.py / stock_name_bootstrap.py
- src/thspypc/services/stock_name.py / stock_list.py
- src/thspypc/_client/service_facade.py
- src/thspypc/client.py / server/app.py
- web/src/components/left/RankPanel.tsx / web/src/data/useData.ts

## 诊断脚本（tests/，保留）

- probe_sz_full_list.py / probe_main_st_board.py：深市/沪 ST 代码表活网探测
- probe_main_all_markets.py / probe_seal_deep_count.py：排序榜全市场与深市涨停数核对
- probe_scale_crosscheck.py：dt200 缩放因子交叉验证
- analyze_seal_sort_pcap.py / dump_seal_sort_flow.py：seal_sort pcap 逐帧流分析
