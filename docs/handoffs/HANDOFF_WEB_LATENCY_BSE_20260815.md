# Web 冷启动提速 / 名称与板块回填 / 北交所路由修正（2026-08-15）

> 本日围绕 Web 看盘的一次收口：冷启动 13s 预热、股票/板块名称偶发缺失、
> 北交所 920083 全部超时、Level2 分时偶发 502。最后用 2026-08-15 客户端
> 抓包确认北交所 Level2 路由在 shlv2，并据实修正协议角色。

## 核心结论

| 问题 | 根因 | 修复 |
|---|---|---|
| Web 首屏 K线/分时/盘口慢 | 后端预热串行建 SH_L2 → SZ_L2 → KLINE_FAST，实测 12.95s；前端又在预热窗口内抢发请求 | 三条通道并行建连（每路独立一代 Passport64），预热降到 ~3.3-5.4s；前端 K线/分时等 `preheat ready`，盘口仍先发 |
| 冷启动重复请求 | dev `React.StrictMode` 双挂载 effect，`useData` 无去重 | dev 移除 StrictMode；部分接口加 TTL+inflight 缓存 |
| 股票名称大部分消失 | 冷启动时名称组缓存未就绪，`stock_list_cached` 把 29,721 条 `name=""` 写进当日磁盘缓存，前端又把空 map 永久缓存 | 名称覆盖率 <80% 不写盘；命中稀疏缓存时用当日名称组自愈；前端空 map 不缓存并 3s 重试 |
| 板块名称大部分消失 | `hot_boards`(pageid=12480) 响应无名称列；本地 `industry.ini` 只覆盖 90 个 881 行业板块，882/885/886 概念板块全部查不到 | 后端用 `fetch_stock_names_full()` 的 `name_48` 组补全 513 个板块名称；前端优先 `b.name` |
| 北交所 920083 全部超时/400 | Level2 账号的 151 行情实际在 **shlv2** 上（2026-08-15 抓包），旧代码走 MAIN/ifindhq（不支持 151）；`intraday` 又先请求不支持的竞价接口 | timeline/K线/报价/五档全部按账号路由到 SH_L2（pageid 1334/10443）；BSE 跳过竞价段 |
| Level2 分时偶发 502 | 4214 注册在新连接上偶尔连续 5 帧都是 init 遗留帧，`CodeListSize` 未出现即抛 ProtocolError | 注册读取放宽到 24 帧并重试一次；intraday bundle 重试后降级为纯盘中分时 |

## 1. Web 冷启动并行预热

`dev.bat` 每次重启后端，`lifespan` 里 `start_preheat()` 原来串行：

```
preheat_l2_connections(): for sh -> sz（每条都要 HTTP 鉴权 + 测速 + login + init）
preheat_service_connections(): 再建 KLINE_FAST
```

三条通道合计 12.95s。改为：

- `client.preheat_service_connections()` 用 `ThreadPoolExecutor(max_workers=3)` 并行开 SH_L2 / SZ_L2 / KLINE_FAST；
- 每条新 socket 使用**自己独立的一代 Passport64**（`_open_manual_push_connection(material=...)` / `_open_independent_main_connection(material=...)`），不共享全局最新通行证，避免一票两用触发 `VerifyCode=-1`；
- `ConnectionManager.adopt` 竞态失败时关闭多余 socket、复用已就绪连接。

实测预热 12,952.9ms → **3,284.4-5,409ms**（受当次 IP 登录速度影响）。

## 2. 服务端/前端短缓存与启动时序

- `server/app.py`：`market_view_fast` 1s、`intraday` 2s、分钟 K线 2s、日周月 K线 15s 的进程内 TTL 缓存（只缓存成功结果）。
- `web/src/api/endpoints.ts`：同上的前端 TTL + in-flight 去重；`api.preheatReady()` 轮询 `/api/status`，ready/skipped/partial/error 才放行 K线/分时，盘口立即发。
- `web/src/main.tsx`：移除 dev StrictMode，消除接口双发。

## 3. 名称/板块缓存守卫

- `stock_list_cached()`：
  - 名称覆盖率 <80% 时不写盘，避免污染当天缓存；
  - 命中旧稀疏缓存时用 `fetch_stock_names_full()` 自愈并回写。
- `web/src/data/useStockNames.ts`：空名称 map 不进入长期缓存，3 秒后自动重试。
- `hot_boards()`：行情记录补 `name`（来源 `name_48` 组），513/513 板块名称齐。

## 4. 北交所路由（2026-08-15 抓包）

抓包文件：`captures_live/bse_920083_20260815_101552.pcapng`（脚本
`tests/capture_bse_920083.py`）。关键事实：

- Level2 客户端把 920083 的 **全部请求发在 shlv2（122.9.115.201）**；
- 报价/五档/K线：`pageid=1334`，K线 `ReqFuquan=Q CodeList=151(920083,); DataType=7,8,9,11,13,19`；
- 分时：`pageid=10443`；客户端还使用 10444 作为另一套 K线/历史上下文；
- MAIN/ifindhq 节点不返回 151（旧代码超时根因）。

代码修正：

- `services/timeline.py`：Level2 market 151/899 指数 → `SH_L2`，普通账号仍 MAIN；
- `services/kline.py`：`_kline_l2_role(151)` → SH_L2；
- `services/quote.py`：Level2 151 的 list_quotes/五档/market_view_pipeline → SH_L2 + pageid 1334；
- `service_facade.intraday()`：151 跳过早盘/尾盘竞价，分时始终走 timeline（非交易日返回最近交易日序列）；
- `web/src/state/StockContext.tsx`：920/43/83/87 开头 K线用 `channel=auto`（Level2 走 1334）。

实测（2026-08-15）：

```
/api/market_view_fast/920083  200，报价+五档
/api/timeline/920083          200，241 点
/api/kline/920083?channel=auto 200，46 根（新股）
/api/intraday/920083          200，241 点
```

## 5. 4214 注册偶发失败

`L2SubscriptionCoordinator.ensure_registered`：

- 读取上限 `max(5, 24)`；
- 第一次没看到 `CodeListSize` 或收到 `CodeListSize=0` 时重试一次；
- `service_facade.intraday()` 对 Level2 三段 bundle 重试一次，仍失败则降级返回
  `phase=continuous` 的 `timeline()` 数据，保证图表不空白。

实测重启后第一次 `/api/intraday/601888` 即可 200（437 点）。

## 关键文件

- src/thspypc/client.py / _client/connection_primitives.py / _client/service_facade.py
- src/thspypc/server/app.py / protocol.py
- src/thspypc/services/timeline.py / kline.py / quote.py / subscription.py
- web/src/api/endpoints.ts / data/useStockNames.ts / state/StockContext.tsx / main.tsx
- tests/capture_bse_920083.py、test_l2_subscription.py、test_stock_list_cached_guard.py 等

## 复现/诊断

- 抓包：`py tests/capture_bse_920083.py --duration 90`（抓包前必须关闭 8765 后端，
  Level2 不能双开）。
- 热态接口自带 `Server-Timing`，`xxx_wait` / `xxx_io` 可区分排队与网络。
