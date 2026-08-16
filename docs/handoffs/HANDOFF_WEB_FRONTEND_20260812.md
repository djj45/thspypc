# 看盘前端 web/ 交接（2026-08-12）

## 一句话

同花顺风格看盘前端，顶层 `web/`（React 18 + TS + Vite），对接 `src/thspypc/server` FastAPI。
**单股四块已跑通**：Header 行情、盘口信息条 + 五档、分时三阶段、日 K、短线精灵。
左侧 2×3 板块栏待做。首版"收盘静态快照"模式，实时推送预留（Fetcher 抽象 snapshot/poll/push 三态，首版只实现 snapshot）。

## 技术栈

- React 18 + TypeScript + Vite 5
- **lightweight-charts 4** —— 日 K（candlestick + volume）
- **ECharts 6** —— 分时（理由见「关键决策」）
- pnpm 11（包管理）；`pnpm-workspace.yaml` 里 `allowBuilds.esbuild=true`（pnpm 11 不再读 package.json 的 pnpm 字段）

启动：
```bash
PYTHONPATH=src python -m thspypc.server --port 8765   # 后端
cd web && pnpm dev                                      # 前端 → http://localhost:5173
# vite proxy 已把 /api/* 转发到 8765，开发期无跨域
```
> 注意：vite 在 Windows 默认绑 IPv6（::1），用 `localhost` 访问，别用 `127.0.0.1`（curl 会连不上，浏览器正常）。

## 目录结构

```
web/
├── index.html / package.json / pnpm-lock.yaml / pnpm-workspace.yaml
├── tsconfig.json / vite.config.ts / .gitignore
└── src/
    ├── main.tsx / App.tsx              # StockProvider 包裹 + 三栏布局
    ├── styles.css                      # 同花顺深色主题（红涨绿跌）
    ├── types.ts                        # Quote/Depth/Kline/Timeline/Auction/Board/Rank/Dxjl + SORT_BY 常量
    ├── api/{client.ts, endpoints.ts}   # fetch 封装 + 类型化端点
    ├── data/useData.ts                 # snapshot hook（poll/push 预留）
    ├── state/StockContext.tsx          # 全局 code + quote
    └── components/
        ├── Header.tsx                  # 代码输入 + 行情（dt10-dt6 前端自算涨跌）
        ├── center/
        │   ├── TimelineChart.tsx       # 分时三阶段（ECharts）
        │   └── KlineChart.tsx          # 日 K（lightweight-charts，周期/复权切换）
        └── right/
            ├── StockInfo.tsx           # 盘口上方股票信息条
            ├── DepthPanel.tsx          # 五档买卖盘
            └── DxjlPanel.tsx           # 短线精灵（点行联动切 code）
```

## 后端配套改动（`src/thspypc/server/app.py`）

app.py 原 8/3 版本未暴露最近新增的 client 能力，补了 10 个薄路由 + 2 处参数：

| 路由 | client 方法 | 备注 |
|---|---|---|
| `/api/board_categories` | `system_block_categories()` | 板块分类树（本地 ini） |
| `/api/hot_boards` | `hot_boards()` | 一次拿全 513 板块全字段，前端本地排序 |
| `/api/dynamic_plates` | `list_dynamic_plates()` | 动态板块（HTTPS） |
| `/api/groups/{name}` | `get_group(name)` | 单个自定义板块成分股 |
| `/api/self_stocks` | `get_self_stocks()` | 自选 |
| `/api/stocks2` | `stock_list_cached(with_names=True)` | 全市场代码表（磁盘缓存） |
| `/api/stock_list_ranked?sort_by=&count=&with_values=1` | `stock_list_hot(...)` | 排序榜翻页 + 数值 |
| `/api/dde_rank?sort_by=&count=` | `dde_rank()` | 主力排行（带 value） |
| `/api/dxjl/latest` | `dxjl_latest()` | 短线精灵最新一页 |
| `/api/kline/{code}` 加 `fuquan` 参数 | `kline(..., fuquan=)` | 前端切前/后复权 |

另：`_market_for_code` 扩展支持指数（1A/1B→16、39x→32、899→144）和北交所（43/83/87/920→151），与 `client.THSClient._market_for_code` 对齐。

## bug 修复（活网验证时发现，都是阻塞路由的真实问题）

1. **`stock_cache.py` 缺 `import time`** —— `save_stock_codes` 用 `time.time()` 但没 import，NameError → `/api/stocks2` 500。
2. **`hot_boards` / `closing_auction` / `intraday` 返回含 `_raw` bytes** —— hd 解析路径把原始未解码字节塞进 `<field>_raw` 键，pydantic 序列化遇 non-UTF-8 → 500。修法：app.py 加 `_jsonable()` 递归剥掉所有 bytes/bytearray 值，套在这三个路由 + hot_boards 上。

> 这类 `_raw` bytes 是后端 service 解析遗留，根因在 service 层；路由层 `_jsonable` 是最小侵入的止血。其他路由将来若也出 utf-8 序列化 500，套 `_jsonable` 即可。

## 关键决策：分时用 ECharts，不用 lightweight-charts

lightweight-charts 是 **bar 等宽**模型（每个数据点占一个等宽列，横轴标签才按时间）。早盘竞价 108 点挤在 10 分钟、尾盘 59 点挤在 3 分钟，盘中每分钟才一点 —— bar 等宽会让竞价段被拉宽、盘中被压缩，**无法同时满足「每点都显示 + 时间比例正确」**（用户明确要求不降采样）。

改用 ECharts `xAxis: type:'value'` + **交易分钟映射**（午休压缩）：
```
早盘竞价 9:15-9:25 → x = -15..-5
上午盘   9:30-11:29 → x = 0..119
午休     11:30-13:00 → 压缩
下午盘   13:00-14:56 → x = 120..236
尾盘竞价 14:57-15:00 → x = 237..240
```
`timeToX()` 把真实时刻映射到 x，`xToLabel()` 反向生成 hh:mm 标签。所有点保留（不降采样），三段时间比例正确，午休压缩（同花顺式）。

日 K 继续 lightweight-charts（它的 candlestick + 缩放/十字光标是强项，bar 等宽对日 K 无害）。

## dt 字段映射（前端用到的，活网验证）

排序榜（`stock_list_ranked` with `with_values=1`，**单次请求只返回当前 sort_by 对应的那个 dt 字段**）：

| 列 | sort_by | 响应 dt |
|---|---|---|
| 涨幅 | 199112 | dt200 |
| 涨速 | 48 | dt48 |
| 主力净流入 | 592890 | dt250 |
| 竞价金额 | 68758 | dt150 |
| 竞价涨幅 | 68762 | dt154 |
| 封单额 | 265260 | dt44 |

个股行情（`list_quotes`）：dt6 昨收 / dt7 今开 / dt10 现价 / dt13 量 / dt48 涨速 / dt66 涨幅(盘后常为 0，前端改用 dt10-dt6 自算)。
**注意**：list_quotes 默认 DataType **不含** dt8(高)/dt9(低)/dt19(额)，盘口信息条这三项暂显示 `--`，需扩展 DataType 才能补全。

## 当前状态 / 遗留

- ✅ 单股四块跑通（600519 实测：行情/五档/分时三阶段/日K/短线精灵）
- ✅ 切股票延迟问题已由后端 commit `988f583` 解决（auction 死等/MAIN IP/kline 等待）；前端 TimelineChart 仍保留了「auction 延后 + 当日缓存」的防御逻辑
- ❌ **左侧 2×3 六格未实现**（同花顺板块/全市场/自定义/自选/动态），是下一阶段主体工作
  - 板块表：`hot_boards` 一次拿全 513，前端本地排序分页（数据就绪）
  - 全市场表：`stock_list_ranked` 排序翻页 + `with_values` 拿当前列数值
- ⚠️ list_queries 缺 dt8/dt9/dt19（信息条高/低/额）
- ⚠️ 实时推送未接（Fetcher 预留 poll/push，首版 snapshot；后续接同花顺 snapshot_subscribe/depth_subscribe/subscribe_realtime）

## .gitignore 修正

根 `.gitignore` 的 `data/`（本意忽略顶层抓包目录）会匹配所有层级的 `data/`，误伤 `web/src/data/`。已改为 `/data/`（锚定根目录），语义不变。

## 2026-08-17 运行态修复

- `dev.sh` 对齐 `dev.bat`：前后端分别打开独立终端窗口，`--backend`/`--frontend`/`--check` 行为一致；macOS 用 Terminal `.command`，Windows Git Bash 用 cmd，无图形终端回退 `.dev-logs/`。
- `SH_L2`/`SZ_L2` 预热连接增加 8901 心跳；连接管理器与 ConnectionFactory 增加真实 socket 存活探测，发现服务端 FIN 后自动重连，修复空闲后 4214 注册 `CodeListSize` 超时导致的 intraday 502。
- 系统板块缓存：无本机 hexin 目录时首次自动从 `cloud.10jqka.com.cn` 全量下载 ZIP 到 `~/.thspypc/blockupdate`，之后每日后台检查版本；本机 `BlockUpdate` 仍优先。
- 板块通道 StockLinkVer 策略调整：优先 `ConfigVer=0` 自行请求全量版本表；仅当该路径失败/零响应时，才回退本机 `StockLink.ini`。
- 股票代码缓存格式 bump 到 version 2，Level2 全量代码表增加 `SH_L2` 的北交所 `151()` 查询，`920xxx` 等北交所股票名称可回填。
