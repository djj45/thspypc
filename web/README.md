# 看盘前端（web/）

同花顺风格看盘界面，React + TypeScript + Vite，对接 `src/thspypc/server` FastAPI 后端。

## 一键启动

在仓库根目录（Git Bash）：

```bash
./dev.sh
```

- 后端 → http://127.0.0.1:8765
- 前端 → **浏览器打开 http://localhost:5173**（用 `localhost`，不是 `127.0.0.1`——vite 在 Windows 绑 IPv6）
- `Ctrl+C` 同时停掉前后端

首次运行会自动 `pnpm install`。

## 手动分别启动

```bash
# 后端
PYTHONPATH=src uv run python -m thspypc.server --port 8765

# 前端（另一个终端）
cd web && pnpm dev
```

## 已实现

单股四块（切换顶栏代码联动）：

- **Header**：代码输入 + 现价/涨跌/涨幅（前端按 `dt10-dt6` 自算，`dt66` 盘后不可靠）
- **盘口区**：股票信息条（今开/昨收/总量）+ 五档买卖盘 + 封单额
- **分时（中上）**：三阶段（早盘竞价 9:15-9:25 ‖ 盘中 9:30-14:57 ‖ 尾盘 14:57-15:00），ECharts 时间线性轴，午休压缩，所有点保留
- **日K（中下）**：candlestick + volume，周期/前/后复权切换
- **短线精灵（右下）**：实时异动列表，点行联动切 code

> 左侧 2×3 板块栏（同花顺板块/全市场/自定义/自选/动态）待做。

## 技术栈

| 用途 | 选型 |
|---|---|
| 框架 | React 18 + TypeScript |
| 构建 | Vite 5 |
| 日K | lightweight-charts 4（candlestick 强项）|
| 分时 | ECharts 6（时间线性轴；lightweight-charts 是 bar 等宽，无法满足"每点显示+时间比例"）|
| 包管理 | pnpm |

## 目录

```
src/
├── App.tsx                 # StockProvider + 三栏布局
├── api/{client,endpoints}  # fetch 封装 + 类型化端点
├── data/useData.ts         # snapshot hook（poll/push 预留）
├── state/StockContext.tsx  # 全局 code + quote
├── types.ts                # 行情/盘口/K线/分时/板块/排序/短线精灵 类型 + SORT_BY 常量
└── components/
    ├── Header.tsx
    ├── center/{TimelineChart,KlineChart}
    └── right/{StockInfo,DepthPanel,DxjlPanel}
```

## 后端依赖

后端必须先起（`dev.sh` 已处理）。前端通过 vite proxy 把 `/api/*` 转发到 `127.0.0.1:8765`，开发期无跨域。

更多见 `docs/handoffs/HANDOFF_WEB_FRONTEND_20260812.md`。
