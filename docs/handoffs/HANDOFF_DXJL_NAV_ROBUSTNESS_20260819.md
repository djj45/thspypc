# HANDOFF 短线精灵改造 + 导航切股 + 连接鲁棒性 + 订阅推送挖掘（2026-08-19）

工作时段：08-18 晚 ~ 08-19 凌晨（约 03:00）。全部改动已验证（活网 + 浏览器 +
632 回归通过），已提交。后端（8765）与 vite（5173）仍在运行未关闭。

## 一、主力净额排序修复（承接 08-18 白天，本次收尾）

背景：L2 排序榜 `SortCount=320` 档服务端返回真值×100 虚值；多请求增量序列会
触发服务端编码切换（后页 ×0.01）。抓包确认同花顺客户端自己只用 29/档小页。

最终方案（`services/stock_list.py` `_ranked_l2.fetch_all`）：
1. **两步策略**：先发探测页（20 条）拿 `sort_total`，再单发一次大请求
   （`SortCount = max(count, sort_total)`）一次拉全。实测独立大请求
   （2560/2900/5400）永远返回真值。
2. 保留漂移守卫：响应缺期望字段（如 592890 回 dt44）→ close(role) 重取重试一次。
3. `_anchor_correct_ranked_values`：锚定样本比值 ∈ [99.9,100.1] 判 ×100 虚值
   并归一（`_client/service_facade.py` `_MONEY_SORT_ANCHORS` + 0xc4 直查锚定）。
4. **已删除** `_align_page_value_scale`（页级对齐会污染真值页——踩过的坑，勿再加）。

验证：连续 3 次全市场主力净额排序 0 乱序、抽查值与 0xc4/DDE 三方一致。

## 二、短线精灵（DxjlPanel 全面改造）

- **名称列替代代码列**：后端 `_attach_dxjl_names`（`service_facade.py`）用当日
  缓存名称表回填 `名称`，名称服务不可用时降级显示代码（前端 title=代码）。
- **最新贴底 + 上拉翻历史**：列表升序（旧→新），初次加载自动滚到底；
  滚到顶部 48px 内自动拉一页历史前插（`/api/dxjl?pages=1&endtime=<微秒游标>`，
  facade `dxjl_history(endtime_us=)` 透传 `now_us`）。去重键 =
  `时间|代码|异动编码|金额`（服务端 endtime 含等号会重发 1 条边界记录，去重消化）。
  前插后补偿 scrollTop 保持视口。跨日记录显示 `MM-DD HH:MM`。
- **红绿配色**：名称/异动类型/金额三列按方向着色（复用 .up/.down）。语义见
  `dirOf()`：打开跌停板=红（上涨事件）、打开涨停板=绿；撤单/封单大减按压力减弱
  方向着色（撤买/涨停封单大减=绿）。
- **横向滚动恢复**：`.dxjl-scroll` overflow-x auto（上一版误设 hidden）。
- **表格 memo 化**：`DxjlTable`（memo）+ 派生 `selectedKey`——快速切股时
  500+ 行不全量 reconcile。

## 三、键盘/滚轮导航切股（新功能）

- 点击任意列表行（`shared.tsx` StockTable，覆盖全市场+4 自定义板块）注册该列表
  为"顺序源"（getter 永远取最新排序）；↑/↓ 与分时/K线区域滚轮按该列表当前顺序
  切换，**首尾循环**。
- 未点过列表：按全市场代码升序循环（RankPanel 注册 `globalCodesRef`）。
- 当前代码不在序列（从短线精灵切入等）：按代码插入位就近取。
- 入口 `App.tsx` `StockNav`：document keydown（输入框内不触发）+ window wheel
  （仅 `.chart-host` 区域，passive:false，120ms 节流）。
- 实现：`StockContext` 的 `setCode(code, source?)` / `navigate(dir)` /
  `navListRef` / `globalCodesRef`。

## 四、快速切股卡顿（三轮根治，勿回退）

现象：按住方向键/滚轮连切 → 盘口分时 K线全空或秒级延迟。根因三层：

1. **请求洪水**：`StockContext` 三条数据通道（盘口 fast / 分时 intraday / K线）。
   现为：**150ms 尾随防抖**（>滚轮 120ms 节流档，持续滚动零请求）+
   **通道闸门 `useLaneGate`**（每通道在途请求最多 1 个，排队任务被最新代码不断
   替换，停下必拉最终代码；任务读 `codeRef.current`，写入守卫
   `target === codeRef.current`，旧响应不上屏——旧的 marketGeneration/
   klineGeneration 已删除）。
2. **后端并发争抢 MAIN**：多面板 quotes_ext + 盘口并发读写同一 socket →
   `WinError 10035/10038` → 空结果 → 并发 connect_main 重连风暴（日志实证 4 组
   批次全挂，对应行永远 "-"）。修复：`_client/service_facade.py` 模块级
   `_MAIN_SERIAL_LOCK`（RLock）串行化 `stock_quote_fields` 与
   `market_view_pipeline`。前端 `useQuoteExt` 对响应缺行自动补拉缺失代码
   （最多 3 轮，500ms 间隔）。
3. **挂死永久占道**：后端偶发被上游死 socket 挂住（凌晨盘后尤甚，kline 最坏
   4×12s+重连 ≈ 1 分钟），前端 fetch 无超时 → 通道 busyRef 永久 true → 该通道
   彻底死亡需刷新页面。修复：`web/src/api/client.ts` 所有请求
   `AbortSignal.timeout(20s)`，超时报错释放通道，下次切换自愈。

另：`RankPanel` 5400 行 rows 映射 useMemo 化（切股每秒 30 次重渲染时不再每帧重建）。

**凌晨上游迟缓是环境因素**（盘后维护时段），盘中请求-应答本身亚秒级；切股流畅度
以盘中表现为准。

## 五、心跳现状结论（用户问答，未改代码）

已有心跳：3s 一轮覆盖 MAIN/KLINE_FAST/L2 推送（L2 带 MSG_PEEK 探活+死连接重建），
30s 一轮覆盖 9601 两路。**但 MAIN/KLINE 心跳是只发不校验**（try_send 进 TCP 缓冲
即"成功"），防不住"连接活着但服务端静默/流失步"。改进方向（未做）：心跳响应
校验 + 连续无响应判失步主动换连接，改动集中在 `connection_runtime.py` 心跳循环。

同花顺秒切根源是订阅推送架构（见下节），不只是心跳。

## 六、订阅推送挖掘（重大进展，样本已够，无需重新抓包）

挖掘脚本：`tests/_type02_mine.py`、`tests/_type02_timeline.py`；中间产物
`captures_live/_type02_frames_dump.txt`、`_type02_timeline.txt`（本地，目录不入库）。
数据源：`captures_live/bse_920083_20260815_101552.pcapng`（交易日 10:15 盘中）。

8901 帧内统一命令子协议：`FD×4 + 8hex长度 + 09 00 16 00 00000012 | 02 00 <cmd>
<LE32 序号> | 载荷`。cmd 共 20 种，关键：

| cmd | 方向 | 语义 |
|-----|------|------|
| 0x56 'V' | 双向 | **订阅管理**：`AddCode=151(920879,...);` 增订、`DelCode=17(...);` 退订、`CodeList=17(600000,);` 整表，带 `pageid=1334`；响应 `CodeListSize=N` + hd3.1 表（**hd3.1 解析器已有**） |
| 0xe0 | 纯 S->C | 盘中周期推送，42B 恒定、无对应请求，内容含 `CodeListSize=N` |
| 0x01 | 双向 | 常规查询族（131/63 帧，≤46KB，疑为我们已有的列表行情路径） |
| 0x5f/0x63/0x69/0x6a/0xde/0xdf 等 | 双向 | 待识别 |

**结论：同花顺秒切 = AddCode/DelCode 订阅集增量调整 + 0xe0/数据帧主动推送，
订阅命令是明文文本，比预期好逆向。**

### 下一步（按序）
1. 交错时间线：按包序合并双向帧，区分"请求应答"与"服务器主动推"的数据帧；
2. 0x56 订阅粒度（pageid+市场+代码集；字段集如何指定）；
3. 0xe0 通知后数据帧跟随方式（推送触发协议）；
4. 实现：订阅 service（新 ConnectionRole 或复用）→ `/api/subscribe` 端点 →
   前端 WebSocket/SSE 替换轮询式请求；列表盘中实时刷新与切股提速一并解决。
   规模参照 0xc4 逆向（约一天，builder+parser+路由+离线回归+活网三方程验证）。

## 七、杂项

- 日K TradingView 归属图标隐藏：`styles.css` `a[href*="tradingview.com"]`（本地
  工具自用；若发布需恢复以符合商标要求）。
- 测试更新：`tests/test_client_service_context.py` 委托测试覆盖
  `dxjl_history(endtime_us=)` 透传；`tests/test_stock_list_service.py` 两步策略
  + 漂移守卫 + 锚定归一（移除了 3 个 _align_page_value_scale 测试）。
- vite 偶发漏监听文件变更（本日两次：shared.tsx/RankPanel.tsx 旧模块缓存，
  touch 即恢复；HMR 半更新会出现方向键失灵假象——刷新即好，非 bug）。用户侧
  遇"功能没生效"先整页刷新。
- 截图回传通道（nodeRepl.emitImage）本日不可用，视觉验证用 DOM/指标级证据替代。

## 八、遗留/待办

- [ ] 订阅推送逆向与接入（第六节，最高优先）
- [ ] 心跳响应校验（第五节）
- [ ] 列表盘中实时刷新（依赖订阅推送）
- [ ] 0xc4 在非 L2 普通账号未验证
- [ ] dt200×2/dt126/dt131 语义
- [ ] K线三件套（昨收基准线/涨跌幅右轴/成交量副图）——用户已取消，备忘
