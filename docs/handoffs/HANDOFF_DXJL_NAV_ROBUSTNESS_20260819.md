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

术语说明：本节“推送”不是盘后订阅推送。工作发生在夜间/盘后，但原始 pcap 是
2026-08-15 10:15 的盘中样本；收盘后服务端通常只接受注册/返回 ACK，不会持续
产生逐笔或盘口变化。旧文中的 `0xe0`/`0x0a` 推送候选也已在下文纠正。

挖掘脚本：`tests/_type02_mine.py`、`tests/_type02_timeline.py`；中间产物
`captures_live/_type02_frames_dump.txt`、`_type02_timeline.txt`（本地，目录不入库）。
数据源：`captures_live/bse_920083_20260815_101552.pcapng`（交易日 10:15 盘中）。

8901 帧内统一命令子协议：`FD×4 + 8hex长度 + 09 + N×(22B子帧头 + 载荷)`。
一个 FDF 外帧可以捆绑多个子帧；22B 子帧头中包含 subtype、`cmd`、模式值、
wire seq 和载荷长度。cmd 共 20 种，关键：

| cmd | 方向 | 语义 |
|-----|------|------|
| 0x56 'V' | 双向 | pageid=1334 的列表订阅桶；模式 0/2/3 是并行 CodeList 分组（精确语义待定），4 是空桶重置形态，5 是 AddCode/DelCode 增量；查询模式 1，响应 `CodeListSize=N` / hd3.1 |
| 0xe0 | 双向 | pageid=5716 的指数订阅桶：C->S 发指数 CodeList，S->C 回 `CodeListSize=2/3`；**不是周期推送通知** |
| 0x01 | 双向 | 常规查询族（131/63 帧，≤46KB，疑为我们已有的列表行情路径） |
| 0x5f/0x63/0x69/0x6a/0xde/0xdf 等 | 双向 | 待识别 |

### 2026-08-19 午休离线纠正（以本节为准）

旧 `_type02_timeline.py` 先按方向拼流、且只查看每个 FDF body 的第一个子帧，
因此把捆绑在同一外帧内的客户端 `0xe0` 漏掉，误判为“纯 S->C 周期通知”。
现已改为按 TCP raw seq 去重/重组、按抓包帧号交错双向事件，并拆出全部 22B
子帧；离线回归覆盖复合子帧、服务端长度副本和乱序/重传。

新证据（同一份 10:15 盘中 pcap）：

1. 共恢复 3462 个 FDF 外帧、1706 个子帧、716 个 type-02 子帧（旧脚本
   漏了复合帧及乱序段）。
2. `0xe0` 恰好 C->S=54、S->C=54，只出现在启动后 0.58–2.05 秒：客户端发
   `CodeList=32(399001,399006,)` 或 `144(899050);16(...)` + `pageid=5716`，
   服务端回 `CodeListSize=2/3`。最后一个 `0xe0` 距首次 `0x56` 12.20 秒，
   所以它不是 `0x56` 的通知或后继帧。
3. `0x56` 模式 5 的增量形态已由集合大小闭环：初始沪股集合 29 条；模式 5 同时
   Add 29 条北交所、Del 28 条沪股，回 `CodeListSize=30`（保留 600000）；
   随后模式 3 携 `CodeList=17(600000,)` 并回 29，模式 4 空载荷后回 0。这里
   **只能确认模式 5 是 delta、模式 4 是 reset 形态**；模式 3 不能据此命名为删除，
   因为 08-19 新抓包中模式 0/2/3 均作为周期 CodeList 分组反复出现。
4. 字段集不放在订阅动作本身，而在同 cmd、subtype `0x0009`、动作 1 的查询
   子帧里。增量切换先查 `DataType=592890,592888`，随后再查完整字段集；
   请求/响应通过 wire seq（如 `0x125e`/`0x1260`）精确配对。
5. `body[0]=0x0a` 也不是主动推送，而是压缩批量响应外壳。现有
   `normalize_8901_response()` 可直接展开：64 个外帧得到 316 个子帧，其中
   172 个 nonzero wire seq **全部 172/172 匹配先前客户端请求**，其余 144 个
   是 zero-wire 的 CodeListSize/管理 ACK。部分外帧同时出现多个 hd1.0/hd3.1，
   只是批量响应被压到一个 FDF 帧。`09 7b d0 ...` 则是已有解析器覆盖的逐笔/
   快照推送，与列表批量响应不同。
6. 已新增纯协议层 `features/list_subscription_protocol.py`：实现 0x56 的
   codes(mode 0/2/3)/delta/clear/query builder、复合子帧封装和服务端响应 parser，并从
   `thspypc` 公共入口导出。它不含 socket/鉴权，尚未接 service。抓包真值和
   TCP 乱序/重传共 9 个离线测试通过；字段统一命名为中性的 `mode`，避免把
   未验证的 2/3 误当动作。

### 2026-08-19 13:05 开盘实时抓包（订阅→推送已闭环）

数据源：`captures_live/kanpan_push_20260819_130548.pcap`，WLAN 接口 4，官方
同花顺 9.60.20 看盘界面，持续 90 秒；共 6936 包、3,080,688 字节、**零丢包**。
抓包期间没有用 thspypc 另行登录，直接观察官方客户端已有连接，避免重复登录和
Passport64 消费问题。

1. 鲁棒 TCP 重组恢复 8901 的 1670 个 `0x0f7f` 深度推送外帧、1726 条盘口记录、
   88 只股票，时间跨度 `+0.000~+89.737s`；另有 221 个指数推送外帧。旧的逐包
   splitter 只计到 1657 个深度帧，少掉的分段帧由 raw TCP seq 重组恢复。
2. 按抓包帧号维护 `(TCP stream, cmd, mode)` 的 CodeList 瞬时状态后，深度记录
   1701/1726（98.6%）命中同一 stream 的当前订阅集。未命中的 25 条来自 25 只
   股票、每只恰好只有首条 1 次，均在抓包开头、相应 CodeList 首次出现之前；
   此后覆盖率为 100%。因此已经确认 **pageid=1334 CodeList 桶与无 wire-seq 的
   `0x0f7f` 盘口主动推送存在直接关联**。
3. `0x56` 在盘中约每 5.5 秒刷新一轮，模式 0/2/3 都会携带 CodeList 周期出现，
   进一步证实 LE32 字段是分组/模式值，不能把 3 泛化为删除动作。
4. 同一抓包内 `0x0a` 有 54 个压缩外壳，展开 183 个子帧；101 个 nonzero wire
   seq 全部 101/101 匹配先前请求，另外 82 个是 zero-wire 管理 ACK。它仍不是
   主动行情推送。
5. 9601 同时抓到 1367 个 `pushrealorder` 帧，解析出 254 条短线精灵异动，约
   169 条/分钟；因此短线精灵现有订阅通道也持续有效。
6. 分析器现支持 `--pcap/--output`，报告保存在
   `captures_live/_type02_timeline_20260819_130548.txt`；全套回归
   **641 passed、19 skipped**。

**最新结论：同花顺的列表链路是“CodeList 分桶维护 + 字段查询响应 + 同 socket
无序号 `0x0f7f` 盘口主动推送”的混合模型。`0xe0` 仍是指数订阅桶，`0x0a` 仍是
请求响应的压缩批量外壳；真正的列表实时推送证据是 `0x0f7f`，且已与 CodeList
状态达到盘初首条之外 100% 的关联覆盖。**

### 2026-08-19 13:21 官方客户端 UI 驱动抓包（页面命令映射）

用户确认 Level2 账号只能维持一个客户端会话，因此没有让 thspypc 同时登录，
也没有尝试跨进程复制 `hexin.exe` 的 Winsock（复制后两个进程会争抢同一接收队列）。
改为自动操作官方客户端的只读看盘界面，同时抓包并记录动作时间。数据源：
`captures_live/kanpan_push_20260819_132109.pcap`，180 秒、7321 包、3,759,832
字节、零丢包；报告为 `_type02_timeline_20260819_132109.txt`。

动作与协议锚点（抓包相对时间）：

| UI 动作 | 协议变化 |
|---------|----------|
| `60` 进入沪深 A 股排行（+29.5s） | mode 4 清空 page 1334 的旧桶；启用 `cmd=0x5f, pageid=982` |
| `61` 进入沪 A 排行（约 +55.3s） | `0x5f mode 0` 换为沪市 CodeList，后续 mode 5 AddCode/DelCode 增量 |
| `63` 进入深 A 排行（约 +69.1s） | `0x5f mode 0` 换为深市 CodeList，后续 mode 5 增量 |
| 输入 `600519`（+103.1s） | mode 4 清空 page 982；page 4214 建立 `cmd=0x02/0xfc/0xe2` 的 600519 详情桶 |
| 输入 `000001`（+131.3s） | `cmd=0x02 mode 0` 主代码换成 000001；并行桶保留 600519 的 mode 3 状态 |
| 返回排行（+151.8s） | mode 4 清空 page 4214 的 `0x02/0xfc/0xe2`，恢复 `0x5f page 982` |

新结论：

1. **`cmd=0x5f / pageid=982` 是涨幅排行列表的主要桶**；沪深榜/沪榜/深榜都会
   使用它，约每 5.46 秒刷新 CodeList，并用 mode 5 做排名变化的增量调整。
2. **`cmd=0x02/0xfc/0xe2 / pageid=4214` 属于选中股票详情页**，不能混入列表
   bucket service。之前“下一步确认 0x5f 是否详情命令”的疑问已经排除。
3. mode 4 在离开页面时同时清空该页全部命令桶，作为 reset/clear 的证据进一步
   增强；mode 2/3 仍应保持中性命名，它们是并行分组/前后状态，不是通用删除。
4. 本次鲁棒重组恢复 1475 个 `0x0f7f` 深度外帧、1576 条记录、141 只股票，另有
   312 个指数推送；`0x0a` 展开后的 225 个 nonzero wire seq 仍全部 225/225
   匹配客户端请求。

路由已用 pcap 四元组和实时 DNS 双重核对：承载沪市 `0x5f` 的 TCP stream 1
对端为 `8.134.115.123:8901`，属于 `shlv2.123ths.com`；深市 stream 2 对端为
`122.9.214.229:8901`，属于 `szlv2.123ths.com`。因此排行桶应复用现有 SH_L2/
SZ_L2 受管连接，**不是 MAIN**。

### 2026-08-19 收盘后代码落地（待次日盘中验证）

已完成以下离线实现：

1. `features/list_subscription_protocol.py`
   - 新增 `RANKING_LIST_COMMAND=0x5f`、`RANKING_LIST_PAGEID=982`；
   - 固化官方排行主字段集 `RANKING_LIST_DATATYPE`（34 个 dt）；
   - query builder 支持抓包中的自定义 `DateTime` / `LackTime`；
   - codes(mode 0/2/3)、delta(mode 5)、clear(mode 4)、query(mode 1) 仍为纯协议层。
2. `services/list_subscription.py` 新增 `ListBucketCoordinator`：
   - 只接受已登录并完成 init 的 `ManagedConnection`，自身不建连、不鉴权；
   - set/delta/clear 只有收到匹配 `CodeListSize` ACK 后才提交本地状态；
   - query 用 `(cmd, subtype, wire_seq)` 匹配，不能要求服务端 mode 等于 1（数据
     响应该字段可为 `0x10010101` 元数据字）；
   - 等 ACK 期间若先收到 `0x0f7f`，转交现有推送分发器，避免桶切换时丢行情。
3. `ConnectionRuntime.deliver_market_push()` 抽出统一的 71B/`0x0f7f` 解析与交付；
   原后台 reader 和列表协调器共用，不复制解析逻辑。
4. `THSClient` 新增：
   - `ranking_depth_subscribe(codes, market=17/33)`：mode 0 批量注册 + 官方字段查询；
   - `ranking_depth_update(add=..., remove=..., market=...)`：mode 5 增量，并按
     官方行为查询新增代码的主字段；
   - `ranking_depth_clear(market=...)`：mode 4 清空；
   - 数据继续从现有 `receive_depth()` / `latest_depth()` / callback 消费。
   三者复用 `ConnectionRole.SH_L2/SZ_L2`，不会另开同角色 socket。
5. 新增 `tests/verify_ranking_depth_live.py`，一次进程完成
   `set → push → delta → push → clear`。脚本只调用一次 `get_client()`，遵守
   Passport64 一票一连接与账号单客户端限制。
6. 离线服务测试覆盖 ACK 后提交、delta 状态、clear、等待 ACK 时转交推送、服务端
   query 元数据 mode、facade 批量激活；最新全套回归：
   **647 passed、19 skipped**。

### 2026-08-19 收盘后 Web 快速切股超时修复

用户连续快速按 ↑/↓ 后，页面最终停在 `300155`，分时、K 线、盘口同时留白并显示
`signal timed out`。现场只读检查确认 Chrome 和后端均未死锁；三个接口随后单独请求
分别在 185ms/42ms/15ms 返回成功。根因是浏览器 20 秒 `AbortSignal.timeout()`
终止等待后，最终股票只记录错误、不自动重试；同时分时错误被合并到整个
`marketView.error`，使已经成功的盘口也被错误组件遮住。

修复：

1. `StockContext` 对盘口/分时/K 线的浏览器超时增加一次条件重试；仅当用户仍停在
   同一股票时才重试，已经切走的旧任务绝不重试。
2. 新增独立 `intradayState`（data/loading/error），分时失败不再污染盘口和页头；
   分时请求进行中也能正确显示自己的 loading 状态。
3. 沪市 ST 行情使用风险警示板市场码 22，但 L2 分时、竞价、历史分时协议必须走
   基础沪市市场 17。facade 在这些入口统一执行 `22 -> 17`，修复 `600745` 的
   `集合竞价暂不支持市场码: 22`。
4. 当前 Chrome 页已通过内置刷新恢复行情；前端生产构建通过，相关测试 71 passed，
   最新全套回归：**648 passed、19 skipped**。

#### 二次复现与最终背压修复（19:33–19:45）

第一次“超时后立即重试”仍不足：用户以约 170ms/次连续切股时，150ms 的盘口/
分时防抖和 40ms 的 K 线防抖都会穿透。后端访问日志确认从 `688836` 起逐只发出
盘口、分时、K 线；其中旧股票 `688836` 的 KLINE_FAST 超时后，公共 `kline()`
默认继续做 4 轮、每轮 12 秒的传输重试。浏览器 20 秒先行放弃，但后端工作线程
仍持有/等待连接，最终股票 `002852` 的请求因此继续排队。500ms 前端立即重试又
产生第二个遗留 HTTP 工作，最终 MAIN 与 KLINE_FAST 同时显示 `signal timed out`；
分时已单独成功。

最终修复：

1. 三条单股通道统一使用 **300ms trailing debounce**，连续切换期间不访问 8901，
   停下后各通道只查询最终股票。
2. Web 交互路由的盘口/分时/K 线统一传 `timeout=6s`；K 线和分时在 Web 层传
   `retries=0`。底层公共 Python API 仍保留原默认重试语义，但任何单个 Web 工作
   都必须先于浏览器 20 秒超时结束，避免浏览器断开后留下后台“僵尸请求”。
3. 前端对 Timeout/网络失败/HTTP 502 最多退避恢复两次（1.5s、4s），且每次都
   检查仍停在原股票；切走后立即放弃旧任务。
4. KLINE_FAST 重试不再探测/等待 MAIN socket；`/api/status` 也不再取得 MAIN
   请求锁，因此一个行情角色超时不会连带拖死状态接口。
5. 独立页面按 170ms 间隔连续切换 25 次，停在 `600550` 后盘口、分时、K 线均
   正常完成，无 loading、无 `signal timed out`、无行情错误；当前页面 `002852`
   也已恢复。前端构建通过，相关测试 89 passed，最新全套回归：
   **649 passed、19 skipped**。

#### 虚拟列表方向键跟随修复（收盘后）

左侧股票表是虚拟滚动列表，原导航源只保存代码顺序；↑/↓ 和图表滚轮切股只更新
选中代码，不更新列表 `scrollTop`，所以越过可视区后选中行不会随之翻出。现在导航
源同时注册 `revealCode()`：仅由最近点击的来源列表按目标索引滚动，隐藏列表不会
误动；滚动位置同时避开粘性表头。独立页面在“全市场”连续向下 15 只后
`scrollTop=110`，目标行完整可见；再向上 15 只回到首行后 `scrollTop=0`，首行位于
表头正下方。前端生产构建通过。

#### 分时与尾盘竞价重叠修复（收盘后）

完整 continuous 分时固定返回 241 点，前端原先直接用数组下标 `0..240` 作横轴；
closing auction 的真实时间又映射为 `237..240`，造成 14:57～15:00 同时绘制蓝色
分时线和橙色尾盘竞价线。现在只要存在 closing auction，continuous 价格线与均价线
保留下标 237（14:57）作为两段的边界锚点，仅裁掉 238～240 的重复尾段；这样尾盘
竞价首笔（通常约 14:57:02）能紧接蓝线，竞价为空时仍保留全部盘中点。

早盘边界同步处理：原先将 09:15～09:25 映射为横轴 `-15..-1`，而 09:30 分时从
`0` 开始，两个独立 series 之间留下一个单位的断口。现改为映射到 `-15..0`，将
09:25～09:30 无撮合空档压缩掉；最后一笔竞价（通常 09:24:59）贴近 `0`，与
09:30 分时首点连续衔接，但不重复绘制盘中区间。

#### Web K线改走 Level2（收盘后）

此前沪深 Web K线显式传 `ifindhq_fast`；该名字虽含 fast，实际使用独立的
`KLINE_FAST` BASIC/MAIN 连接和 pageid 9355，并非 Level2。现统一传
`channel=level2`：沪市及北交所复用 SH_L2、深市复用 SZ_L2，使用抓包确认的
pageid 1334。Level2 账号启动预热也只建 SH_L2/SZ_L2，不再额外鉴权、打开未使用的
KLINE_FAST；普通账号的独立 fast 通道能力仍保留，显式调用时可按需懒建连。

#### 官方客户端快速切股复核与 Web 两阶段提速（21:50 抓包）

离线重放 `captures_live/kline_fast_20260819_215045.pcap`，按 FDF 外帧、子帧及
`stream + wire_seq` 重新配对。旧 `capture_kline_fast.py` 报告的“220 个 K线请求/
响应 0ms”不可用：它在整个 TCP payload 上搜字符串，会把同包的盘口、
分时和 K线子帧混在一起；取不到响应时又退回请求时刻，所以显示 0ms。

新结论：

1. `DataType=272,229,271,228... + DateTime=8192` 是盘中分时，不是 K线。
   `1A0002/399002` 是沪深伴随指数；目标股与同市场指数合并在同一
   `CodeList`，另一市场仍发指数伴随请求。
2. 真正的立即日 K 是 `pageid=1334` / `route=0x0168` /
   `DateTime=16384(-568-0)` 的 21 字段图表扩展请求。共 113 个，85 只不同
   股票；完整响应中位 18.83ms、P95 26.05ms、最大 32ms。快速段 100ms
   内最多 6 个、1s 内最多 19 个请求，官方没有 300ms 切股防抖。
3. 停在同一股票约 0.96~1.11s 后，官方才补发 `route=0x0100` /
   `DataType=7,8,9,11,13,19` / `DateTime≈16384(-2006-0)` 的完整历史请求。
   即“快速首屏 + 停稳后补全”两阶段；本地缓存用于立即绘制，但抓包中
   每次切股仍实际收到了中位约 8.9KB 的网络 K线响应，不是纯本地命中。
4. 79.7s 的盘后抓包没有任何盘口、指数或短线精灵主动推送；12.8s
   客户端静默期服务端只有 3 个心跳。K线是请求-响应，不依赖收盘后订阅。

基于此完成 Web 第一/二阶段优化，取代上文“三通道统一 300ms”的临时
保守策略：

1. 盘口首屏和 K线切股后立即发起；分时因与 K线共用市场 L2 socket，
   仅保留 60ms 短合并窗口。每条 lane 仍只保留当前工作和最新待执行工作，
   旧响应仍按当前代码过滤，不会上屏。
2. `StockContext` 新增 128 项 K线 LRU，key 为“股票+周期+复权”。切回已看
   组合时先绘制缓存，同时后台刷新，不再先清空图表。
3. Web `/api/kline` 显式传 `latest=True`；排到共享 socket 时已被新请求
   取代的 K线会在发送前淘汰。公共 Python API 默认 `latest=False`，语义不变。
4. Web K线/分时/盘口首屏的单次协议慢尾从 6s 收紧为 2s，且仍零传输
   重试；底层公共 API 的默认超时/重试不变。这仍不能中断已进入 socket
   读取的旧请求，但将极端阻塞上界从 6s 降到 2s；真正无阻塞还需后续实现
   官方式 `wire_seq` 多路复用。

前端生产构建通过；相关 Python 测试及后续预热回归均通过，最新全套回归
**651 passed、19 skipped**。本轮只做离线测试，官方
Level2 客户端仍在使用账号，没有启动后端或新建 8901 登录。

##### 首次实际启动卡 36s 的追加修正

首次加载时页面 K线、全市场和同花顺板块长时间不显示。`/api/status`
现场证据为 `connected=true`，但 `preheat.state=ready` 直到 **36420.4ms** 才完成。
原因是后台预热的首次 MAIN 登录命中 `all_hosts_failed` 后固定退避 30s；
退避期间前台 `market_view_fast` 已登录成功，但浏览器仍只看
`preheat=running`，把 K线/分时和依赖 L2 的全市场排行一直挡住。

修正：

1. `waitForPreheat()` 一旦看到 `status.connected=true` 立即放行，各业务由
   `ConnectionManager` 按需单飞建 L2，不等后台预热的状态字样。
2. `_connect_with_retry()` 的 30s sleep 改为 250ms 可中断检查；前台已登录时
   预热线程立即接管现有会话，不再空等30s。
3. 连接 ready 后对当前运行后端实测：K线 320 根 15ms，全市场 5400 行 69ms，
   同花顺板块 513 行 225ms；三个接口均有非空数据。

##### 快速切股后盘口/K线/分时同时卡住的现场修正

PID 27860 的卡住现场表现为 `/api/status` 仍可返回，但
`market_view_fast`、Level2 K线、分时、全市场排行及板块接口均超过 5s；用户提供的
访问日志中，`000723` 的盘口与分时已经 `200 OK`，对应 K线没有完成记录，此后只剩
`/api/status`。稍后线程自行恢复，接口又回到盘口 17ms、K线 15ms、分时 68ms，
说明不是永久死锁，而是旧业务请求长时间占用 socket lane 后形成的累计排队。

根因在 `MarketSession`：路由虽然传入 `timeout=2s`，但 `_request_lock.acquire()`
和同步请求前的 `dispatcher.wait_idle()` 都是无限等待，2s 只在拿到通道并开始 socket
读取后才生效。前端兜底又是 20s，所以一个慢请求足以让三个前端 lane 长时间保持
loading，看起来像整页冻结。

修正：

1. `request`、`request_latest`、`receive`、`dispatch` 均从入口建立总 deadline；
   等 socket lane、等 dispatcher、发送和收包共享同一超时预算。
2. 等 lane 或 dispatcher 超时直接抛 `TimeoutError`，Web 转为 502，让旧请求释放
   前端 lane；不再无限排队，也不新建/重复登录 Level2 连接。
3. 浏览器最终兜底由 20s 收紧为 6s，覆盖 Web 2s 协议预算和一次短恢复，但旧股票
   不再能占住页面 20s。
4. 新增“lane 被占时按预算退出”和“dispatcher 非 idle 时按预算退出”回归；最新
   全量测试 **653 passed、19 skipped**，前端生产构建通过。

运行态注意：诊断期间没有重启或新建第二个后端，PID 27860 保留原 Level2 会话。
前端改动可 HMR；`MarketSession` 后端修正需要下次正常停止旧进程后再启动才能生效。

##### 竞价金额全量排序修正

`SortBy=68758` 的小榜（`count=20`）返回 `dt150` 真值，但 Level2 大
`SortCount` 响应会混入真值乘 `1e4/1e6/1e8` 的记录。旧代码把这些缩放值直接用于
SH/SZ 两榜全局合并，现场首行 `920717 dt150=1.3344e12`，而独立
`dt17×dt7=13344`，几千元的小额因此排到亿元记录前面。

修正：全量竞价金额榜返回后，复用现有行情连接，以精简 `DataType=5,7,17`、
400 码/批查询全部记录的独立真值；识别 `×1e2/×1e4/×1e6/×1e8` 后写回
`dt150` 并全局重排。Web 只显示新后端明确给出的 `auction_amount` 校准字段；旧后端
无此字段时回退可视区 `quotes_ext`，避免前端先热更新时把原始 `dt150` 显示成几万亿。

唯一后端重启为 PID 9108 后活网验证：降序 5400 行 425ms、升序 5400 行
278ms，两个方向均 0 个逆序点；降序前20与独立小榜完全一致，第一名 688836 为
1,488,324,200 元且与直接行情一致。全量回归 **655 passed、19 skipped**，前端
生产构建通过。

##### 新股首日日 K 的 hd1.0 修正

688836 于 2026-08-19 上市，Web 分时和盘口正常，但日 K 返回 502。唯一后端的
日志显示三条 K 线通道都在 2s 后超时；普通股票同连接正常。关闭后端后，用官方
客户端抓取 `captures_live/kline_fast_20260819_234415.pcap`，逐 FDF 帧和方向重组
后确认：官方发送 `pageid=1334`、`ReqFuquan=Q`、
`DataType=7,8,9,11,13,19`、`DateTime=16384(-1438-0)`，约 10ms 收到一条
`hd1.0/flag=0x42` 响应，而不是批量历史使用的 `hd3.1`。

该记录解码为 2026-08-19，开 1100、高 1100、低 800.08、收 845，量
25,657,935、额 23,159,535,000，与官方客户端首根日 K 一致。根因是
`KlineService` 只识别 `hd3.1`，收到有效 `hd1.0` 后仍继续读，最终把下一次
socket timeout 报成 502；不是服务端缺数据，也不需要用分时/快照本地合成。

修正复用现有 `codecs.hd.parse_hd1_response()`：K 线包装器只验证 0x42/0x46、
提取 22B 股票壳并移除它，然后交给通用 hd1.0 字段/数值解码；服务读取循环同时
接受 hd1.0 与 hd3.1。真实 pcap 响应离线复放通过。

2026-08-20 活网追加：普通 DNS 首选沪节点对 688836 静默，但官方抓包节点
`122.9.202.190` 在 11ms 返回 175B hd1.0；结构声明 28B 行，帧内实际只有 27B，
最后 1B 紧随 FDF 帧体到达。这与 list_quotes/十档已有的截尾怪癖相同。KlineService
现复用 `_repair_short_record()`，传入 K 线 22B 股票壳长度后补读末字节，再交给上述
解析器。

官方客户端退出后启动唯一后端做生产接口验证，普通 DNS 选出的沪 Level2 节点也已
正常返回，不需要硬编码抓包节点或增加跨节点回退：

- `/api/kline/688836?period=day&count=320&fuquan=Q&channel=level2` 返回 200，
  `Server-Timing total=34.8ms`，内容为上述 2026-08-19 首日 1 根日 K；
- 另一次首次请求客户端端到端约 39.5ms，重复请求约 3.1ms，证明 K 线缓存生效；
- 同连接请求 600519 返回 321 根（端到端约 200.1ms），普通 `hd3.1` 历史路径未受
  影响；
- 最终全量回归 **659 passed、19 skipped**。

随后复核发现 Web K 线缓存会把空列表也视为成功结果写入 15 秒缓存：快速切股时
`latest-wins` 淘汰的旧请求返回 `[]`，合法空结果也为 `[]`，二者都会让相同参数的
后续请求短暂命中“无 K 线”。现为 `_cached()` 增加可选缓存谓词，K 线路由只缓存
非空结果；空结果直接返回但不落缓存。离线回归覆盖“首次空结果不缓存、第二次重新
请求得到数据、第三次才命中非空缓存”。

运行态说明：最终活网验证时唯一后端 PID 13208 的主、沪 Level2、深 Level2 连接
均 ready；验证完成后已正常关闭，`127.0.0.1:8765` 当前无监听，未留下 Level2
账号会话。明日先确认官方客户端未运行，再按下节步骤启动后端。

#### 次日盘中验证步骤（必须按序）

1. **先完全退出官方同花顺**，任务管理器确认无 `hexin.exe`。Level2 账号只允许
   一个客户端会话，不能官方客户端与 thspypc 并发登录。
2. 先测沪市：

   ```powershell
   py tests/verify_ranking_depth_live.py --market 17 `
     --codes 600519,600000,600036 --add 600009 --remove 600000 --seconds 40
   ```

3. 进程结束并释放连接后再测深市：

   ```powershell
   py tests/verify_ranking_depth_live.py --market 33 `
     --codes 000001,000002,000063 --add 000333 --remove 000002 --seconds 40
   ```

4. 成功标准：set/delta/clear 均收到 ACK；set 后初始代码有连续十档推送；delta 后
   新增代码开始推送、删除代码不再进入本地队列；连续竞价记录买卖盘各 10 档。
5. 若 set ACK 成功但无推送，追加 `--no-query` 做 A/B，判断触发条件是 CodeList
   管理本身还是与 subtype-09 字段查询组合有关。失败时保留原始帧，不自动尝试
   第二个 host，也不在同进程重复登录。

### 下一步（按序）
1. 次日按上节脚本完成 `0x5f/page982` 沪深盘中验证；验证前不再改线协议。
2. 验证通过后，将排行订阅状态提升为后端长驻 service 生命周期，并接入连接断线
   后的重新注册；绝不能为不同桶重复登录。
3. 将深度推送归一为列表行所需字段，通过 WebSocket/SSE 给前端增量更新；普通
   hd3.1 查询仅用于首屏和丢帧后的校准，不再作为主要刷新来源。
4. 继续用官方 UI 被动抓包映射 `0x53~0x57/0x63` 对应的首页榜单，不与官方
   客户端并发登录 Level2。
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
