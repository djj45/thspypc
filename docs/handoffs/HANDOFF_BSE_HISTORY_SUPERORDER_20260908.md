# 北交所历史分时 + 超级盘口协议逆向（2026-09-08 抓包）

抓包：`captures_live/bse_920083_20260908_154431.pcapng`（普通账号）与
`captures_live/bse_920083_20260908_155532.pcapng`（L2 账号复核，均含票据勿提交）。
官方客户端操作：920118 分时翻历史（含跳到 6/8、8/19）+ 超级盘口。

**两次抓包交叉确认：协议族与账号类型无关**——7176/6144 窗、8192 窗在两种
账号下完全同形；仅子帧 route 编号随连接变化（0x0112↔0x013e 等），实现时
按族取观测值并容错。当日分时主体另见 `DateTime=8192(0-0)` + 双基准三联
+ dt 272,14,271,13,19,40,54,39,10,38,23,15,22,6,45,1110,1111,380
（含 dt14/15 买卖力量）——是分钟K合成之外的官方正路，将来可切换。

市场结构（用户确认）：BSE 有早盘竞价（09:15-09:25）、**无尾盘竞价**，
连续竞价至 15:00；分时含 14:57-15:00；分钟K 全日 241 根
（上午 120 + 下午 121）。超级盘口为**秒级逐笔**，时间不连续（流动性差）。

## 1. 超级盘口逐笔（含当日竞价窗）—— DateTime=7176

请求（pageid=10443，route=0x01fc，flag14=0x0040，seq 滚动）：

```
CodeList=151(920118,);\r\nDataType=10,27,33,49,\r\n
DateTime=7176(1788830100-1788830700)\r\n
LackTime=0,0,0,0,0,0,0,0\r\npageid=10443\r\n
```

- 7176 = 窗口类型 tag；括号内为 **unix 秒** 区间；实测窗 1788830100-1788830700
  = 2026-09-08 09:15~09:25（早盘竞价 10 分钟）。用户滚动产生多个 600s 窗。
- dt：10(价) 27/33(买卖未匹配?) 49(累计量)。
- 与沪深 7176 逐笔回放同族，但 BSE 是**平文本窗**（沪深为嵌套 subframe pair）。
- 响应：flag=0x003a 表（code=920118, rsize=20, 抓包内 ×11；920119 ×1）。
  20B/行 ≈ time(4B) + 4×4B 字段。行数=窗内逐笔事件数（不连续、秒级）。

## 2. 历史分时主体 —— DateTime=8192(bar_index 窗)

请求（route=0x0112，benchmark 三联 CodeList，seq 滚动）：

```
CodeList=16(1A0002,);32(399002,);151(920118,);\r\n
DataType=207,13,19,54,204,10,203,210,23,202,209,22,201,208,6,1110,407,1111,\r\n
DateTime=8192(132520542-132520897)\r\nDTPrevOff=-61\r\n
LackTime=0,3,0,0,0,0,0,0\r\npageid=10443\r\n    （另有 pageid=10444 变体）
```

- 8192 = 0x2000 = 既有 `TIMELINE_PERIOD`；窗口是 **bar_index 区间**
  （132520897-132520542=355 = 一个交易日分钟跨度，与当日 132727390..132727744 同构）。
  **（已解，见 §5：bar 起点 = packed-date×2048+606；本条 132520542 回溯
  = packed(2026-06-03)，旧抓包另见 132530782 = packed(2026-06-08)，
  当时按日历分钟推算产生的 ~64127 差异源于错误假设，公式已由
  4 个标定日期 + 金样本逐字节锁定。）**
- dt 集与 4417 历史分时族一致（207/204/203/210/202/209/201/208 竞价族 + 13/19/10/22）。
- **与现有 `build_history_timeline_query`（4417）同构**：补 market=151 的
  benchmark 组合（16(1A0002,)+32(399002,)+151(code,)）与 route 即可复用。
- 响应：flag=0x0082 表（首 code 壳=1A0002，rsize=56，dual-shell 含 920118）。

## 3. 历史竞价逐笔 —— DateTime=6144(unix 窗)

```
CodeList=151(920118,);\r\nDataType=10,27,33,49,\r\n
DateTime=6144(1780449300-1780449900)\r\n   ← 历史日 09:15~09:25
LackTime=0,...\r\npageid=10444\r\n   route=0x0100
```

- 6144 = 历史竞价窗 tag；与 7176 同为 unix 秒窗。L2 复核包实测窗口：
  2026-06-08 / 2026-08-19 / 当日 09:15-09:25（用户在历史日历上跳转）。
- 响应疑为 flag=0x0096 大表（rsize=112, 28 字段, 29KB）待解。

## 4. 其他确认

- pageid 10443 与 10444 并存：10443=分时页族，10444=超级盘口/回放页族
  （dt 族相同：76,77,78,79 五档 / 24dt 分时 / 223-230 大单统计 / 331xxx 盘口）。
- 当日分时（已上线）：分钟K 合成（`_bse_timeline_from_kline`），官方同走分钟K。
- 历史分时的 bar_index 窗起点获取：翻页锚点=上一窗最早 bar_index（与 K 线翻页同则）。
- 832982 等老代码已停用（迁移 920xxx），服务端无数据属正常。

## 5. 实现状态（2026-09-08 晚更新：日期标定抓包后全部落地）

日期标定抓包 `captures_live/bse_920083_20260908_161904.pcapng`（L2 账号，
用户按 09-07/09-04/08-31/09-01 四个日期各开一次历史分时）**解决了 bar↔日期
映射**：每个历史视图同时发出 6144(unix 窗，日期直接可读) + 8192(bar 窗)，
配对后证实 **bar 起点 = packed-date 游标 `((y-1900)<<9|m<<5|d)×2048+606`，
与沪深 `date_to_normal_timeline_bar` 完全同公式**（09-07→132725342、
09-04→132719198、09-01→132713054、08-31→132708958，窗宽 355）。旧卡点
中"日历分钟推算不符"是因为错用了连续分钟假设——正确公式是 packed-date。
8192 请求实为 **嵌套三子帧**（wrapper 0x0012/0x0002 + 主体 0x0112/0x0009/
hist=0x20 + 尾帧 0x0212/0x0002），pageid=10444；响应个股表 0x0042/rs28/fc7
（字段 1,10,13,19,22,23,54），由既有 `parse_history_timeline_response`
按 normal_table 形状直接解析（241 行/日，槽位缺失集与沪深
`_HISTORY_TIMELINE_BAR_OFFSETS` 完全一致）。6144 响应也是 0x003a/rs20/fc5
表（非 0x0096），dc 高 16 位是修饰位（行数取 `dc&0xFFFF`）。

1. **已实现（活网验证通过 2026-09-08）**：BSE 超级盘口逐笔窗口
   - `superorder_protocol.build_bse_tick_window_query`（7176 平文本窗，
     route=0x01fc、[14:18]=40 00 08 1c、pageid=10443、滚动 seq）
   - `superorder_protocol.parse_bse_tick_response`（flag=0x003a 表 →
     `{code, ts, price, volume(=dt49差分), dt27/dt33}`；count=dc&0xFFFF）
   - `services/superorder.bse_tick_window`（BSE_MAIN 车道读循环，tag/route
     等变体透传）
   - `service_facade.superorder` market=151 分支；金样本
     `tests/test_bse_superorder.py`（920118 竞价 7 笔）。活网
     `/api/superorder/920118?start=09:15&end=09:25` 返回 7 笔，
     首笔 ts/价/量/dt27/dt33 与金样本逐值一致。
2. **已实现（活网验证通过 2026-09-08）**：BSE 历史分时 + 历史竞价
   - `history_timeline_protocol.build_bse_history_timeline_query`
     （pageid=10444 嵌套三子帧，双基准 16(1A0002,)+32(399002,)，
     seq 滚动 0x1155+2n）——与官方帧 body 逐字节一致。
   - `services/timeline.bse_history_timeline`（BSE_MAIN 车道读循环）。
   - `service_facade._bse_history_timeline`（241 行→minute_index 映射，
     失败/非交易日返回 []）接入 `intraday` 历史分支。
   - `service_facade._bse_opening_auction`（6144 竞价窗，tag=6144、
     pageid=10444、route=0x0100、[14:18]=00 00 00 18；当日与历史同协议，
     失败静默留空），接入 `intraday` 当日+历史分支（BSE 分时从此带
     09:15-09:25 竞价点，无尾盘竞价段）。
   - 金样本：`tests/test_beijing_timeline.py`（8192 请求 body、
     fixtures/history_timeline/bse_920118_20260904_8192.bin 241 行）、
     `tests/test_bse_superorder.py`（6144 请求 body、
     bse_920118_20260904_6144.bin 28 笔竞价）。
   活网 `/api/intraday/920118?trade_date=2026-09-04` 返回 241 连续 +
   28 竞价；08-31 返回 241+7（与抓包金样本一致）；当日 241+7
   （首笔 09:15:05@22.19 与 7176 金样本一致）。
3. **两个活网关键开关（2026-09-08 A/B 实测，缺一不可）**：
   - **init MarketDate 必须含 32(0)**：`stock_list_protocol.INIT_MARKET_DATE
     = "16(0);32(0);144(0);"`。同连接同请求字节下，仅
     `MarketDate=16(0);144(0);` 时服务端对含 151 的 CodeList 回
     `CodeListSize=0` 且不下发个股表；补 32(0) 后立即正常。MarketCode 与
     C-UACS 经同批实验确认不是开关。
   - **必须连 main.123ths.com 组**：ifindhq 组（原硬编码 MARKET_HOSTS）
     节点同样回 CodeListSize=0。新增 `ConnectionRole.BSE_MAIN` 车道
     （`resolve_market_hosts(..., main_only=True)`），BSE 历史分时/竞价/
     逐笔全部走该车道；MAIN 竞速可能落在 ifindhq 节点，不能复用。
4. 前端：SuperorderPage 逐笔图表用 `price/volume` 键，BSE 记录已对齐；
   历史分时复用现有 intraday 接口（trade_date 参数），TimelineChart 的
   opening_auction 点按 `time` 定位（timeToX 的竞价区 -15..0）。
   BSE 页面的沪深专属接口全部优雅降级（返回空、不抛 400 错误横幅）：
   `_register_l2_snapshot_code`（stock-ready）、`depth_quote`（十档）、
   `order_queues`（买一/卖一队列）、`_load_replay`（4096 回放索引）。

## 6. 超级盘口页面（SuperorderPage）现状与差距（2026-09-08 分析，未实现）

**为什么 BSE 页面上只剩「分时走势 · 大单金额」一张图**：该页每个区块都绑定
沪深 Level2 专有通道，北交所没有对应通道，本次只做了优雅降级（空态、
不再弹 400 错误横幅）。面板 ↔ 数据源对照：

| 页面区块 | 数据源 | 北交所 |
|---|---|---|
| 顶部「4096 盘口回放」图 | `/api/superorder-replay`（4096 全表，沪深 L2） | 无通道 → 0 快照 |
| 「光标时刻十档」 | 4096 快照 / WS 十档推送 | 无 → 空 |
| 「买一/卖一委托队列」 | `/api/order-queues`（7173/7174） | 无 → 空 |
| 「逐笔成交/挂单/撤单」明细 | `/api/superorder-window`（7169 成交 + 7175/7170/7171 挂撤单打包） | 挂撤单无通道，整体失败 |
| 「分时走势 · 大单金额」 | `/api/intraday`（统一三阶段） | **已支持** |

**北交所官方「超级盘口」的形态完全不同**：就是秒级逐笔列表
（`DateTime=7176` 平文本窗），无十档回放、无挂撤单队列。后端 7176 逐笔
已实现并活网验证（`/api/superorder/920118?start=…&end=…` 竞价窗 7 笔与
金样本逐值一致），但**页面 UI 没有接这条数据流**——明细表只消费
`windowData.trades`（沪深 7169/4096 窗口）与 WS 推送。

**接页面时的两个硬约束（实测）**：

1. **7176 窗口 <10 分钟服务端不回数据**：`7176(09:15:00-09:16:00)` 请求
   超时（`BSE tick window timed out after 2 unsolicited frames`），官方同款
   `7176(09:15:00-09:25:00)` 正常。页面按光标任意区间拉取时必须先对齐到
   官方 10 分钟桶（或由后端在 `bse_tick_window` 内扩窗到所在桶）。
2. **`/api/superorder-window` 对 BSE 整体失败**：它先取 7169 成交
   （BSE 走 7176 分支可用），再取 7175/7170/7171 挂撤单
   （`_superorder_l2_role(151)` 抛错）→ 502。BSE 要单独走
   `/api/superorder`，或让 window 端点对 151 只返回 trades 段。

**实现建议（下一步，未做）**：SuperorderPage 增加 BSE 分支——按 10 分钟桶
调 `/api/superorder` 取逐笔，渲染成列表（官方形态）＋可选价位散点图；
十档/队列面板对 BSE 保持"无此通道"空态。后端已就绪，纯前端接线 + 桶对齐。
