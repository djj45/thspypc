# 指数竞价轮询、行情推送与字段逆向（2026-08-11）

## 结论速览（经 `client.auction()` 真值对账确认）

- **共享 `097bd00f` 行情推送在集合竞价阶段确实持续下发**，本包共 1595 帧
  （沪链路 stream0=1307、深链路 stream1=288），其中生产解析器识别出 332 帧
  单指数快照；其余主要是个股/多代码行情，不能全部统计成指数帧。时间覆盖
  09:14:49 → 09:19:42。链路为 `8901 + pageid=5716/PushField
  CodeList(16:241;32:241) → CodeListSize 回执 → 097bd00f 指数快照`。这条链路是
  普通指数行情推送，不是竞价分时曲线的数据源。
- **同花顺客户端的指数竞价分时通过显式轮询更新，不是主动推送**。客户端在
  `pageid=6240` 上约每 10 秒发送一次
  `T_URL=/quote/auction/USH/USHI_1A0001.dat`（深市为
  `USZ/USZI_399001.dat`），服务端返回 `{"Auction":[...]}` JSON。JSON 每条记录
  直接携带 `markettime/newprice/leadprice/volume`，客户端收到后追加竞价点并重绘。
- **`097bd00f` 竞价阶段帧不带当前 `Auction.newprice`**。竞价撮合价变化（如
  1A0001 9:15=3962.03 → 9:25=3950.71）在整帧任意 offset（步进 1，ths-float
  解码）里都找不到。此前把 off39/59 命名为实时 `leadprice` 证据不足；它只是
  与早期领先价接近的近静态快照/参考价，不能替代 JSON 中随时间变化的
  `leadprice`。
- 真值对账（`client.auction()` 当日竞价全量记录）：

  | 指数 | newprice 9:15→9:25（真值，变化） | leadprice 9:15（真值） | 推送帧近静态值 | 结论 |
  |---|---|---|---|---|
  | 1A0001 | 3962.03 → 3950.71 | 3966.68 | off39=3966.59 / off55=3966.25 | 接近但不等于实时 leadprice |
  | 399001 | 14289.80 → 14266.44 | 14325.20 | off59=14316.96 | 接近但不等于实时 leadprice |
  | 399006 | 3523.35 → 3533.89 | 3533.78 | off59=3537.21 | 接近但不等于实时 leadprice |

- `parse_index_push` 已于本日盘后修复：竞价帧按 off33 代码判市场，沪深北均返回
  `phase="auction" + reference_price`；不再把近静态参考价命名成实时 `price`。
- `capture_index_push.py` 已改用生产解析器识别竞价布局，不再因 OHLC 哨兵丢弃
  1A0001/399001，也能识别北证50 117-121B 竞价帧。
- 分析器原先还会漏掉 `pageid=6240` 轮询：后续纯 `T_URL` 请求不带 `CodeList`，
  `_request_info()` 会直接返回 None；响应侧又只分析 `CodeListSize` 和
  `097bd00f`，没有解析 `Auction` JSON。这正是“客户端曲线在变、报告里却没有
  推送数据”的原因。

## 抓包与时间范围

主文件：

```text
captures_live/index_push_20260811_091425.pcapng
大小：5,673,196 bytes
有效报文时间：09:14:49.802 - 09:19:42.487（约 5 分钟，覆盖盘前 + 9:15 竞价开始后 ~4 分 42 秒）
网卡：iface 4 (WLAN 10.30.116.69)
TCP 流：7 条（stream 0=沪市主，stream 1=深市主，2-6=辅助）
```

真值来源：当日 11:34 用 `client.auction("1A0001"/"399001"/"399006")` 拉回的
竞价全量记录（每指数 20 条，9:15:27 → 9:25:00）。

## 1. 指数竞价分时的真实更新链路：约 10 秒轮询

上证指数 stream 0 的开盘竞价 `T_URL` 请求时间：

```text
frame 1720  t=22.165767s  初始上下文 + Auction T_URL
frame 2013  t=32.141854s  纯 Auction T_URL
frame 2222  t=42.146895s  纯 Auction T_URL
frame 2357  t=52.150753s  纯 Auction T_URL
frame 2544  t=62.146554s  纯 Auction T_URL
frame 2723  t=72.155853s  纯 Auction T_URL
```

除初始上下文外，相邻请求约 10.000 秒。对应响应通常在 25-35ms 后到达，例如
frame 2013（32.141854s）→ frame 2014（32.167194s）：

```json
{"Auction":[{"markettime":"1786410922","newprice":"3962.208523","leadprice":"3965.410889","volume":"107894820.000000"}]}
```

下一轮 frame 2223 已返回两个更新点，`newprice=3962.074713/3961.175353`。深证
stream 1 同样从 `USZI_399001.dat` 每约 10 秒查询，响应 JSON 结构相同。

注意区分两个节奏：**本包的网络轮询周期约 10 秒**；JSON 内 `markettime` 的新增
撮合点节奏由服务端决定，不能把撮合点间隔写成网络请求周期。

## 2. 帧长分布（重组完整 THS 帧）

`reconstruct_frames` 按 `fdfdfdfd` 外层包重组后，`097bd00f` 内层推送帧分布：

| stream | 帧长 | 数量 | 内容 |
|---|---|---|---|
| 0 (沪) | 277 | 258 | **单一指数快照**：1A0001×88, 1B0680×85, 1B0688×83, 1A0002×2 |
| 0 (沪) | 577/565 | 551/261 | 多代码打包帧（含 600021 等个股代码，疑似多指数合并） |
| 0 (沪) | 121 | 61 | 899050 北证50 紧凑帧（竞价版，比盘中 97-98B 长） |
| 1 (深) | 281 | 8 | **单一指数快照**：399001×4, 399006×4（60 秒/帧，慢速） |
| 1 (深) | 521 | 198 | **成分股/异动明细帧**（72 种 `!XXXXXX` 个股代码，非指数快照） |

要点：
- 沪市用 277B 单指数帧，每 ~2-3 秒一帧（快）。
- 深市用 281B 单指数帧，但**每 60 秒才一帧**（慢）；521B 高频帧是成分股明细，
  不含指数点位。
- 沪深推送频率差异显著，不是分析器漏抓。

## 3. 沪市 1A0001 字段布局（277B，已部分验证）

fixture（首帧，t=12.5s，相对 pcap 起点 09:14:49.8）：

```text
097bd00f7f7c0090 0653696f 97b48083 81808080 8101fc7d f717fee7 ffffff3f
10314130303031                                    ← off33: "1A0001" (6B ASCII)
73 0d06a0                                          ← off39: 近静态参考价=3966.59 (LE32 thsfloat)
00...0000 510d06a0                                ← off55: 第二快照价=3966.25
00...（off 63-77 全 0，竞价期 open/high/low/amount/volume 哨兵）
0d090000 8e000000 8f000000                        ← off 83-95：竞价实时区（每帧变）
f0b7c6 131dfaed ...                               ← off 90-150：非对齐变化区
```

| offset | 字段 | 编码 | 真值对账 |
|---|---|---|---|
| 0-3 | magic `097bd00f` | — | — |
| 14-21 | 市场标志 `80838180808081` + `01` | — | 沪市竞价末字节=01 |
| 33-38 | 代码 | 6B ASCII | "1A0001" |
| 39-42 | **近静态参考价（字段名待定）** | LE32 thsfloat | 3966.59，接近早期 leadprice 但不随 JSON 同步变化 |
| 55-58 | 第二快照价 | LE32 thsfloat | 3966.25（恒定） |
| 63-77 | open/high/low/amount/volume | LE32 thsfloat | 竞价期全 `FFFFFFFF`→0（未确定） |
| 83-150 | 竞价实时区 | 非对齐/未完全解 | 每帧变化，但**不含 newprice** |

**关键结论**：off 39 是近乎恒定的参考价，**不是**实时撮合价 `newprice`，也没有
足够证据把它正式命名为实时 `leadprice`。整帧扫描（步进 1，全 offset ths-float
解码）找不到 3962→3950 单调递减的字段。

## 4. 深市 399001 字段布局（281B，已部分验证）

fixture（首帧，t=55.9s）：

```text
097bd00f7f7c00a0 0653696f c1b48083 81808080 81028007 f717fee7 ffffff3f
20333939303031                                  ← off33: " 399001"? 实际 off33="399001"
c9eed6a4 b3c9                                  ← off39: GBK 名称
d6b8 00...                                      ← 名称填充 0x00 到 off59
a175dab0                                        ← off59: 近静态参考价=14316.96
00...（off 63-77 哨兵）
```

| offset | 字段 | 编码 | 真值对账 |
|---|---|---|---|
| 14-21 | 市场标志 `80838180808081` + `02` | — | 深市竞价末字节=02 |
| 33-38 | 代码 | 6B ASCII | "399001" |
| 39-46 | 中文名 | GBK | "深证成指"（off39-46，到 0x00） |
| 59-62 | **近静态参考价（字段名待定）** | LE32 thsfloat | 14316.96，接近早期 leadprice 但不随 JSON 同步变化 |
| 63-77 | open/high/low/amount/volume | LE32 thsfloat | 哨兵 0 |

**深市与沪市布局差异**：
- 沪市代码@33 → 参考价@39（紧邻，差 6B）
- 深市代码@33 → 中文名@39 → 参考价@59（中间多 20B 名称区）
- 这与盘中布局相反（盘中深市代码@22、价格@48；沪市代码@33、价格@39）。
  **竞价帧深市代码位置从 22 移到了 33**，与沪市对齐。

## 5. 已识别的 bug

### 5a. `index_push_protocol.py` 深市判别失效（已修复）

`parse_index_push` L112 要求 `body[14:22] == SZ_INDEX_FLAG`（
`8083818080808120`，盘中 fixture 末字节=`20`）。竞价帧末字节是 `02`（深）/`01`
（沪），不匹配。且深市竞价帧 `body[14:21]` 也等于沪市前缀，会落入沪市分支后
因 `code[1].isalpha()` 失败（399001 第二位是数字）而 `return None`。

**修复方向**：判别应基于代码本身（off33 的 6B ASCII），不依赖 body[14:22] 末字节。
或末字节改用掩码/范围判断。

**实现**：现按 off33 代码格式区分 `1A/1B` 与 `399`；深市名称区和 off59
参考价正常解析。盘中深市仍保留 code@22 的原布局。

### 5b. `capture_index_push.py` 分析器误标 899050（已修复）

`_push_info` L405 取 `codes[0]`，`_decode_ohlc` 只认 `code.startswith("899")`
的 compact 分支。1A0001/399001 走 standard 分支时 OHLC 全 0（竞价哨兵）→
`_decode_ohlc` 的 `all(0 < value < 10M)` 校验失败 → 丢弃。

**实现**：分析器复用 `parse_index_push()` 的 `phase` 结果；竞价帧输出参考价，盘中
帧才输出 OHLC。今日 pcap 重跑后识别 1A/1B、399 和 899 三套竞价布局。

### 5c. 899050 竞价帧（121B）ohlc=None（已修复）

竞价 899050 帧长 121B（盘中 97-98B），`_decode_bj50_compact` L371 要求
`len(body) in (97,98)`，121B 不匹配 → None。

**实现**：97/98B 继续按盘中 compact 字段解析；117-121B 按竞价名称区右移后的
`code+26` 返回 `reference_price=1122.875`，不误套盘中 `code+6`。

### 5d. `capture_index_push.py` 漏掉竞价 T_URL/JSON

原 `_request_info()` 只有发现指数 `CodeList` 才保留请求，所以首次上下文之后每
10 秒一次、不带 `CodeList` 的纯 `T_URL` 全被丢弃。响应分析也没有调用
`parse_index_auction_response()`，导致 `Auction` JSON 没进入报告。

已修复方向：从 `/quote/auction/(USH|USZ)/...dat` 反推出市场和代码，单独记录
`auction_requests`；解析响应中的 `Auction/CloseAuction` 并与同 stream 最近一次
同类型请求关联，报告请求间隔、响应延迟、记录数以及首末 `newprice`。

## 6. 实现与验证状态

1. **查询 API**：继续使用 `client.auction("1A0001")` / `client.auction("399001")`。
   市场码由 1A/1B/399 前缀自动推断；内部用 `pageid=6240` 上下文 + `T_URL` 做一次
   请求，返回当前已经产生的全部 `Auction` 点。本方法不是后台轮询器；需要实时
   追踪时由调用方约每 10 秒再次调用并按 `markettime` 去重。
2. **解析器**：`parse_index_auction_response()` 支持 `Auction/CloseAuction`、NUL 前
   缺根对象末 `}`、数字/字符串 `markettime`，并把抓包里的小数字符串
   `volume="107894820.000000"` 归一化为整数。
3. **离线验证**：2026-08-11 pcap 已证明请求节奏、请求响应配对和真实 JSON 字段；
   单元测试已加入 frame 2014 的真实字段值。因今天已过竞价时间，仍需在
   **2026-08-12 09:15-09:25** 运行
   `uv run python tests/verify_index_auction_live.py` 做活网端到端回归。脚本只调用
   一次 `get_client()`，复用同一个 `THSClient` 查询三大指数两轮，不重复登录。
4. **推送解析已修复**（§5a）：off33 代码判市场，兼容竞价帧代码位置右移
   （22→33）和深市中文名区；真实沪/深/北竞价帧均加入离线契约测试。
5. **抓包分析已修复**（§5b/§5c）：竞价参考价和盘中 OHLC 分阶段展示，北证
   117-121B 单独解析；今日 pcap 已成功重跑并重新生成报告/JSONL。
6. **非对齐变化区 off 83-150**（沪）仍未命名，但已用同包 6240 JSON 真值确认
   整帧不存在可直接替代 `Auction.newprice` 的 THS-float 字段。它不阻塞生产功能：
   竞价分时继续以 6240 JSON 为唯一数据源；该区只保留为可选协议研究项。
7. **离线回归**：指数推送、十档解析和客户端服务上下文定向测试合计
   `107 passed`；排除已知不再返回数据的 HFD1 全市场旧契约后，全量为
   `527 passed, 17 skipped, 1 deselected`（2026-08-11 盘后）。

## 7. 产物

- pcap：`captures_live/index_push_20260811_091425.pcapng`
- 分析报告：`captures_live/index_push_20260811_091425_index_push_report.json`
- 逐帧 JSONL：`captures_live/index_push_20260811_091425_index_push_frames.jsonl`
- 本次逆向脚本：`tests/_dde_auction_push_decode.py`
- 次日活网验证：`tests/verify_index_auction_live.py`
- 真值：当日 `client.auction("1A0001"/"399001"/"399006")` 各 20 条

## 8. 2026-08-12 执行清单

### 8.1 09:14 前准备

1. 官方同花顺客户端保持完全退出；不要提前打开板块或指数页面，保留当天第一次
   打开时的板块成分股增量推送触发机会。
2. 准备两个 PowerShell 窗口。窗口 A 在 09:14:30 左右启动一段覆盖到 09:26 的
   8901 原始抓包：

   ```powershell
   uv run python tests/capture_index_push.py --iface 4 --duration 720
   ```

   若次日网卡编号变化，先不传 `--iface` 重新选择，不能盲用 4。该 pcap 同时保留
   MAIN、上海 Level2 和深圳 Level2 的 8901 流量，后续既能分析指数 6240，也能
   离线检查首次打开板块时的成分股增量帧。
3. 全程只让一个程序占用 Level2 账号。不要同时登录官方客户端和 thspypc，也不要
   为沪深市场各建一个新客户端；所有验证脚本都只调用一次 `get_client()` 并复用
   获胜连接/客户端。

### 8.2 09:15-09:25：指数竞价查询与官方客户端抓包

1. 窗口 B 在 09:15 后先运行：

   ```powershell
   uv run python tests/verify_index_auction_live.py --repeat 2 --interval 10
   ```

   成功标准：1A0001、399001、399006 均返回非空 `Auction`；`markettime` 唯一，
   `dt10/lead_price/volume` 类型正确；第二轮能报告新增时间点。脚本结束会统一关闭
   缓存客户端，不重复登录。
2. 脚本退出后再启动官方同花顺客户端。第一次进入看盘时立即打开目标板块的成分股
   页面并记录操作的墙钟时间，随后依次打开上证指数、深证成指、创业板指竞价分时；
   每页至少停留 20-30 秒，最后停在一个指数页直到 09:25 后。
3. pcap 成功标准：
   - 沪市出现 `USH/USHI_1A0001.dat`，深市出现
     `USZ/USZI_399001.dat` / `USZI_399006.dat`，约 10 秒轮询；
   - 6240 响应能解析 `Auction.newprice/leadprice/volume`，覆盖至 09:25；
   - 首次打开板块附近保存请求、回执和随后服务端帧的完整时间窗，不因当前分析器
     尚未分类就删除未知帧；
   - 1A/1B 指数位于上海 Level2 流，399 指数位于深圳 Level2 流。

### 8.3 09:30 后：十档生产 API 活网验收

1. 先完全退出官方同花顺，再运行：

   ```powershell
   uv run python tests/verify_depth_push_live.py --codes 600519,000001 --seconds 45
   ```

2. 成功标准：沪深两只股票都收到队列事件和按代码回调；连续竞价记录各有 10 档
   `bids/asks`；`latest_depth()` 与最后事件一致；退订最后一只后读取线程及两个 L2
   通道关闭。600519 自动走上海 Level2，000001 自动走深圳 Level2。
3. 当前 `depth_unsubscribe()` 是经过明确记录的本地过滤语义：仍有其他代码时不发送
   未经抓包确认的单码退订帧。明日主要验收换股、本地退订、断线清理和事件频率，
   不把“必须发现 wire unsubscribe”作为通过条件。

### 8.4 P1：71B 触发链（不与上述登录并行）

若 P0 均完成且账号会话已稳定，再按 `HANDOFF_71B_TICK_PUSH_20260807.md` 执行一次：

```powershell
uv run python tests/_replay_71b_subscribe.py 002384 --replay-raw --seconds 30
```

触发则保存首个 71B 前的最小请求集合；未触发则保存完整输出后停止，不在短时间内
循环新建 8901 登录。HFD1 全市场旧契约和 4096 多日覆盖都不是明日待办。
