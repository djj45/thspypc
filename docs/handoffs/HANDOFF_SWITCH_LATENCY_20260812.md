# 切股票延迟优化(2026-08-12)

## 背景

切一只股票触发 6 个请求(quote + auction + timeline + closing_auction + kline + depth),
后端 runtime 单连接串行。各接口实测耗时(000001,优化前):

```
quote 0.01s | depth 0.02s | timeline 0.13s | closing_auction 0.04s
auction 12-15s ⚠(盘后死等)  kline 2.0-2.4s ⚠(固定等待)
```

auction 和 kline 是两个大头。本轮定位并修复了三个根因。

## 修复 1:auction 盘后死等 → L2 历史路径

**根因**:`services/auction.py` 用 `_is_historical_date(trade_date)` 判断路径。
盘后 `trade_date=None` → `resolve_trade_date` 返回今天 → `_is_historical_date(今天)=False`
→ 走 L2 实时 `pageid=1334` → 非竞价时段服务端不响应 → 死等 `timeout=12s`。

**修复**:改用"是否在竞价时段"判断,而非"日期是否历史"。

```python
# 新增 _in_auction_session(now):判断 9:15-9:25(周一到周五)
elif _is_historical_date(trade_date) or not _in_auction_session():
    frame = _build_l2_history_auction_bundle(...)  # L2 历史 pageid=4417
else:
    frame = build_auction_query(...)  # L2 实时 pageid=1334(仅 9:15-9:25)
```

- 9:15-9:25 实时竞价:走 L2 实时 1334(拿实时撮合)
- 其它时段:走 L2 历史 4417(拿当日完整序列,实测 ~39ms)
- **保持 L2 拓扑**(shlv2/szlv2),不逃到 MAIN(一度考虑过 MAIN 历史 9355,11ms 但偏离拓扑,已放弃)

**探针验证**(`tests/probe_auction_offsession.py`):实时 1743ms → 历史 39ms。

⚠ 修复过程中一度走偏(想逃到 MAIN 历史 9355),经拓扑纠正(同花顺个股业务全走 L2)
后回到 L2 历史路径。教训记录在 `HANDOFF_KLINE_FAST_PATH` 顶部。

## 修复 2:MAIN 登录失败 → 改优先 ifindhq(与同花顺一致)

**根因**:`protocol.py:resolve_market_hosts` 自 2026-08-06 起强制优先
`main.123ths.com`(为北交所 market 151)。但 DNS 抓包 + nslookup 铁证:

- 同花顺客户端查 `ifindhq.123ths.com`,**不查 `main.123ths.com`**
- 当前 passport 不下发 main 域名
- `main.123ths.com` 的 5 个 IP(8.134.108.168, 218.245.102.0, 139.9.188.254,
  8.134.116.126, 1.1.181.10)全部 VerifyCode=-1(被服务端拒绝)
- `ifindhq.123ths.com` 的 12 个 IP(1.94.9.136, 8.132.233.199 等)可用
- **两组 IP 零重叠**

thspypc 强制补 main → 拿到被拒 IP → 登录全失败。

**修复**:改成跟着 passport 走,优先 ifindhq(与官方客户端 DNS 抓包一致),main 仅作回退:

```python
domains = fallback_domains if fallback_domains else main_domains  # ifindhq 优先
if not domains:
    domains = ["ifindhq.123ths.com"]  # passport 都没有时硬编码 ifindhq
if main_domains and main_domains[0] not in domains:
    domains = domains + main_domains  # main 作为回退追加(北交所兜底)
```

**验证**:实测 `connected_ip = 8.132.233.143`(ifindhq 的 IP),日志 `ifindhq fallback → 12 个 IP`。
不再出现 main 的 5 个坏 IP。

DNS 抓包方法论:`tshark -f "tcp port 80 or udp port 53" -Y "http or dns"` 抓同花顺启动流量,
直接看它查什么域名、得什么 IP。比猜 pcap 可靠。

## 修复 3:K 线固定 2s 等待 → 收满即返回

**根因**:`services/kline.py` 收到首个含 `hd3.1` 的响应后,无条件 `sock.settimeout(2.0)`
继续读(为了兼容少数服务器把大响应拆成多个 hd3.1 分片)。但正常响应一个帧就含完整的
`count+1` 根,那 2s 是纯等待。

**修复**(`kline.py`):

```python
KLINE_FRAGMENT_TAIL_TIMEOUT = 0.02  # 短历史尾读仅保留 20ms 分片兼容窗口

if len(records) >= count + 1:
    break  # ★ 收满 count+1 根立即返回,不再等待
sock.settimeout(KLINE_FRAGMENT_TAIL_TIMEOUT)  # 不足才短暂尾读(兼容分片)
```

**效果**(连接预热后第二轮):

```
000001: 460ms(首次该市场,含 shlv2/szlv2 建连)
000002:  13ms  ← 同市场复用
600519:  15ms  ← 沪市复用
```

从 2.4s 降到 13ms(复用连接)。首次某市场仍含 L2 建连 + 通行证重试开销(~0.5-1.6s)。

## 仍存在的延迟(后续)

| 项 | 现状 | 说明 |
|----|------|------|
| L2 首次登录通行证重试 ~1.5s | 未修 | MAIN 消费通行证后,L2 用同一通行证 VerifyCode=-1,触发重新 HTTP 鉴权。AGENTS.md 第 4 条的协议限制。可考虑 get_client 时预建 L2 |
| kline 单次请求(冷连接)~2.4s | 已大幅缓解 | 主要由固定 2s 等待造成(修复 3 已解决);连接预热后 13ms |

## 工具产出

| 文件 | 作用 |
|------|------|
| `tests/probe_auction_offsession.py` | 竞价三路径计时(实时/历史/对照) |
| `tests/probe_kline_datatype.py` | K线 DataType/period 隔离探测(monkeypatch) |

## 测试

- `test_auction_service.py`:新增 `_in_auction_session` 边界 + 非竞价走 4417 + 竞价走 1334
- `test_market_host_resolution.py`:重写反映 ifindhq 优先(4 测试)
- `test_kline_service.py`:新增完整窗口只读一帧的测试
- 全量 538 passed + 19 skipped( auction 29 + host_resolution 4 + kline 14 + 其它)

## 2026-08-12 第四阶段：页面聚合请求

新增 `/api/market_view/{code}`。浏览器切换股票时不再并发发送
`quote + intraday + kline + depth` 四个 HTTP 请求，而是发送一个聚合请求。
后端内部按物理连接拆成两条并行 lane：

- MAIN lane：`quote → depth`
- 对应市场 L2 lane：`intraday → kline`

每条 socket 内保持单读者串行，两条独立 socket 并行。前端把 K 线周期和复权状态提升到
`StockProvider`，四个面板共享同一份 `market_view`；同时合并相同参数的在途 Promise，
避免 React StrictMode 开发模式重复挂载造成重复请求。

真实热态连续切换各 50 只（单 HTTP、每次四类数据均完整）：

```
SH: avg=58.3ms median=57.7ms p95=62.1ms max=88.2ms >100ms=0
SZ: avg=49.3ms median=49.3ms p95=51.1ms max=60.5ms >100ms=0
```

`Server-Timing` 会同时记录 `main_*` 与 `sh_l2_*` / `sz_l2_*`，可直接确认两条
lane 没有互相排队。全量测试：572 passed + 19 skipped；前端生产构建通过。

## 2026-08-13 第五阶段：复刻 PC 客户端分阶段首屏

保留 `/api/market_view` 兼容接口，页面改用三阶段调度：

1. `/api/market_view_fast/{code}`：MAIN 上 `quote → depth`，与市场 L2 上实时
   `1334/8192 timeline` 并行；返回后立即显示首屏。
2. `/api/intraday_auctions/{code}`：补充早盘、尾盘竞价并合并到同一张分时图。
3. `/api/kline/{code}`：竞价请求结束后才进入相同市场 L2 lane；切周期只重拉 K 线。

前端用请求代次阻止旧股票结果回写，并合并 StrictMode 下的相同在途请求。若切股发生
在 fast 尚未完成时，旧股票的竞价和 K 线不会发送。已发送的 socket 请求不可中途取消，
但其结果也不会覆盖新股票。

时段边界：9:15前 fast 不请求实时 `timeline`，避免服务器保留的上一交易日241点被
误当作当天数据；随后 `intraday_auctions` 按默认日期语义回退最近交易日，并一次返回
该日早盘竞价、241点盘中分时和尾盘竞价。周末/节假日同样显示最近交易日全量数据。
9:15–9:30 只补当天已产生的早盘竞价；9:30后 fast 才请求当天盘中分时；
14:57后竞价补全包含尾盘阶段。

2026-08-13 预盘热态实测：fast 后端约 19ms（行情+盘口，分时为空），日 K 后端
约 13–15ms。盘中 fast 目标由抓包和单接口实测约束为 20–30ms。全量测试：
576 passed + 19 skipped；前端生产构建通过。

## 2026-08-13 第六阶段：消除 MAIN 约 70ms 的偶发长尾

### 现象

`market_view_pipeline()` 已经把行情与五档盘口请求先后写入 MAIN socket，再由一个
dispatcher 统一读帧。正常热请求约 18ms，但无间隔连续切股时偶尔出现 56–70ms：

```text
median ≈ 17.7ms，max ≈ 57ms
```

这不是解码长尾。逐帧打点显示，慢请求的 CPU 时间接近 0，短记录补读
`_repair_short_record()` 约 0.01ms；真正的等待集中在第一个行情响应：

```text
quote frame: 约 55.8–56.5ms
depth frame: 约 0.02–0.09ms
```

两个响应几乎同时到达，符合 Nagle 与对端 delayed ACK 组合产生的约 40ms 等待。
Python 创建的 TCP socket 默认 `TCP_NODELAY=0`，而 pipeline 原先连续执行两次
`sendall()` 发送两个小请求；第二次写入有机会被内核暂存到首个小包获得 ACK 后。

### 可逆 A/B 证据

在同一 MAIN 长连接、同一进程中，用 `600519` / `000001` 交替 500 次，仅切换
`TCP_NODELAY`：

| 配置 | 中位数 | p95 | 最大值 | >50ms |
|---|---:|---:|---:|---:|
| 默认 `TCP_NODELAY=0` | 17.70ms | 19.09ms | 57.34ms | 2/500 |
| 临时设置 `TCP_NODELAY=1` | 9.10ms | 10.71ms | 13.97ms | 0/500 |
| 恢复 `TCP_NODELAY=0` | 17.77ms | 20.81ms | 57.04ms | 3/500 |

恢复默认后长尾重新出现，排除了股票、解析器和服务器节点偶发变化等解释。

### 修复

1. `ManagedConnection` 收编任何真实行情 socket 时设置
   `TCP_NODELAY=1`。这个入口覆盖 MAIN、KLINE_FAST、SH_L2、SZ_L2，以及断线后
   重新建立并被连接管理器收编的新 socket；不需要在各登录分支重复设置。
2. `ResponseDispatcher.submit()` 将同一批 pipeline 请求拼接后执行一次
   `sendall()`，保留每个请求自己的换行策略。这样减少系统调用，也避免同一批次的
   第二个小请求独立进入 Nagle 状态。
3. 不支持 `setsockopt()` 的测试替身或包装 socket 保持兼容；系统不支持低延迟选项时
   仅放弃该提示，不影响已经成功建立的行情连接。

### 修复后活网验证

2026-08-13，MAIN 节点 `139.159.135.214:8901`，沪深两只股票交替 500 次：

```text
TCP_NODELAY=1
n=500 avg=11.71ms median=11.38ms p95=14.45ms p99=16.20ms
max=17.52ms >30ms=0 >50ms=0
```

结果说明本地可控的 70ms 长尾已消除。以后若再次看到高延迟，应先根据逐连接
`Server-Timing` 区分 MAIN、KLINE_FAST、SH_L2/SZ_L2；单只股票或特定服务器完全
不响应导致的秒级超时属于另一类问题，不能与本次 TCP 小包长尾混为一谈。

新增/更新的回归覆盖：

- `test_managed_connection_disables_nagle`：连接收编时开启 `TCP_NODELAY`；
- dispatcher pipeline 单次写入及逐请求换行策略；
- quote/depth 响应乱序时仍能正确分派。

全量测试：590 passed + 19 skipped。
