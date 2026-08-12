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
KLINE_FRAGMENT_TAIL_TIMEOUT = 0.25  # 尾读窗口从 2.0s 降到 0.25s

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
