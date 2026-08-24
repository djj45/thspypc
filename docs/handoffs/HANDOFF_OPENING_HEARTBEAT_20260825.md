# 2026-08-25 开盘交接：心跳响应与实时页面验收

> 执行日期：2026-08-25（周二）
>
> 当前分支：`codex/refactor-protocol-foundation`
>
> 详细历史：[`HANDOFF_DXJL_NAV_ROBUSTNESS_20260819.md`](HANDOFF_DXJL_NAV_ROBUSTNESS_20260819.md)

## 一、当前结论

2026-08-24 已完成心跳响应校验的 observe-only 实现：

- 3 秒长心跳继续保活；60 秒发送一次官方短探针。
- 短探针 wire shape 为 `09 + 3B little-endian monotonic-ms token + 00`，不带尾部换行。
- 兼容 8901 reader 得到的 4B ACK `09 00 00 00` 和 9601 reader 得到的 5B ACK
  `09 00 00 00 00`。
- 12 秒无下行记一次 miss，连续两次标记 `unresponsive`；探针后的业务下行也能证明
  socket 活跃。业务 lane 忙而没有实际发送探针只计 `skipped_busy`，不计 miss。
- Dispatcher/既有推送线程仍是唯一 reader；心跳线程不直接 `recv`，不会与业务抢帧。
- `/api/status` 暴露 `heartbeat.lanes`。当前 `mode=observe_only`，只记录状态，不自动
  关闭、重新登录或恢复订阅。

60 秒周期不是猜测：`captures_live/kanpan_20260824_103723.pcap` 的90秒官方样本中，
每条新建8901连接只在约第60秒出现一次短探针。曾以30秒试跑时，服务端严格隔次
响应，导致 `healthy/suspect` 交替，故已校正为60秒。

最终离线结果：

- Python：`725 passed, 20 skipped`
- Web：`npm run build` 通过（653 modules，仅既有 chunk-size 提示）
- `git diff --check`：无空白错误，仅 Windows LF/CRLF 提示

## 二、8月24日活网证据

### 14:10~15:50 第一轮

- 仅运行一个8765后台，MAIN/SH_L2/SZ_L2成功 ready。
- 旧30秒配置下，MAIN共6次短探针收到3次显式ACK，证明短探针发送、Dispatcher读取、
  ACK识别和状态恢复链路真实可用。
- 后台静置到收盘后，旧MAIN最终累计55次miss。15:46的行情请求在旧socket上收到
  `WinError 10054`；现有恢复路径重新HTTP鉴权并换新MAIN后才查询成功。
- 心跳监控在下一3秒tick切换到 `generation=2`，旧socket的迟到结果没有污染新代状态。

### 15:52~15:56 第二轮（60秒配置）

- SZ_L2首次 `VerifyCode=-1` 后执行唯一一次fresh HTTP鉴权，fresh Passport登录成功；
  没有出现第二次 `-1`。
- MAIN连续两轮短探针无响应，被标记 `unresponsive`。随后行情请求在旧连接上也因
  `dispatcher did not complete: quote:600519` 超时；自动重新鉴权换新MAIN后重试成功。
- 因此两次miss准确预警了本轮僵死MAIN。最终行情成功来自新连接，不能写成旧socket
  收到业务下行后自行恢复。

这些证据足以保留observe-only实现，但还不足以开启自动淘汰：60秒配置尚未在健康的
交易时段连接上连续收到两轮ACK。

## 三、登录硬规则

1. 只启动一个后端；不要同时运行官方客户端、独立活网脚本或第二个 `THSClient`。
2. 不手写串行socket登录；必须复用 `get_client()` / `login_socket_for_domains()`。
3. 一个Passport首次并发竞速出一个 `VerifyCode=0` 后已经被消费；后续必须复用获胜
   socket，不能拿同一Passport登录第二条8901连接。
4. 首次 `VerifyCode=-1` 允许重新HTTP鉴权一次。fresh Passport仍返回 `-1` 时立即停止
   本轮：关闭后台，不启动Vite，不执行页面/API复验，不尝试第三代票据或下一节点。

## 四、8月25日开盘执行顺序

### 09:10~09:14：唯一实例和基线

1. 确认8765/5173无监听，并确认没有官方同花顺客户端或遗留测试进程。
2. 启动唯一后端：

   ```powershell
   $env:PYTHONPATH='src'
   py -m thspypc.server --host 127.0.0.1 --port 8765
   ```

3. 读取一次 `http://127.0.0.1:8765/api/status`，记录：
   `server`、`preheat`、`heartbeat.probe_interval_seconds` 和所有lane初值。
4. 必须看到 `probe_interval_seconds=60`。若出现第二次 `VerifyCode=-1`，按上节立即停止。

### 09:15~09:18：P0 心跳验收

后端保持静置至少130秒，期间每20~30秒保存一次 `/api/status`。MAIN通过条件：

- `generation` 始终不变；
- `probes_sent >= 2`；
- `explicit_acks >= 2`；
- `consecutive_misses == 0`；
- 最终 `state=healthy`；
- 日志无 `WinError 10054`、Dispatcher reader异常或额外登录。

若只收到业务帧而没有显式ACK，记录 `responses/inbound_frames/last_rx_age_ms`，但不要把
它写成“短ACK连续两轮通过”。若出现miss，先保存完整状态和日志；observe-only不会
自动处理，不要立即打开多个API并发刺激连接。

### 心跳通过后：实时页面回归

只有P0完成且登录规则未触发停止时，才启动唯一Vite并执行：

1. `601318&view=timeline` 冷启动：`stock-ready`、分时、十档、7169和WebSocket均无
   5xx；十档20行；逐笔时间持续推进；10秒内0 WebSocket重连。
2. 切到 `000001`：当前日4096 `/superorder-replay` 必须 `count > 0`，超级盘口能渲染
   十档、委托队列和连续交易窗口。
3. 再切回 `601318`：所有请求保持200，实时流继续推进，不能出现旧股票帧污染。
4. 打开短线精灵/板块功能后再次查看 `/api/status`，记录实际建立的
   `realorder`、`board_stats`、`sh_l2`、`sz_l2` lane；未激活的lane保持idle不算失败。

## 五、通过与停止标准

可以标记“60秒心跳盘中通过”必须同时满足：唯一实例、没有第二次`-1`、同一MAIN
generation连续两轮显式ACK、0 miss。页面回归与心跳验收分别记录，不能用页面200
替代ACK通过。

以下任一情况立即停止新增动作并保留现场：

- fresh Passport再次 `VerifyCode=-1`；
- generation意外变化或日志显示后台自行新建了额外socket；
- 连续两次miss后业务请求也在旧socket超时；
- 出现抢读、帧错位、持续5xx或WebSocket重连风暴。

自动淘汰/重连仍是后续任务。即使明日observe-only验收通过，也应先根据各lane实测
结果设计“摘除旧socket → fresh auth → 恢复订阅”的单次恢复状态机及其测试，不要在
开盘过程中直接打开自动重连开关。

## 六、收尾

验收结束后正常关闭浏览器、Vite和后台，确认8765/5173无监听；把时间、节点、各lane
最终计数、Passport拒绝次数、页面HTTP/WebSocket结果追加到本文件和详细交接文档。
