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
- 12 秒无下行记一次 miss：首次标记`suspect`，连续两次标记`ack_silent`；短ACK
  静默不再等同断线。只有明确的socket读写/关闭错误才标记`unresponsive`。探针后的
  业务下行也能证明socket活跃；业务lane忙而没有实际发送探针只计`skipped_busy`，
  不计miss。
- Dispatcher/既有推送线程仍是唯一 reader；心跳线程不直接 `recv`，不会与业务抢帧。
- `/api/status` 暴露 `heartbeat.lanes`。当前 `mode=observe_only`，只记录状态，不自动
  关闭、重新登录或恢复订阅。

60 秒周期不是猜测：`captures_live/kanpan_20260824_103723.pcap` 的90秒官方样本中，
每条新建8901连接只在约第60秒出现一次短探针。曾以30秒试跑时，服务端严格隔次
响应，导致 `healthy/suspect` 交替，故已校正为60秒。

最终离线结果：

- Python：`730 passed, 20 skipped`
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

## 七、2026-08-25 09:11~09:22 实盘结果：短ACK不能单独判死

- 09:11确认8765/5173无监听、无官方同花顺或其他Python活网进程，只启动一个8765。
  SZ_L2首次`VerifyCode=-1`后执行唯一一次fresh HTTP鉴权并成功；MAIN、SH_L2、SZ_L2
  均ready+initialized，没有第二次`-1`。MAIN节点`8.134.121.153`、generation始终为1。
- 09:12~09:15的前4轮60s短探针（含09:15后的响应窗口）全部无ACK；长心跳仍每3秒
  成功写入。随后只发一个`600519`行情请求，同一MAIN在12.30s内返回1行，价格
  1305.10；日志没有传输异常、重新鉴权或换节点。紧接着第5轮短探针约8秒后收到本轮
  唯一一次显式零token ACK，状态恢复healthy。
- 第6、7轮又连续miss并进入unresponsive。09:19:51再次用同一MAIN查询`600519`，
  1.97s成功返回，server和generation均未变化，业务下行令monitor恢复healthy。之后
  第8~10轮仍未收到显式ACK，最终统计为`probes_sent=10 / explicit_acks=1`，但同一
  socket两次业务请求均成功，不能把9次短探针静默解释为死连接。
- 结论：当前短探针对真死连接有灵敏度（8月24日旧MAIN连续miss后业务也10054/超时），
  但对健康连接缺乏特异性。`consecutive_misses>=2 => unresponsive`会稳定误报，必须
  保持observe-only；自动淘汰/重新登录仍禁止启用。实盘后已把“短ACK静默”和“连接
  已失效”拆成两个状态：短探针miss最多标记`ack_silent/suspect`，只有传输层读写或
  socket关闭错误才标记`unresponsive`并进入恢复候选。
- 因P0“同generation连续两轮显式ACK”未通过，本轮没有启动Vite，也没有执行多页面/
  WebSocket并发回归。09:22正常关闭唯一后台；09:28复核8765/5173均无监听。

## 八、09:28后判定语义修正

- `HeartbeatMonitor.fail_probe()`第二次及后续超时现返回`ack_silent`，不再返回
  `unresponsive`；显式ACK或任意合法业务下行仍恢复`healthy`并清零连续miss。
- 新增`note_transport_failure()`；MAIN/KLINE/L2/REALORDER/BOARD_STATS的明确
  `OSError`、连接关闭或非超时Dispatcher错误会记录`transport_failures`和
  `last_transport_failure_age_ms`，此时才进入`unresponsive`。普通Dispatcher响应
  deadline属于探针静默，不算传输失败。
- Web状态类型已加入`ack_silent`及两项传输失败指标。新增回归锁定：两次探针超时、
  真实ConnectionError、旧socket隔离及业务下行恢复。最终Python全量
  **728 passed、20 skipped**；Web生产构建通过（653 modules，仅既有大包提示）。
- 当前仍为observe-only。该修正消除了今天已证实的假“断线”语义，但没有把短ACK
  变成可靠探针；自动恢复前仍需设计一次同socket、低副作用的业务复核门。

## 九、09:37~13:24 修正后实盘复验与午后恢复

### 心跳语义与通道证据

- 09:37第一次重启后MAIN已`VerifyCode=0`，但初始化超时。该Passport已经消费，未调用
  `/api/connect`复用旧票据；直接关闭整个进程，09:42由新进程重新HTTP鉴权。
- 09:42新进程MAIN、SH_L2、SZ_L2全部ready。MAIN同一generation连续两次短探针均收到
  显式ACK：`probes_sent=2 / responses=2 / explicit_acks=2 / misses=0 /`
  `transport_failures=0`，满足本文件P0的“同代两轮ACK”标准。
- 进程在午休期间保持运行。13:14恢复页面时，旧连接的真实关闭错误被正确记录为
  `unresponsive + transport_failures=1`；恢复后的MAIN切为generation 2、节点
  `139.9.188.254`，SH_L2/SZ_L2也换代并恢复healthy。新MAIN随后再次达到2/2显式ACK，
  证明代际隔离和修正后的状态恢复在实盘成立。
- 打开看盘页时SH_L2、SZ_L2各出现一次旧Passport的`VerifyCode=-1`，每条lane都只进行
  一次fresh HTTP鉴权并成功，没有第二次`-1`。REALORDER实际建立并得到1/1显式ACK；
  BOARD_STATS没有出现在状态中，因此本轮不宣称已验证。

### 页面回归

- `601318`分时页十档20行、逐笔300行正常，成交时间持续推进；HTTP首屏接口全为200，
  WebSocket accepted/open。
- 切到`000001`超级盘口后，当前日4096返回400个快照，十档、买卖队列和连续成交窗口
  均正常渲染；再回`601318`后没有旧股票数据污染。
- 看盘页板块、短线精灵、榜单和批量行情均正常返回。午后冷恢复时曾出现一次
  `/api/market_view_fast/601318` 502，紧随其后的同接口及其他首屏请求全部恢复200；
  页面没有持续错误或重连风暴。

### 本轮发现并修复的两个恢复缺口

1. Header原来只在React首次挂载时读取一次`/api/status`，MAIN换节点后仍显示旧节点
   `218.245.102.0`，而后端已经是`139.9.188.254`。现改为每15秒刷新，并在窗口focus或
   从后台恢复可见时立即刷新；组件卸载会清理timer/listener。
2. 长时间空闲后的第一个`market_view_fast`可能正好撞到失效MAIN并向浏览器暴露一次
   502。该幂等首屏接口现在允许一次同请求传输恢复：第一次`OSError`后由
   `ThsRuntime`按既有单客户端路径标记旧MAIN失效，下一次调用才执行正常重连。若该次
   重连失败（包括内部fresh Passport后仍失败），立即返回502，不再进行第三次尝试。
   其他接口和非传输错误没有扩大重试范围。

13:20用上述最终代码再次启动唯一后端：MAIN `8.134.108.168`，SH/SZ预热均ready，
三条lane均generation 1且`transport_failures=0`。`601318`分时页显示当前节点，十档和
逐笔正常，成交时间从13:22:12推进到13:22:44；日志确认WebSocket保持open，且15秒
`/api/status`轮询持续200。该进程随后MAIN统计为`probes=2 / responses=2 /`
`explicit_acks=0 / inbound_frames=4 / misses=0 / healthy`：本节点两次短探针窗口由业务
下行证明存活但没有显式零token ACK，再次说明不能把ACK静默当作传输故障。

最终离线回归：Python **730 passed、20 skipped**；Web生产构建通过（653 modules，仅
既有chunk-size提示）；`git diff --check`无空白错误，仅Windows LF/CRLF提示。新的
冷恢复单次重试已由两条离线契约覆盖（成功恢复；一次重连失败后立即停止），但尚未为
验证它而主动破坏当前实盘socket。

## 十、13:32~13:34 BOARD_STATS 独立通道验证

- 验证前确认8765/5173无监听、无其他thspypc活网进程。诊断只使用
  `thspypc.testing.get_client()`返回的单个缓存客户端；MAIN登录
  `8.134.108.168:8901`成功。
- MAIN的Passport已被其`VerifyCode=0`消费，因此打开新的BOARD_STATS socket前显式
  执行一次`authenticate(force=True)`，取得generation 2 fresh Passport。该票据首次
  登录`8.132.233.77:9601`即`VerifyCode=0`，没有发生`-1`。
- `board_stats_interval(["881121", "885897"], timeout=15)`等待15.14秒后返回空列表。
  ConnectionManager中的`ConnectionRole.BOARD_STATS`仍为active，故结论是“通道登录
  成功、statscalc业务无响应”，不能把空列表解释成登录失败或业务成功。
- BOARD_STATS lane只在第一个60秒短探针时注册。首轮无响应后状态为`suspect`；第二轮
  收到显式零token ACK并恢复`healthy`。最终为`generation=1 / probes_sent=2 /`
  `responses=1 / explicit_acks=1 / inbound_frames=1 / consecutive_misses=0 /`
  `transport_failures=0`。因此9601登录、Dispatcher读响应、ACK识别和状态恢复链路均
  已获活网证据。
- 验证进程随后调用`close_all_clients()`退出；8765/5173/8901/9601无遗留监听或诊断
  进程。

BOARD_STATS只能标记为“连接与心跳通过”，不能标记为“statscalc功能可用”。当前公开
懒建连实现`_connect_board_stats_server()`在已有`_auth`时会直接复用current Passport，
没有像其他独立角色一样先取得fresh材料；本次验证为遵守一次性Passport规则而在调用前
手动刷新。若未来正式启用该入口，必须先把fresh鉴权下沉到角色连接工厂，并锁定：首次
`-1`只刷新一次，fresh后仍`-1`立即停止。当前Web看盘继续使用8901板块排行，不接入旧
statscalc路径。
