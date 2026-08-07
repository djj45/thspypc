# HANDOFF: 71B 逐笔推送触发条件调查（2026-08-07）

## 背景

71B 逐笔成交推送帧（magic `09 7b d0 01`，含价格/量/方向/seq）的**触发条件**调查。
thspypc 现有的 `snapshot_subscribe` 只能收到 549B 十档盘口推送（`09 7b d0 0f`），
收不到 71B 逐笔。本次彻底分析了 `captures_live/kanpan_push_20260807_130011.pcap`。

## 关键发现（按确定性排序）

### 1. 71B / 549B 来自相同的服务器 IP 池

抓包统计 71B/549B 的来源服务器 IP：

| 服务器 IP | 71B 帧数 | 549B 帧数 |
|-----------|---------|----------|
| 122.9.205.228 | 415 | 212 |
| 8.134.115.123 | 100 | 273 |

两个 IP 同时推 71B 和 549B。thspypc 解析的 sz L2 IP 池（8.134.112.142、
121.37.31.87 等）**不包含**这两个 IP，但 thspypc 连 8.134.112.142 / 122.9.205.228
都能收 549B——**所以 IP 不是 71B 的决定因素**。

### 2. ★ 71B 来源服务器是「服务器主动 login」类型（决定性发现）

flow1（122.9.205.228）和 flow2（8.134.115.123）的 TCP 握手序列：

```
+0.000s  C→S  SYN
+0.013s  S→C  SYN-ACK
+0.013s  C→S  ACK
+0.027s  S→C  ★ Reply=login VerifyCode=0   ← 服务器主动推 login！
+0.7s    C→S  subreal×8 + 5716 订阅         ← 客户端不发 login，直接订阅
```

**TCP 连接完成后 14-27ms，服务器主动推送 `Reply=login VerifyCode=0`**。客户端
**不发 login 帧**，握手后直接发 subreal 订阅。

而 thspypc 的 `_open_manual_push_connection`（`connection_primitives.py:725`）
走标准 login 流程：`create_connection → sendall(login_body) → 读 VerifyCode →
sendall(init)`。这种「客户端主动 login」的会话类型与同花顺不同——服务器仍推
549B（十档），但**不开 71B 逐笔通道**。

### 3. 71B 触发前的完整订阅序列

flow1（122.9.205.228/53906，深市 002384）71B 首帧 +19.22s 前的请求链：

| 时间 | 事件 |
|------|------|
| +0.74s | subreal×8（URS/UCT/UNX/UCX/UME/UGF×2/UNS，pageid=**5716**）|
| +1.84s | 首个 **549B** ← 5716 触发 |
| +5.65s | subreal×8（pageid=**1334**）|
| +16.42s | subreal×8（pageid=1334）再次 |
| +16.74s | 1334 L2 分时订阅（DT=272,229,271,228,13,227,19,40,226,54,39,225,10,38,224,223,230,6,45,1110,1111,380）|
| +16.75s | 1334 订阅（DT=10,27,33,49，DateTime=7176 范围）|
| +17.52s | 1334 订阅（DT=7,8,9,11,13,19，含 ReqFuquan=Q）|
| +18.51s | 4214 订阅（DT=10,24,30,69,70,127）|
| +18.54s | 4214 单子帧（DT=7,8,9,10,13,14,19,69,70,74,75,85,90,92,130,...）|
| **+19.22s** | **首个 71B** ★ |

### 4. thspypc 复刻结果（活网验证）

构造完整订阅序列（subreal5716+subreal1334+1334分时+4214多DT），连 122.9.205.228：

- **549B 正常收到**（60s 收 39 帧，~1.5s/帧，CodeListSize=1）
- **71B 始终为 0**（即使等 60s）

对比抓包：同花顺 549B 首帧 +1.84s，71B 首帧 +19.22s（订阅后 ~3s）。
thspypc 订阅后等 60s 仍无 71B——**不是时间问题，是会话类型问题**。

### 5. 「服务器主动 login」无法用纯 Python socket 复刻

直接 `socket.create_connection` 连 122.9.205.228 / 8.134.115.123，
**等 5s 服务器不主动推 login**，发 subreal 后连接被中止（WinError 10053）。

抓包里同花顺 TCP 握手后 14-27ms 服务器就主动 login，thspypc 的 Python socket
连上后服务器静默。差别推测在 **TCP 指纹**（window size / MSS / timestamp 选项）
或**连接来源识别**，超出纯应用层协议复刻范畴。

## 帧布局参考（已破译，待触发后即可用）

### 71B 逐笔（`parse_snapshot_push`，已实现）

```
[0]     0x09            帧类型
[1:5]   7b d0 01 7f     魔数
[28]    市场标记         0x11=沪 0x21=深
[29:35] ASCII 代码
[39:43] u32 LE          成交序号（递增）
[47:51] ths_float       成交价格
[51:53] u16 LE          成交量（股）
[55]    1/5             方向（1=主动买 5=主动卖）
帧间隔 ~0.11s（真逐笔），非定时快照
```

### 549B 十档（`parse_depth_push`，已实现 + 活网验证）

magic `7b d0 0f`，含完整十档买卖价量 + 昨收/开盘/最高/最低/现价。
解析器已实现并活网验证（002384 现价 ~201）。**待接入 `snapshot_loop`**。

## 待办

1. **549B 接入 `snapshot_loop`**：`connection_runtime.py` 的 `snapshot_loop` 目前
   只调 `parse_snapshot_push`（71B），需增加 `is_depth_push` + `parse_depth_push`
   分支，把 549B 十档也解析并回调。这是**确定可用的成果**。

2. **71B 触发条件**：需突破「服务器主动 login」的连接建立。可能的下一步：
   - 抓同花顺客户端建立推送连接时的**完整 TCP 选项**（SYN 包的 window/MSS/
     timestamp），用 raw socket（如 `scapy` 或 Windows Npcap）复刻 TCP 指纹
   - 或检查同花顺是否在连接前通过 HTTP API 注册了推送 session token
   - `tests/_71b_server_login.py` 是验证脚本骨架

3. **subreal 注册**：thspypc 的 `snapshot_subscribe` 目前不发 subreal。即使 71B
   暂不可用，subreal(5716) + 5716 批量订阅可能提升 549B 推送频率（抓包里
   subreal 后 549B 高频，thspypc 不发 subreal 时 549B 仅 ~1.5s/帧）。

## 相关文件

- `src/thspypc/features/snapshot_protocol.py` — `parse_snapshot_push` / `parse_depth_push`
- `src/thspypc/_client/connection_primitives.py:725` — `_try_open_manual_sock`（标准 login 流程）
- `tests/_replay_71b_subscribe.py` — 订阅序列重放脚本（多场景）
- `tests/_71b_server_login.py` — 「服务器主动 login」验证脚本
- `captures_live/kanpan_push_20260807_130011.pcap` — 原始抓包
- `captures_live/_71b_trigger_payloads.bin` — 提取的 71B 触发前 12 个原始请求包
