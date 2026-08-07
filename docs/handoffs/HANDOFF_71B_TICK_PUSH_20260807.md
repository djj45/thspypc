# HANDOFF: 71B 逐笔推送触发条件调查（2026-08-07，含收盘后更正）

## 背景

71B 逐笔成交推送帧（magic `09 7b d0 01`，含价格/量/方向/seq）的**触发条件**调查。
thspypc 现有的 `snapshot_subscribe` 只能收到 549B 十档盘口推送（`09 7b d0 0f`），
收不到 71B 逐笔。分析对象为 `captures_live/kanpan_push_20260807_130011.pcap`
（2026-08-07 13:00 抓包，收盘后从私库下载到本机）。

## ★ 结论更正（2026-08-07 收盘后复查 pcap）

早期结论「服务器主动 login / TCP 指纹决定 71B」**是误读，已推翻**：

1. **客户端发了 login**。flow1 握手后 +0.0231s（frame 19）客户端发 2541B login
   帧（`Ask=login` + `__manual` 身份 + Passport64），+0.037s 服务器才回
   `Reply=login VerifyCode=0`（frame 33）——那是**响应**，不是服务器主动推送。
   早期只解码了服务器帧，漏掉了 frame 19，误判为「服务器主动 login」。

2. **登录身份不是决定因素**。flow1 用 `UserName=__manual`（MANUAL 身份），
   flow2 用 `UserName=thsuser`（STANDARD 身份）——**两条流都收到了 71B**。
   thspypc 的 `_open_manual_push_connection` 用 thsuser + init，与 flow2 一致。

3. **TCP 指纹路线废弃**。早期怀疑 SYN 的 window/MSS/timestamp 决定会话类型
   （客户端 SYN 无时间戳选项，`MSS=1460, NOP, WScale=8, NOP, NOP, SACK`），
   但「服务器主动 login」的前提不成立，指纹差异不再相关。

4. **首帧 71B 时间修正**。flow1 首帧 71B 在 **+18.596s**（frame 2907），不是
   早期记录的 +19.22s；它紧跟 frame 2855（+18.545s 的 4214 DT 大集合单子帧）
   仅 ~50ms。

5. **真正差异在 4214 订阅变体**。thspypc 复刻序列只覆盖了 DT 大集合等部分帧，
   未包含 71B 出现前 4214 批量帧（frame 2831）里的多个 DateTime/LackTime 变体
   （详见下文「订阅序列」），且**原始字节重放从未跑过**（payload 文件此前缺失，
   已从 pcap 重新生成）。

## 事实记录（按确定性排序）

### 1. 71B / 549B 来自相同的服务器 IP 池

flow1（122.9.205.228:8901）与 flow2（8.134.115.123:8901）**同时推 71B 和 549B**。
thspypc 解析的 sz L2 IP 池不包含这两个 IP，但连 122.9.205.228 能收 549B——
**IP 不是 71B 的决定因素**。

### 2. login 是标准「客户端主动发」流程（更正）

flow1（53906 → 122.9.205.228）：

```
+0.000s  frame 2   C→S  SYN
+0.013s  frame 13  S→C  SYN-ACK
+0.013s  frame 15  C→S  ACK
+0.023s  frame 19  C→S  login 2541B
          Ask=login / C-Version=E029.60.20.0031 / UserName=__manual /
          Password=__manual / VerifyType=1 / Mac64 / C-SupportPushVer=1.0 /
          C-SupReqDataVer=hq6.0 / C-SupPushDataVer=hq6.0 / Passport64=...
+0.037s  frame 33  S→C  Reply=login VerifyCode=0（对 frame 19 的响应）
+0.736s  frame 141 C→S  subreal×8（pageid=5716）+ 订阅
          （本连接无 init 帧）
```

flow2（53905 → 8.134.115.123）：

```
+0.015s  frame 17  C→S  login 2535B（UserName=thsuser / Password=thsuser，
          与 thspypc 的 STANDARD 身份相同）
+0.027s  frame 23  S→C  Reply=login VerifyCode=0
+0.030s  frame 27  C→S  init 1722B（MarketCode=16;144;，C-Modules=MEQT）
```

结论：**不存在「服务器主动 login」的会话类型**；两条流分别覆盖
MANUAL 无 init / STANDARD 有 init，都触发 71B。

### 3. 71B 触发前的完整订阅序列（修正后）

flow1（122.9.205.228/53906，深市 002384），首帧 71B = **+18.596s（frame 2907）**：

| 时间 | 帧 | 事件 |
|------|-----|------|
| +0.74s | 141 | subreal×8（URS/UCT/UNX/UCX/UME/UGF×2/UNS，pageid=5716）|
| +1.84s | - | 首个 549B ← 5716 触发 |
| +5.65s | 1606 | subreal×8（pageid=1334）|
| +16.42s | 2562 | subreal×8（pageid=1334）再次 |
| +16.43s | 2568 | subreal×8 + 1334 分时双子帧（DT=272,...380）|
| +16.48s | 2588 | 1334 批量订阅 2704B（含多组 DT 组合，见下）|
| +16.74s | 2636 | 1334 L2 分时订阅（双子帧，DT=272,...45,1110,1111,380）|
| +16.75s | 2639 | 1334 订阅 DT=10,27,33,49，DateTime=7176(1786065300-1786065900)|
| +17.52s | 2698 | 1334 订阅 DT=7,8,9,11,13,19，ReqFuquan=Q |
| +18.50s | 2814 | subreal×8 连续 6 轮（pageid=1334，7696B）|
| +18.51s | 2816 | 4214 注册 + 订阅 DT=10,24,30,69,70,127 |
| +18.53s | 2831 | 4214 批量订阅 2141B（关键变体，见下）|
| +18.54s | 2854 | 4214 DT=10,12,13，DateTime=7169(-27-0) |
| +18.545s | 2855 | 4214 单子帧 DT 大集合（213B）|
| **+18.596s** | **2907** | **首个 71B** ★（距 2855 仅 ~50ms）|
| +18.73s | 2938 | 002384-002407 代码表订阅 DT=10,6,66,1111 |
| +18.86s | 2945 | 4214 DT=10,12,13 再发 |
| +18.96s | 2952 | 4214 DT=10,27,33,49，DateTime=7176 |

frame 2588（1334，2704B）内含的 DT 组：

- DT=10,24,30,69,70,127（DateTime=0(0-0)）
- DT=272,...380 分时（CodeList=32(399002,);33(002384,);）
- DT=7,13,19,11,74,9,8,802,407,471,456,463,1330,900,455,2097453,899,454,804,460,803
  （DateTime=16384(-512-0)，LackTime=0,3,0,0,0,0,0,0）
- DT=10,85,130,6
- DT=13,18,24,25,...,157（大集合）
- DT=70,69,10,9,8
- DT=7,8,9,10,13,14,19,69,70,74,75,85,90,92,130,6,45,66,380,402,407,663,665,1606,2081,262763
  （DT 大集合）

frame 2831（4214，2141B）内含的关键变体（thspypc 复刻未覆盖）：

- L2 分时 DT 大列表（272,...380），**LackTime=0,3,0,0,20031231,2,132659934,2**
- DT=45，DateTime=16384(-10-0)
- DT=10，DateTime=7174(-1-0) / 7173(-1-0)
- DT=30,31,...,35,104,105,108,109,112,113,116,117,120,121,127,152,153,156,157,6
- DT=24,25,...,29,102,103,106,107,110,111,114,115,118,119,127,150,151,154,155,6
- DT=10,85,130,6
- DT=13,18,24,...,157（大集合）
- DT=70,69,10,9,8
- **DT=7,49,12,18,75,10，DateTime=4096(-35-0)，LackTime=0,3,0,0,0,0,0,0**
- DT 大集合

### 4. thspypc 复刻结果（活网验证）

复刻序列（subreal5716+subreal1334+1334分时+4214 多 DT），连 122.9.205.228：

- **549B 正常收到**（60s 收 39 帧，~1.5s/帧，CodeListSize=1）
- **71B 始终为 0**（即使等 60s）

修正解读：复刻只覆盖了 DT 大集合等**部分** 4214 变体，未包含 frame 2831 的
DateTime/LackTime 变体、DT=10,12,13（DateTime=7169）等；且**原始字节重放未跑过**
（`_71b_trigger_payloads.bin` 当时缺失）。不能据此断定「会话类型不同」。

### 5. 「服务器主动 login」理论的来源与排除

`tests/_71b_server_login.py` 基于错误理论：连上后**只等服务器推 login、不发
login 帧**。服务器本就不会主动推，等 5s 无响应属预期；之后发 subreal 被中止
（WinError 10053）也不能说明问题。该脚本结论与 raw socket 复刻路线一并作废，
仅保留作参考。

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

### 549B 十档（`parse_depth_push`，已实现 + 活网验证 + 已接入）

magic `7b d0 0f`，含完整十档买卖价量 + 昨收/开盘/最高/最低/现价。
解析器已实现并活网验证（002384 现价 ~201）。**已接入 `snapshot_loop`**
（提交 d0c30d0，`connection_runtime.py` 优先匹配 71B、否则走 549B 分支）。

## 待办

1. **549B 接入 `snapshot_loop`**：✅ 已完成（提交 d0c30d0）。

2. **71B 触发条件（修正后路线）**：
   - 下个交易日先跑**原始字节重放**：
     `py tests/_replay_71b_subscribe.py 002384 --replay-raw --seconds 30`
     （`captures_live/_71b_trigger_payloads.bin` 已从 pcap 重新生成，
     含首帧 71B 前的 12 个请求包，字节级一致）
   - 若触发：逐包删减做二分定位，找到最小触发集合
   - 若未触发：补发 frame 2831/2854/2952 等未覆盖变体（DT=10,12,13 +
     DateTime=7169(-27-0)、DT=7,49,12,18,75,10 + DateTime=4096(-35-0)、
     LackTime=20031231 分时变体），或对照 flow2 的请求链再查

3. **subreal 注册**：thspypc 的 `snapshot_subscribe` 目前不发 subreal。即使 71B
   暂不可用，subreal(5716) + 5716 批量订阅可能提升 549B 推送频率（抓包里
   subreal 后 549B 高频，thspypc 不发 subreal 时 549B 仅 ~1.5s/帧）。

## 相关文件

- `src/thspypc/features/snapshot_protocol.py` — `parse_snapshot_push` / `parse_depth_push`
- `src/thspypc/_client/connection_primitives.py:725` — `_try_open_manual_sock`（thsuser + init，与 flow2 一致）
- `tests/_replay_71b_subscribe.py` — 订阅序列重放脚本（`--replay-raw` 为原始字节重放）
- `tests/_71b_server_login.py` — ⚠ 基于已被推翻的「服务器主动 login」理论，仅参考
- `captures_live/kanpan_push_20260807_130011.pcap` — 原始抓包（已从私库下载到本机）
- `captures_live/_71b_trigger_payloads.bin` — 71B 首帧前 12 个请求包（收盘后从 pcap 重新生成）
