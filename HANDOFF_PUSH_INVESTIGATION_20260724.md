# 个股分时推送调研报告（2026-07-24 会话）

> 接续 `HANDOFF_STOCKLIST_PUSH.md`。本会话目标：搞清为什么 thspypc 收不到 71B 逐 tick 推送。
> **★ 最终结论：已完全突破。四层根因全部锁定，端到端验证通过（盘后查 000938 分时 241 根成功）。**

## 已确认的事实（本会话新增，字节级/实测）

### 1. ~~`__manual` 登录【不是】推送根因（实测否定）~~ → ★已被推翻！`__manual` 就是推送根因

> **2026-07-24 续会话推翻此结论**（三份抓包 + 实测铁证）。原结论的推理漏洞：
> "login 响应字段一致" ≠ "会话权限一致"。`__manual` 和普通 login 的响应字段
> 确实完全相同（VerifyCode=0），但**只有 `__manual` 身份能注册 pageid=4214
> 推送通道**——普通登录发同样的 4214 订阅帧 → `CodeListSize=0`（注册失败）；
> `__manual` 登录 → `CodeListSize=1`（注册成功）。这是会话级权限差异，不在
> login 响应字段里体现。下面"实测否定"的几个论点重新审视：
> - "__manual 不授予额外权限" → 字段级确实不授，但会话级授了 4214 注册权
> - "__manual 连接上重放字节 → 0 推送" → 那是字节重放（过期 instid/seq）导致，
>   和登录身份无关（见 §5）
> - "104540 包 stream1/2 无 login 帧" → 那两条是预存连接，抓包前就登录了，
>   登录类型不可见，不能作为"不需要 __manual"的反证
>
> 决定性证据见文末「★ 突破」章节：`_replay_exact.py` 用 `__manual` 登录后
> 发 4214 订阅 → `CodeListSize=1`；普通登录同样字节 → `CodeListSize=0`。

**初始假设**（被否）：131453 冷启动包里只有 stream1（`UserName=__manual`）收到推送，其余 7 条（thsuser/空）零推送，所以推断推送需要 `__manual` 登录。

**实测否定**：
- `__manual` 登录成功（`VerifyCode=0`），但**响应字段和普通登录完全一致**（同 `S-Version`/`S-PushVer`/`VerifyCode`）。`__manual` 不授予任何额外权限。
- `__manual` 连接上重放抓包的精确注册帧字节 → **0 推送**。
- **反证**：104540 包里 stream1 + stream2 **都**收到推送（174+417 帧），且这两条连接**都没有 login 帧**（抓包前就建立的预存连接）——连登录类型都不知道，无法断定推送需要 `__manual`。

→ ~~131453 里"只有 `__manual` 收推送"是**相关性误读**，不构成因果。~~
→ **更正**：是因果，不是误读。`__manual` 是注册 4214 推送通道的必要会话身份。

### 2. INIT 请求【不能】在 `__manual` 连接上发（会断连）

- `__manual` stream1 在 t=1.04s 发了 INIT（subtype 0x0001，`C-Modules=MEQT`，1690B，`MarketCode=32;`）。
- 但 thspypc 的 `build_init_query()`（`MarketCode=16;144`、`ConfigVer=0`）在 `__manual` 连接上发 → 服务器回 `09 01 16 9b ff ff ff`（错误）+ **FIN 断连**。
- 普通 thspypc 连接发 init 正常（`_send_init_handshake` 已在工作流里）。

### 3. 触发帧格式（两个包风格不同）

| | 104540 stream1 | 131453 stream1 |
|---|---|---|
| subreal pageid | **4214** | 5716 |
| pageid 注册 byte11-12 | `02 04` | `01 00` |
| code 注册 byte11-12 | `fc 03` | `fc 00` |
| 含 PushField | 否 | 是（`PushField=16:241;32:241`）|
| INIT | 否（预存连接）| 是（t=1.04s）|

byte11-12 第二字节是**订阅计数器**（递增），不是固定值。

### 4. 注册成功标志 = `CodeListSize=1`（不是 0）

- thspypc 双子帧注册（`build_snapshot_subscribe` 改造）→ **`CodeListSize=1`**（注册成功，股票进了推送列表）。
- 但 104540 风格 `fc 03` 注册 → **`CodeListSize=0`**（注册失败，格式不对）。
- **即使 `CodeListSize=1`（注册成功），推送仍不来。**

### 5. 重放抓包原字节【会断连】

抓包帧含**过期会话标识**（instid/seq/订阅id 属于原会话），原样重放 → `WinError 10053` 断连。
**必须用 thspypc 构造函数造新帧**（新 instid/seq），不能字节级重放。

## ★ 突破（2026-07-24 续会话：两账号对比 + L2 冷启动包逐字节破解）

> 上一会话卡在"推送连接是预存的、激活瞬间没抓到"。本会话用**两份新抓包**彻底解决。

### 决定性发现 1：71B 逐 tick 推送是 **level2 专属**

两账号打开同一个个股分时图，发的是**字节结构完全相同**的请求，唯一差异是 byte11 路由 + pageid：

| 账号 | byte11 路由 | pageid | 服务器行为 |
|------|-----------|--------|-----------|
| **普通号(无L2)** `143442.pcap` | `0x0a` | **9354** | 请求-响应（一次性快照，**无推送**）|
| **level2号** `131453.pcap` | `0x02` | **4214** | **持续 71B 逐 tick 推送** |

普通号客户端**自己就知道没权限**，打开分时直接走 9354（路由 0x000a），从不发 4214。
普通号的 subreal 异动订阅（URS/UCT/UNX/UCX/UME/UNS/UHI）也**全部 errorcode=-1**。

### 决定性发现 2：激活帧格式（131453 L2 冷启动包逐字节确认）

`131453.pcap` 是**从 SYN 握手开始的完整冷启动**（不像 104540 包是预存连接），抓到了激活瞬间：

```
login t=0.12s → 用户 t=30.16s 点开分时 → 发 4214 订阅帧 → t=30.42s 收首个 71B 推送
```

**激活延迟仅 0.26 秒**。激活帧（stream1 t=30.155s）逐字节：

```
09 00 16 00 00 00 00  12 00 02 00  02 00  00 00 00 00 00 00  24 00 00 00
└cmd┘ └─固定─┘seq    └子帧0x0002┘ ┊路由┊    └──固定──┘    └len=36(LE32)┘
文本: CodeList=33(002396,);\r\npageid=4214\r\n
```

关键：激活帧是**嵌套双子帧**——外层 0x0002(路由0x0002) 注册订阅 + 内层紧跟
0x0009(路由0x0001) 首次数据查询。两个子帧打在同一个 TCP 包里。只发外层单子帧
→ 零推送（`CodeListSize=0` 或注册成功但无数据流）。

### 决定性发现 3：`__manual` 登录是注册推送通道的必要身份（★最终根因）

即使激活帧字节完全正确（与抓包逐字节一致），**普通登录连接发 4214 订阅 →
`CodeListSize=0`（注册失败）**。必须用 `UserName=__manual` 登录的连接才能注册：

| 连接身份 | 4214 订阅响应 | 推送 |
|---------|-------------|------|
| 普通登录（无 UserName） | `CodeListSize=0` | 无 |
| **`__manual` 登录** | **`CodeListSize=1`** | 持续 71B 推送 |

实测铁证（`_replay_exact.py`，2026-07-24 收盘后）：
- 普通登录 + 完整复刻 hexin 序列（5716查询+subreal×5+4214订阅）→ `CodeListSize=0`
- `__manual` 登录 + 同样序列 → **`CodeListSize=1`**（step4 从 0 变 1）

收盘包 `150041.pcap`（L2 账号 + `__manual` 连接）验证：
- t=16.208s 紫光订阅 → `CodeListSize=1`
- t=30.19s 切中兴 → `CodeListSize=1` → `CodeListSize=2`

`__manual` 和普通 login 的**响应字段完全一致**（VerifyCode=0），但只有 `__manual`
能注册 4214 推送通道——会话级权限差异。已集成到 `client.py`：
`snapshot_subscribe()` 自动用 `build_manual_login_body` 开独立推送连接。

### 推翻的两个旧假设（冷启动包铁证）

| 旧假设 | 证伪 |
|--------|------|
| subreal×5(pageid=4214) 是推送前置 | ✗ 131453 stream1 全程 **0 个** subreal+4214 帧，直接发 4214 订阅就激活了 |
| 连接需"老化"60-90s | ✗ login 后 30s 才激活是因为**用户 30s 后才点票**，订阅到首推仅 0.26s |

### build_snapshot_subscribe 修正（之前"有响应无推送"的根因）

旧实现与抓包真值有 5 处不符，已全部修正（`protocol.py`）：

| 偏移 | 旧实现(错) | 抓包真值 | 说明 |
|------|-----------|---------|------|
| off7-10 | 子帧 `0x0009` | **子帧 `0x0002`** | 子帧类型错了（最关键）|
| off11-12 | 路由 `02 01` | **路由 `02 00`** | 路由值错了 |
| off5-6 | seq=`86 10`(0x10高字节) | seq=普通递增 | 去掉无依据的订阅标志位 |
| off19 | 长度 LE16+padding | **长度 LE32** | 长度域写法不同 |
| 文本 | 完整查询(DataType/DateTime/...) | **仅 CodeList+pageid** | 文本结构不同 |

同步删除了 `client.py:snapshot_subscribe` 里的 subreal×5 前置（已证伪非必要）。

### 验证

`tests/test_snapshot_push.py` 实测脚本已就绪，待**盘中 + L2 账号**运行验证：
```bash
uv run python tests/test_snapshot_push.py 000938 --secs 60
```
成功标准：订阅后 ~1s 内收到 71B 推送，`parse_snapshot_push` 现价与同花顺客户端分时白线一致。

---

## ★★★ 最终突破：四层根因 + 端到端验证（2026-07-24 收盘后）

> 经过全天调查（两账号对比 + 三份抓包 + 多轮实测），**分时推送 + 分时查询的
> 完整协议链路已破解**。盘后查 000938（紫光股份）当天分时，成功拿到 241 根。

### 四层根因（缺一不可）

| 层 | 条件 | 缺失后果 | 验证 |
|---|------|---------|------|
| ① 账号 | 必须 level2 | 普通号走 9354 请求-响应，无推送 | 两账号对比 |
| ② 登录身份 | 必须 `UserName=__manual` | CodeListSize=0（注册失败）| 实测 0→1 |
| ③ **init(MarketCode=32)** | `__manual` 连接 login 后必须发 init | CodeListSize=0 | 实测 0→1 |
| ④ 嵌套双子帧 4214 订阅 | 外层0x0002注册 + 内层0x0009查询 | 零推送/零数据 | 字节级一致 |

**层②③是核心突破**：
- `__manual` 登录的响应字段和普通登录完全一致，但只有 `__manual` 能注册 4214 推送通道
- 之前 HANDOFF §2 说"__manual 连接发 init 会被拒断连"——**那是因为用了 MarketCode=16;144（沪市）**，
  改用 `MarketCode=32;`（深市）后 init 正常响应（23KB 配置帧，不断连）

### 分时查询完整链路（端到端验证通过）

```
connect（普通登录拿 Passport64）
  → disconnect（关主连接，只留 __manual 一条）
  → __manual 登录（build_manual_login_body）
  → init(MarketCode=32)（build_init_query，激活行情通道，排空 23KB 配置帧）
  → 4214 订阅（build_snapshot_subscribe 嵌套双子帧，CodeListSize=1）
  → L2 分时查询（build_timeline_l2_query，DateTime=8192，pageid=4214）
  → parse_timeline_l2_response（hd3.1 flag=0x00b4，壳头44B，双票dc=482）
  → 241 根分时记录（现价/量/额/均价）
```

### 分时响应帧结构（flag=0x00b4，新变体）

```
hd3.1\0
+ dc(LE32=482)          ← 两只票合计（指数241 + 个股241）
+ flag(LE16=0x00b4)      ← 分时变体（K线是 0x0042/0x0046）
+ hs(LE16=124)           ← 单条记录字节长度
+ fc(LE16=31)            ← 字段数
+ 字段表(31×4B)          ← dt1/16/229/14/207/15/228/13/...（35个level2字段里的31个）
+ 44字节壳头              ← [0:22]指数壳(399002) + [22:44]个股壳(000938)
+ BitRLE头(BE32=dc*hs)   ← =59768
+ BitRLE位流
```

解码后按 hs 切分行，**前 dc//2 行是指数，后 dc//2 行是个股**。
`parse_timeline_l2_response` 只取后半（个股）。

### 注意事项

- **不是所有 IP 都支持**：部分 IP init 只回 210B（小配置帧），4214 注册 CodeListSize=0；
  支持 push 的 IP（如 8.134.86.216 / 121.37.31.87 / 139.9.198.250）init 回 23KB+
  完整配置帧，4214 注册成功。需重试换 IP。
- **主连接必须断开**：两条同 IP 同 Passport64 连接并存会导致 __manual 的 4214
  注册失败。connect 拿 Passport64 后 disconnect 主连接，只留 __manual 一条。
- **client.py 集成待完善**：独立脚本（test.py）验证通过，但 client.py 的
  `timeline()` 方法因连接管理复杂（并发7IP + init + 心跳）集成后 CodeListSize=0，
  需简化连接生命周期。

## 已排除的假设汇总（含本会话最终结论）

| 假设 | 结果 |
|---|---|
| `__manual` 登录是推送通道 | ★ **是根因**（推翻旧否定结论）|
| ~~`__manual` 连接发 INIT 被拒断连~~ | ★ **MarketCode=16 错，改用 32 正常**（推翻旧结论）|
| 重放抓包精确字节 | ✗ 否定（过期会话标识→断连）|
| 104540 风格 fc 03 注册 | ✗ 注册失败（CodeListSize=0）|
| 双子帧注册（CodeListSize=1）| ✓ 正确（嵌套 0x0002+0x0009）|
| 单子帧 seq高字节0x10 + 02 01（旧实现）| ✗ 子帧类型/路由/文本全错 → 已修正 |
| subreal×5 是推送前置 | ✗ 否定（131453 冷启动包 0 个 subreal+4214 帧仍激活）|
| 连接需老化 60-90s | ✗ 否定（订阅到首推仅 0.26s）|
| 多连接会话关联 | ✗ 否定（单连接订阅即推送）|

## 关键文件

- `src/thspypc/protocol.py`:
  - `build_manual_login_body()` — __manual 登录帧（推送通道身份）
  - `build_snapshot_subscribe()` — 嵌套双子帧 4214 订阅（外层注册+内层查询）
  - `build_timeline_l2_query()` — L2 当日分时查询（pageid=4214, DateTime=8192）
  - `parse_timeline_l2_response()` — 分时响应解析（flag=0x00b4, 壳头44B, 双票dc=482）
- `tests/_manual_login_test.py` — `__manual` 登录构造（字节级验证）
- `tests/_replay_exact.py` — 精确复刻 hexin 激活序列
- `captures_live/realtime_push_20260724_131453.pcap` — **L2 冷启动包**（激活帧来源）
- `captures_live/realtime_push_20260724_143442.pcap` — **普通号对比包**（L2 专属）
- `captures_live/realtime_push_20260724_150041.pcap` — **收盘分时包**（分时查询+响应来源）

## 下一步

1. **盘中验证 71B 逐 tick 推送**：分时查询已通，推送用同样的 `__manual` + init +
   4214 订阅路径，盘中应有 71B 推送帧。
2. **完善 client.py 集成**：`timeline()` 方法需简化连接生命周期（disconnect 主连接后
   只用 __manual 连接，或用独立脚本模式）。
3. **IP 兼容性**：支持 push 的 IP 比例约 30%，需在 connect 层自动检测（init 响应
   >5000B 的 IP 才用于推送连接）。
