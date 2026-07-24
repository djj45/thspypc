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
3. ~~**IP 兼容性**：支持 push 的 IP 比例约 30%，需在 connect 层自动检测（init 响应
   >5000B 的 IP 才用于推送连接）。~~ → **★ 已由「沪深分服」章节彻底解决**（见下）。

---

## ★★★★ 沪深 L2 分服突破（2026-07-24 续会话）

> 上一节"四层根因"解决了**怎么发**订阅帧，但遗留一个困惑：**为什么只有约 30%
> 的 IP 能成功**（init 回 23KB+、CodeListSize=1），其余 init 只回 210B、注册失败？
> 本会话从 passport 的 `M_hqdns` 字段找到真因——**沪深 L2 是两套完全独立的服务器**，
> 之前把它们的 IP 混在一起随便取，连错市必然失败。

### 决定性证据：M_hqdns 完整拓扑（首次完整捕获）

HTTP 80 鉴权响应的 passport 里 `M_hqdns` 字段下发**全部行情服务器域名**，格式为
`域名:端口:市场码;:`，逗号分隔。实测原文（`tests/diag_l2_hosts.py` 打印）：

```
shlv2.123ths.com:8901:16;144;:,      ← 沪市 L2（主板16 + 科创板144）
szlv2.123ths.com:8901:32;:,          ← 深市 L2（32）
fu4.123ths.com:8901:96;128;88;URS;UCT;UNX;UCX;UME;216;48;:,   ← 异动/板块
hkus.123ths.com:8901:176;112;:,      ← 港股（一组）
hkus.123ths.com:8901:168;184;200;:,  ← 港股（二组）
ifindhq.123ths.com:8901:232;120;104;56;:,   ← 国际行情
fu2.123ths.com:8901:64;80;UGF;UZC;UDE;:,    ← 港股相关
euhq.123ths.com:8901:160;:,          ← 欧洲
fu6.123ths.com:8601:UZX;:,           ← 另端口（8601）
usotc.123ths.com:8901:UNS;UHI;:,     ← 美股 OTC
```

**域名前缀直接对应市场**：`sh`lv2=沪、`sz`lv2=深、`hkus`=港、`euhq`=欧、
`usotc`=美。**域名后的市场码**（16/144/32...）是该服务器服务的市场清单。

### 铁证：shlv2 与 szlv2 的 IP 集合 0 重叠

DNS 解析两组域名，IP 完全不交集：

| 域名 | 市场 | IP 数 | 解析结果 |
|------|------|-------|---------|
| `shlv2.123ths.com` | 沪 16/144 | **5** | `8.134.115.123` `8.134.98.163` `1.1.113.11` `122.9.115.201` `122.9.202.190` |
| `szlv2.123ths.com` | 深 32 | **9** | `139.9.198.250` `122.9.205.228` `8.134.112.142` `1.1.141.107` `121.37.31.87` `8.134.86.216` `122.9.214.229` `8.134.101.39` `8.134.99.165` |
| **交集** | — | **0** | **完全无重叠** |

（DNS 轮询，每次解析具体 IP 可能微变，但 sh/sz 两组**永远不交叉**。）

### 重新解释本文件之前的所有"IP 困惑"

| 旧困惑（本文件原文） | 真因（沪深分服视角） |
|--------------------|--------------------|
| §注意事项"支持 push 的 IP 比例约 30%" | 不是随机 30%。深市票（szlv2 9 个 IP）命中概率高、沪市票（shlv2 5 个）命中概率低，混合取样看似"约 30%" |
| §注意事项"init 响应 >5000B 的 IP 才支持推送" | 真相是 **init 的 MarketCode 必须匹配 IP 所属市场**。连 szlv2 的深市 IP 却发 init(16;144 沪市) → 服务器只回 210B 小帧 |
| §2 "`__manual` 连接发 init 用 MarketCode=16 被拒，改 32 正常" | **误判**。当时连的是 szlv2 的深市 IP，发沪市 init(16) 当然被拒。不是 16 vs 32 谁对，是 **IP 与 MarketCode 必须配套** |
| "坏 IP 需重试换 IP" | 不是"坏"，是**连错市**。换到同市的另一个 IP 才对 |

### 第五层根因：按沪深选服（补全四层表）

原"四层根因"表需补第五层：

| 层 | 条件 | 缺失后果 |
|---|------|---------|
| ① 账号 | level2 | 走 9354 无推送 |
| ② 登录 | `__manual` | CodeListSize=0 |
| ③ init | MarketCode=32 | CodeListSize=0 |
| ④ 嵌套双子帧 | 0x0002+0x0009 | 零推送 |
| **⑤ IP↔MarketCode 配套** | **沪票连 shlv2 IP + init(16;144)；深票连 szlv2 IP + init(32)** | **init 只回 210B、CodeListSize=0（即"30% IP 支持"假象）** |

### 已落地的代码改造（2026-07-24）

- `protocol.py`：
  - `resolve_l2_hosts_grouped()` — 返回 `{"sh": [...], "sz": [...]}`，按 shlv2/szlv2 分组 DNS
  - `pick_l2_market(market)` — 把 17/16/144→"sh"、32/33→"sz"，连接池路由键
  - 旧 `resolve_l2_hosts()`（合并列表）保留，向后兼容
- `client.py`：
  - `_push_sock`（单连接）→ `_push_socks: dict`（沪深连接池，同时持有两条）
  - `_open_manual_push_connection(market)` — 按 market 选 sh/sz 组，IP 逐个重试，
    init 的 MarketCode 按市匹配（sh→`16;144;`、sz→`32;`）
  - `_snapshot_loop` — `select` 同时等沪深两条连接（单线程，不新增线程）
  - `snapshot_subscribe`/`timeline`/`_timeline_query_once` — 全部按 `pick_l2_market` 路由

### 验证

- `tests/diag_l2_hosts.py` — 打印 M_hqdns 原文 + shlv2/szlv2 分组 DNS + 交集对比（本节证据来源）
- 分组函数端到端验证通过：sh=5 IP、sz=9 IP、合并 14=sh+sz 去重、pick_l2_market 路由正确
- **盘中实测待办**：分别订阅沪市票（如 603118）和深市票（如 000938），确认两者都
  `CodeListSize=1` + 收到 71B 推送（需交易时段 + L2 账号）

### 关键文件（本会话新增/改动）

- `src/thspypc/protocol.py` — `resolve_l2_hosts_grouped`、`pick_l2_market`（新增）
- `src/thspypc/client.py` — `_push_socks` 池 + 按沪深分服（改造）
- `tests/diag_l2_hosts.py` — 沪深分服诊断脚本（新增，本次验证用）


---

## ★★★ 最终成功：沪深分时端到端验证通过（2026-07-24 晚）

> 经过一整晚的弯路（0x0a 卡点 → 抓包对照 → 各种错误假设），最终发现真因
> **极简单：init 是必须的**。回退到下午（§分时查询完整链路）的成功配置后，
> 沪深两市分时全部拿到 241 根。

### 端到端验证结果

| 票 | 市场 | L2 服务器 IP | init MarketCode | 结果 |
|----|------|-------------|-----------------|------|
| 000938 紫光 | 深 | `8.134.112.142`(szlv2) | `32;` 23742B | **241根** 41.01→41.45 (+1.07%) |
| 603118 共进 | 沪 | `8.134.115.123`(shlv2) | `16;144;` 49191B | **241根** 15.75→15.77 (+0.13%) |

沪深分服改造**端到端验证成功**：深市连 szlv2+init(32)，沪市连 shlv2+init(16;144)，
各自独立、互不干扰、同时可查（连接池 `_push_socks` 持有沪深两条）。

### 正确的五层根因（最终版）

| 层 | 条件 | 缺失后果 |
|---|------|---------|
| ① 账号 | level2 | 走 9354 无推送 |
| ② 登录 | `__manual` | CodeListSize=0 |
| ③ **IP 分服** | **沪票连 shlv2 IP；深票连 szlv2 IP** | init 只回 210B（"30% IP 支持"假象） |
| ④ **init 配套** | **init 的 MarketCode 匹配市场（沪16;144 / 深32）** | init 只回 210B、CodeListSize=0 |
| ⑤ 嵌套双子帧订阅 | 0x0002+0x0009 | 零推送 |

层③④是本会话核心突破（沪深分服），不可分割。

### 本会话走过的弯路（记录以免重蹈）

| 错误假设 | 实际 |
|---------|------|
| "init 不是注册的必要条件"（szlv2 不发 init 也 CodeListSize=1） | CodeListSize=1 ≠ 能拿数据。不发 init → 服务器回 0x0a 聚合帧而非 hd3.1。**init 必须发** |
| "0x0a 是新格式需逆向" | 不是。0x0a 是缺 init 的降级响应。发 init 后直接回 hd3.1 |
| "需要嵌套 5 子帧请求" | 不需要。单子帧（外层 0x0009）就够，hexin 多子帧是它自己画多条曲线用的 |
| "主连接同 IP 是关键（会话预热）" | 不是。全新 szlv2 IP 也能成功 |
| "Passport64 head128 签名不完整导致降级" | 不是。head128 没问题，纯粹是缺 init |

### 最终正确的代码状态

- `protocol.py`：
  - `resolve_l2_hosts_grouped()` / `pick_l2_market()` — 沪深分组（新增，本次核心）
  - `build_timeline_l2_query()` — **回退到单子帧版本**（8a45b4a），LackTime=`0,3,0,0,20031231,2,0,0`
- `client.py`：
  - `_push_socks: dict` — 沪深连接池（单连接→池改造）
  - `_open_manual_push_connection(market)` — 按 market 选 sh/sz IP + init 配套 MarketCode
  - `_snapshot_loop` — `select` 双连接
  - `timeline(skip_init=False)` — **默认发 init**（skip_init 参数保留供调试，但默认 False）

### 关键文件

- `src/thspypc/protocol.py` — `resolve_l2_hosts_grouped`、`pick_l2_market`（新增）
- `src/thspypc/client.py` — `_push_socks` 池 + 按沪深分服 + init 配套（改造）
- `tests/test_timeline.py` — 分时获取测试（`--no-init`/`--main-ip` 调试开关 + INFO 日志）
- `tests/diag_l2_hosts.py` — 沪深分服诊断（M_hqdns 拓扑 + IP 交集对比）
- `captures_live/timeline_20260724_190949.pcap` — hexin L2 分时抓包（对照来源）
- `captures_live/hexin_timeline_resp_000938.bin` — hexin 真实响应（hd3.1，241条，解析参照）
- `captures_live/_stream1_raw.txt` — hexin stream1 原始 hex（请求序列）

---

## ★★★ 性能优化 + Passport64 时效（2026-07-24 深夜续）

> 端到端验证通过后，针对"比同花顺慢"做了三轮优化，并定位了间歇性登录失败的根因。

### 性能优化三轮（6 只股票连续切换，平均 0.27s）

| 轮次 | 优化点 | 解决的问题 | 效果 |
|------|--------|-----------|------|
| ① 查询直接 return | `_timeline_query_once` 拿到数据后立即返回 | 旧实现 `settimeout(2.0)+continue` 白等下一帧 timeout | 复用查询 2.13s→**0.13s** |
| ② init 短 timeout | 配置帧排空用 0.5s timeout 替代固定 3s 循环 | init 末尾白等 3s | 首次 5.23s→1.05s |
| ③ 后台预热另一市 | 首次建好某市后，后台异步建另一市；主流程 join 等待 | 首次切跨市要等 init（4-5s） | 跨市 9.13s→**0.44s** |

最终：所有查询 0.1-0.7s，平均 0.27s，与 hexin 秒加载体感一致。

### 后台预热机制（复刻 hexin 启动即双连）

hexin 启动时同时连 sz+sh 两条 L2 服务器，切任何票都秒加载。thspypc 原是惰性的——
遇到某市票才建该市连接。`_preheat_other_market()` 在首次建好某市连接后，后台线程
异步建另一市：

```
timeline(000938深) → 建 sz 连接 → 触发 _preheat_other_market("sz")
                                   └─ 后台线程建 sh 连接（init 4-5s，用户无感）
timeline(000063/000001深) → 复用 sz（0.13s），期间 sh 预热进行中
timeline(603118沪) → key=sh 不在池 → join 等预热线程 → 直接用预热的 sh 连接（0.44s）
```

关键：主流程发现 key 不在 `_push_socks` 时，**先 join 等预热线程**（`_preheat_threads`），
再决定是否自己建——避免预热线程和主流程重复建连接竞争（早期版本建了两次 sh 连接）。

### Passport64 时效（间歇性 VerifyCode=-1 根因）

**现象**：同一账号短时间内多次运行，`__manual` 登录突然全 IP 失败，PromptText：
```
认证失败：我们发现您的登录通行证有被修改的痕迹，我们无法确认您的身份。
```
但单跑一次（重新 `full_http_auth`）又成功。

**根因**：`__manual` 登录对 Passport64 新鲜度敏感。主连接 login 已"消费"了该票据
（服务器侧记录会话），`__manual` 再用同一票据登录被判"通行证被修改"。这不是限流/封禁
（同花顺客户端能正常打开），是**同一 Passport64 被重复用于新登录**触发服务器保护。

**不是过期的证据**：`signdate=2026072311` / `signvalid=2026072911`（有效期一周），
但短时间内重复 `__manual` 登录仍被拒。主连接已建立的不受影响（会话已激活），只有
**新的 `__manual` 登录**会被拒。

**解决**：`_open_manual_push_connection` 的 `_try_round()` 检测到 "通行证/身份" 类
PromptText（返回 `"stale_passport"` 标记）→ **立即跳出剩余 IP 循环**，重新
`full_http_auth` 拿新鲜 Passport64 再试一轮：

```
__manual[sz] 139.9.198.250 登录失败...通行证被修改
票据失效（139.9.198.250），跳过剩余 IP 直接重新鉴权   ← 只试 1 个，不试 9 个
重新 HTTP 鉴权拿新鲜 Passport64...
重试一轮 → 139.9.198.250 登录成功                   ← 新票据首 IP 即成
```

早期版本（试完全部 9 个 IP 才重试）耗时 16s，优化后 **1s** 即恢复。

### 完整的 timeline 连接生命周期

```
connect()                    # HTTP 鉴权 → 主连接 login（普通登录）
  ↓
timeline(code)
  ├─ key = pick_l2_market(market)        # 深→sz / 沪→sh
  ├─ if key not in _push_socks:
  │    ├─ 若该市正在预热 → join 等预热线程
  │    ├─ _drop_connection()             # 关主连接（双连接并存会 CodeListSize=0）
  │    ├─ _open_manual_push_connection()  # __manual 登录 + init(配套MarketCode)
  │    │    └─ 票据失效 → 自动重新鉴权重试
  │    ├─ _push_socks[key] = sock
  │    └─ _preheat_other_market(key)     # 后台预热另一市
  └─ _timeline_query_once()
       ├─ 4214 订阅（首次该 code）→ CodeListSize=1
       └─ L2 分时查询 → hd3.1 响应 → parse_timeline_l2_response → 241 根
```

### 关键文件（本轮新增/改动）

- `src/thspypc/client.py`:
  - `_preheat_other_market()` — 后台预热 + `_preheat_threads` join 等待（新增）
  - `_try_round()` — 票据失效快速恢复（`stale_passport` 标记 + 重新鉴权）
  - `_timeline_query_once` — 拿到数据直接 return（去掉白等 timeout）
  - init 排空短 timeout（3s→0.5s）
- `tests/test_timeline_switch.py` — 6 只股票连续切换验证（沪深跨市 + 计时）
