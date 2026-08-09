# 同花顺行情协议与 thspypc 实现指南

> 目标：读这一份文档就能理解 thspypc 如何登录、如何向哪台服务器发送什么请求、如何解析响应，
> 以及各功能在源码里的位置，无需再逐行翻源码。需要精确到字节时，再按“代码地图”进入对应文件。
>
> 适用范围：A 股（沪深北）免费 PC 行情。日期基准：2026-08-06，协议以同花顺 PC 客户端抓包逆向为准。
> 2026-08-06 增补：买卖力量字段（dt14/dt15）、北交所（BSE）分时协议（pageid 10443/11695）、main.123ths.com 网关发现。
> 2026-08-01 增补：系统板块（行业/概念板块指数、成分股）通道与协议、历史分时 packed-date 游标修正。

---

## 1. 系统总览

thspypc 是一条**三层链路**：

```mermaid
flowchart LR
    A[HTTP 鉴权<br/>auth.10jqka.com.cn:80] -->|passport64 + M_hqdns 域名清单| B[行情 TCP 8901]
    B --> B1[MAIN 普通行情]
    B --> B2[shlv2 沪市 L2]
    B --> B3[szlv2 深市 L2]
    B1 --> C[普通: 9354 当日分时 / 9355 日K·历史分时 / 竞价 / 列表]
    B2 --> D[L2: 1334 分时·日K·竞价 / 4214 十档·逐笔 / 4417 历史]
    B3 --> E[同左，深市]
    B --> B4[REALORDER 9601 异动订阅/推送]
    B --> B5[fu4 板块指数 8901 通道]
```

三层职责：

1. **HTTP 鉴权**（`src/thspypc/features/auth_protocol.py`、`src/thspypc/protocol.py`）：账号密码/二维码换 `Passport64`，
   并拿到服务器域名清单 `M_hqdns`。鉴权不建立行情连接。
2. **行情 TCP 8901**（`src/thspypc/_transport/`、`src/thspypc/_client/connection_primitives.py`）：
   每类服务器各自 `login → init → 请求/响应`，连接按角色（MAIN / SH_L2 / SZ_L2 / REALORDER /
   BOARD / BOARD_CONSTITUENT_SH / BOARD_CONSTITUENT_SZ）复用，
   带单飞锁、心跳和失败治理。
3. **业务协议**（`src/thspypc/features/*_protocol.py`）：请求是 **GBK 文本行**（`CodeList/DataType/DateTime/pageid`），
   响应是 **hd1.0 / hd3.1 二进制表**，部分响应外层还有 8901 LZ77 压缩。

---

## 2. 帧封装与压缩（公共编解码）

所有 8901/9601 消息都包一层 FDF 信封（`src/thspypc/codecs/framing.py`）：

```text
FD FD FD FD | 8 位 ASCII hex 帧长 | body
```

- 发送：`encode_frame(body)`，调用方通常再追一个 `\n`。
- 接收：`read_frame()` 扫描 magic → 读 8 字节长度 → 读 body；兼容服务器偶发“第 5 个 FD”
  和帧头前的 `\x00`。

**8901 外层压缩**（`src/thspypc/codecs/compression.py`）：部分响应（尤其 `cmd=0x0a` 的沪市帧）
整体是 LZ77 变体压缩（64K 哈希字典 + 滑动窗口），解析前先调
`normalize_8901_response(body)` 解压，再找业务标记。

**两种业务表结构**：

| 标记 | 用途 | 结构 |
|---|---|---|
| `hd1.0` | 竞价、历史分时 | `record_count(4B) flag(2B) record_size(2B) field_count(2B)` + 字段表(`field_count×4B`) + 壳段 + 定长记录 |
| `hd3.1` | 当日分时、K线、部分当日尾盘 | 同上表头，但记录区是 **BitRLE 位平面**：先 `_decode_bitrle_0x13746d0` 解出位平面，再 `_transpose_bitplane_0x1763410` 转置成行 |

字段表每项 4 字节：`datatype(1B) fmt(1B) flags(1B) width(1B)`。记录里 `dt<datatype>` 就是“第几个字段”，
宽 4 的按 THS float 解码（`decode_ths_float`），非 4 字节的保留 `dt<id>_raw`。

---

## 3. 账号类型、权限与能力模型

### 3.1 账号类型（`src/thspypc/models.py`、`features/account_profile.py`）

| 类型 | passport 判定（两者同时满足才成立） | 说明 |
|---|---|---|
| `STANDARD` 普通 | `userclass=10000` 且 `level2=255` | 走 MAIN，基础行情，**不发、不解析** L2 大单字段 |
| `LEVEL2` | `userclass=30002` 且 `level2=16;32;48` | 走 shlv2/szlv2，可用 4214/4417 |
| `UNKNOWN` | 其他组合 | 保守拒绝进特权通道，报 `UnsupportedAccountFeatureError` |

判定原则：**单一字段不构成证据**，未验证的组合一律 `UNKNOWN`，防止普通账号被误路由到 L2 通道。

### 3.2 能力（Capability）与三态 Support

每个业务都对应一个 `Capability`，只有证据为 `YES` 才放行：

| 通道 | 能力 |
|---|---|
| MAIN | `BASIC_QUOTE`、`BASIC_TIMELINE`、`BASIC_HISTORY_TIMELINE`、`BASIC_AUCTION` |
| SH_L2 / SZ_L2 | `L2_MARKET_ACCESS`（进通道前提）+ `L2_TIMELINE`、`L2_AUCTION`、`L2_HISTORY_TIMELINE`、`L2_SNAPSHOT_PUSH` |
| REALORDER 9601 | `REALORDER`、`REALORDER_BASIC_ANOMALIES`、`REALORDER_LEVEL2_ANOMALIES` |

`Support` 三态：`YES` 放行；`NO` 抛 `CapabilityUnavailableError`；`UNKNOWN` 抛
`UnsupportedAccountFeatureError`。证据由 `AccountEvidenceRecorder` 在真实业务成功后逐步沉淀，
“域名能连上 / 登录成功”本身不算授权证据。

> 系统板块不设独立 Capability 枚举，由 `ConnectionRole.BOARD` 连接角色门控；L2 侧成分股
> 连接复用 `L2_MARKET_ACCESS` 能力门禁（`board_constituents` 会显式请求该能力，成功后回填
> `l2_market_init/manual_login` 证据，后续调用不再依赖账号是否开过 L2 推送连接）。

---

## 4. 登录流程

入口：`client.authenticate()`（只做 HTTP 鉴权）、`client.connect_main()`（鉴权 + MAIN 连接，
`connect()` 是它的兼容别名）、`connect_with_qrcode()`、`connect_cached()`。

### 4.1 HTTP 三步鉴权（`protocol.full_http_auth`）

```text
fetch_rsa_pubkey()          # 取 RSA 公钥
  → http_unified_login()    # 账号密码 → userid / sessionid
  → http_mainverify()       # userid+sessionid+imei → Passport64（含 M_hqdns 服务器清单）
```

`imei`（32 位十六进制设备指纹）与 `Mac64` 均由算法本地生成（`generate_imei`），可完全脱机运行。

### 4.2 TCP 8901 login（`_client/connection_primitives.py`）

1. 从 `M_hqdns` 解析候选域名：MAIN 优先 `main.123ths.com`（passport 不含时硬编码补入，
   支持北交所 market 151），DNS 失败时回退 `ifindhq.123ths.com`；L2 只取 `shlv2.123ths.com` /
   `szlv2.123ths.com`（`resolve_market_hosts` / `resolve_l2_hosts`）。
2. **并发 TCP 测速**选最快 IP，再**并发向多个 IP 发 login 帧**，取第一个 `VerifyCode=0` 的连接，
   其余关闭——复刻 hexin 策略，避免串行重复 login 触发 `VerifyCode=-1` 会话冲突。
3. login 帧（`features/auth_protocol.build_login_body`）：

   ```text
   09 41 09 00 zh_CN.GBK <check> 09
   Ask=login
   C-Version=...
   UserName=thsuser          # 普通身份（__manual 身份保留在 MANUAL 分支）
   Password=thsuser
   VerifyType=1
   Mac64=...
   C-SupportPushVer=1.0
   C-SupReqDataVer=hq6.0
   C-SupPushDataVer=hq6.0
   Passport64=<HTTP 鉴权所得>
   ```

4. 响应为文本字段（`parse_login_response`）：`VerifyCode=0` 成功；`-1` 有两类独立原因：
   login 帧内容问题（sk/sv、动态 check 字节，见 HANDOFF §2）与同账号短时串行重登的会话冲突
   （level2 单点登录）。后者用并发登录 + 长连接心跳解决（见 4.5），换 IP 可临时恢复，不是封禁；
   连续 5 个 IP `-1` 提前放弃并返回 `session_conflict`。
5. **板块通道（fu4）登录壳走身份回退链**：`_open_board_channel` 对每个 IP 按
   `BOARD → STANDARD → MANUAL` 顺序尝试（2026-08-01 实测 L2 三种壳都接受；普通账号偶发对
   `__manual`/无用户名壳回 `PromptText=-6`，`thsuser` 壳通过）。真实客户端抓包的 BOARD 壳
   是唯一基准：Level2 无 UserName/Password（suffix=计算 check+09，抓包 `aa 09`）；普通账号
   `UserName=__manual`（`\r\n\n` 分隔，suffix 固定 `5e 07`）。

### 4.3 init 握手（`build_init_query` / `parse_init_response`）

login 成功后必须紧跟 init（subtype `0x0001`），激活行情查询通道；**跳过 init 直接查 K线会超时**
（list_quotes 不依赖 init，容易掩盖此问题）：

| 通道 | init 内容 | 期望响应 |
|---|---|---|
| MAIN | 标准 init | 服务器配置帧 ~49KB（S-OS/S-Version/SName），0.1s 返回 |
| shlv2 | `MarketCode=16;144;` | 配置帧 23KB+；<5000B 视为该 IP 未激活，换 IP |
| szlv2 | `MarketCode=32;` | 同上；深市必须连 szlv2（MAIN 节点对 L2 只回 210B 小帧） |
| BOARD（fu4） | `MarketCode=96;128;88;216;48;`（含 MarketDate/StockLinkVer） | 引导是逐帧流水（subreal 注册 → init → qureal-init → 分类表 → StockNameVer），见 11 节 |

### 4.4 登录后

- MAIN/REALORDER 启动心跳线程（`build_heartbeat_8901`）。
- 能力证据写入 `AccountEvidenceRecorder`，路由 profile 随证据升级。
- 连接治理：`connect_main` 距上次成功 <20s 且连接存活时直接复用；K线失败 IP 进黑名单；
  L2 连接建立时会短暂占用主连接（`_drop_main`），故竞价/分时脚本期间不同时跑其他查询。

### 4.5 多会话并发登录与长连接（名称同步，2026-08-08）

全市场组名称同步如果逐组“登录一次 → 下载 → 断开 → 再登录”，会被同花顺按同账号短时
重复登录拒绝（`VerifyCode=-1`）。真实客户端冷启动的做法是**一次并发登录所有市场连接，
之后保持长连接并每 3s 心跳复用**。

- 实测：8 组（shlv2/szlv2/fu4/hkus×2/ifindhq/fu2/usotc）并发登录约 3.2s 全部成功；
  长连接 + 心跳 8s 后仍可用；同一账号串行重登则出现 `-1`。
- 实现：`services/stock_name.py::download_all_stock_names` 用 `ThreadPoolExecutor`
  并发登录每组的 `*.123ths.com:8901`，每个 socket 配发送锁 + 3s 心跳线程，然后逐组
  重放引导、解码 `[name_*]` 段并写 `~/.thspypc/stockname/` 缓存。
- 单组入口 `download_stock_name_group` 保留，适合低频手动验证；批量刷新请走
  `THSClient.fetch_all_stock_names()`。

---

## 5. 服务器矩阵与权限

详细版见 `docs/architecture/SERVER_MATRIX.md`。已实现角色：

| 角色 | 地址 | 登录/init | 权限前提 | 已验证用途 |
|---|---|---|---|---|
| HTTP | `auth.10jqka.com.cn:80` | 三步鉴权 | 有效账号/二维码 | passport、signature、M_hqdns |
| MAIN | `main.123ths.com:8901`（优先，支持北交所）/ `ifindhq.123ths.com:8901`（回退，不支持北交所） | 普通登录 + 标准 init | `BASIC_*` | 日K、9355 当日分时、9355 历史分时、早盘/尾盘竞价、股票列表、批量行情、北交所分时(10443/11695) |
| SH_L2 | `shlv2.123ths.com:8901` | Level2 passport + thsuser 壳；init `16;144;` | `L2_MARKET_ACCESS` + `L2_*` | 沪市 L2 分时、竞价、快照推送、历史分时 |
| SZ_L2 | `szlv2.123ths.com:8901` | 同左；init `32;` | 同左 | 深市 L2 同左 |
| BOARD | `fu4.123ths.com:8901` | 板块壳（身份回退链 BOARD→STANDARD→MANUAL）；引导 subreal URS/UCT/UNX/UCX/UME → `MarketCode=96;128;88;216;48;` → qureal-init×10 → `[5],[55]` 分类表 → StockNameVer | `ConnectionRole.BOARD` | 板块行情/分时/竞价（仅板块指数，不做成分股） |
| BOARD_CONSTITUENT_SH/SZ | 沪 `shlv2.123ths.com:8901` / 深 `szlv2.123ths.com:8901`（普通账号走 `main.123ths.com:8901`） | 股票网关身份（沪 `thsuser` / 深 `__manual`）；MKT_INIT 用股票市场集（`16;144;` / `32;` / `16;32;144;`）+ 两轮 subreal/pageid | `L2_MARKET_ACCESS`（L2 侧） | 按板块查成分股（881121 双账号 176 条，约 4-5s） |
| REALORDER | 固定 seed `106.14.65.90:9601`（官方客户端可缓存动态节点） | 独立 9601 登录 | `REALORDER` | 异动历史/订阅/推送 |

路由约束：

- MAIN 只从 `main`/`ifindhq` 解析 IP；`fu4/hkus/euhq` 等域名能登录但不响应沪深基础行情，禁止混入。
- shlv2 与 szlv2 是两套不重叠的 IP 池；沪票连 shlv2、深票连 szlv2，`MarketCode` 必须匹配。
- L2 业务（4214/4417）**禁止回退到 MAIN 9354/9355**；深市 4417 走 MAIN 只回短帧。
- 板块指数只能走 fu4；**成分股独立连接必须走股票行情网关**（普通 main / L2 沪 shlv2 /
  L2 深 szlv2），连错到 fu4 `globalthsindex-gateway` 时全部 subreal 注册回 `errorcode=-1`，
  业务查询只回 26B 空 Sort 响应（2026-08-01 复盘，见 11.5）。
- DNS 会轮换，文档/代码中的 IP 只是某次观测，运行时应实时解析 `M_hqdns`。

---

## 6. 业务请求速查总表

请求头固定 23 字节：`hdr[0]=0x09`；`hdr[5:7]=seq`；`hdr[7:11]=0x12 00 09 00`；
`hdr[11:13]=route`；`hdr[17]/hdr[18]` 为标志/周期高位；`hdr[19:23]=文本长度`。
文本行首尾是 `\r\n`，编码 GBK。

| 业务 | 账号 | pageid | period | DataType | 连接 | 响应 |
|---|---|---|---|---|---|---|
| 当日分时 | 普通 | 9354 | 8192(0-0) | 10 字段 | MAIN | hd3.1 241 行 |
| 当日分时 | L2 | 4214 | 8192(0-0) | 31 字段 + 基准指数 | shlv2/szlv2 | hd3.1 |
| 指数当日分时 | 普通/L2 | 9354 / 4214 | 8192(0-0) | 含 10、40 的指数字段表 | main/shlv2/szlv2 | hd3.1 0x3E/0x86/0x9E |
| 历史分时 | 普通 | 9355 | 8192(bar起-止) | 18 字段 | MAIN | hd1.0 7 字段表 |
| 历史分时 | L2 | 4417 | 8192(bar起-止) | 26 字段 | shlv2/szlv2 | hd1.0 23 字段表 |
| 指数历史分时 | 普通/L2 | 77 | 8192(bar起-止) | 13,19,40,10,23,22,6 | main/shlv2/szlv2 | hd1.0 0x42 |
| 指数早盘竞价 | 当天 | 6240 | T_URL | JSON | main/shlv2/szlv2 | `Auction` |
| 指数尾盘竞价 | 当天且仅三大指数 | 6240 | T_URL | JSON | main/shlv2/szlv2 | `CloseAuction` |
| 早盘竞价 | 普通 | 9354 当日 / 9355 历史 | 7176 / 6144 | 10,27,33,49 | MAIN | hd1.0 |
| 早盘竞价 | L2 | 4214 当日 / 4417 历史 | 7176 / 6144 | 10,27,33,49 | shlv2/szlv2 | hd1.0 |
| 尾盘竞价 | 普通 | 9354 当日 / 9355 历史 | 7424 | 10,49,287 | MAIN | hd1.0/hd3.1 |
| 尾盘竞价 | L2 | 4214 当日 / 4417 历史 | 7424 | 10,49,287 | shlv2/szlv2 | hd1.0（历史）/ hd3.1（当日） |
| 日K | 任意 | 9355 | 0x4000(-count-0) | 7,8,9,11,13,19 | MAIN | hd3.1 |
| 周K | 任意 | 9355 | 0x5001(-count-0) | 同左 | MAIN | hd3.1 |
| 月K | 任意 | 9355 | 0x6001(-count-0) | 同左 | MAIN | hd3.1 |
| 分钟K | 任意 | 9355 | 0x3005/0x300F/0x301E/0x303C | 同左 | MAIN | hd3.1 |
| 板块行情列表 | 板块通道 | L2 5716/1341 · 普通 392 | 8192 | 见 11.2 | fu4 | hd3.1 0x130 |
| 板块指数分时/竞价 | 板块通道 | L2 6002 · 普通 4181 | 8192(packed) / unix 区间 | 见 11.2 | fu4 | 0x42 / 0x32 |
| 板块成分股 | 成分连接 | L2 6000 · 普通 4180 | 8192 | 见 11.2 | main/shlv2/szlv2 | hd3.1 0x64 |
| **北交所个股分时** | 普通/L2 | **10443** | 8192(0-0) | 14,13,19,54,10,23,15,22 | **main** | hd3.1 0x0046 |
| **北证50指数分时** | 普通/L2 | **11695** | 8192(0-0) | 272,207,42,271,… | **main** | hd3.1 0x006e |
| 短线精灵历史翻页 | 任意 | —（纯文本协议） | — | `DXJL_DATATYPE` | REALORDER 9601 | hq1.0 |

> 竞价类请求的 `DateTime` 两个参数是 **unix 时间戳区间**（如 9:15-9:25）；分时/历史分时是
> **bar 游标区间**；K线是 **`-count-0` 回溯窗口**。三者语义不同，勿混用。

> **pageid 与账号类型（2026-08-05 看盘抓包对齐）**：上表的 9354/9355 是**普通账号**路径
> （MAIN 通道），抓包与真实客户端普通账号一致。**Level2 账号**的真实客户端用 `pageid=1334`
> （走 L2 连接）做分时/K线/竞价主体（DataType 仍含 L2 大单字段 dt223-230，不丢失），再用
> 4214/4417 做历史/L2 增强。thspypc 已于 2026-08-05 对齐：分时/日K/当日竞价改 1334，
> 历史分时/历史竞价保留 4417（有 fixture 背书）。详见
> `docs/handoffs/HANDOFF_KANPAN_CAPTURE_20260805.md`。普通账号路径（9354/9355）保持不变。

---

## 7. 当日分时（`timeline`）

客户端入口：`client.timeline(code, market=...)` → `TimelineService.timeline` →
`select_timeline_plan` 按账号自动选 BASIC/LEVEL2。

### 7.1 普通账号（MAIN 9355，2026-08-06 抓包修正）

> **2026-08-06 修正**：当日分时走 pageid=**9355**（同历史分时 builder），非 9354（已废弃）。
> DataType 末尾追加 `14,15`（主动买卖累计量），用于计算买卖力量红绿柱。

请求文本（`features/history_timeline_protocol.py build_normal_history_timeline_query(today=True)`，两段子帧）：

```text
CodeList=33(000938,);
DataType=207,13,19,54,204,10,203,210,23,202,209,22,201,208,6,1110,407,1111,14,15,
DateTime=8192(0-0)
DTPrevOff=-367
LackTime=0,3,0,0,0,0,0,0
pageid=9355
```

prefix 子帧 route `0x006C`；query 子帧 route `0x016C`，`history_flag=0x20`。
加 dt14/dt15 后响应 flag 从 0x005e 变为 **0x0066**（rs 56→64）。

响应：`hd3.1`（flag 0x0066，`record_count=241`），`parse_index_timeline_response` 解析。
字段含 dt10(现价)、dt13/dt19(累计量/额)、**dt14/dt15(主动买/卖累计)**。

### 7.2 Level2 账号（1334，2026-08-05 抓包对齐）

请求文本（`build_timeline_l2_query`，route `0x0201`，`hdr[18]=0x20`，seq 高字节 `0x10`）：

```text
CodeList=32(399002,);33(000938,);      # 深市自动带基准指数；沪市为 16(1A0002,)
DataType=1,16,229,14,207,15,228,13,227,19,40,226,54,18,204,39,225,10,203,210,38,224,23,202,209,223,230,15,22,201,208,
DateTime=8192(0-0)
LackTime=0,3,0,0,20031231,2,0,0
pageid=1334                             # 2026-08-05 改：原 4214，DataType/route 不变
```

关键点：

- 必须先通过 `L2SubscriptionCoordinator.ensure_registered` 在对应市场 L2 连接上注册 4214
  订阅（普通身份发同样的订阅帧会 `CodeListSize=0`）。
- 31 个 L2 字段含 `dt201-230` 大单金额双线（`dt227/dt229`=主动买/卖额，差值为主力净额曲线）。
  **pageid 改 1334 不影响 L2 字段**——抓包确认 1334 请求的 DataType 仍含 dt223-230。
- 解析入口 `parse_timeline_l2_response`（校验 flag=0x00B4）；深市必须连 szlv2。

### 7.3 指数白线与领先线（黄线）

指数代码使用指数市场码：沪市 `1A/1B` 自动推断为 16，深市 `399` 自动推断为 32；解析器同时接受
指数市场码 144。指数不是个股，不走数字股票的快照注册，也不附加 399002/1A0002 基准代码。
当日请求仍按账号选择：普通账号使用 `build_timeline_query` 的 9354，Level2 使用
`build_timeline_l2_query` 的 4214。响应是带 26B shell 的 `hd3.1` BitRLE 表，已确认 flag 为
`0x003E/0x0086/0x009E`。

字段语义以抓包和同花顺客户端画面逐点对照为准：

- `dt10` 是指数白线的绝对点位；
- `dt40` 不是绝对点位，而是相对上一交易日收盘点位的**有符号基点数**；
- `lead_change_bp = int32(dt40)`，`lead_change_pct = lead_change_bp / 100`；
- `lead_price = prev_close × (1 + lead_change_bp / 10000)`，即客户端黄线（领先/等权线）。

`client.timeline()` 会在未显式传入 `prev_close` 时查询日 K 得到上一交易日收盘点位，再补齐
`lead_change_bp`、`lead_change_pct`、`prev_close`、`lead_price`，同时保留原始 `dt40`。例如：

```python
rows = client.timeline("1A0001")
print(rows[-1]["dt10"], rows[-1]["lead_price"])
```

### 7.4 买卖力量（红绿柱，dt14/dt15）

指数分时图零轴上下的红绿柱（买卖力量对比）来源是 **dt14/dt15**（累计主动买入/卖出量），
不是 dt22/dt23。

**关键纠正（2026-08-06）**：dt22/dt23 经实测**不是累计主动买卖量**——在 Level2(0x009e)
和普通账号(0x005e)两张表里都非单调（109-111/82-96 个回撤点），翻转任何单个 bit 都不能修复。
dt14/dt15 严格单调（0/240），`dt14 + dt15 ≈ dt13`（成交总量）。

| 字段 | 含义 | 单调性 | 买卖力量 |
|---|---|---|---|
| **dt14** | 累计主动买入量 | 0/240 ✓ | buy_force = dt14[t] - dt14[t-1] |
| **dt15** | 累计主动卖出量 | 0/240 ✓ | sell_force = dt15[t] - dt15[t-1] |
| dt22 | 实时快照（非累计） | 109/240 ✗ | ✗ 不可用 |
| dt23 | 实时快照（非累计） | 82/240 ✗ | ✗ 不可用 |

`services/timeline.py _enrich_buy_sell_force` 在分时 records 含 dt14/dt15 时自动计算：
- `buy_force`：本分钟主动买入量
- `sell_force`：本分钟主动卖出量
- `net_force = buy_force - sell_force`（正=红柱/买强，负=绿柱/卖强）

普通账号 9355 和 Level2 1334 的 DataType 都含 14/15，结果完全一致。
**北证50（899050）dt14/dt15 全为 0**——服务端不提供北交所指数的主动买卖拆分，
与同花顺客户端一致（客户端也没有北证50 买卖力量）。

### 7.5 北交所分时（BSE，pageid 10443/11695）

北交所（BSE）用与沪深完全不同的 pageid 和 market 码，走 `main.123ths.com` 的 MAIN 连接
（不分 BASIC/LEVEL2，均走 MAIN）：

| 标的 | market | pageid | DataType | dt14/dt15 | 响应 flag |
|---|---|---|---|---|---|
| 北交所个股（920xxx/83xxx/43xxx/87xxx） | **151** | **10443** | `14,13,19,54,10,23,15,22` | ✓ 含 | 0x0046 |
| 北证50 指数（899050） | **144** | **11695** | `272,207,42,271,228,13,…` | ✗ 无 | 0x006e |

**网关发现（关键）**：北交所数据只在 `main.123ths.com` 的 IP 上可用（如 `218.245.102.0`），
`ifindhq.123ths.com` 不支持。`resolve_market_hosts` 硬编码优先 `main.123ths.com`（passport
不含此域名），DNS 失败时才 fallback ifindhq。init MarketCode 不需要加 151。

请求 builder：`build_beijing_timeline_query`（个股，route SUB1=0x014a/SUB2=0x0100）、
`build_beijing_index_timeline_query`（指数，route SUB1=0x003e/SUB2=0x013e），均为双子帧 0x09。
parser：`BEIJING_TIMELINE_FLAGS = {0x0046, 0x006e}`，放宽 dt40 要求。

`_market_for_code` 按代码前缀路由：`43/83/87/920` → market 151，`899` → market 144。

---

## 8. 历史分时（`history_timeline`）

客户端入口：`client.history_timeline(code, date, market=...)`；非交易日/当天之外一律走历史页。

### 8.1 普通账号（MAIN 9355）

请求（`build_normal_history_timeline_query`，两段子帧）：

```text
# 段1 prefix：subtype 0x0002, route 0x006C
CodeList=33(000938,);
pageid=9355

# 段2 query：subtype 0x0009, route 0x016C, history_flag
CodeList=33(000938,);
DataType=207,13,19,54,204,10,203,210,23,202,209,22,201,208,6,1110,407,1111,
DateTime=8192(132479582-132479937)      # packed-date 游标（两账号统一）
DTPrevOff=-367
LackTime=0,3,0,0,0,0,0,0
pageid=9355
```

bar 游标用**打包日期**编码：`(year-1900)<<9 | month<<5 | day`，再 `×2048 + 606`
（`date_to_normal_timeline_bar`）。响应为 `hd1.0` 普通表：flag `0x0042`、`hs=28`、`fc=7`，
每行 `bar_index + dt10/13/19/22/23/54`（基础价量额）。

**请求模式（2026-08-01 修正）**：客户端分时窗口放大后走 route `0x006C`，服务端回**全量 241 点**；
窗口较小时走 route `0x007A` 稀疏模式，服务端只下发部分分钟（实测 07-23 201/241、06-30 185/241，
多张 0x42 表、行乱序）。`build_normal_history_timeline_query` 恒走 0x6C 全量；抓包复现历史分时
前务必先把分时窗口放大/最大化。

### 8.2 Level2 账号（4417）

请求（`build_history_timeline_query`，三段子帧流水线）：

```text
# 段1 prefix：subtype 0x0002, route 0x0058（深） / 0x007C（沪）
CodeList=33(000938,);
pageid=4417

# 段2 full：subtype 0x0009, route 0x0100|base, history_flag
CodeList=32(399002,);33(000938,);       # 深市个股自动带基准 399002；沪市不带
DataType=229,207,228,13,227,19,226,54,204,225,10,203,210,224,23,202,209,223,230,22,201,208,6,1110,407,1111,
DateTime=8192(132477534-132477889)      # packed-date 游标
DTPrevOff=-61
LackTime=0,3,0,0,0,0,0,0
pageid=4417

# 段3 tail：subtype 0x0002, route 0x0200|base
CodeList=32(399002,);
pageid=4417
```

bar 游标与普通账号一样用 **packed-date 编码**（`(year-1900)<<9 | month<<5 | day) × 2048 + 606`）。
2026-08-01 抓包铁证：07-23 请求游标 `132627038 = packed(07-23)`；旧 ordinal 公式只在
05-13/14、07-24 等日期巧合一致（07-23 会误标成 07-26）。`build_history_timeline_query` 内部统一
调用 `date_to_normal_timeline_bar`；`date_to_timeline_bar`（ordinal）仅保留给竞价 4417 上下文
预热兼容。241 个交易点的偏移固定为 `0..29, 34..93, 98..128, 227..285, 290..349, 354`。

响应为 `hd1.0` Level2 表：flag `0x007E/0x0082`、`hs=88/92`、`fc=22/23`。解析器
（`parse_history_timeline_response`）按字段表动态取值，用 bar 锚点定位物理行（不按固定步长硬切），
得到 23 字段：

2026-08-01 确认：L2 4417 响应体恒含**两张表**——`0x007E`（基准 399002/1A0002，22 字段、无 dt54）
+ `0x0082`（目标股，23 字段、含 dt54），且恒为全量 241 点（无 0x7A 稀疏模式）。

`bar_index, dt10, dt13, dt19, dt22, dt23, dt54, dt201-204, dt207-210, dt223-230`

- `dt10` 价格、`dt13` 累计成交量、`dt19` 累计成交额；
- `dt54` 历史分时为 `0xFFFFFFFF` 哨兵 → 0.0；
- `dt201-230` 为 Level2 大单金额双线（`dt227/dt229`=主动买/卖额累计，差=主力净额曲线）。

### 8.3 指数历史分时（pageid=77）

指数历史分时不是 9355/4417 个股协议。`build_index_history_timeline_query` 使用单请求：

```text
CodeList=16(1A0001,);
DataType=13,19,40,10,23,22,6,
DateTime=8192(132651614-132651969)     # packed-date 游标
LackTime=0,3,0,0,0,0,0,0
pageid=77
```

响应为 `hd1.0` 0x42 表，按 `bar_index` 锚点恢复盘中记录；`dt40` 同样按有符号基点解码，
`client.history_timeline()` 默认通过日 K 自动取目标日的昨收并还原 `lead_price`。

**指数历史分时没有早盘或尾盘竞价序列。** 同花顺客户端只提供沪深创业板指数的**当天**竞价；
查询历史指数时，`client.intraday()` 只返回带 `phase="continuous"` 的盘中记录，不调用
`auction()` / `closing_auction()`。个股历史分时仍按 9/10 节分别请求竞价并合成三段。

---

## 9. 早盘竞价（`auction`，9:15-9:25）

客户端入口：`client.auction(code, trade_date=...)` → `AuctionService.auction`。

### 9.1 普通账号（MAIN）

`build_basic_auction_query`：当日 `pageid=9354/period=7176`，历史 `pageid=9355/period=6144`；
route `0x0100`，`hdr[18]=period>>8`：

```text
CodeList=33(000938,);
DataType=10,27,33,49,
DateTime=6144(1784855700-1784856300)    # 历史：9:15-9:25 unix 时间戳
LackTime=0,0,0,0,0,0,0,0
pageid=9355
```

### 9.2 Level2 账号（shlv2/szlv2）

- 当日：`build_auction_query`，`pageid=4214/period=7176`，route 字节 `fc 01`，
  `hdr[15]=0x40、hdr[17]=0x08、hdr[18]=0x1C`，seq 高字节 `0x01`。
- 历史：`build_l2_history_auction_query`，`pageid=4417/period=6144`；但服务层
  （`_build_l2_history_auction_bundle`）会把三条请求用 `\n` 流水线一次发出（复刻 PC 客户端）：

  ```text
  ① 历史分时上下文（pageid=4417，日期=目标日的下一个工作日，seq 0x10EC）
  ② 尾盘竞价   （pageid=4417，period=7424，seq 0x00EF）
  ③ 早盘竞价   （pageid=4417，period=6144，seq 0x00F1）
  ```

  `auction()` 读帧时用 9:15-9:25 窗口过滤出早盘结果；`closing_auction()` 用 14:57-15:00 窗口。

### 9.3 响应字段

`parse_auction_response`（hd1.0，字段表 `fc=5`）：

| 字段 | 含义 | 备注 |
|---|---|---|
| `time`（dt1） | unix 秒 → datetime | 9:15:00-9:24:57，沪 3 秒/深 9 秒一个 tick |
| `dt10` | 撮合价（虚拟开盘价） | |
| `dt49` | 累计竞价量（股，÷100=手） | |
| `dt27` | 买方未匹配量 | 撮合被动方被吃光时为哨兵 → `None` |
| `dt33` | 卖方未匹配量 | 同上，每 tick 恰好一侧为 None |

沪市原始响应走 `cmd=0x0a` 外层压缩，`parse_auction_response` 先
`normalize_8901_response` 解压，再按定长行（hs=20，fc=5）解析。旧启发式
`_parse_auction_sh` / `_split_auction_state_rows` 兜底已删除（2026-08-07）——
「19 字节短行」是外层未解压造成的假象，normalize 后沪深均为定长行。

### 9.4 指数当天开盘竞价（T_URL）

指数竞价不是个股的 7176/6144 表，而是 `pageid=6240` 的 `T_URL` JSON 接口，仅提供当前交易日：

```text
# 沪市
T_URL=/quote/auction/USH/USHI_1A0001.dat
# 深市（深证成指/创业板指同形）
T_URL=/quote/auction/USZ/USZI_399001.dat
```

PC 客户端先在同一 8901 外层帧中发送 `CodeList + pageid` 子帧和开盘 `T_URL` 子帧。
`T_URL` 文本实际以单个 `\r` 结束，但头部声明长度比实际文本多 1；这是抓包确认的线协议，不应
“修正”为普通 `\r\n`。响应 JSON 根为 `Auction`，字段 `markettime/newprice/leadprice/volume`；
解析后另提供 `time`、`dt10=newprice`、`lead_price=leadprice`、`auction_type="opening"`。

---

## 10. 尾盘竞价（`closing_auction`，14:57-15:00）

客户端入口：`client.closing_auction(code, trade_date=...)`。

- 普通账号：`build_basic_auction_query(closing=True)`，当日 `9354` / 历史 `9355`，`period=7424`。
- Level2：`build_l2_closing_auction_query`，当日 `4214` / 历史 `4417`，`period=7424`；
  历史同样走 9.2 的三条流水线 bundle。
- DataType 固定 `10,49,287,`；DateTime 为 `7424(14:57 时间戳-15:00 时间戳)`。

响应（`parse_closing_auction_response`）：

- 历史 4417：`hd1.0`，flag `0x0036`、`hs=16`、`fc=4`，字段 `[1,10,49,31]`
  （`time/dt10/dt49/dt31`）。
- 当日 4214：可能是 `hd3.1` BitRLE，同一解析器两条分支都处理。
- **容错**：历史帧末条记录固定被截断 1 字节 → 补零保留收盘点；`record_count` 声明多 1 时，
  遇时间戳出窗即停（保留已解记录）。

实测节奏：沪市约 61 点（3s/tick），深市约 20-21 点（9s/tick）——市场真实节奏，非 bug。

### 10.1 指数当天尾盘竞价（T_URL）

指数尾盘竞价只存在于当前交易日，并且客户端只为三大指数提供：上证指数 `1A0001`、深证成指
`399001`、创业板指 `399006`。对应 URL 为：

```text
/quote/auction/USH/USHI_CLOSE_1A0001.dat
/quote/auction/USZ/USZI_CLOSE_399001.dat
/quote/auction/USZ/USZI_CLOSE_399006.dat
```

直接只发 close URL 不能稳定复现 PC 行为。正确线序是：

```text
① 一个外层帧：CodeList 子帧 + 开盘 T_URL 上下文子帧
② 一个 LF（0x0A）分隔
③ 一个外层帧：CloseAuction T_URL 子帧
```

两条 T_URL 均以单个 `\r` 结尾且声明长度 `+1`。服务读取时会跳过先到达的 `Auction` 响应，直到
JSON 根为 `CloseAuction`；解析别名为 `dt10=newprice`、`lead_price=leadprice`、
`auction_type="closing"`。2026-08-04 同花顺 PC 客户端抓包与活网 API 逐点一致，三个指数均为
12 点（约 15 秒一个点）：

| 指数 | 首点 | 15:00 白线 `dt10` | 15:00 黄线 `lead_price` |
|---|---|---:|---:|
| 上证指数 1A0001 | 14:57:11 | 3822.2800 | 3872.138424 |
| 深证成指 399001 | 14:57:12 | 13885.7110 | 13722.634096 |
| 创业板指 399006 | 14:57:12 | 3488.9663 | 3402.620768 |

历史指数没有对应的竞价 URL 数据；传历史日期时接口会明确报错，而不是回退到个股协议。

---

## 11. 系统板块（`system_blocks`）

系统板块 = 行业/概念板块发现、成分股、板块指数（行情/分时/竞价）。**数据源决策（2026-08-01）**：
全程以抓包同花顺 Windows 客户端的 8901 数据形式为准，不用 `basic.10jqka.com.cn` 网页接口兜底；
本地 `BlockUpdate/block_*.ini` + `industry.ini`（block_hq 缓存）只作**离线 oracle**（稳定 ID /
名称/成分股真值），不是查询路径。

### 11.1 通道与路由（双账号抓包铁证）

| 业务 | 通道 | 说明 |
|---|---|---|
| 板块指数（行情/分时/竞价） | 专用板块通道 `fu4.123ths.com:8901` | 独立 `ConnectionRole.BOARD`；在 MAIN 上原样重放引导帧只回 `CodeListSize=0` |
| 成分股 | 股票行情网关：普通 `main.123ths.com` / L2 沪 `shlv2.123ths.com` / L2 深 `szlv2.123ths.com` | 独立连接角色 `BOARD_CONSTITUENT_SH/SZ`；连错到 fu4 `globalthsindex-gateway` 时全部 subreal 注册回 `errorcode=-1`、业务只回 26B 空 Sort |

板块通道引导序列（`features/system_blocks_protocol.py`，分三阶段发送、阶段间 0.2-0.6s、每帧后带
`0x0a`）：subreal 注册（URS/UCT/UNX/UCX/UME，pageid L2=5716 / 普通=392）→ pageid 注册 →
`MarketCode=96;128;88;216;48;` init（含 MarketDate/StockLinkVer）→ qureal-init×10（instid
0xE0000/0x290000 起、步长 0x20000）→ `DataType=[5],[55]` 分类表 → StockNameVer（L2 双子帧 /
普通 upstockname）。**板块指数统一 `market=48`**（881xxx 行业指数 / 885xxx、886xxx 概念指数）。

成分股引导（独立连接）：普通账号 `thsuser` + MKT_INIT `MarketCode=16;32;144;`；L2 沪 `thsuser`
+ `16;144;`；L2 深 `__manual` + `32;`；subreal class 后缀普通账号为 `UNSI/UHII`。普通账号流程：
先等 Sort 代码页（`SortBegin=0`）→ 发 527527 → 完整字段；L2 不分页，把整市场 universe 按沪/深
两条连接下发（0x64 表；一帧可含多张 hd3.1 表，解析器会扫描后续表）。

### 11.2 请求与响应

板块指数请求为双子帧（前缀 CodeList+pageid + 查询 DataType/DateTime/LackTime/pageid），历史分时
用 packed-date 游标。账号差异只体现在 pageid：

- Level2：`5716/1341`（板块列表+当日分时）、`6000`（成分股+当日分时）、`6002`（板块历史分时/K线/竞价）；
- 普通：`392`（板块列表）、`4180`（成分股+当日分时）、`4181`（历史分时/K线/竞价）。

| 响应表型 | 行宽 | 字段 | 业务 |
|---|---|---|---|
| `0x130` | 344B | dt5(16B 代码)、dt55(20B GBK 名称)、dt6/7/8/9/10/13/19…（dt5/dt6 出现两次，取首次） | 旧版兼容：板块详情页相关行业/概念板块的周期行情推送 |
| `0x64` | 95B | dt5(7B 代码)、dt215…dt66 共 21 字段 | 板块成分股行情 |
| `0x42` | 28B | dt1/10/13/19/22/23/40 | 板块指数分时（242 点/日，dt1=packed bar 游标） |
| `0x32` | 12B | dt1(unix 秒)/10/49 | 板块集合竞价 |

> **2026-08-02 实测修订**（`system_blocks_20260802_*.pcap`）：
> - 板块列表查询（普通 pageid=392）前缀/查询子帧路由为 **0x006C/0x016C**
>   （L2 5716 为 0x0052/0x0152），查询子帧**不带** history flag（字节 17=0x00），
>   `LackTime=0,0,0,0,0,0,0,0`，seq=0x01C4/0x0068。08-01 跨机抓包中的
>   旧列表形态为 0x0039/0x0139、同样无 history flag 且 LackTime 全 0；同路由
>   另有 `DataType=527527`、history flag、`LackTime=0,3,…` 的独立请求，不能混为
>   一个“旧形态”。当前服务端对旧列表形态静默不回复。列表直接响应是
>   0x20/0x1c/0x22 紧凑表（513 行，无名称列）。
> - `0x130` 是响应表 flag，不是请求 opcode。08-01 抓包逐码对齐显示，它由
>   pageid=4180/4181 板块详情页的相关行业/概念板块批量查询触发：服务端周期推送
>   “请求代码 + 当前板块”组成的 0x130 名称行情表，不是 pageid=392 列表请求的
>   直接响应。客户端同时上报了非零 StockLinkVer/StockNameVer，因此触发它不需要
>   删除本地 `BlockUpdate/*.ini` 或 `industry.ini`。
> - 0x42 表有**两种用途**：分时字段集 [1,10,13,19,22,23,40]（242 点/日）与
>   日K 字段集 [1,7,8,9,11,19,13]（DateTime=16384，dt1=YYYYMMDD，596 根/次）；
>   `parse_board_timeline_response` 按字段集区分，日K 走
>   `parse_kline_hd3_response`。
> - 竞价请求 08-02 实测为单查询子帧（pageid=6000/6002，route 0x01FC，
>   h17=0x1C，LackTime 全 0）；与 08-01 双子帧形态的差异仍需同环境受控复验。

稳定 ID：行业 `881xxx`（与 `q.10jqka.com.cn/thshy` 同源）；概念/地域为十六进制 block_id（如
`C024`=BC电池）；概念板块在 8901 中的代码域为 885xxx/886xxx（已见 9354/9355 带 881xxx/885xxx/
886xxx 代码列表的请求样本）。

### 11.3 本地离线 oracle（`features/system_blocks.py`）

| 文件 | 内容 |
|---|---|
| `BlockUpdate/block_2B.ini` | 概念板块：hex block_id → 名称 + 成分股（`17:688981,-105:920045` 格式，~390 个） |
| `industry.ini` | 同花顺行业：881xxx → 名称 + 成分股（~90 个） |
| `BlockUpdate/block_tree.ini` | 板块树：根 `[@10001]` → 分类根（2B 概念 / 47 地域 / 7 港股…）→ 分组/叶子 |
| `BlockUpdate/block_47.ini` 等 | 地域/港股/基金/指标股等分类 |

### 11.4 门面与代码位置

- 离线缓存门面（无需登录）：`client.system_blocks`（`SystemBlocksService`）、
  `system_block_categories()`、`list_system_blocks(category=None)`、`get_system_block_constituents(block_id)`。
- 活网门面：`client.board_quotes(codes)`、`board_timeline(code, date)`、`board_auction(...)`、
  `board_constituents(block_id)`（`ServiceFacade` → `BoardService`）。
- 代码：`features/system_blocks_protocol.py`（builder/parser）、`features/system_blocks.py`
  （本地缓存解析）、`services/system_blocks.py`（`BoardService`）、
  `_client/connection_primitives.py::_open_board_channel`（fu4/成分建连 + 引导）、
  `_transport/tracing.py`（逐帧收发转储 `THS_FRAME_DUMP_DIR`）。
- 回归：`tests/test_system_blocks_protocol.py`（9 项离线）、`tests/test_board_channel.py`、
  `tests/test_frame_trace.py`（逐字节对照）、`tests/verify_board_online.py`（活网四接口）。

### 11.5 新通道排查要点（2026-08-01 成分股空列表复盘）

1. `VerifyCode=0` 只证明 login 壳被接受，**不等于通道角色已绑定**；通道可用性由引导阶段逐帧响应
   （errorcode / CodeListSize / 配置帧）确认。
2. “必须走 fu4”只适用于**板块指数**；成分股是例外（股票行情网关）。推广结论前先用“抓包流对端
   IP ↔ passport `M_hqdns` 域名 ↔ 登录回执 S-Name”三方核对。
3. 排障先开 `THS_FRAME_DUMP_DIR` 看逐帧服务端显式错误码，再做字节 diff；字节对照三要素：
   同一后端、同一账号类型、同一版本环境（StockLink.ini 版本表）。
4. “返回空”不等于“走通只是没数据”：能力门禁、deadline break、accept 过滤都可能吞掉错误。

---

## 11b. 股票名称全量同步的服务器分组（2026-08-08）

全量名称下载用二进制 `0x001c StockNameVer` 帧（`MarketCode=...` + `StockNameVer=;;`）
在新建的 123ths.com 会话上触发，域名按账号类型分组：

| 账号/市场 | MarketCode 组 | pageid | 域名 |
|---|---|---|---|
| level2 | 16;144;208 | 5716 | `shlv2.123ths.com` |
| 普通 | 32;208 | 392 | `main.123ths.com` |
| 任意 | 32 | 5716/392 | `szlv2.123ths.com` |
| 任意 | 96;128;88;216;48 | - | `fu4.123ths.com` |
| 任意 | 176;112 / 168;184;200 | - | `hkus.123ths.com` |
| 任意 | 120;104 | - | `ifindhq.123ths.com` |
| 任意 | 64 | - | `fu2.123ths.com` |
| 任意 | UNS/UHI | - | `usotc.123ths.com` |

实现：`features/stock_name_bootstrap.py` 固化引导模板；
`services/stock_name.py::download_full_stock_names` 开新 socket 登录、重放引导、
发触发帧并解码 `name_16_16`。公开入口：`THSClient.fetch_stock_names_full()`。
全量下载后每段 ConfigVer + 名称缓存到 `~/.thspypc/stockname/`，下次上报缓存版本；
服务器静默表示缓存已最新。上报真实旧 ConfigVer（如 20260306）会触发服务器只回
变化的段及新 ConfigVer；编造版本会被忽略。

全市场组批量刷新走 `THSClient.fetch_all_stock_names()`（`download_all_stock_names`）：
一次并发登录所有组并保持长连接 + 3s 心跳，避免串行重登触发 `VerifyCode=-1`（见 4.5）。

`ifindhq` 的 120/104 组特殊：`StockNameVer=;;` 不回名称；2026-08-09 抓包确认
真实客户端用 `MarketCode=104;` 加上 104_* 段 ConfigVer 触发，服务器才回
`[name_120_120]` / `[name_104_104]`。内容为 iFinD 指数/债券名称，对应 Windows
端 `stockname_120_0.txt` / `stockname_120_1.txt`，不是 A 股股票名，非核心。
响应是 `0x0a` 压缩帧，读帧后必须先用 `decode_name_frame` 解码，不能按原始
`[name_` 字符串过滤。

## 12. K线：日K / 周K / 月K / 分钟K（`kline`）

客户端入口：`client.kline(code, period=..., count=..., anchor=...)`，周期名支持
`"1min"/"5min"/"15min"/"30min"/"60min"/"day"/"week"/"month"/"quarter"/"year"`
（2026-08-03 抓包确认 1分K=0x3000、季K=0x6003、年K=0x7001），映射见
`client._KLINE_PERIOD_CODES`。

请求（`features/kline_protocol.py build_kline_query`，**普通账号走 MAIN**，pageid=9355；
**Level2 账号走 L2 连接**，pageid=1334 route=0x0100，见 `build_kline_l2_query`）：

```text
ReqFuquan=Q
CodeList=33(000938,);
DataType=7,8,9,11,13,19,
DateTime=16384(-count-anchor)           # 周期码(根数-窗口终点)，0x4000=日K
LackTime=0,0,0,0,0,0,0,0
pageid=9355                             # 普通账号；Level2 账号=1334
```

| 周期 | 周期码 | route | hdr[17] |
|---|---|---|---|
| 1分K / 5min / 15min / 30min / 60min | 0x3000 / 0x3005 / 0x300F / 0x301E / 0x303C | 0x0001 | 0x05 |
| 日K | 0x4000 | 0x0001 | 0x00 |
| 周K / 月K / 季K / 年K | 0x5001 / 0x6001 / 0x6003 / 0x7001 | 0x014E | 0x01 |

字段：`dt7`=开、`dt8`=高、`dt9`=低、`dt11`=收、`dt13`=量、`dt19`=额；
`ReqFuquan=Q` 为前复权。

`DateTime={period}(-{count}-{anchor})` 语义（2026-08-03 抓包确认）：取
`count` 根、以 `anchor` 为终点，服务端返回 **`count+1` 根**（含终点，受上市日
截断）。`anchor=0`=最新一根；日/周/月/季/年K 的 anchor 是 **YYYYMMDD 日期**，
分钟K 的 anchor 是 **bar_index**。**往前翻页** = 把 anchor 设为上一窗口最早
一根（日期或 bar_index）再请求，可一直回溯到上市日（客户端 000938 日K：
`(-1938-0)` → `(-3103-20180727)` → `(-4349-20041109)`，服务端逐段返回
1939/3104/1195 根，MAIN/9355 与 L2/4417 结果一致）。

响应：`hd3.1`（flag `0x0042/0x0046`），BitRLE 位平面解压 + 转置
（`parse_kline_hd3_response`），输出 `{code, time/bar_index, open, high, low, close, volume, amount}`。

注意：不再做"坏 IP/数据完整性"校验——登录成功即信任该 IP，服务端返回多少根就
返回多少（新股/上市日截断自然根数少，属正常）；仅传输失败（超时/断连）时自动
断连重试。K线查询要求 MAIN init 已激活。

---

## 13. 服务编排与客户端入口

### 13.1 services/ 层职责

| 类 | 文件 | 职责 |
|---|---|---|
| `TimelineService` | `services/timeline.py` | 个股/指数当日与历史分时：选 plan → 发请求 → 读帧 → 解析；指数黄线保留 dt40 |
| `AuctionService` | `services/auction.py` | 个股早盘/尾盘竞价；历史 L2 三条 bundle；指数当天 T_URL 开盘/尾盘线序 |
| `KlineService` | `services/kline.py` | 单请求持有 MAIN 锁，读到 hd3.1 为止 |
| `BoardService` | `services/system_blocks.py` | 板块行情/分时/竞价（BOARD 通道）+ 成分股（独立连接事务） |
| `ConnectionManager` | `_transport/connection_manager.py` | 角色连接注册表 + capability 门控 |
| `L2SubscriptionCoordinator` | `services/subscription.py` | 4214 订阅注册/保活 |

所有请求在 `ConnectionManager.acquire()` 通过后，持该连接的**单飞锁**执行，读完解析出记录即返回；
只读到压缩/非目标帧则继续读（`max_frames` 上限）。

### 13.2 客户端 API 一览（`THSClient` = `ConnectionPrimitives` + `ServiceFacade`）

| 方法 | 底层 |
|---|---|
| `timeline(code, market, prev_close)` | 个股/指数：普通→9354 / L2→4214；指数额外还原黄线 |
| `history_timeline(code, date, market, prev_close)` | 个股：普通→9355 / L2→4417；指数→77 并还原黄线 |
| `auction(code, trade_date)` | 个股→9354/9355/4214/4417；指数当天→6240 T_URL |
| `closing_auction(code, trade_date)` | 个股→9354/9355/4214/4417；三大指数当天→6240 T_URL |
| `intraday(code, trade_date)` | 个股三段合并；历史指数仅盘中，记录均加 `phase` 标签 |
| `kline(code, period)` | MAIN 9355，日/周/月/分钟 |
| `board_quotes / board_timeline / board_auction / board_constituents` | 板块指数与成分股（见 11 节） |
| `list_quotes / market_snapshot` | MAIN 批量行情（非本文范围） |
| `stock_list / stock_list_hot` | MAIN 股票列表与排序榜（非本文范围） |

### 13.3 `intraday()` 编排

```text
opening_auction = auction(trade_date)        # 9:15-9:25
continuous      = history_timeline(date)     # 历史：241 点；当天：timeline()
closing_auction = closing_auction(trade_date)# 14:57-15:00
合并输出，每条记录带 phase 字段

例外：historical and index -> 只查询 continuous；历史指数没有两段竞价数据
```

---

## 14. 常见问题与注意事项

1. **dt 号语义不跨接口复用**：`dt33` 在竞价=卖方未匹配量、分时=成交额、list_quotes=注册制
   上市日；`dt49` 在竞价=累计量。语义由所在接口的字段表定义。
2. **普通账号不伪造 L2 字段**：历史分时普通表只有 7 个基础字段，代码不硬造 dt201-230。
3. **L2 历史必须走 shlv2/szlv2**：MAIN 对 4417 只回短帧；非 L2 域名 init 只回 210B。
4. **`VerifyCode=-1` 不是封禁**：多为同 IP 短时重复 login（L2 单点登录）会话冲突，换 IP 即恢复。
5. **连接还活着时别急着重连**：20s 内重复 connect 反而触发 -1；心跳保活。
6. **`DateTime` 语义三套**：竞价=unix 时间戳区间；分时/历史分时=bar 游标区间；K线=回溯窗口。
7. **竞价末条记录截断**是服务器常态（历史尾盘帧固定少 1 字节），解析器已容错，不代表丢数据。
8. **深市 L2 竞价 tick 9 秒、沪市 3 秒**是市场节奏差异，不是 bug。
9. **能力证据不足时接口明确报错**（`CapabilityUnavailableError`/`UnsupportedAccountFeatureError`），
   不会静默返回空列表冒充成功。
10. **板块指数必须走 fu4、成分股必须走股票行情网关**（main/shlv2/szlv2）；连错后端时 subreal
    注册全部 `errorcode=-1`，现象是等约 47s 后返回空列表。
11. **登录成功 ≠ 通道就绪**：新通道（fu4/成分）必须以引导阶段逐帧响应为准（开
    `THS_FRAME_DUMP_DIR`），不能拿 `VerifyCode=0` 当作绑定成功。
12. **指数黄线 dt40 是有符号基点，不是价格**：必须结合上一交易日收盘点位还原；直接按 THS float
    或无符号整数解释都会得到错误曲线。
13. **历史指数无竞价**：只有上证指数、深证成指、创业板指有当天尾盘竞价，不要把个股历史竞价
    协议套到指数上，也不要用空数组伪装成服务端存在历史竞价数据。
14. **买卖力量用 dt14/dt15，不是 dt22/dt23**：dt22/dt23 是实时快照（非累计、非单调），
    翻转任何 bit 都不修复；dt14/dt15 严格单调（`dt14+dt15≈dt13`），是真正的主动买卖累计量。
15. **北交所走独立 pageid + main.123ths.com**：个股 market=151/pageid=10443，指数 market=144/
    pageid=11695，均走 main.123ths.com 的 MAIN 连接。ifindhq 不支持北交所。北证50 无买卖力量
    （dt14/dt15 全 0，与客户端一致）。

---

## 15. 代码地图

| 文件 | 职责 |
|---|---|
| `src/thspypc/client.py` | `THSClient` 门面、连接治理、`_run_default_service`、K线周期映射 |
| `src/thspypc/protocol.py` | HTTP 鉴权、login/init/heartbeat 帧、8901 压缩入口、公共常量 |
| `src/thspypc/features/auth_protocol.py` | login 帧构造（thsuser/__manual）、login 响应解析 |
| `src/thspypc/features/timeline_protocol.py` | 当日分时请求 + hd3.1 解析；指数 dt40 有符号解码与黄线还原；买卖力量 flag (0x005e/0x0066/0x0046/0x006e) |
| `src/thspypc/features/history_timeline_protocol.py` | 个股 9355/4417、指数 77 历史分时请求 + hd1.0 解析、bar 游标编码；北交所分时 builder (10443/11695) |
| `src/thspypc/features/auction_protocol.py` | 个股竞价表与指数 6240 T_URL builder/parser（Auction/CloseAuction） |
| `src/thspypc/features/kline_protocol.py` | K线请求构造 + hd3.1 BitRLE 解析 |
| `src/thspypc/features/system_blocks.py` | 本地 block_hq 缓存解析（离线 oracle：板块树/概念/行业） |
| `src/thspypc/features/system_blocks_protocol.py` | 板块通道引导 + 板块指数/成分股 builder/parser（0x130/0x64/0x42/0x32） |
| `src/thspypc/features/account_profile.py` | 账号类型判定、能力证据沉淀 |
| `src/thspypc/services/timeline.py` | 分时 plan 选择、读帧循环、L2 订阅前置 |
| `src/thspypc/services/auction.py` | 个股竞价、历史 L2 三条 bundle、指数当天 T_URL 上下文/尾盘 bundle |
| `src/thspypc/services/kline.py` | K线服务（MAIN 锁 + 多帧收集） |
| `src/thspypc/services/system_blocks.py` | `BoardService` 四接口 + `SystemBlocksService`（本地缓存门面） |
| `src/thspypc/services/subscription.py` | 4214 订阅注册/保活 |
| `src/thspypc/_transport/` | ConnectionRole/Spec/Manager、MarketSession（单飞锁） |
| `src/thspypc/_transport/tracing.py` | 逐帧收发转储（`THS_FRAME_DUMP_DIR`：C2S/S2C 原始字节 + 逐帧 hex/文本） |
| `src/thspypc/_client/connection_primitives.py` | TCP login/init、并发测速与登录、L2 手动连接、fu4 板块通道/成分连接建连（身份回退链） |
| `src/thspypc/_client/service_facade.py` | `timeline/history_timeline/auction/closing_auction/intraday/kline` 门面 |
| `src/thspypc/codecs/` | framing（FDF）、hd 字段表、numeric（THS float）、compression（8901 LZ77 / BitRLE） |
| `docs/architecture/SERVER_MATRIX.md` | 服务器域名/权限/路由详细矩阵 |
| `docs/handoffs/*.md` | 各协议逆向证据链（竞价、分时、推送、历史分时、系统板块） |

---

## 16. 短线精灵 / 异动（`realorder`，9601）

短线精灵（异动精灵）走独立的 **9601 端口**（`REALORDER_HOST=106.14.65.90`），与 8901 行情通道
隔离。三类业务：

| 业务 | method | 说明 |
|---|---|---|
| 历史翻页查询 | `qurealorder` | 按市场拉历史异动，分页 |
| 实时订阅 | `subrealorder` | 注册推送（market=16/32/151/48） |
| 实时推送 | `pushrealorder` | 盘中服务器主动推（~500-800 帧/分钟） |

### 16.1 历史翻页请求（`build_qurealorder_query`）

纯文本帧（`\x09` + GBK 文本行），字段顺序（2026-08-05 抓包对齐）：

```text
instid=<实例号>
method=qurealorder
reqtype=4
maxcount=<每页条数>
[endtime=<微秒游标>]     # 翻页时带；首页不带
datatype=<异动类别表达式>
market=<市场码>
accept_ziptype=snappy    # 2026-08-05 抓包：真实客户端 46/46 帧全带
rettype=hqfile
```

**maxcount 取值**（真实客户端按市场/场景动态选，不写死）：

| maxcount | 适用 market | 含义 |
|---|---|---|
| 80 | 16(沪)/32(深)/151(北交所)/48(板块) | 个股市场标准每页条数（异动多） |
| 120 | 151/16/32/48 | 北交所等异动较少市场的翻页条数 |
| 1000 | 48(板块)/16(首批) | 板块异动少，一次拉满；或首批全量加载 |

thspypc 默认 80（适用个股市场）；查板块异动（market=48）建议传 1000。

**accept_ziptype=snappy**：客户端声明可接受 snappy 压缩响应。实测盘后小响应**未压缩**
（明文 hq1.0，`record_count=80 record_len=45`，数据区可见明文股票代码）；盘中大响应是否
压缩待验证。thspypc 解析器按明文 hq1.0 处理，无需解压逻辑。

**datatype（异动类别）**：普通账号 23 类、Level2 全选 53 类（`STANDARD_REALORDER_CATEGORY_IDS` /
`ALL_REALORDER_CATEGORY_IDS`）。带阈值的类别形如 `1074269398{19[10000~-]|17[5000000~-]}`
（成交手数≥1万 OR 成交金额≥500万）。`DXJL_DATATYPE` 是默认 4 类基础表达式。

### 16.2 响应解析（`parse_qurealorder_response`）

响应为 `hq1.0` 表（与 hd1.0 类似的定长记录表）：`record_count / field_count / record_length`
+ 字段表 + 定长记录。字段由 datatype 决定（时间、代码、异动类型、价量等）。

---

## 17. 看盘界面协议缺口（2026-08-05 抓包）

对照同花顺 PC 看盘主界面布局抓包（`tests/capture_kanpan.py`），记录 thspypc 未实现的协议。
完整抓包结论见 `docs/handoffs/HANDOFF_KANPAN_CAPTURE_20260805.md`。

### 17.1 盘口逐笔协议（未实现，复杂，P2-R&D）

Level2 账号在盘口/逐笔区用了未实现的 period。**2026-08-05 盘后两轮 `capture_superorder.py`
抓包（带秒表逐操作对齐，深市 000938）钉死了触发时机**，修正了此前若干误判。
完整结论见 `HANDOFF_KANPAN_CAPTURE_20260805.md` §H。

**UI 操作 → 协议请求对应表**（秒表对齐铁证）：

| UI 操作 | 触发的请求 |
|---|---|
| 冷启动进看盘 | pageid=5716 基础订阅 |
| 打开股票（看盘页面） | pageid=1334 全套（**含 16384 日K，默认加载**，非用户主动切） |
| 进入 L2 分时通道 | pageid=4214 分时全套 |
| 进入逐笔成交面板 | `4214 DT=7173(-1) + 7169(-27)` 初始 |
| **逐笔成交翻页** | `4214 DT=7169(<unix区间>)` 区间滚动（从 15:00 往前滚）★ |
| **打开超级盘口** | **pageid=4260 全套**（7174/7173/7169/4096/7424/7176 成组） |
| 超级盘口浏览 | `4260 DT=7169(<unix区间>)` 区间覆盖全天（9:33-13:01） |

**四个 period 的修正结论**（基于秒表对齐 + 两轮抓包逐条吻合）：

| period | pageid | DataType | 业务（修正后） | 证据等级 |
|---|---|---|---|---|
| **7169** | **4214 + 4260** | 10,12,13 | **逐笔成交/超级盘口历史回放**。**双 pageid 都用**：4214（逐笔面板）+ 4260（超级盘口）。unix 时间戳区间落在真实交易时段，历史回放铁证 | ✅ 强（翻页区间滚动） |
| **7173** | 4214 + 4260 + 4417 | 10 | **买一委托队列**。响应 `flag=0x2A, hs=4, fc=1, dt56`；历史需先用同连接 4096 建立 4417 上下文 | ✅ `order_queue(side="buy")`，Level2 专属 |
| **7174** | 4214 + 4260 + 4417 | 10 | **卖一委托队列**。编码与 7173 同构；空侧只返回 ACK | ✅ `order_queue(side="sell")`，Level2 专属 |
| **4096** | 4214 + 4260 + **4417** | 4214: 7,49,12,18,75,10,6,66 / 4260: 20+字段 / 4417: 7,10,12,13,...157,6,66,1110 | **超级盘口分时曲线/盘口回放**。盘中 4260（flag=0xFE hs=216），盘后/历史 **4417**（flag=0x9E hs=120，2026-08-07 抓包确认）；4214 是小快照 | ✅ `snapshot_replay`（4260 盘中 + 4417 历史，活网验证） |

**⚠ 修正此前误判**：
1. ~~「真实 pageid 是 4214，非 HANDOFF_SUPERORDER 推测的 4260」~~ → **错**。两轮抓包证明
   **4214（逐笔面板）和 4260（超级盘口）都用 7169**，两个 UI 入口共用同一 period。
2. ~~「7174 偶发」~~ → **错**。两轮均复现，与 7173 成对。
3. **16384 日K**：打开股票时看盘页面**默认加载**，与逐笔/超级盘口无关。

> **2026-08-09 补充**：7173/7174 业务和响应已通过 688693 涨停买队列、
> 000779 跌停卖队列与客户端截图逐项确认。队列高位 `0x08000000` 是主力单标记；
> 详情与 API 见 `docs/guides/ORDER_QUEUE.md`。历史队列目前只确认最近一个交易日。

> 请求构造与竞价/分时同族（route=0x02FC）。逐笔回放单帧
> 440KB+，变长字段，`HANDOFF_SUPERORDER_20260726` 的 fmt 子标记 22/34 未破译。暂不实现。
> 2026-08-05 盘后新增**深市 000938 样本**（`superorder_20260805_195859_resp_stream1.bin`），
> 与沪市 603118 对照完成字段表破译。详见 `HANDOFF_KANPAN_CAPTURE_20260805.md` §H。

### 17.2 9601 板块统计协议（statscalc / calcext）

真实客户端板块列表除 8901（392/1334）外，还走 9601 的纯文本计算协议。两者
共享一个帧封装：``\x09`` + ``\n`` 分隔的 GBK key=value 文本 + ``\x00`` 结束符
（请求与响应同构，**无二进制子帧头、无 route/seq**，纯文本协议）。

| method | 节点 | 请求特征 | 返回 | 用途 |
|---|---|---|---|---|
| `statscalc` | 独立统计节点 `8.132.233.77:9601`（不在 DNS/passport，客户端缓存发现） | `instid/method/market=48/codelist=48(881xxx,...)/datatype=330342/dataclass=intervalcalc/interval=0-0/rightstype=forward/period=0/datetime=0(0-0)/rettype=hdfile` | hd1.0 表（每码 24B：code8+pad8+date4LE+value4float） | 板块批量统计（区间涨跌幅/涨速聚合、涨跌停统计） |
| `calcext` | REALORDER 节点 `106.14.65.90:9601`（普通）/ `122.9.184.31:9601`（L2），与 `qurealorder` 共享 socket | `instid/method/codelist=<m>(<code>,)/datatype=199359/rightstype=forward/rettype=json` | JSON `{"data":[{"3":<market>,"4":"<code>","199359":<value>}]}` | 单板块/个股扩展计算（流通市值等） |

**节点路由铁证**（``SERVER_MATRIX.md``）：statscalc 走独立统计节点，不能复用
REALORDER seed ``106.14.65.90``；calcext 与 qurealorder 共用 REALORDER 节点。

**thspypc 实现**（2026-08-05）：
- ``features/board_stats_protocol.py``：请求构造（``build_statscalc_query`` /
  ``build_calcext_query``）+ 响应解析（``parse_statscalc_response`` /
  ``parse_calcext_response``），字段顺序逐字节对齐抓包。
- ``services/board_stats.py`` ``BoardStatsService``：statscalc 走
  ``ConnectionRole.BOARD_STATS``（独立统计节点，懒连接），calcext 走
  ``ConnectionRole.REALORDER``（复用 9601 socket，门控用 ``Capability.REALORDER``
  与短线精灵一致）。
- 公开 API：``board_stats_interval`` / ``board_stats_updownlimit`` /
  ``board_calcext``。statscalc 节点不可达时优雅降级返回空列表（可降级
  ``board_quotes``）。

**⚠ 使用注意**：statscalc 是**低频计算协议**——抓包确认真实客户端请求间隔约 **9 秒**
（服务端区间聚合计算耗时），连续高频调用会被限流导致超时。正确用法是低频轮询
（≥10s 间隔），首次请求还需预留独立节点建连时间（~15s）。calcext 无此限制，可连续调用。

与 thspypc `board_quotes`（8901 fu4 通道，pageid 392/5716，取预存字段）是不同
协议；statscalc 是服务端计算型，功能更强。两者可互补、交叉验证。

### 17.3 看盘界面指数实时推送（✅ 已实现 2026-08-05）

客户端启动时通过 pageid=5716 + ``PushField=16:241;32:241`` + subreal（URS/UCT/
UNX/UCX/UME）一次性注册**五大指数全局推送列表**，服务端持续推送 ``09 7b d0 0f``
头的二进制帧。页面切换只做分时/K线查询，不负责建立基础指数快照推送。

**五大指数**（客户端启动注册列表）：

| 代码 | 名称 | 服务器 | 帧格式 |
|---|---|---|---|
| 1A0001 | 上证指数 | 8.134.115.123:8901（沪） | 298-302B，代码@33 |
| 1B0680 | 科创50 | 同上 | 同上 |
| 899050 | 北证50 | 同上 | 97-98B 紧凑帧，代码@29 |
| 399001 | 深证成指 | 121.37.31.87:8901（深） | 321B 定长，代码@22 |
| 399006 | 创业板指 | 8.134.86.216:8901（深） | 同上 |

**字段布局**（4 字节 LE THS-float，深市/沪市字段顺序一致，起点偏移不同）：

| 字段 | 含义 | 深市偏移 | 沪市偏移 | 北证（相对代码） |
|---|---|---|---|---|
| dt6 | 昨收（固定） | 48 | 39 | — |
| dt7 | 开盘（固定） | 52 | 43 | — |
| 最高 | 日内最高 | 56 | 47 | — |
| 最低 | 日内最低 | 60 | 51 | — |
| dt10 | **最新价**（变化） | 64 | 55 | code+6 |
| dt19 | 成交额（递增） | 76 | 63 | code+14 |
| 成交量 | （递增） | 80 | 67 | code+10 (dt13) |

北证50 紧凑帧无 dt6/dt7/高/低（需从分时响应取）；另有 code+30=dt22、code+34=dt23。
存在 93B 子类型（字段掩码不同），按非稳态帧处理。

**thspypc 实现**：``features/index_push_protocol.py`` 的 ``parse_index_push``，
支持深市（399xxx）/ 沪市（1A0001/1B0680）/ 北证（899050）三套布局。活网验证
（2026-08-05 盘中）：399001=14129/+1.76%、1A0001=3872/+1.32%、1B0680=1928/+4.72%、
899050=1114。

### 17.4 北证50 分时（✅ 已实现 2026-08-06）

北证50（899050，market=144）当日分时走**专用 pageid=11695**（非 9354/9355），
走 `main.123ths.com` 的 MAIN 连接。DataType `272,207,42,271,228,13,…`（Level2 风格，
无 dt14/dt15 → **无买卖力量**，与同花顺客户端一致）。响应 flag=0x006e。

详见 §7.5 北交所分时。
