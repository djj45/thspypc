# thspypc 架构与演进约束

本文描述当前代码的稳定边界，以及后续增加协议功能时应遵守的迁移顺序。目标是
渐进式拆分，不进行一次性重写，也不破坏已有公开导入路径。

## 当前分层

```text
THSClient                         公开门面与兼容入口
    ├── ServiceFacade             service-backed 公开行情方法
    ├── ConnectionPrimitives      MAIN/BSE_MAIN/L2/REALORDER 登录与建连原语
    ├── ConnectionFactory         角色建连与 MAIN 登录编排
    ├── ConnectionRuntime         心跳、推送 reader 与关闭顺序
    ├── MarketSession             8901 同步请求生命周期
    ├── BlockManager              自定义板块/自选股 HTTP 能力
    ├── L2 1334/4214 connections 沪深 L2 分时、竞价与推送
    └── 9601 realorder            异动历史与实时推送

features/                        各业务纯协议 builder/parser
services/                        能力校验、连接选择与完整业务工作流
codecs/                          帧、压缩、hd1/hd3、数值编码
server/                          FastAPI 单用户 REST + WebSocket（见下节）
web/                             React 看盘前端（仓库顶层，vite + echarts）
protocol.py                      历史 API 兼容导出 + HTTP 鉴权/主机解析
parse_hfd1.py                    全市场快照解码
qr_login.py                      二维码和凭证缓存
```

`THSClient` 保留对象构造、HTTP 鉴权、服务组合及旧入口兼容；底层登录建连位于
`_client/connection_primitives.py`，角色选择和后台生命周期位于
`_client/connection_runtime.py`，公开业务门面位于
`_client/service_facade.py`，同步业务工作流默认位于 `services`，本地股票代码缓存
位于 `_client/stock_cache.py`。这些模块均不反向导入或保存 `THSClient`。

## 连接不变量

8901 响应可能被 `CodeListSize`、`MarketTime`、心跳等帧穿插，且当前没有可直接
关联公开请求的 request id。因此：

1. 每条 8901 socket 同一时间只能有一个同步业务请求；
2. 请求锁必须覆盖设置 timeout、发送、读取和匹配全部响应；
3. 业务请求进行中，后台心跳跳过本轮发送；反向同理——业务请求等待心跳短探针
   让道时设 **3 秒上限**（探针必须可被业务请求打断，不能让业务白等一个完整
   探针超时周期）；
4. 不允许功能方法脱离 `MarketSession` 新增“只锁 send、锁外 read”的代码；
5. 需要真正并行时，应增加独立连接或实现单 reader + 帧分发器，不能让多个线程
   直接读取同一 socket。`KLINE_FAST`（K 线快路径独立 MAIN 连接）就是按此
   规则落地的并行化实例。

当前 `MarketSession` 是同步 single-flight 实现。它是安全基线，不代表未来不能
升级为 dispatcher。

## 新功能的纵向切片

每个新功能按以下路径交付：

1. 保存并标注最小请求/响应样本；
2. 在协议层实现纯函数 builder/parser；
3. 为 builder/parser 增加离线回归；
4. 通过正确的 session/channel 接入 `THSClient`；
5. 明确无数据、超时、权限不足和不支持帧的语义；
6. 完成多市场、多股票、多交易日活网验证；
7. 更新 `docs/plans/FEATURE_GAP_ROADMAP.md`。

五档盘口 `depth_quote` 是第一条按此路径接入的门面功能。

## 计划中的模块边界

只有在对应功能发生修改时才迁移，避免纯搬家式大改：

```text
transport/    8901、4214、9601 的连接、重试和帧读取
codecs/       hd1/hd3、压缩、位流和数值编码
features/     quote、kline、timeline、auction、depth、stock_list
services/     system_blocks、fund_flow、f10、watchlists
models.py     稳定业务字段及原始 dt 字段的兼容容器
errors.py     超时、权限、协议、无数据等错误分类
```

F10、系统板块等 HTTP 能力应作为独立 service，不进入 8901 `MarketSession`。

## 测试边界

计划逐步整理为：

```text
tests/unit/          无网络、每次必跑
tests/fixtures/      脱敏后的协议真值与元数据
tests/integration/   需要账号/网络，默认不跑
tools/capture/       抓包工具
tools/reverse/       一次性逆向和诊断脚本
```

在目录迁移完成前，新代码至少要有无需账号的离线测试，活网脚本不能作为唯一验收。

## 前端 / API 层接入约束（已落地）

> **状态（2026-09-08）**：本节规划的 `api.py` 已落地为 `src/thspypc/server/`
> （FastAPI 单用户 REST + WebSocket，接口见 `docs/guides/WEB_API.md`），配套
> `web/` React 看盘前端。下文保留当初的分层约束，作为该层继续演进时的边界。

为同花顺风格前端（自选股 + K线 + 分时 + 盘口 + 异动 + 板块）提供 HTTP 接口时，
在 `THSClient` 之上保留一层薄 HTTP 适配（`server/app.py`），其正确性依赖下层的
两个前置条件（均已完成）。

### 分层位置

```text
前端（React/Vue/桌面客户端）
        ↓  HTTP / JSON / WebSocket
api.py        路由 + 鉴权 + JSON 序列化 + 请求编排
        ↓
THSClient（公开门面）→ services（默认）
        ↓
features → codecs
```

`api.py` 的职责应严格限定为协议无关的 HTTP 适配，不重复承担下层已解决的职责：

| 该做 | 不该做（已下沉到下层） |
|------|----------------------|
| HTTP 路由（`/api/kline?code=600519&period=day`） | 协议字节构造（features） |
| 参数校验、鉴权、限流 | 通道选择、能力检查（services） |
| 协议字段翻译（`dt10`→`price`、`dt6`→`prevClose`） | socket 读写与锁（_transport） |
| 请求编排（一次页面加载并发取 quotes+kline+depth） | 字段含义映射（features parser） |
| 错误码统一（`CapabilityUnavailableError`→403、`ChannelUnavailableError`→503） | — |

### api.py 的下层前置条件（已完成）

`tests/web_dashboard.py` 已暴露核心矛盾：它在 HTTP 层加了一把全局 `_query_lock`
来绕过 `list_quotes` 的「锁 send 不锁 read」缺陷（见该文件 §285-289 注释）。
该问题现已在下层完成收口：

1. **MAIN 业务默认切到 service 路径**：`list_quotes`/`kline`/`depth_quote`、
   股票列表、快照和名称等公开方法均默认委托 service。

2. **socket 读所有权由 `_transport` 统一保障**：让 `ManagedConnection` /
   `ConnectionManager` 保证单连接串行读，使 `_query_lock` 这类 web 层补丁可以删除。
   这是连接不变量 §5（不允许功能方法脱离 session 新增「只锁 send、锁外 read」）
   的落地；旧同步业务查询器已经删除。

`web_dashboard.py` 不再需要用跨角色全局锁补偿底层读竞争；`api.py` 可以保持为
一层薄 HTTP 适配，不承担连接治理。

### 不同前端规模的决策

- **数据校验看板**（如现有 `web_dashboard.py`）：无需单独抽 `api.py`，handler 直调
  client + 全局锁够用，抽出反而过度设计。
- **同花顺级正式前端**：必须抽 `api.py`，且先满足上述两个前置条件。
- **前后端分进程/分仓库**：`api.py` 是必须的 HTTP 边界，还需额外考虑：
  长连接复用（一个 API 进程常驻 8901，多前端共享）、会话管理（扫码登录态）、
  推送（WebSocket 转发 9601 异动 / 4214 快照）。

### 字段翻译约定

`api.py` 应把协议槽位号（`dt10`/`dt6`/`dt27`/`dt33`）翻译成前端友好的稳定语义
名（`price`/`prevClose`/...）。注意同一 dt 号跨接口语义不同（见 README「dt 号跨
接口语义不同」表），翻译必须按接口绑定，不能全局映射。L2 多出的 `dt201-230` 等
字段作为可选扩展存在，不能为了统一结果而伪造普通账号没有的数据。

### 鉴权与连接生命周期

`AuthService` 只负责通过 HTTP 生成不可变的 `AuthMaterial`。一次材料包含
`Passport64`、登录 profile 和 generation。它可作为首次登录阶段的并发候选票据，
但任一 8901 host 返回 `VerifyCode=0` 后该票据即视为已消费；后续需要新连接时
必须重新 HTTP 鉴权，不能拿同一票据再登录另一台服务器（见 `AGENTS.md`）。

- `THSClient.authenticate()`：只获取或刷新 `AuthMaterial`，不连接行情服务器。
- `THSClient.connect_main()`：按需连接 `main.123ths.com`（缺失时回退
  `ifindhq.123ths.com`），在 MAIN socket 上执行
  `login -> 标准 init`；`connect()` 是其兼容入口。
- `KLINE_FAST`：K 线快路径（`channel="ifindhq_fast"`）的独立 MAIN 连接，
  登录/init 与 MAIN 相同，只是不与 MAIN 业务共用单飞锁。
- `BSE_MAIN`：北交所（market 151）专用连接——只在 `main.123ths.com` 组登录
  （`main_only=True`，不回退 ifindhq），登录/init 与 MAIN 相同。北交所历史
  分时/竞价窗/当日超级盘口共用该连接（路由依据见
  `docs/architecture/SERVER_MATRIX.md`）。
- `SH_L2` / `SZ_L2`：首次 Level2 请求时分别连接 `shlv2` / `szlv2`，在各自
  socket 上执行 `thsuser` 标准行情登录壳 -> 市场 init。
- `BOARD` / `BOARD_CONSTITUENT_SH` / `BOARD_CONSTITUENT_SZ`：板块指数通道
  （fu4）与成分股独立连接，身份按账号类型分支（详见 SERVER_MATRIX）。
- `REALORDER`：首次 9601 请求时建立并登录独立连接。
- `BOARD_STATS`：9601 statscalc 独立统计节点（懒连接，可环境变量覆盖）。

每个角色都独立拥有 TCP 登录态、init 状态、读写锁和重连策略。普通账号支持应通过
`AccountProfile` / `Capability` 决定允许建立哪些角色连接，而不是改变上述生命周期
或让一个 socket 的登录状态被另一个 socket 继承。
