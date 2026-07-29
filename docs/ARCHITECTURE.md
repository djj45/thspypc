# thspypc 架构与演进约束

本文描述当前代码的稳定边界，以及后续增加协议功能时应遵守的迁移顺序。目标是
渐进式拆分，不进行一次性重写，也不破坏已有公开导入路径。

## 当前分层

```text
THSClient                         公开门面、登录与功能编排
    ├── MarketSession             8901 同步请求生命周期
    ├── BlockManager              自定义板块/自选股 HTTP 能力
    ├── 4214 manual connections   沪深 L2 分时与竞价
    └── 9601 realorder            异动历史与实时推送

protocol.py                       请求构造、响应解析、数值/压缩编解码
parse_hfd1.py                     全市场快照解码
qr_login.py                       二维码和凭证缓存
```

`THSClient` 和 `protocol.py` 仍然偏大。后续按“修改到哪个功能，就迁移哪个功能”
逐步拆分，旧模块保留兼容性 re-export。

## 连接不变量

8901 响应可能被 `CodeListSize`、`MarketTime`、心跳等帧穿插，且当前没有可直接
关联公开请求的 request id。因此：

1. 每条 8901 socket 同一时间只能有一个同步业务请求；
2. 请求锁必须覆盖设置 timeout、发送、读取和匹配全部响应；
3. 业务请求进行中，后台心跳跳过本轮发送；
4. 不允许功能方法脱离 `MarketSession` 新增“只锁 send、锁外 read”的代码；
5. 需要真正并行时，应增加独立连接或实现单 reader + 帧分发器，不能让多个线程
   直接读取同一 socket。

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
7. 更新 `FEATURE_GAP_ROADMAP.md`。

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

## 前端 / API 层接入约束

当后续需要为同花顺风格前端（自选股 + K线 + 分时 + 盘口 + 异动 + 板块）提供
HTTP 接口时，应在 `THSClient` 之上增加一层 `api.py`（或独立服务进程）。但该层
**不是现在就要做的事**，它的正确性取决于下层先收尾的两个前置条件。

### 分层位置

```text
前端（React/Vue/桌面客户端）
        ↓  HTTP / JSON / WebSocket
api.py        路由 + 鉴权 + JSON 序列化 + 请求编排
        ↓
THSClient（公开门面）/ services（opt-in）
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

### 抽 api.py 之前的两个前置条件

`tests/web_dashboard.py` 已暴露核心矛盾：它在 HTTP 层加了一把全局 `_query_lock`
来绕过 `list_quotes` 的「锁 send 不锁 read」缺陷（见该文件 §285-289 注释）。
这说明 socket 读所有权问题没真正下沉，只是被 web 层打了补丁。因此抽 `api.py`
之前必须先：

1. **MAIN 业务默认切到 service 路径**：`list_quotes`/`kline`/`depth_quote` 等目前
   是 opt-in（显式 `configure_service_context` 才走 service），默认走旧路径直接
   碰 `_sock`。只有全切到 service，`api.py` 才能依赖稳定的「请求锁覆盖 send+read」
   语义，无需自己加全局锁。

2. **socket 读所有权由 `_transport` 统一保障**：让 `ManagedConnection` /
   `ConnectionManager` 保证单连接串行读，使 `_query_lock` 这类 web 层补丁可以删除。
   这是连接不变量 §5（不允许功能方法脱离 session 新增「只锁 send、锁外 read」）的
   最终落地——目前 MAIN 旧路径仍是该不变量的违规点。

前置条件达成后，`web_dashboard.py` 的 `_query_lock` 应能直接删除；届时 `api.py`
就是一层薄薄的 HTTP 适配，没有连接治理负担。

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
`Passport64`、登录 profile 和 generation，可供多个连接角色复用，但不代表任一
TCP socket 已登录。

- `THSClient.authenticate()`：只获取或刷新 `AuthMaterial`，不连接行情服务器。
- `THSClient.connect_main()`：按需连接 `ifindhq`，在 MAIN socket 上执行
  `login -> 标准 init`；`connect()` 是其兼容入口。
- `SH_L2` / `SZ_L2`：首次 Level2 请求时分别连接 `shlv2` / `szlv2`，在各自
  socket 上执行 `__manual login -> 市场 init`。
- `REALORDER`：首次 9601 请求时建立并登录独立连接。

每个角色都独立拥有 TCP 登录态、init 状态、读写锁和重连策略。普通账号支持应通过
`AccountProfile` / `Capability` 决定允许建立哪些角色连接，而不是改变上述生命周期
或让一个 socket 的登录状态被另一个 socket 继承。
