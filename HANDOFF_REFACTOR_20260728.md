# `client.py` / `protocol.py` 渐进重构交接（2026-07-28）

> 目标：在不破坏公开 API、不改变协议行为的前提下，把当前约 3064 行的
> `client.py` 和约 4997 行的 `protocol.py` 逐步拆成可独立测试的连接层、codec、
> 协议功能模块和业务 service。
>
> 当前分支：`feat/stock-list-full`
>
> 基线提交：以远端该分支最新提交为准；开始前运行 `git pull --ff-only`。
>
> 架构约束以 `docs/ARCHITECTURE.md` 为准。本文给出具体迁移顺序，不取代该文档。

## 1. 重构原则

这次不是一次性重写。每一步都必须满足：

1. 公开入口保持不变：

   ```python
   from thspypc import THSClient
   from thspypc.protocol import build_kline_query
   from thspypc.transport import MarketSession
   ```

2. 请求和响应字节保持不变；纯搬迁提交不顺便修改协议算法。
3. 每移动一组函数，都在旧模块 re-export，已有脚本不需要同步修改。
4. 一次提交只做一种事情：搬迁、连接治理、功能行为修改不能混在一起。
5. 每条 socket 只能有一个收帧所有者；锁必须覆盖发送和完整响应读取。
6. 离线测试先通过，活网测试只作为额外验收。
7. 不清理或提交工作区里现存的 `_*.py`、抓包分析草稿和未跟踪文件。
8. 账号等级不能直接散落成 `if level2`；登录差异、账号能力、连接可用性和
   行情请求方案必须分别建模。普通账号未验证的能力保持 `UNKNOWN`，不能猜测为
   支持或不支持。

不要以“文件行数变少”作为唯一目标。真正目标是让依赖方向稳定：

```text
THSClient（公开门面）
    ↓
业务 Service
    ↓
ConnectionManager / MarketSession
    ↓
纯协议 builder / parser
    ↓
基础 codec
```

底层模块不能反向导入 `THSClient` 或 service。

## 2. 当前主要问题

### 2.1 `protocol.py` 混合了五类职责

当前同一个文件包含：

- HTTP 鉴权、RSA、Passport64、登录帧；
- DNS/市场服务器发现、设备指纹；
- fdf envelope、socket 读帧；
- hd1/hd3、BitRLE、位平面、THS 数值 codec；
- K 线、分时、竞价、盘口、股票列表、名称、异动等业务协议。

这导致修改历史分时 parser 时也要在近 5000 行文件中工作，并且公共导入和内部
实现没有边界。

### 2.2 `client.py` 同时承担门面、连接和业务实现

当前 `THSClient` 同时负责：

- HTTP/TCP 登录与 IP 轮换；
- 主 8901 连接；
- `shlv2` / `szlv2` 的 `__manual` 连接和预热；
- 9601 异动连接；
- 心跳、实时快照后台线程；
- 每一种行情的发送、收帧、重试和解析；
- 股票列表/IP 本地缓存；
- BlockManager 门面。

历史分时暴露了最危险的问题：成功实发需要 L2 socket，但公开方法仍容易沿用
主连接。业务方法直接碰 `_sock` / `_push_socks`，使通道选错和多个线程抢帧很难
从结构上避免。

### 2.3 兼容面较大

源码和测试中有大量：

```python
from thspypc.protocol import ...
import thspypc.protocol as proto
```

部分诊断脚本还会导入下划线开头的内部函数。因此第一阶段必须保留
`protocol.py` 文件作为兼容门面，不能直接把它和同名目录互换后一次性重写。

### 2.4 当前把 Level2 账号行为写进了门面和连接层

当前实现和样本主要基于 Level2 账号，普通账号虽然已有部分协议真值，但还没有
端到端接入：

- 登录后只打印 passport 的 `level2/userclass/qsuserclass`，没有形成可供业务
  路由使用的账号能力模型；
- HTTP 产品参数、`ACCOUNT_TYPE`、TCP login 字段集来自当前 PC Level2 样本，
  尚未封装成可替换的登录协议配置；
- `timeline()` 直接等同于 `__manual + pageid=4214` 的 L2 分时，而普通账号已经
  确认使用主连接 `pageid=9354` 请求-响应；
- `auction()`、`snapshot_subscribe()` 和当前历史分时协议都默认需要 L2 通道；
- `_push_socks` 是否存在被当成能力判断，但“有权限”“passport 含 L2 地址”
  和“本次 DNS/socket 可用”是三件不同的事；
- `connect_with_passport64()` 没有明文 passport 字段，账号等级只能是未知，
  不能按普通账号处理。

因此不能通过复制一个 `NormalTHSClient` 解决。目标是保留单一 `THSClient`
公开门面，在内部按“账号能力 → 请求方案 → 连接角色”选择实现。

## 3. 目标目录

建议与 `docs/ARCHITECTURE.md` 对齐：

```text
src/thspypc/
├── __init__.py
├── client.py                    # THSClient 公开门面
├── protocol.py                  # 旧协议导入兼容门面
├── transport.py                 # MarketSession 兼容门面
├── models.py
├── errors.py
│
├── codecs/
│   ├── __init__.py
│   ├── framing.py               # fdf envelope 和 read_frame
│   ├── numeric.py               # decode_ths_float 等数值编码
│   ├── compression.py           # 8901 normalize、BitRLE、位平面
│   └── hd.py                    # hd1/hd3 字段表和通用记录
│
├── features/
│   ├── __init__.py
│   ├── auth_protocol.py
│   ├── quote_protocol.py
│   ├── kline_protocol.py
│   ├── timeline_protocol.py
│   ├── auction_protocol.py
│   ├── stock_list_protocol.py
│   ├── stock_name_protocol.py
│   ├── snapshot_protocol.py
│   └── realorder_protocol.py
│
├── _transport/
│   ├── __init__.py
│   ├── session.py
│   ├── connection.py
│   ├── connection_manager.py
│   └── dispatcher.py            # 暂不实现，只保留未来边界
│
└── services/
    ├── __init__.py
    ├── quote.py
    ├── timeline.py
    ├── auction.py
    ├── stock_list.py
    └── realorder.py
```

说明：

- 使用 `features/*_protocol.py`，避免与业务 service 同名时难以辨认。
- 保留顶层 `protocol.py`，由它导入并重新导出新模块的名字。
- 保留顶层 `transport.py`。连接实现先放 `_transport/`，避免同名文件/目录迁移
  一次性影响所有 import。
- `services/` 只做通道选择、重试、响应匹配和业务返回值，不处理二进制细节。
- `codecs/` 和 `features/` 不能导入 `client.py`、`services/` 或真实 socket 状态。

## 4. 今晚推荐范围

今晚不要直接拆完整 `THSClient`。先完成“基础 codec + 兼容门面”，建立以后所有
迁移都能复用的模式。

### Step 0：冻结基线

```powershell
git switch feat/stock-list-full
git pull --ff-only
$env:PYTHONPATH = "src"
uv run pytest -q
```

记录基线测试数量。2026-07-28 最近一次结果为：

```text
32 passed, 4 skipped
```

由于测试中有需要网络或以 `return` 代替 `assert` 的旧脚本，数量可能随环境变化；
重点是重构前后相同测试集不能新增失败。

先建立一个新的重构分支：

```powershell
git switch -c codex/refactor-protocol-foundation
```

如果在非 Codex 环境手工操作，也可以使用项目自己的分支名，但不要直接在
`feat/stock-list-full` 上连续堆大量搬迁提交。

### Step 1：增加公开 API 合同测试

新增 `tests/test_public_api.py`，至少验证：

```python
def test_top_level_client_import():
    from thspypc import THSClient
    assert THSClient.__name__ == "THSClient"


def test_protocol_compatibility_exports():
    from thspypc.protocol import (
        encode_frame,
        read_frame,
        decode_ths_float,
        build_kline_query,
        build_history_timeline_query,
    )
    assert callable(encode_frame)
    assert callable(read_frame)
    assert callable(decode_ths_float)
    assert callable(build_kline_query)
    assert callable(build_history_timeline_query)


def test_transport_compatibility_export():
    from thspypc.transport import MarketSession
    assert MarketSession.__name__ == "MarketSession"
```

再检查 `thspypc.__all__` 中已有名字仍能读取。不要在这个提交里移动代码。

建议提交：

```text
test: freeze public import contracts
```

### Step 2：抽取 `codecs/framing.py`

从 `protocol.py` 原样移动：

```text
FRAME_MAGIC
encode_frame
read_exact
_read_frame_body_length
read_frame
```

`codecs/framing.py` 只允许依赖标准库 `socket`，不能导入 `protocol.py`。

`protocol.py` 改成：

```python
from .codecs.framing import (
    FRAME_MAGIC,
    encode_frame,
    read_exact,
    read_frame,
)
```

为了兼容诊断脚本，第一阶段可以继续 re-export `_read_frame_body_length`。不要复制
两份实现；实现只能存在于新文件。

验证：

```powershell
uv run pytest tests/test_frame_reader.py tests/test_transport.py `
  tests/test_public_api.py -q
uv run pytest -q
```

建议提交：

```text
refactor: extract frame codec
```

### Step 3：抽取 `codecs/numeric.py`

先只移动稳定且低耦合的：

```text
decode_ths_float
```

如果发现与它紧密配对的纯数值 encode helper，可以一起移动；不要顺手移动
hd1/hd3 parser。

`protocol.py` 继续 re-export：

```python
from .codecs.numeric import decode_ths_float
```

需要同时确认：

- `parse_hfd1.py` 仍可从旧入口工作；
- 分时、K 线、竞价和盘口离线测试没有数值差异；
- 函数对象只有一份实现。

建议提交：

```text
refactor: extract numeric codec
```

### Step 4：抽取 `codecs/compression.py`

从 `protocol.py` 移动：

```text
normalize_8901_response
_decode_bitrle_0x13746d0
_transpose_bitplane_0x1763410
```

这些函数属于同花顺二进制 codec，不属于某个具体业务。内部 helper 一并移动，
不要让新模块再从旧 `protocol.py` 导入下划线函数，否则会形成循环依赖。

重点回归：

```powershell
uv run pytest tests/test_8901_normalizer.py `
  tests/test_history_timeline_response.py `
  tests/test_snapshot_push.py -q
```

还要对关键 fixture 做“正规化输出 SHA 或完整 bytes 不变”验证。如果现有测试只
检查解析结果，建议补一个固定输出长度和摘要断言。

建议提交：

```text
refactor: extract market compression codecs
```

### Step 5：到此停止并评估

如果以上步骤全部完成，今晚已经建立了可复制的拆分模式。不要因为还有时间就直接
移动全部业务协议。先确认：

- `git diff` 没有算法变化；
- 全套离线测试通过；
- 旧 import 路径通过；
- `protocol.py` 只减少实现，没有出现反向依赖；
- 每个提交都能单独通过测试和回滚。

有余力时可以开始 `codecs/hd.py`，但不要同晚再改历史分时状态机。

## 5. 后续协议拆分顺序

基础 codec 稳定后，按依赖从低到高迁移。

### Phase A：通用 hd codec

移动：

```text
_parse_hd_field_table
_parse_hd_records
parse_hd1_response
parse_hd3_response
```

`parse_kline_hd3_response` 和 `parse_timeline_l2_response` 暂时留在各自 feature，
不要把所有带 `hd3` 名字的函数都塞进通用模块。

验收标准：

- 通用 hd 模块不知道股票代码、pageid 或具体业务字段含义；
- 返回原始 `dt<N>`；
- 业务字段映射仍由 feature parser 完成。

### Phase B：按纵向功能拆协议

推荐顺序：

1. `quote_protocol.py`
2. `kline_protocol.py`
3. `timeline_protocol.py`
4. `auction_protocol.py`
5. `stock_list_protocol.py`
6. `stock_name_protocol.py`
7. `snapshot_protocol.py`
8. `realorder_protocol.py`
9. `auth_protocol.py`

先迁移五档/K 线等结构稳定功能，再迁移仍在逆向的历史分时和竞价。这样可以先验证
模块边界，而不会把“搬迁导致的错误”和“codec 仍未破解”混在一起。

每个 feature 模块应包含同一业务的：

```text
常量
请求 builder
响应 parser
仅供该业务使用的 helper
```

例如 `timeline_protocol.py` 最终应包含：

```text
build_timeline_query
build_timeline_l2_query
build_history_timeline_query
parse_timeline_l2_response
parse_history_timeline_response
date_to_timeline_bar
timeline_bar_to_date
历史分时相关常量/helper
```

但它不负责选择 `szlv2` 还是 `shlv2`，也不负责重试。

## 6. `client.py` 拆分方案

协议层迁移稳定后再动 `client.py`。

### 6.1 先建立连接对象

目标不是立刻实现异步 dispatcher，而是把现有 single-flight 规则应用到每条连接：

```python
class ManagedConnection:
    def request(self, frame, *, timeout, matcher): ...
    def try_send(self, frame): ...
    def close(self): ...
```

每个实例自己持有：

```text
socket
RLock
连接角色
市场
登录身份
init 状态
关闭/失效状态
```

`ConnectionManager` 负责：

```text
main              普通 8901
sh_l2             __manual + shlv2 + init(16;144)
sz_l2             __manual + szlv2 + init(32)
realorder         9601
```

连接角色应使用枚举或明确 key，不要继续让各业务方法自行拼 `"sh"` / `"sz"`。

每种连接角色还要声明登录身份和前置能力：

```text
MAIN        普通 8901；STANDARD 身份；普通/L2 账号共用
SH_L2       shlv2；MANUAL 身份；init(16;144)；要求沪市 L2 能力
SZ_L2       szlv2；MANUAL 身份；init(32)；要求深市 L2 能力
REALORDER   9601；能力是否对普通账号开放需要活网确认
```

普通账号不能解析后就顺手预热 `SH_L2/SZ_L2`。`ConnectionManager.acquire(role)`
应先检查账号能力，再解析地址和建 socket；权限不足与 DNS/网络失败必须是不同错误。

### 6.2 解决 L2 socket 的读所有权

这是重构最重要的不变量。

当前同一 L2 socket 可能涉及：

- 当日分时同步查询；
- 集合竞价同步查询；
- 历史分时同步查询；
- 71B 实时快照推送；
- 后台快照读取线程。

不能让后台 `_snapshot_loop` 和同步 service 同时 `read_frame()`。

短期安全方案：

```text
每条 L2 socket 一个 RLock
同步请求持锁覆盖 send + read-until-match
后台推送 reader 仅在拿到同一锁时读取
拿不到锁就稍后再轮询
```

长期方案才是：

```text
每条 socket 一个 reader thread
reader 根据帧类型分发到同步等待队列或 push queue
其他线程永远不直接 recv
```

今晚不要实现长期 dispatcher。先保持 single-flight，确保连接对象能够承载未来
升级。

### 6.3 再提取业务 service

第一个建议提取 `TimelineService`，因为它同时覆盖：

- `timeline`
- `auction`
- `history_timeline`
- L2 市场选择
- 历史分时当前的连接错误

但最好把竞价最终放入独立 `AuctionService`；第一步允许共用 L2 连接 helper。

service 构造时注入依赖：

```python
class TimelineService:
    def __init__(self, connections, protocol_api):
        self._connections = connections
        self._protocol = protocol_api
```

不要把整个 `THSClient` 传给 service，否则只是把巨型类换成互相调用的巨型对象。

`THSClient` 最终只保留：

```python
def history_timeline(self, code, date, ...):
    return self._timeline.history(code, date, ...)
```

### 6.4 推荐 service 迁移顺序

```text
QuoteService       list_quotes / depth_quote
TimelineService    timeline / history_timeline
AuctionService     auction
StockListService   stock_list / snapshot / names / cache
RealOrderService   dxjl / subscribe_realtime
AuthService        最后迁移，登录链路风险最高
```

五档盘口适合作为第一个 service 样板，因为已有纯 builder/parser、公开类型和离线
测试。历史分时适合作为第二个，用来验证 L2 通道抽象。

### 6.5 普通账号兼容合同

不要建立 `NormalTHSClient` / `Level2THSClient` 两套门面。账号差异用组合对象表达，
建议先在 `models.py` 增加以下内部模型，待稳定后再决定哪些公开导出：

```python
class Capability(Enum):
    BASIC_QUOTE = auto()
    BASIC_TIMELINE = auto()
    L2_TIMELINE = auto()
    L2_AUCTION = auto()
    L2_SNAPSHOT_PUSH = auto()
    L2_HISTORY_TIMELINE = auto()
    REALORDER = auto()


class Support(Enum):
    YES = auto()
    NO = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class AccountProfile:
    kind: Literal["standard", "level2", "unknown"]
    capabilities: Mapping[Capability, Support]
    passport_fields: Mapping[str, str]
```

必须使用三态能力：

- `YES`：passport 字段和已验证行为都证明可用；
- `NO`：有普通账号对照样本或明确权限响应证明不可用；
- `UNKNOWN`：缺少字段、外部 Passport64 登录、或尚未完成普通账号实测。

`level2` 字段、`userclass/qsuserclass`、`M_hqdns` 中的 `shlv2/szlv2` 都只是
能力证据，不能单独兼任账号类型、连接健康状态和业务成功状态。字段值映射在拿到
普通账号脱敏样本前不得猜测。

登录协议参数也要从全局常量收拢为配置对象：

```python
@dataclass(frozen=True)
class LoginProtocolProfile:
    product: str
    qsid: str
    http_version: str
    tcp_version: str
    account_type: bytes
    supports_manual_identity: bool
```

当前已经验证的参数先成为默认 profile，builder 默认参数继续生成完全相同的字节。
普通账号抓包确认后再增加 profile。登录编排通过内部 `LoginStrategy`/`AuthTicket`
边界完成，不在 `full_http_auth()` 里持续堆账号分支：

```python
class LoginStrategy(Protocol):
    def authenticate(self, credentials, device) -> AuthTicket: ...
    def build_login(self, ticket, identity: LoginIdentity) -> bytes: ...
```

`AuthTicket` 至少保留原始 passport、解析字段、服务器目录和 `AccountProfile`。
`THSClient` 后续可增加默认值为 `"auto"` 的账号模式提示；现有构造参数和调用方式
保持不变。自动协商只能在明确的鉴权/权限拒绝时切换策略，不能把网络 timeout 当成
账号类型证据。

业务 service 根据账号能力选择请求计划：

| 功能 | 普通账号计划 | Level2 账号计划 |
|------|--------------|-----------------|
| `list_quotes` / `kline` / `depth_quote` | `MAIN` | `MAIN` |
| `timeline(mode="auto")` | `MAIN + pageid=9354` | `SH_L2/SZ_L2 + pageid=4214` |
| `timeline(mode="basic")` | 强制 `9354` | 强制 `9354`，用于对照 |
| `timeline(mode="level2")` | 明确权限错误 | 严格使用 L2 通道 |
| `auction` | 协议确认前报不支持 | `SH_L2/SZ_L2 + 4214/7176` |
| `market_snapshot` | `MAIN + hfd1.0` | `MAIN + hfd1.0` |
| `snapshot_subscribe` | 明确不支持逐 tick 推送 | L2 4214 推送 |
| `history_timeline` | 普通协议确认前报不支持 | L2 4417 |
| `realorder` | 待普通账号活网确认 | 保持现有 9601 行为 |

`timeline()` 返回值继续保持 `list[dict]`；L2 多出的 `dt201-230` 等字段作为可选
原始字段存在，不能为了统一结果而伪造普通账号没有的数据。

新增 `errors.py` 时至少区分：

```text
CapabilityUnavailableError     账号明确没有所需权限
UnsupportedAccountFeatureError 当前账号类型的协议尚未实现
ChannelUnavailableError        有权限，但 DNS/socket/init 失败
ProtocolError                  收到帧但无法识别或解析
```

权限不足不能继续与无行情数据共用 `[]`/`False`。空列表只表示请求成功但没有数据；
为了兼容已有调用方，错误语义调整应单独提交，并在发行说明中明确。

普通账号实现前必须先保存脱敏真值：

```text
HTTP 主验证请求参数与 passport 关键字段
普通 TCP login 请求/响应
M_hqdns 服务器目录
pageid=9354 沪深各一份请求与响应
普通账号调用 4214/7176/9601 时的明确权限失败表现
```

对应离线测试至少覆盖：

- 普通账号 profile 永远不建立或预热 `SH_L2/SZ_L2`；
- Level2 `timeline(auto)` 仍生成当前 4214 字节并选择对应市场 L2 连接；
- 普通账号 `timeline(auto)` 生成 9354 字节并只使用 `MAIN`；
- `UNKNOWN` 不被静默当成普通或 L2，严格能力调用给出可诊断错误；
- 权限不足、网络失败、协议错误和真正无数据的返回语义互不混淆。

## 7. 依赖和导入规则

建议写入代码评审检查表：

```text
codecs       → 只能依赖标准库或 models/errors
features     → 可依赖 codecs、models/errors
transport    → 可依赖 codecs/framing、models/errors
services     → 可依赖 features、transport、models/errors
client.py    → 可依赖 services、transport、auth/block 门面
protocol.py  → 仅兼容 re-export，不应被新内部模块导入
```

严禁：

```text
features → protocol.py
codecs → features
transport → services
services → client.py
```

如果新模块需要从 `protocol.py` 导入某个 helper，说明该 helper 还没迁到正确底层。
先移动 helper，不要用延迟 import 掩盖循环依赖。

## 8. 兼容层策略

### 8.1 `protocol.py`

迁移过程中允许它同时包含：

```text
未迁移的旧实现
已迁移函数的 re-export
```

禁止：

- 新旧文件各保留一份相同实现；
- wrapper 无意义地重新组装参数；
- 为了通过 import 测试吞掉 ImportError；
- 新内部模块再次从兼容门面导入。

对下划线 helper 的兼容期可以短一些，但在删除前要用 `rg` 搜索全部脚本。

### 8.2 `client.py`

公开 `THSClient` 类和参数保持不变。内部可以逐步增加：

```text
self._connections
self._quotes
self._timeline
...
```

旧 `_sock`、`_push_socks` 在诊断脚本迁移完之前可以暂时作为兼容属性，但它们应
只读地指向 ConnectionManager 内部 socket，不允许新代码继续使用。

### 8.3 `__init__.py`

顶层导出较多。每次迁移后运行：

```python
import thspypc
for name in thspypc.__all__:
    assert hasattr(thspypc, name), name
```

不要在纯搬迁阶段顺手精简 `__all__`。

## 9. 测试目录的后续整理

暂时不要大规模移动测试，否则 Git diff 会掩盖源码重构。协议和 client 稳定后再分：

```text
tests/unit/          必须断网可跑
tests/fixtures/      脱敏 raw 响应及元数据
tests/integration/   需要账号/网络
tools/capture/       抓包
tools/probe/         活网探针
tools/reverse/       一次性分析脚本
```

建议先给现有测试增加 marker：

```python
@pytest.mark.integration
```

以后默认：

```powershell
uv run pytest -m "not integration" -q
```

但 marker 配置和目录移动应单独提交，不要夹在 codec 搬迁提交里。

## 10. 每个迁移提交的验收清单

提交前逐项检查：

- [ ] `git diff --check` 无空白错误。
- [ ] 新模块没有导入 `thspypc.protocol` 兼容门面。
- [ ] 旧 import 路径仍可使用。
- [ ] `thspypc.__all__` 全部可解析。
- [ ] builder 的完整 bytes 或 SHA 与迁移前一致。
- [ ] parser 对真实 fixture 的结果与迁移前一致。
- [ ] 没有修改 `.env`、账号、Passport64、IMEI。
- [ ] 没有暂存 `_*.py`、pcap 或临时分析输出。
- [ ] 相关测试通过。
- [ ] 全套离线测试通过。
- [ ] `git status --short` 中暂存范围只包含当前迁移。

纯搬迁提交如果出现业务值变化，应立即停止，把算法修复拆到下一提交。

## 11. 建议提交序列

今晚：

```text
test: freeze public import contracts
refactor: extract frame codec
refactor: extract numeric codec
refactor: extract market compression codecs
```

后续：

```text
refactor: extract generic hd codecs
refactor: model account capabilities and login profiles
refactor: extract quote protocol
refactor: extract kline protocol
refactor: extract timeline protocol
refactor: centralize managed market connections
refactor: extract quote service
refactor: extract timeline service
feat: route standard accounts through basic timeline
fix: route historical timeline through l2 session
```

最后一条属于行为修复，必须与结构搬迁分开。

## 12. 历史分时与本次重构的衔接

历史分时专项状态见：

```text
HANDOFF_HISTORY_TIMELINE_20260728.md
docs/HISTORY_TIMELINE_VARLEN_INVESTIGATION.md
```

重构期间不要改变这些已经验证的事实：

- 日期 epoch 是 `1849-04-06 / ordinal 675064`；
- 深市实发成功通道是 `__manual + szlv2 + init(32)`；
- `399002` 可替换，不是硬依赖；
- PC 三段请求不等于服务器最小请求已经确定；
- 强状态省略 codec 未完全破解；
- 多请求碰到容易变体不能作为生产正确性方案。

推荐在 `timeline_protocol.py` 迁移完成后，再做历史分时状态机；推荐在
`ConnectionManager` 完成后，再把 `THSClient.history_timeline()` 切到 L2 通道。
不要在同一个提交里同时做这两件事。

## 13. 遇到问题时的回退方法

由于每一步都是独立提交，优先：

```powershell
git show --stat HEAD
git diff HEAD^ HEAD
git revert <有问题的单个提交>
```

不要使用 `git reset --hard` 或删除整个工作区；当前目录有大量未跟踪逆向脚本，
它们可能仍有价值。

出现循环导入时，不要加更多函数内 import。按依赖规则找出放错层的 helper，把它
下沉到 codec/features。

出现活网行为变化时：

1. 先运行同一 raw fixture 的离线 parser；
2. 比较 builder 完整 bytes；
3. 比较发送通道、trailing newline、timeout 和读帧循环；
4. 最后才怀疑服务器随机行为。

## 14. 推送代理

PowerShell：

```powershell
$env:http_proxy  = "http://127.0.0.1:10808"
$env:https_proxy = "http://127.0.0.1:10808"
$env:all_proxy   = "socks5://127.0.0.1:10808"
$env:HTTP_PROXY  = "http://127.0.0.1:10808"
$env:HTTPS_PROXY = "http://127.0.0.1:10808"
$env:ALL_PROXY   = "socks5://127.0.0.1:10808"
git push
```

`cmd.exe`：

```bat
set http_proxy=http://127.0.0.1:10808
set https_proxy=http://127.0.0.1:10808
set all_proxy=socks5://127.0.0.1:10808
set HTTP_PROXY=http://127.0.0.1:10808
set HTTPS_PROXY=http://127.0.0.1:10808
set ALL_PROXY=socks5://127.0.0.1:10808
git push
```

当前远端使用 SSH URL。代理变量是否被 SSH 使用取决于另一台电脑的 SSH 配置；
若推送失败，先检查 SSH 连通性，不要修改已经通过测试的重构提交。

## 15. 今晚完成定义

如果今晚做到以下几点，就算第一阶段完成，不需要强行拆完大文件：

- 新增公开导入合同测试；
- `framing`、`numeric`、`compression` 三个基础 codec 完成单一实现迁移；
- `protocol.py` 旧导入完全兼容；
- 全套离线测试无新增失败；
- 每个步骤独立提交；
- 未触碰历史分时算法和连接行为；
- 为下一次 `hd.py` / `quote_protocol.py` 迁移留下清晰边界。

完成后把实际提交号、测试结果和未完成项追加到本文顶部，再开始下一阶段。

## 16. 当前执行进度（2026-07-28）

当前工作分支：

```text
codex/refactor-protocol-foundation
```

已完成但尚未提交：

- `tests/test_public_api.py` 冻结顶层、协议和 transport 公开导入；
- `codecs/framing.py`：`FRAME_MAGIC`、帧编码和同步读帧；
- `codecs/numeric.py`：`decode_ths_float`；
- `codecs/compression.py`：8901 正规化、BitRLE、位平面转置；
- `codecs/hd.py`：通用字段表、记录区、hd1.0 和标准 hd3.1；
- `protocol.py` 对以上名字继续兼容 re-export，测试确认新旧入口是同一函数对象；
- `models.py` 增加 `AccountKind`、`Capability`、`Support` 和不可变
  `AccountProfile`；后续增加不可变 `AccountEvidence`，分别记录 MAIN、L2
  entitlement、manual 登录、L2 init 和各业务响应的三态证据；
- `features/account_profile.py`：提供保守的 `build_account_profile(evidence)`；
  passport 文本仅原样保存，不解释空 `level2` 等字段。明确普通 entitlement
  才把账号归为 STANDARD 并关闭 L2；manual 成功本身不宣称 L2，init/业务成功
  只提升已观察能力，矛盾证据直接报错；
- `AccountEvidenceRecorder`：线程安全、原子地演进证据快照；MAIN ready、
  entitlement、manual/init 和业务能力均为显式更新，更新前验证矛盾。超时、DNS、
  RST 和 parser 失败走 `record_transient_failure()` 保持原快照，不会把瞬时故障
  误写成权限 NO；
- recorder 已接入实际状态变化点：MAIN TCP 登录成功记录基础行情；manual
  VerifyCode=0 只记录 manual YES；仅通过大响应验收的 L2 init 记录市场访问 YES；
  只有明确“无 Level2/L2 权限”文本才记录普通 entitlement，stale passport 和一般
  VerifyCode/网络失败不降权；订阅、分时、竞价、历史分时及基础行情只有解析出
  有效结果后才提升对应能力；
- `errors.py` 建立权限不足、账号协议未实现、通道不可用和协议解析错误分类；
- `features/auth_protocol.py` 收拢当前已验证的登录 profile，现有 HTTP/TCP 登录
  常量从默认 profile 读取；
- `features/quote_protocol.py`：列表行情 builder、五档盘口 builder/parser 及字段
  常量完成单一实现迁移，完整请求字节 SHA 保持不变；
- `features/kline_protocol.py`：K 线周期/字段常量、builder、hd3.1 parser 和时间
  helper 完成单一实现迁移；日、周、5 分钟请求帧的完整字节 SHA 保持不变；
- `services/kline.py`：新增 MAIN-only `KlineService`，普通与 Level2 账号均只要求
  `BASIC_QUOTE=YES`；一次请求锁覆盖发送、通知帧过滤、最多 16 帧读取和多 hd3.1
  帧合并。首个数据帧前 timeout 继续作为连接失败，拿到数据后的 2 秒收尾 timeout
  正常结束；收到 K 线帧但 parser 为空时抛 `ProtocolError`，成功后回写 MAIN
  证据；
- 公开 `kline()` 在显式 service context 后 opt-in 委托 `KlineService`，未配置时
  保留旧 `_kline_query_once()`。重连、服务器 IP 轮换、坏 IP 黑名单以及“小于请求
  根数 50%”的完整性重试仍留在 client 编排层，迁移没有改变这些活网策略；
- 修复迁移前 `_kline_decode_time` 声明丢失、函数体落在分时 parser 返回语句之后
  而不可达的问题；日期、Unix 时间戳和日内 bar 序号均有离线合同测试；
- `features/timeline_protocol.py`：明确拆分普通账号 `pageid=9354` 与 Level2 账号
  `pageid=4214` 两个当日分时 builder，并迁移 Level2 hd3.1 parser；沪深两市四种
  请求帧 SHA 均保持不变，真实 `000938` Level2 语料可解析 241 点；
- `features/history_timeline_protocol.py`：迁移历史分时日期/bar 换算、三段嵌套
  builder、状态省略 parser 和行锚点 helper；请求 SHA、日期锚点、89–92 字节
  物理行恢复和真实语料结果保持不变；
- `_transport/session.py`、`connection.py`、`connection_manager.py`：建立
  `MAIN/SH_L2/SZ_L2/REALORDER` 角色、登录身份、每连接 single-flight 锁、
  capability 先行检查、连接缓存和关闭生命周期；顶层 `transport.py` 保持兼容导出；
- `ConnectionManager` 的 opener 合同现明确为“返回已完成对应身份登录及 init 的
  role-ready socket”，因此 opener 创建的 wrapper 自动标记 ready；`adopt()` 仍
  要求调用方显式传入旧 socket 的 init 证据，4214 协调器会在发送前拒绝未 init
  的借用连接；
- 新增 `OpenedConnection(socket, owns_socket, initialized, request_lock)` 作为
  opener 的结构化返回值；旧 opener 直接返回 socket 的形式保持兼容并默认由
  manager 拥有、已 ready。结构化形式允许旧 client 建连后把 socket 登记为借用，
  同时共享原请求锁，避免双重关闭；
- `ConnectionManager.adopt()`：可把已经完成登录/init 的旧 socket 收编到角色
  registry，并复用旧 request lock；默认只借用、不接管关闭责任，也可显式转移
  所有权。同一 socket 重复收编幂等且可提升 init 状态，不同 socket 抢占同一角色
  或同一 socket 跨角色复用均被拒绝，收编不能绕过账号 capability 检查；
- `ConnectionManager.update_profile()`：账号证据演进后可原子替换不可变画像；
  画像读取、角色 capability 校验和连接表变更由同一把锁保护。能力升级保留已有
  MAIN wrapper；降级为普通/UNKNOWN、L2 市场访问不再为 YES 时摘除 L2 wrapper，
  REALORDER 不再明确为 YES 时同样摘除。失效过程等待正在进行的单连接请求结束；
  manager 自有 socket 会关闭，借用 socket 只让 wrapper 失效，真实关闭仍归旧
  client；
- `THSClient.configure_service_context(profile)` / `sync_service_connections()`：
  在调用方显式提供不可变 `AccountProfile` 后，内部建立无隐式联网 opener 的
  service registry，并借用 `_sock` 与 `_push_socks`；主连接复用 `_sock_lock`，
  L2 连接使用每市场 request lock，旧 client 仍负责关闭；context 持有共享
  `L2SubscriptionCoordinator` 和长生命周期 Quote/Timeline/Auction service。
  重复同步、socket 替换、profile 偷换、普通账号误收编 L2 和 disconnect 后
  wrapper 失效均有离线合同；
- `configure_service_context()` 现可省略 profile，从该 client 已记录的证据生成
  保守画像；已有 context 可通过 `refresh_service_profile_from_evidence()`（或再次
  省略 profile 调用 configure）刷新。刷新不会自动重新收编刚因降级失效的旧 L2
  socket，避免普通账号画像把遗留 push socket 再次注册；
- `configure_service_context(..., allow_open=True)` 提供显式受控 opener；默认
  `False` 仍禁止隐式联网。opt-in 后 MAIN 通过旧 `connect()`，沪深 L2 通过旧
  `__manual + init` 建连，并立即登记回 `_sock/_push_socks`；manager 仅借用并
  共享旧锁，重复 acquire 不重复建连，失败分类为通道错误，context 建立后不能
  偷换 open 模式；
- `services/timeline.py`：建立 `auto/basic/level2` 纯路由策略。普通账号 auto
  选择 `MAIN + pageid=9354`，Level2 auto 按市场选择 `SH_L2/SZ_L2 +
  pageid=4214`；未知账号不作静默推断；
- `TimelineService.timeline()` 已接通可离线验证的 Level2 4214 工作流：角色获取、
  请求发送和响应匹配共用每连接锁；普通账号 basic 在 opener 前明确报
  `UnsupportedAccountFeatureError`，等待真实 9354 响应 parser；公开
  `timeline()` 在显式配置 service context 后 opt-in 委托，Level2 缺 socket、
  未 init 或有后台快照读者时均拒绝发送，未配置时保留旧活网路径；
- `TimelineService.history_timeline()` 已接通 Level2 4417 工作流：要求
  `L2_HISTORY_TIMELINE=YES`，按沪深获取 L2 角色，识别明文 hd1.0 与 0x0a
  压缩候选；普通/未知账号和未知能力均在 opener 前失败，未 init 的借用连接也
  在发送前失败；公开 `history_timeline()` 在显式配置 context 后 opt-in 委托到
  该 L2 工作流，未配置时暂时保留旧 MAIN 实验路径；
- `services/quote.py`：建立第一个业务 service 样板，只获取 `MAIN` 并把发送、
  最多 8 帧响应匹配和解析放在同一个连接锁生命周期内；通知帧、无数据和明确
  parser 失败分别处理；公开 `list_quotes()` 和 `depth_quote()` 在显式配置
  service context 后 opt-in 委托该 service，未配置时仍走原实现。协议错误分别
  兼容为空列表/空字典，五档盘口原有 transport 重连次数和市场推断保持不变；
- `features/stock_list_protocol.py`：迁移 `DataType=199112` 排序分页 builder、
  分页元数据以及 16-bit dc 的 hd3.1/hd1.0 变体 parser；默认、翻页和自定义排序
  三组完整请求 SHA 保持不变，真实抓包首帧仍解析 59 条且前三条代码一致。
  `protocol.py` 只兼容 re-export，诊断脚本依赖的压缩私有 helper 也继续保留；
- `services/stock_list.py`：新增 MAIN-only `StockListService.ranked()`，普通与
  Level2 账号均要求 `BASIC_QUOTE=YES` 并只获取 MAIN；分页期间跳过通知帧、按
  code 去重、保留旧实现的“达到 count 后返回完整最后一页”行为。声明有数据但
  parser 为空时抛 `ProtocolError`，真正空页仍返回空列表；成功页回写 MAIN 证据；
- 公开 `stock_list_hot()` 在显式 service context 后 opt-in 委托
  `StockListService`，参数和本机名称缓存填充行为保持不变；未配置 context 时
  继续走旧实现；
- 同一 `features/stock_list_protocol.py` 继续迁移 `build_init_query()`、
  `parse_init_response()` 和严格的重放容器 parser。默认/自定义 init 请求 SHA
  保持不变，包内重放资源固定为 4 段（10690/5468/8223/2839B），截断、非法段数
  和尾随字节均拒绝。真正的全量语料是
  `list_quote_fields_20260723_203100_resp_stream0.bin` 第 39 帧，可稳定解析
  `dc=7479, unk=0x18, hs=71` 和 7479 条代码；此前计划点名的
  `init_frame_43.bin` 只有正规化后的服务器信息，不含全量 hd3.1 表；
- `StockListService.full_list()` 在 MAIN 的 single-flight 生命周期内原样发送
  四个启动重放段（不追加换行），保持 0.3 秒段间节奏、总超时和拿到全量表后的
  3 秒收尾窗口；选取最大代码表，明确区分大帧 parser 失败，并支持注入响应读取、
  时钟、sleep 和重放段做离线测试。普通与 Level2 画像均只使用 MAIN；
- 公开 `stock_list()` 在显式 service context 后 opt-in 委托 `full_list()`，
  未配置 context 时继续保留旧重放实现；本机名称目录读取仍位于 client 边界，
  service 不反向依赖 `THSClient`；
- `features/stock_name_protocol.py`：迁移 `build_upstockname_request()`、名称段
  扫描、纯文本 GBK parser、代码/名称过滤和块编码启发式；默认与自定义请求 SHA
  保持不变。真实 `upstockname_stream37_server.bin` 仍解析 22 个文本段和 3510
  个键，`stream35` 的 `name_16_16` 仍明确返回 `skipped`，没有猜测未破解 LZ；
  `protocol.py` 对 builder/parser 及历史私有 helper 继续同对象 re-export；
- `services/stock_name.py`：新增 MAIN-only 增量名称工作流，持有单连接锁覆盖未封帧
  请求发送与多帧读取，合并 `names/by_segment/skipped/segments`，普通与 Level2
  账号均只要求 MAIN 基础行情能力。通知帧得到结构化空结果，成功解析文本段或识别
  块状段后才回写 MAIN 证据；
- 公开 `fetch_stock_names()` 在显式 service context 后 opt-in 委托
  `StockNameService`，未配置时保留旧探索路径。网络服务不会自动发送股票列表启动
  重放，也不会把本机 `load_hexin_names()` 当作协议响应；后者仍是 A 股名称的默认
  可靠来源；
- `features/auction_protocol.py`：完成周期/字段/哨兵常量、请求 builder、竞价
  时间窗、状态短行恢复、盘后历史段切分、沪市旧流启发式扫描和总 parser 的
  单一实现迁移；标准 hd1.0、0x0a 压缩、多打包状态和历史段真实语料结果保持
  不变，沪深最近交易日与指定日期请求 SHA 保持不变；
- `features/snapshot_protocol.py`：完成 snapshot 协议单一实现收拢。除 4214
  双子帧订阅 builder 外，MAIN 全市场 `build_market_snapshot_query()`、
  71B L2 push 的 `parse_snapshot_push()` / `is_snapshot_push()` 及两组字段常量
  均已迁入；默认/自定义 MAIN 请求和沪深/自定义 L2 请求完整 SHA 保持不变，
  `protocol.py` 只兼容 re-export；
- `services/market_snapshot.py`：新增 MAIN-only `MarketSnapshotService`，普通与
  Level2 账号均只要求 `BASIC_QUOTE=YES`，在同一 MAIN 请求锁内跳过通知帧并匹配
  `hfd1.0`；收到 HFD1 却解析为空时抛 `ProtocolError`，仅通知/超时返回空列表，
  成功后回写 MAIN 证据。历史 `hfd1_0_response.bin` 离线语料稳定解析 1209 条，
  结构锚点已冻结，旧启发式数值没有被提升为可靠行情合同；
- 公开 `market_snapshot()` 在显式 service context 后 opt-in 委托
  `MarketSnapshotService`，未配置时保留旧 MAIN 路径。它和 4214 L2 逐 tick push
  是两类独立协议：前者普通/Level2 共用 MAIN，后者仍要求
  `L2_SNAPSHOT_PUSH=YES` 和市场 L2 socket；该 MAIN service 不参与 L2 push 的
  注册和收帧；
- `services/subscription.py`：建立按 `ManagedConnection + market + code` 记忆的
  L2 注册协调器；只在 `CodeListSize>=1` 后记成功，同连接复用、换连接重注册，
  每连接独立串行化注册，不阻塞另一市场；
- 公开 `snapshot_subscribe()` 在显式 service context 后 opt-in 使用账号能力、
  `SH_L2/SZ_L2` 角色和共享 `L2SubscriptionCoordinator`。普通账号、未知账号、
  缺少 socket 和未完成 init 均在发送前得到明确错误；`CodeListSize=0` 继续兼容
  旧门面的 `False` 返回，重复订阅在同一 live connection 上不重复发送注册帧；
- L2 push 没有提取第二个 reader service：原 `_snapshot_loop` 继续作为唯一后台
  收帧者，callback、`latest_price()`、`stop_snapshot()` 和 disconnect 语义保持
  不变。同步注册和后台读取现在共用 `_push_request_locks[market]`，新增代码注册
  不会再与 reader 并发 `recv`；Timeline/Auction/history_timeline 在后台 reader
  存活时仍明确拒绝同步读取；
- `services/auction.py`：组合 Level2 集合竞价工作流，明确要求
  `L2_AUCTION=YES`，按市场选择 `SH_L2/SZ_L2`，跳过通知帧并只解析 `0x0a`
  或 `hd1.0` 候选；与 `TimelineService` 均在查询前确认 4214 注册，两者可共享
  协调器避免同连接同代码重复注册；普通账号、未知账号、未知能力和非法市场均在
  opener 前失败；公开 `auction()` 在显式配置 service context 后 opt-in 委托，
  未配置时保留旧活网路径。opt-in 模式下普通账号、缺少 L2 socket 和后台快照线程
  抢占读权都有明确错误；
- `features/realorder_protocol.py`：收拢 9601 的 `qurealorder` 历史分页、
  `subrealorder` 实时订阅、`pushrealorder` parser、len-minus-one 帧读取、
  30 秒心跳以及异动类别/过滤常量；查询、订阅和心跳请求字节已用长度与 SHA
  冻结，历史 hq1.0 与 push 记录有合成语料合同，`protocol.py` 继续保持同对象
  兼容导出。旧 RealOrder 源块已经从 `protocol.py` 物理删除，模块完整
  `__all__` 和包级历史入口均有同对象回归合同。8901 的 `subreal` 前置序列仍
  属于 L2 snapshot，不并入 9601 模块；
- `_transport/MarketSession` 与 `ManagedConnection` 新增只读 `receive()` 上下文，
  允许无需先发送请求地独占 socket 收帧。9601 的发送、查询响应读取、push 读取、
  心跳和关闭现在都共享同一 request lock；
- `services/realorder.py`：新增 `RealOrderService`，只获取 `REALORDER` 角色并明确
  要求 `Capability.REALORDER=YES`。历史查询在同一锁生命周期内发送并匹配 hq1.0，
  若查询响应前夹入 push 帧则暂存，后续 `receive_pushes()` 优先交付，不让查询
  错读推送；实时接收每帧短暂持锁，给分页查询和非阻塞心跳留下调度机会，不创建
  第二个后台 reader；
- 公开 `dxjl_page()` / `dxjl_latest()` / `dxjl_history()` /
  `subscribe_realtime()` / `receive_pushes()` / `receive_pushes_locked()` 在显式
  service context 后 opt-in 委托 `RealOrderService`，未配置时保留旧 9601 行为。
  9601 借用连接共享 `_realorder_lock`，心跳忙时跳过本轮，不与业务读写竞争；
- 普通账号的 RealOrder 能力仍未做乐观假设：只有画像中
  `REALORDER=YES` 才允许 9601 路由，包括未来经活网证据确认的普通账号；
  `REALORDER=NO` 和 `UNKNOWN` 都在 opener 前失败。也就是说普通账号兼容入口已经
  预留，但不会把 Level2 账号当前可用的 9601 行为误当成普通账号事实；
- `features/auth_protocol.py`：在原有 `LoginProtocolProfile` 基础上收拢
  signature/head128、Passport64 过滤、passport 字段解析、普通身份与
  `__manual` 身份 login body、login 响应解析。`protocol.py` 的历史公开名称绑定
  到同一批函数，普通和 `__manual` 登录帧长度/SHA 未变化；该纯协议层不接触
  socket、账号画像或 capability；
- `services/auth.py`：新增 `AuthService` 和不可变 `AuthMaterial`。一次 HTTP
  鉴权生成同代 `auth_info/passport_fields/passport64/profile/generation` 快照，
  MAIN、沪深 L2 `__manual` 和 REALORDER 均消费同一份 Passport64；重新鉴权会
  原子替换 current generation，已经交给在途连接的旧快照不被修改；
- `THSClient.connect()`、二维码/缓存凭证路径、外部 Passport64 登录、
  `__manual` 票据刷新和 9601 登录均已改为通过 `AuthService` 构造登录身份。
  `_auth` 继续镜像当前认证 dict，兼容已有板块代码、诊断脚本和测试注入；原有
  主连接 IP 测速/轮换、20 秒复用窗口、并发登录、心跳和错误分类没有下沉。
  2026-07-28 活网修正 MAIN 普通登录不再发送 L2 init；带 MarketCode 的 init
  只保留在 `__manual + shlv2/szlv2` 分服和显式 stock-list 重放流程。扫码/缓存
  路径原先向 `_do_tcp_login()` 传入不存在的 `max_retries` 参数也已修正；
- 同次活网排查进一步确认 MAIN 的 A 股请求只应路由到 `ifindhq.123ths.com`。
  `fu4/hkus/euhq` 节点可以返回 VerifyCode=0，但不响应沪深 `list_quotes`；
  旧实现又向 MAIN 发送默认 `MarketCode=16;144;` 的 L2 init，导致部分节点立即
  FIN。修正后 MAIN 不发 init，DNS 只取 ifindhq；测速缓存若含当前候选集以外的
  IP 会失效重测，避免旧的跨域名缓存绕过筛选；
- 修正后的活网矩阵 4/4 通过：`enable_heartbeat=False` 两轮和 `True` 两轮均完成
  登录、立即行情查询和等待后二次查询；有心跳两轮各发送 2 次心跳后连接仍存活，
  排除首秒断连由心跳触发；
- ★ 2026-07-29 活网验证推翻「MAIN 不发 init」结论：上述修正把 MAIN 登录收尾
  重构为 `_finalize_main_login`，但**误删了 `_send_init_handshake()` 调用和整个
  方法**，导致 kline 回归。跨分支对照实验定位根因：旧分支 `feat/stock-list-full`
  登录后调 init（`client.py:490`），kline 能收到响应（仅 parser 有 NameError）；
  新分支 `1cf409d` 删了 init，kline 跨 4 个 IP 全超时，而 `list_quotes`/`depth_quote`
  仍正常（hd1.0/hd3.1 不强依赖 init，掩盖了回归）。`build_kline_query` 字节两分支
  完全一致（sha8 `897f7634`），故回归不在 builder，而在登录后没发 init 激活通道。
  K线走 hd3.1 flag=0x0042/0x0046，服务器要求 init（subtype 0x0001）激活通道才响应；
  补回 `_send_init_handshake` 后 kline 立即恢复（实测返回 6 根日K，7/21–7/28）。
  「不发 L2 MarketCode init」的正确含义是：MAIN 不走 `__manual` L2 manual 路径
  （那是 shlv2/szlv2 专用 init(16;144)/(32)）；但 MAIN 自己的 `build_init_query()`
  配置帧是激活 A 股行情通道的必要步骤。之前观察到的「带 MarketCode init 在 fu4/hkus/euhq
  节点 FIN」是**节点选错**（非 ifindhq），不是 init 本身的问题——DNS 收窄到 ifindhq 后，
  带 `MarketCode=16;144;` 的 MAIN init 稳定激活通道且不触发 FIN；
- 同次活网验证还顺带修复了 `test_stock_cache::test_live` 和 `test_stock_list::test_live`：
  这两个之前因 init 缺失导致 stock-list 重放通道未激活而失败，补回 init 后均通过；
- `tests/test_main_login_finalization.py` 的两个契约已修正：原断言
  `sock.sent == []`（MAIN 登录后什么都不发）违背 hexin 协议，改为断言
  `_send_init_handshake` 被调用（激活行情通道）+ 旧 socket 正确关闭替换；
- 活网新旧路径逐字段对比（`tests/test_service_live.py`，opt-in service context）
  3/3 一致：`list_quotes`/`depth_quote`/`kline` 在同一次连接、同一服务器数据上，
  旧协议路径与新 service 路径解析结果逐字段相同，确认重构未改变 MAIN 业务协议行为；
- 普通账号登录差异的扩展点明确落在 `LoginProtocolProfile`：未来拿到普通账号
  抓包后，可单独提供 product/securities/HTTP version/TCP version/qsid/
  account_type 以及是否支持 `__manual`，并注入 `AuthService`，无需改业务
  service 或连接角色。当前默认仍是唯一经过字节与活网验证的 Level2 profile；
  不根据空 `level2`、`userclass` 文本或普通身份登录成功猜测普通账号协议。
  `AuthService` 只暴露 passport 字段作为证据，账号种类和能力仍由
  `AccountEvidenceRecorder` 在 MAIN/L2/9601 的明确行为之后判定；
- `Capability.L2_MARKET_ACCESS` 单独表达 `__manual` L2 市场通道权限，避免把某个
  具体业务能力同时当作账号类型和 socket 健康状态；
- 登录帧长度和 SHA 回归确认普通身份与 `__manual` 身份字节均未变化。

AuthService 接入并完成旧 RealOrder 源块清理后的扩大离线回归：

```text
274 passed, 2 skipped, 1 deselected
```

其中两个 skip 是本机缺少部分历史分时可选语料；deselected 项是
`tests/test_stock_cache.py::test_live`。单独运行时账号登录成功，
随后服务端在股票列表回放段发送期间以 WinError 10053 中止连接。真实 K 线抓包
`kline_20260724_000441_resp_stream1.bin` 也已离线回放成功：15 帧、18,846 根记录
均能解析；诊断脚本中 373 根历史前复权记录因价格为负不满足其金融约束，因此脚本
沿用旧逻辑返回非零，不属于 parser 迁移失败。

全量 `pytest -q` 仍会收集旧活网/本机工具测试，已知非重构失败：

```text
tests/test_stock_list.py::test_offline  配置的 tshark.exe 路径不存在
tests/test_stock_list.py::test_live     活网连接可能被服务器中止
tests/test_stock_cache.py::test_live     登录成功后活网连接被服务器中止
```

本轮初步重构至此完成。旧认证 builder/parser 和旧 RealOrder 源块均已从
`protocol.py` 物理删除，历史名称分别 compatibility re-export 到
`features/auth_protocol.py` 与 `features/realorder_protocol.py`。删除后遗留的
RealOrder framing import 已清理，8901 心跳和 snapshot 前置 `subreal` 仍保留在
原兼容层；公开协议导出与包级历史导出均已离线核对，不改变协议字节或 service
行为。
普通账号 9354 parser、普通账号专用 profile 的真实字段和普通账号 9601 行为仍
明确属于下一阶段，必须等待对应账号抓包/活网证据后再实现。
`market_snapshot_with_quotes()` 暂不下沉或自动组合 `StockListService`，它仍是
client 边界上的显式混合策略，避免名称目录、全市场 HFD1 和逐批行情在 service
内部形成隐式网络瀑布。
