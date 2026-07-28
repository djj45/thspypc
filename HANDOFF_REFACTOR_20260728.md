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
refactor: extract quote protocol
refactor: extract kline protocol
refactor: extract timeline protocol
refactor: centralize managed market connections
refactor: extract quote service
refactor: extract timeline service
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
