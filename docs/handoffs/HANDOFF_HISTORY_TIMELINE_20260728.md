# 历史分时专项交接（2026-07-28）

> 归档位置：`docs/handoffs/`。文中未特别说明的路径均相对仓库根目录。
>
> 目标：在另一台电脑上继续完成 PC 同花顺 `pageid=4417` 历史分时协议。
>
> 当前分支：`feat/stock-list-full`
>
> 结论先行：请求日期编码、8901 外层正规化、指数定长表、个股完整锚点型的
> 价/量/额已经打通；离“完全破解”还差正确 L2 通道接入、最小请求 A/B、强状态
> 省略 codec、混合响应代码绑定、dt54 与 dt201-230 全字段校验，以及沪市实发闭环。

## 1. 已经确定的事实

### 1.1 正确网络通道

历史分时成功实验使用：

```text
__manual 登录
  → 深市连接 szlv2
  → init(MarketCode=32)
  → 在同一 TCP 连接发送 pageid=4417
```

此前在普通主行情连接上测试子帧增删时出现的超时或断连，不能用于证明
“服务器必须三段”或“缺少某个壳就断连”。当前
`THSClient.history_timeline()` 仍沿用主行情 `MarketSession`，尚未迁移到上述
已验证通道，所以它只是实验接口，不是端到端完成状态。

### 1.2 PC 客户端实际请求形态

2026-07-28 新抓包 `captures_live/timeline_20260728_170849.pcap` 显示，深市个股
历史分时通常在一个 `fdfdfdfd` envelope 里发三个内部子帧：

```text
目标股壳        subtype=0x0002, route=base
完整混合查询    subtype=0x0009, route=base+0x100
伴随代码壳      subtype=0x0002, route=base+0x200
```

000938 和 000001 的 PC 请求都带 `399002`。但 route base 不是协议常量：不同
请求见过 `0x58`、`0x26`、`0x7c`。它更像会话/请求相关标签。当前构造器默认
`0x58/0x158/0x258`，该组值在手工实发中能成功，动态生成规则仍未追。

指数请求常见两段：

```text
完整查询 0x0009
目标壳   0x0002
```

这只是“客户端怎么发”的证据，不等于“服务器最少要求什么”。

### 1.3 399002 不是硬依赖

在正确的 `__manual + szlv2 + init(32)` 连接上，把请求中的伴随代码
`32(399002,)` 替换为 `33(000001,)`，两种写法都成功：

```text
等长原位替换
33(000001,);33(000938,);

同市场合并
33(000001,000938,);
```

返回正规化后包含两张 `flag=0x0082 / hs=92 / fc=23` 个股表。第一张明确标记
000001。修正日期后请求 2026-05-14，000001 的首点为：

```text
价格 11.14
累计成交量 381,200
累计成交额 4,246,568
```

与 `thsdk.min_snapshot("USZA000001", date="20260514")` 精确一致。该强省略变体
安全恢复 225 个锚点，对 thsdk 的逐点命中为：

```text
价格     218 / 225
成交量   224 / 225
成交额   224 / 225
```

因此 `399002` 是客户端选择的大盘伴随序列，不是服务器硬编码依赖。剩余少量
不一致来自尚未恢复的状态省略，不影响“返回的是 000001”这一身份结论。

原始实发样本已经纳入仓库：

```text
captures_live/history_companion_000001_000938_20260514_20260728_174530.bin
大小：31079 bytes
SHA-256：06CFE29ABD257B19499863FA317E7B1DD30F170842D690D1B280B316528C2BCE
```

### 1.4 日期编码已经修正

历史分时 `DateTime=8192(start-end)` 的 start：

```text
bar_start = (date.toordinal() - 675064) * 2048 + 606
bar_end   = bar_start + 355
epoch     = 1849-04-06
```

已验证锚点：

```text
2026-05-13 → 132475486
2026-05-14 → 132477534
2026-06-30 → 132573790
2026-07-23 → 132620894
```

旧值 `675063 / 1849-04-05` 整体早一天。证据不是 UI 日期猜测，而是：

- 旧包中 `bar_start=132477534` 的 399002 全序列对应 thsdk 2026-05-14；
- 替换成 000001 后，同一 bar 的价/量/额也对应 thsdk 2026-05-14。

### 1.5 响应外层和表结构

原始 8901 响应可能是 `cmd=0x0a` 压缩。必须先经过
`normalize_8901_response()`；压缩流中偶然出现的字面量 `hd1.0` 不能直接当表头。

正规化后的常见表：

```text
指数：flag=0x007e, hs=88, fc=22
个股：flag=0x0082, hs=92, fc=23
```

个股逻辑字段：

```text
dt1/10/13/19/22/23/54/201-204/207-210/223-230
```

241 个交易时点的 bar 偏移：

```text
0..29, 34..93, 98..128, 227..285, 290..349, 354
```

当前 parser 对“完整锚点型”用这些 bar 定位物理行，已安全返回：

```text
bar_index, dt10, dt13, dt19, dt22, dt23
```

000938 的 2026-05-14 完整锚点样本可解 241 点，首末价/量/额均与 thsdk 一致。
另一日期服务端响应本身少一个可验证 bar，parser 保留 240 点，不伪造缺失点。

## 2. 离完全破解还差什么

按阻塞关系排序如下。

### P0：把公开 API 接到正确连接

`THSClient.history_timeline()` 目前使用主行情 `_sock/_market_session`。需要复用
`timeline()` 已经实现的市场 L2 连接建立逻辑，但不要为了历史查询先发送 4214
当日分时订阅：

```text
深市股票/指数 → szlv2 + init(32)
沪市股票/指数 → shlv2 + init(16;144)
```

还要给同一 `_push_socks[key]` 上的请求/读取加严格串行锁，避免历史分时、当日
分时、竞价、实时推送后台读线程互相抢帧。不能只把 socket 换掉而忽略读所有权。

### P0：在正确连接上确定最小请求

对同一股票、同一历史日期、同一条已初始化 socket，依次测试并保存原始响应：

```text
A. PC 三段：目标壳 + 混合完整查询 + 伴随壳（已知成功）
B. 目标单票两段：完整查询 + 目标壳
C. 仅一个 0x0009 完整查询子帧
```

每一种至少发 3 次，记录：

- 是否收到业务表，而不只是 ACK；
- 响应表数量、flag/hs/fc、代码标签；
- TCP 是否仍可继续处理下一请求；
- 返回数据是否与 thsdk 对应代码/日期一致。

测试顺序用 A → B → A → C → A。中间重新发 A 是为了区分“请求形态失败”和
“socket/票据已坏”。不能再用错误连接上的断连推导最小协议。

### P0：完整恢复强状态省略 codec

当前最难的核心。强省略型会省略：

- `bar_index` 的中高位；
- 字段表里的部分重复字节；
- 记录字段的前值/高位/零值；
- 逻辑 `hs=92` 之外或之内的状态控制字节。

当前依靠完整 bar 锚点只能恢复约 225-240 点，且个别价量仍错。必须从“扫描
可能的 bar”转为真正的顺序状态机。建议做法：

1. 固定代码、日期，重复请求直到拿到至少两种不同 raw 变体。
2. 每份先用 `normalize_8901_response()`，按 hd1 表逐张切出，不要直接全局扫描。
3. 用同日 thsdk 241 点和完整锚点型作为双 oracle。
4. 从第一行开始逐字节对齐，记录每个控制字节对“复用前值、复用高位、字段缺省”
   的影响。
5. 先只恢复 `dt1/10/13/19` 到 241 点全等，再扩展 dt22/23/54。
6. 最后恢复 dt201-230；不要先写只适合一个样本的 89/90/91/92 字节硬切。

“多请求几次直到碰到容易变体”只可用于采集语料，不能作为生产解析方案。

### P0：混合响应中的代码绑定

正规化响应可能有多张表，但后面的个股表不一定重复 ASCII 代码。当前
`parse_history_timeline_response(body, code=...)` 依赖代码壳，第二张表可能无法
选中。需要：

- 请求构造时保留 CodeList 顺序；
- 表解析返回所有表及其结构信息；
- 有代码标签时显式绑定；
- 标签省略时按请求顺序和表数量绑定；
- 最后用市场、首条业务值和 thsdk 测试防止错绑。

不要把“第一张表”永久等同于目标股票；000001 替换实验中第一张恰好是伴随票。

### P1：沪市闭环

当前成功实发只证明深市通道。沪市需要至少：

- 600519、600276、688981 等普通沪市/科创板；
- `shlv2 + init(16;144)`；
- 抓一份 PC 客户端沪市历史分时请求，确认它选的伴随代码和三段顺序；
- 进行同样的 A/B、随机变体和 thsdk 逐点验证。

在拿到沪市历史抓包前，不要把 `1A0001` 或 `1A0002` 写成必然默认值。

### P1：完成验收矩阵

“完全破解”的最低标准：

- 深市和沪市都能通过公开 API 稳定查询；
- 日期无 off-by-one；
- 服务器接受的最小请求形态有主动 A/B 证据；
- 伴随指数不是硬依赖；
- 混合表无论是否带 ASCII 代码都绑定正确；
- 每个有效交易日稳定产出全部可用时点，不依赖随机重试；
- dt10/dt13/dt19/dt54/dt201-230 与 thsdk 或客户端真值逐点一致；
- 多股票、多日期、至少两类 wire 变体均通过；
- 关键 raw 响应作为离线 fixture，断网也能回归。

## 3. 今晚建议执行顺序

### 第一步：在另一台电脑恢复环境

```powershell
git clone git@github.com:djj45/thspypc.git
cd thspypc
git switch feat/stock-list-full
uv sync
```

确认 `.env` 中有账号配置，但不要提交 `.env`。`thsdk` 可安装在任意路径；本机
曾使用：

```text
D:\code\gh\thsdk
C:\Users\23027\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe
```

另一台电脑优先确认 `import thsdk` 和它依赖的 `hq.dll` 实际可用，不要照抄绝对
路径。可先运行：

```powershell
python -c "from thsdk import THS; print('thsdk ok')"
```

### 第二步：先跑离线回归

```powershell
$env:PYTHONPATH = "src"
uv run pytest tests/test_history_timeline_response.py -q
```

测试包含本次 000001 替换实发样本，不需要联网。

### 第三步：复现实发真值

本机已有探针：

```powershell
python -u tests/probe_history_timeline_companion.py `
  --date 20260514 `
  --target 000938 `
  --companion 000001 `
  --merge-same-market
```

预期看到 000001 首点 `11.14 / 381200 / 4246568`，并输出与 thsdk 的命中统计。
如果 `python` 不是安装 thsdk 的解释器，用实际的 thsdk venv Python 执行。

### 第四步：新增最小请求 A/B 探针

不要直接改生产默认值。先让探针支持 `--shape pc3|target2|full1`，每次把：

- 完整请求 hex；
- route base；
- raw 响应；
- normalize 后各 hd1 表头；
- socket 后续是否健康；
- thsdk 匹配统计

写到同一份 JSON/文本清单。A/B 结束后再决定
`build_history_timeline_query()` 的默认形态和参数命名。

### 第五步：拆分 table parser 与 row codec

建议把当前单函数拆成三个纯函数：

```text
normalize_8901_response(raw)       # 已有
split_history_timeline_tables(buf) # 新增：枚举每张表、壳、边界
decode_history_timeline_table(tbl) # 新增：顺序状态机
```

生产客户端只负责连接、发送、收帧和代码绑定；不要在 socket 读取循环里继续堆
字节扫描启发式。

## 4. 关键文件

```text
src/thspypc/protocol.py
  build_history_timeline_query
  date_to_timeline_bar / timeline_bar_to_date
  normalize_8901_response
  parse_history_timeline_response

src/thspypc/client.py
  history_timeline / _history_timeline_once
  timeline / _open_manual_push_connection

tests/test_history_timeline_response.py
  离线结构、日期、真实响应回归

tests/probe_history_timeline_companion.py
  正确 szlv2 通道实发 + thsdk 对照

docs/HISTORY_TIMELINE_VARLEN_INVESTIGATION.md
  变长响应的技术调查

captures_live/history_companion_000001_000938_20260514_20260728_174530.bin
  000001 替换 399002 后的真实强省略响应
```

## 5. 容易踩的坑

- `sendall(frame + b"\n")`：构造器返回 fdf envelope，现有 L2 路径实发还会追加换行；
  做 A/B 时保持其他条件一致。
- 不要在压缩 raw 中直接找第一个 `hd1.0` 就解释字段头，先 normalize。
- `dc=242` 不等于 242 个交易时点；真实 schedule 是 241 点。
- `hs=92` 是逻辑字段区，不保证物理行固定 92 字节。
- 后一张表可能省略代码字符串；代码绑定必须结合请求顺序。
- route base 在 PC 请求中会变化，`0x58` 只是已成功值，不是已破解常量。
- 000001 同时可指深市股票；沪市指数要用内部代码和正确 market，不能只看数字。
- 日期必须以 thsdk 返回业务值校验，不能只按 UI 点击时刻或抓包文件名标注。
- 不要提交账号、Passport64、IMEI、`.env` 或完整登录流量。

## 6. Git 推送代理

用户给的是 `cmd.exe` 语法：

```bat
set http_proxy=http://127.0.0.1:10808
set https_proxy=http://127.0.0.1:10808
set all_proxy=socks5://127.0.0.1:10808
set HTTP_PROXY=http://127.0.0.1:10808
set HTTPS_PROXY=http://127.0.0.1:10808
set ALL_PROXY=socks5://127.0.0.1:10808
git push origin feat/stock-list-full
```

PowerShell 对应：

```powershell
$env:http_proxy  = "http://127.0.0.1:10808"
$env:https_proxy = "http://127.0.0.1:10808"
$env:all_proxy   = "socks5://127.0.0.1:10808"
$env:HTTP_PROXY  = "http://127.0.0.1:10808"
$env:HTTPS_PROXY = "http://127.0.0.1:10808"
$env:ALL_PROXY   = "socks5://127.0.0.1:10808"
git push origin feat/stock-list-full
```

当前 remote 是 SSH URL。上述 HTTP 环境变量是否被 SSH 客户端使用取决于本机
SSH 配置；若 push 失败，应先区分 GitHub SSH 连通性问题和代码问题，不要改提交。
