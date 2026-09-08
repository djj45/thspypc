# thspypc — 同花顺 Windows PC 免费版行情协议纯 Python 实现

模仿 [thspy](https://github.com/djj45/thspy)（Mac 版逆向）的登录实现，改成 **Windows PC 免费版协议**，连 **8901** 端口。**已实测登录成功（VerifyCode=0），含 Level2 账号。行情查询已打通（个股列表实时行情）。**

> 本项目源自对真实 hexin.exe（PC 免费版）的抓包分析。协议参考见 `D:\code\ths_takehome\ths\PROTOCOL.md`。

## ✅ 已实现

- HTTP 三步鉴权（RSA 公钥 → unified_login → mainverify）
- head128 + passport64 构造（PC 版动态 raw 长度结构头）
- PC 免费版 login 帧构造（8901 端口），VerifyCode=0 后直接复用 MAIN 长连接
- **M_hqdns 动态域名解析**：从 passport 解析服务器域名 → DNS 查询拿最新 IP（不硬编码）
- 多 IP 冗余连接 + 失败诊断
- **设备指纹全自动生成**：`generate_imei()` + `generate_mac64()`（算法已逆向，无需抓包）
- **二维码扫码登录**：终端显示二维码，手机同花顺扫码即登录（无需账号密码）
- **30天免登录凭证缓存**：扫码一次，30天内重启免扫码秒登录
- **实测**：Level2 账号成功登录 8901，拿到带 level2/sid 权限的 passport
- **个股列表行情查询**（`list_quotes`）：hd1.0/hd3.1 响应解析，纯 Python 移植
  hexin.exe 真实机器码（BitRLE 解码 + 位平面转置），无 unicorn 依赖。实测解出
  600056 等股票的 现价/昨收/开盘/涨幅/竞价金额
- **个股五档/十档盘口**（`depth_quote`）：买卖各五档价格/挂单量、档位金额以及
  涨跌停封单额。Level2 账号可用 `ten_levels=True` 请求十档，普通账号五档即完整复刻。
- **全市场股票列表**（`stock_list`）：MAIN 单请求拉取全市场代码表，无需抓包重放
  全部代码（约7500+条），hd3.1 BitRLE 解码，自动翻页
- **热门股排序查询**（`stock_list_hot`）：DataType=199112 排序查询（同花顺打开 A 股
  列表时发的请求），服务器返回按 SortBy 排序的前 N 条代码
- **自定义板块/自选股管理**（`blocks`）：分组 CRUD + 成分股增删 + 自选股 +
  动态板块查询。走标准 HTTPS（cookie 鉴权），移植自 thspy，实测列出 95 个分组。
- **短线精灵（异动）**（`dxjl_*`）：9601 端口 qurealorder 历史查询，hq1.0 响应解析。
  实测解出 大笔买入/卖出、涨停封板、打开跌停板 等异动（含金额/涨跌幅）。
- **心跳保活**（自动）：connect() 后后台线程每 3 秒（8901）/30 秒（9601）发心跳，
  维持长连接。实测静置 10 秒后连接仍可用。
- **短线精灵实时推送**（`subscribe_realtime` + `receive_pushes`）：9601 subrealorder
  订阅 + pushrealorder 推送接收。盘中 ~500-800 帧/分钟，异动代码/金额/涨幅/方向
  普通账号支持 23 类基础异动；Level2 “全选”共 53 类（额外 30 类盘口/挂撤单
  等高级异动）。通道可用、基础异动集和 Level2 高级异动集分别建模。
- **K线查询**（`kline`）：1分/5分/15分/30分/60分/日/周/月/季/年K线，hd3.1 flag=0x0042/0x0046
  响应解析，连接复用（一次 connect 查多只多周期）。
- **沪深分时查询**（`timeline`）：当日逐点分时（现价/量/额/均价，241 根）。
  普通账号走 MAIN `pageid=9355`，Level2 账号走 `pageid=1334`。
- **历史分时**（`history_timeline`）：普通账号走 MAIN `pageid=9355` 的基础
  七字段响应，Level2 保留 `pageid=4417` 大单字段路径。
- **早盘/尾盘竞价**（`auction` / `closing_auction`）：分别覆盖 9:15-9:25 与
  14:57-15:00；`intraday` 按显示顺序合并早盘竞价、盘中分时和尾盘竞价。
  ★ **沪深分服**：shlv2（沪）/szlv2（深）是两套独立 L2 服务器（IP 0 重叠），
  按股票市场选对应 IP + 配套 init MarketCode（沪 16;144 / 深 32）。
  ★ **后台预热**：首次建好某市连接后异步预热另一市，跨市切换 0.44s（复刻 hexin 秒加载）。
- **全市场快照**（`market_snapshot` / `market_snapshot_with_quotes`）：沪市 hfd1.0
  空括号单请求，配合 stock_list + list_quotes 混合方案覆盖全市场。
- **系统板块与板块行情**（`system_blocks` / `board_*`）：行业/概念板块发现、成分股、
  板块指数行情/分时/竞价，板块通道走 fu4，成分股走股票行情网关。
- **板块辅助计算**（`board_stats_*` / `board_calcext`）：9601 旧 `statscalc`
  区间/涨跌停聚合 + `calcext` 扩展计算。注意它不是板块涨幅/涨速排行榜；当前
  客户端排行走 8901 的 `pageid=12480/1334` 字段查询与排序。
- **逐笔成交与超级盘口**（`superorder` / `snapshot_replay`）：7169 逐笔成交回放、
  4096 盘口快照回放，沪深通用。
- **买一/卖一委托队列**（`order_queue` / `order_queues`）：7173/7174 Level2 专属，
  历史队列需先用 4096 建立 4417 上下文。
- **DDE 排名 API**（`dde_rank`）：pageid=10723 排序请求，普通 MAIN / Level2
  沪深合并排序。
- **批量资金字段查询（0xc4 金额表）**（`stock_quote_fields`）：pageid=1334 +
  扩展 DataType（含 592890/592888），一次请求同时拿 主力净额 dt250(元)/
  DDE 主力 dt248(亿)/总市值 dt202(元) + 全套基础行情。响应为 hd3.1 0xc4
  变体（大批量 BitRLE+64B 前导 / 小批量 hd1.0 明文+60B 前导），fmt 0x79/0x7B
  与 0x70 同为 THS 定点浮点。2026-08-18 逆向，详见
  `docs/handoffs/HANDOFF_MONEY_TABLE_0XC4_20260818.md`。
- **股票名称全量同步**（`fetch_all_stock_names`）：按服务器分组并发登录拉取
  `name_16_16`，无需安装客户端。
- **逐 tick 快照与十档推送底层**（`snapshot_subscribe` / `latest_depth`）：4214 实时
  快照已可用；549B 十档推送 parser/缓存已接入，专用流式 API 尚待收口。
- **北交所（BSE）行情族**（市场码 151，920xxx 等，2026-09 打通）：行情/代码表、
  当日分时（1 分钟K合成 + 6144 竞价段）、历史分时（pageid=10444 的 8192
  packed-date bar 窗，241 行/日）、**盘中超级盘口**（`bse_superorder_day`：
  pageid=1207 注册 + `DateTime=4096(0-0)` 三子帧，响应 0x0096 大表，
  每行逐笔事件并携带完整五档快照，活网 973 行与页面总量/总额逐值一致）、
  **竞价逐笔窗**（`bse_tick_window`：7176 当日 / 6144 历史，09:15-09:25，
  含买/卖未匹配）。北交所无沪深式 L2 通道（十档回放/委托队列/挂撤明细），
  且必须连 main.123ths.com 组（独立 `BSE_MAIN` 车道，ifindhq 组不回数据）；
  协议族与账号类型无关（双账号抓包确认）。详见
  `docs/handoffs/HANDOFF_BSE_HISTORY_SUPERORDER_20260908.md`。
- **Web 看盘服务与前端**（`thspypc.server` + `web/`）：FastAPI 单用户
  REST + WebSocket（个股逐笔/十档/队列与短线精灵实时流），配套 React
  看盘前端（看盘/分时/超级盘口三视图，见下文「看盘前端」）。

## 代码架构

公开使用入口仍是 `THSClient`，但协议实现已经从原来的单体 `protocol.py` 拆成分层
模块。`protocol.py` 目前主要承担历史 API 的兼容导出；新增实现应放入对应的新模块，
避免再次扩大兼容层。

```text
src/thspypc/
|-- client.py               # THSClient 公开门面和旧调用兼容
|-- _client/                # THSClient 内部实现（不属于公开导入路径）
|   |-- connection_runtime.py    # 角色建连与心跳/推送生命周期
|   |-- connection_primitives.py # MAIN/L2/REALORDER 登录建连原语
|   |-- service_facade.py        # service-backed 公开行情方法
|   `-- stock_cache.py            # 股票代码表自然日缓存
|-- models.py               # 账号证据、账号画像、能力和行情数据模型
|-- codecs/                 # 帧、压缩、数值及 hd1/hd3 基础编解码
|-- features/               # 各业务的纯协议 builder/parser
|-- _transport/             # 按角色管理的 socket、会话和请求锁
|-- services/               # 能力校验、连接选择及完整业务工作流
|-- protocol.py             # 历史协议 API 兼容层
`-- transport.py            # 旧 transport API 兼容层
```

典型调用链：

```text
THSClient
  -> ServiceFacade / ConnectionPrimitives
  -> AuthService / AccountEvidenceRecorder
  -> ConnectionFactory / ConnectionRuntime
  -> ConnectionManager
  -> QuoteService / KlineService / TimelineService / ...
  -> features/*_protocol.py
  -> codecs/
```

各层职责：

- `codecs` 只处理可复用的二进制格式，不感知账号、市场权限或业务流程。
- `features` 提供无网络副作用的请求构造和响应解析，适合使用抓包语料做离线回归。
- `_transport` 以 `MAIN`、`SH_L2`、`SZ_L2`、`REALORDER` 等角色管理连接和读写所有权。
- `services` 根据 `AccountProfile` 和 `Capability` 选择连接并组合完整工作流。
- `THSClient` 保持现有公开调用方式，行情、L2 与 REALORDER 默认委托 service；
  `configure_service_context()` 仅保留给需要注入明确 profile/socket 的高级调用方。

### 普通账号兼容边界

普通账号与 Level2 账号都使用独立证据选择请求路径。重构提供
`LoginProtocolProfile`、账号证据收集、三态能力模型
（`YES` / `NO` / `UNKNOWN`）以及按连接角色路由的扩展点：

- 普通账号可以使用独立的 product、version、qsid、account type，并声明是否支持
  `__manual` 登录身份，无需修改业务 service。
- HTTP passport 的成对实测签名提供账号类型基线：普通账号
  `userclass=10000 + level2=255`，Level2 账号
  `userclass=30002 + level2=16;32;48`。单字段或未知组合仍保持 `UNKNOWN`；
  MAIN/L2/9601 的明确响应继续提供更细粒度的能力证据。
- 只有明确为 `YES` 的能力才会进入对应专用通道；`NO` 和 `UNKNOWN` 会在创建连接
  前返回明确错误，避免普通账号误走 Level2 请求。

2026-07-29 普通账号冷启动抓包已确认 MAIN 登录，以及日 K、9355 当日分时、
9355 历史分时、早盘竞价和尾盘竞价的沪深请求/响应。普通账号只返回基础字段；
代码不会伪造 Level2 大单字段。9601 的基础 23 类异动也已单独建模。

## 三种登录方式

### 方式 1：账号密码（imei/Mac64 自动生成）

```bash
# .env 配置账号密码即可（imei/mac64 不用填，自动生成）
#   THS_USERNAME=账号
#   THS_PASSWORD=密码
uv run python tests/test_login.py
```

### 方式 2：二维码扫码（无需账号密码）

```bash
uv run python tests/test_qr_login.py
# 终端打印二维码 + 存 qr_login.png
# 手机同花顺 APP 扫 qr_login.png → 自动完成 8901 登录
# 扫码时勾选「30天免登录」→ 凭证缓存 30 天
```

### 方式 3：带缓存的二维码登录（推荐，日常开发用）

```python
from thspypc import THSClient

client = THSClient(username="", password="")  # 账号密码留空
result = client.connect_cached()
# 首次：弹二维码扫码（勾选30天免登录）
# 后续30天内：读 ~/.ths_qr_credentials.json 秒登录，无需掏手机
```

三种方式都输出：
```
✓ 登录成功！服务器: 116.63.108.136:8901
  VerifyCode = 0
```

### 凭证缓存机制（自适应）

扫码返回的 `account`+`password` 对同一账号是稳定的（勾选/不勾选「30天免登录」
返回值完全相同，唯一区别是 `expireTime` 字段）。thspypc 采用**自适应缓存**——
不靠时间预判凭证是否有效，而是「先试再说」：

```
connect_cached() 流程:
  1. 有缓存 → 先用缓存凭证试登录（不预判是否过期）
  2. 成功 → 秒登录完成（凭证实际有效）
  3. 失败 → 清缓存 → 弹二维码扫码 → 重新缓存
```

这样无论服务器实际让凭证活多久，都能自动适应，**不需要关心手机端是否勾选了30天**。

| 手机端操作 | `expireTime` | 自适应行为 |
|-----------|-------------|-----------|
| 勾选 30天 | 未来时间戳 | 30天内每次都试，直到服务器拒绝才回退扫码 |
| 不勾选 | `0` | 同样每次都试，失败自动回退（保护期3天，超过才省去无谓请求） |

缓存文件：`~/.ths_qr_credentials.json`，含 `account`/`password`/`expire_time`/`saved_at`。

## 设备指纹算法（已逆向，无需抓包）

| 参数 | 算法 | 来源 |
|------|------|------|
| **Mac64** | `base64(0x18 + 前4个网卡MAC)` | GetAdaptersInfo |
| **imei** | `MD5(第1个网卡MAC大写连字符 + "0"*30).hex()` | GetAdaptersInfo + BIOS采集fallback |

详见 `protocol.py` 的 `generate_mac64()` / `generate_imei()`。
imei 逆向过程见 `ths/HANDOFF_IMEI.md`（通过 hexin 内存 patch 捕获 MD5 输入破解）。

## 二维码登录协议（已逆向）

```
1. GET  upass.10jqka.com.cn/scan/creatCode  → qrid
2. 二维码 = http://mobile.10jqka.com.cn/?source=PC&qrid=<qrid>
3. POST upass.10jqka.com.cn/scan/getInfoNew (轮询4s) → status=3 返回 account+password
4. account+password → full_http_auth → passport → 8901 login
```

详见 `PROTOCOL.md` §14。抓包用 mitmproxy + 系统代理（网页版走浏览器可抓明文）。

## 逆向过程中的关键发现（thspy Mac 版 → PC 版的 4 处差异）

直接照搬 thspy 的 Mac 实现会被 8901 拒绝（VerifyCode=-1）。实测定位到 4 处必须改：

| # | 差异点 | thspy (Mac) | thspypc (PC) | 不改的后果 |
|---|--------|-------------|--------------|-----------|
| 1 | mainverify 参数 | `product=同花顺Mac至尊版` `qsid=7004` `version=macpro_3.5.2` | `product=E02` `securities=同花顺统一版` `qsid=6800` `version=9.60.20.0031` | passport 身份是 Mac，被 PC 网关拒（-6:） |
| 2 | mainverify 的 imei | MAC 地址字符串的 base64 | **32 字符十六进制设备 ID**（`MD5(MAC+"0"*30)`） | passport 设备绑定错误 |
| 3 | passport 字段截断 | 截断到 `userflag=`（丢 bind/sk/sv） | **不截断**，保留全部字段 | 丢失会话密钥 sk/sv，服务器拒（-6:） |
| 4 | Passport64 结构头 | Mac 样本 kind=`2d` | PC：`uint16_le(raw长度) + 06 + 80 00`，如 1722→`ba 06 06 80 00` | raw 长度声明不一致时严格服务器直接拒绝 |

## 个股列表行情查询（`list_quotes`）

登录后可在同一条 8901 socket 上查个股列表实时行情。**账号密码一行搞定，无需抓包**：

```python
from thspypc import THSClient

with THSClient("账号", "密码") as client:
    client.connect()
    recs = client.list_quotes(["600056", "600057", "600058", "600059", "600060", "600061"],
                              market=17)
    for r in recs:
        price, prev, open_p = r.get("dt10"), r.get("dt6"), r.get("dt7")
        bid_vol = r.get("dt17")
        chg = (price - prev) / prev * 100 if price and prev else None
        bid_amt = bid_vol * open_p if bid_vol and open_p else None   # 竞价金额
        print(f"{r['code']}: 现价={price} 涨幅={chg:.2f}% 竞价金额={bid_amt:.0f}")
```

输出（2026-07-17 实测）：
```
600056: 现价=9.78  涨幅=1.45%  竞价金额=2531520
600057: 现价=6.18  涨幅=2.15%  竞价金额=416845
...
```

### DataType 字段含义（精简7列默认集 `LIST_QUOTE_DATATYPE_DEFAULT`）

| DataType | 字段 | 含义 |
|----------|------|------|
| 5 | code | 代码（1B 长度前缀 + ASCII） |
| 7 | dt7 | 开盘价（竞价涨幅 = (dt7-dt6)/dt6） |
| 49 | dt49 | 竞价委托笔数 |
| 13 | dt13 | 全天成交量（成交额 = dt13 × dt10） |
| 48 | dt48 | 4 分钟涨幅 |
| 10 | dt10 | 现价 |
| 17 | dt17 | 竞价成交量（竞价金额 = dt17 × dt7） |
| 6 | dt6 | 昨收价 |
| 66 | dt66 | 涨幅 |
| 1111 | dt87 | 日期 + 小数 |

> 主力净额/DDE 主力/总市值 → 走下文 0xc4 金额表直查；封单额 → 排序榜
> `sort_by=265260`（响应 dt44）。

## 批量资金字段查询（0xc4 金额表，`stock_quote_fields`）

同花顺客户端在列表页对显式代码子集发的"刷新主力净额"请求（pageid=1334 +
29 个扩展 DataType），响应即 0xc4 金额表——一次拿全价格 + 资金字段：

```python
with THSClient("账号", "密码") as client:
    client.connect()
    rows = client.stock_quote_fields(["600519", "601318", "000001", "300561"])
    for r in rows:
        print(f"{r['code']}: 主力净额={r['main_inflow']/1e8:.2f}亿 "
              f"DDE主力={r['dde_main']}亿 总市值={r['market_cap']/1e12:.2f}万亿")
```

输出（2026-08-18 盘后实测）：
```
600519: 主力净额=-1.43亿 DDE主力=-0.0089亿 总市值=1.62万亿
601318: 主力净额=-1.07亿 DDE主力=-0.0195亿 总市值=0.93万亿
000001: 主力净额=-1.04亿 DDE主力=-0.0483亿 总市值=0.21万亿
300561: 主力净额=-0.26亿 DDE主力=-0.655亿 总市值=0.005万亿
```

### 0xc4 金额表响应字段（`MONEY_QUOTE_DATATYPE`，2026-08-18 抓包逆向）

| 字段 | fmt | 含义 |
|------|------|------|
| dt250 | 0x7B | 主力净额（元，负值=净流出） |
| dt248 | 0x7B | DDE 主力（亿，与 `dde_rank` 逐码一致） |
| dt202 | 0x79 | 总市值（元） |
| dt13×dt10 | 0x70 | 成交额（表内无 dt19，本地乘算） |
| dt7/10/17/6/48/66… | 0x70 | 与基础列表含义相同 |

编码细节（两种形态、前导布局、单码不应答等边界）见
`docs/handoffs/HANDOFF_MONEY_TABLE_0XC4_20260818.md`。

## 个股五档盘口（`depth_quote`）

`depth_quote` 复用登录后的 8901 长连接，自动按代码推断沪深市场。盘后仍可取
服务器保存的最后一份盘口快照。Level2 账号传 `ten_levels=True` 时按市场走
shlv2/szlv2 请求十档，普通账号请求十档会返回权限错误：

```python
with THSClient("账号", "密码") as client:
    client.connect()
    depth = client.depth_quote("600519")
    for level in depth.get("buy", []):
        print(level["level"], level["price"], level["qty"], level["amount"])
    print("封单类型:", depth.get("seal_type"))
    print("封单额:", depth.get("seal_amount"))
```

返回的 `buy`/`sell` 各包含最多五档（`ten_levels=True` 时最多十档）。
`seal_amount` 单位为元；正常交易状态为 `0.0`，涨停或跌停时分别按买一或卖一
的价格与挂单量计算。

### Level2 十档实时事件（`depth_subscribe`）

Level2 账号可在沪深 L2 通道上订阅多只股票。深度事件与旧式现价回调分开，既可
按代码回调，也可从事件队列顺序读取；合并推送帧中的每只股票都会独立分发：

```python
client.depth_subscribe("600519", callback=lambda depth: print(depth["code"], depth["bids"]))
client.depth_subscribe("000001")

event = client.receive_depth(timeout=2.0)  # 超时返回 None
latest = client.latest_depth("000001")

client.depth_unsubscribe("600519")
client.depth_unsubscribe("000001")
```

现有抓包没有确认 4214 单码退订帧，因此存在其他订阅时，`depth_unsubscribe()`
只停止该代码的本地回调、队列交付和缓存；最后一个快照/深度订阅退出时关闭后台
读取线程及沪深 L2 通道。普通账号会在建连前按 capability 明确拒绝。

## 全市场股票列表（`stock_list`）

获取沪深+北交所+新三板+基金全市场代码表（约 7400 条），用于批量行情查询。

```python
with THSClient("账号", "密码") as client:
    client.connect()
    # 拉取全市场代码表（MAIN 单请求）
    stocks = client.stock_list()  # [{code:"600000", name:""}, ...]
    print(f"共 {len(stocks)} 只")

    # 拿到代码后批量查行情
    codes = [s["code"] for s in stocks if s["code"].startswith("6")][:50]
    recs = client.list_quotes(codes, market=17)
```

**机制**：在 `main.123ths.com`（旧 passport 缺失时回退 `ifindhq.123ths.com`）
的已登录 MAIN 连接上发送一个
`DataType=[5],[55]` 空代码组请求，触发服务器返回全量 hd3.1 代码表。
线上报文共 147 字节；逐帧 A/B 已确认旧抓包序列的其余 153 帧均不需要。
服务器角色、权限和完整最小请求见
[行情服务器矩阵](docs/architecture/SERVER_MATRIX.md)。

⚠️ **限制**：
- 默认 `with_names=False` 时 `name` 恒为 `""`；`stock_list(with_names=True)` 会自动
  从 123ths 名称同步接口填充名称（全平台纯网络，无需安装同花顺客户端）
- 覆盖全市场（沪 600/601/603/688 + 深 + 北交所 870-875/920 + 新三板 830-839 + 基金 430/400）
- 非交易日也可用（实测周日正常拉取代码表）

### 带本地缓存的代码表（`stock_list_cached`）

`stock_list()` 每次都要从 MAIN 拉取代码表。如果一天内要多次用全量代码表，
用缓存版：当天首次走网络拉取并写盘，之后直接读缓存（~瞬时），跨自然日自动失效。

```python
with THSClient("账号", "密码") as client:
    client.connect()

    # 当天首次：走网络拉取（~6s）+ 写盘 ~/.ths_stock_codes.json
    stocks = client.stock_list_cached()
    # 当天再次：直接读缓存（<0.1s，不发网络请求）
    stocks = client.stock_list_cached()

    # 强制刷新（忽略缓存重新拉取）
    stocks = client.stock_list_cached(refresh=True)
```

返回的每项含派生的 `market` 字段（沪=17/深=33），可直接按市场分流喂给 `list_quotes`：

```python
# market 字段按代码前缀派生（17=沪市A股, 33=深市A股, None=北交所/基金等）
from thspypc import market_from_code
sh = [s["code"] for s in stocks if s["market"] == 17]   # 沪市，直接喂 list_quotes(market=17)
sz = [s["code"] for s in stocks if s["market"] == 33]   # 深市，直接喂 list_quotes(market=33)
```

**缓存细节**：
- 路径 `~/.ths_stock_codes.json`（见 `default_stock_cache_path`），JSON 格式
- 缓存格式带 `version` 字段；旧格式会被忽略并自动全量刷新
- 失效口径：**按自然日**——写入的日期与查询日不同即失效（隔夜自动刷新）
- 仅在拉取到有效结果（非空且名称覆盖足够）时写盘，避免失败拉取被缓存一整天
- 缓存与账号无关（全市场代码表共享一个文件），换账号无需清缓存
- Level2 账号会额外从 `SH_L2`（shlv2）拉取北交所 `151()` 代码表，合并后
  `920xxx` / `43xxxx` / `83xxxx` / `87xxxx` 等北交所代码会带名称

底层缓存函数（无需登录即可独立使用）：`save_stock_codes` / `load_stock_codes` /
`is_stock_cache_expired` / `market_from_code` / `default_stock_cache_path`。

### Passport64 生成 + login 帧校验

> 完整字节级逆向见 [`docs/handoffs/HANDOFF_LOGIN_PROTOCOL_20260810.md`](docs/handoffs/HANDOFF_LOGIN_PROTOCOL_20260810.md)。

`build_passport64` 自动从服务端返回的 `passport_bytes`（54 字段）里**过滤掉 10 个路由
字段**（M_hq/M_hqdns/M_wg/M_zx/UpdateSvr/download/Foss_url/DownloadSelfStock/
UploadSelfStock/signlength），保留含 sk/sv 的 **44 个身份/会话字段**（~2320 字符）。
44 字段集和 hexin 抓包完全一致（2026-08-10 逐字段值对比确认）。

`build_login_body`（`features/auth_protocol.py`）动态写入两字节小端长度：
`suffix = uint16_le(len(fixed) + len(Passport64) + 1)`。过去所谓 K 只是
`(len(Passport64)+1)&0xff`，不是版本或票据常量。

**当前协议要点**（2026-08-17 历史抓包 + 活网闭环）：
- raw Passport64 前两字节动态声明完整 raw 长度；后三字节为 PC `06 80 00`
- passport 尾部是 `\r\n\x00`，HTTP passport 的尾随 `|` 产生的空段必须过滤
- login suffix 是完整 16 位 wire-tail 长度，不存在 K 或固定高字节
- 新增 `LoginIdentity.L2`：L2 push 通道（shlv2/szlv2）用无 UserName 的 7 字段壳
- 当前 2296 字符票据自然得到 STANDARD=`C4 09`、L2/BOARD=`A2 09`

官方新鉴权样本中唯一 STANDARD 连接发往 shlv2，但目前样本不足，生产 MAIN 路由
暂不因此修改。长度生成算法已经动态化，不再需要维护 account_type/K 配对表。

> **sk/sv 必须保留**：thspypc 的 head128（移植自 thspy Mac 版 `signature_to_nibbles`）
> 没有把 sk/sv 编码进 signature，必须保留 sk/sv 明文字段作为补偿。

`THSClient.connect()`（账号密码 HTTP 鉴权）已内置，直接可用，无需抓包。
`connect_with_passport64()` 仍保留，用于直接传入外部 Passport64（如抓包调试）。

诊断工具：
- `tests/capture_login_compare.py`（抓 hexin 8901 login 帧 4 维度对比）
- `tests/verify_all_logins.py`（全 7 类服务器登录冒烟验证）
- `tests/verify_order_details_online.py`（L2 4214 挂单撤单端到端）
- `thspypc.testing.latest_trade_date()`（盘后/周末也能返回最近交易日，供 `board_timeline`
  等需要明确日期的查询用）

`latest_trade_date()` 的交易日历数据源按优先级自动选择：
1. **a-trade-calendar 包**（`pip install a-trade-calendar`，纯本地 CSV，含法定节假日，
   数据覆盖 2005-2027，import 时自动联网更新）。**可选依赖**——thspypc 不强制安装。
2. **深交所官网 API**（`szse.cn`，运行时联网，按月缓存）。a-trade-calendar 未安装时自动使用。
3. **跳周末**（不识别节假日）。前两者都不可用时兜底。

> `latest_trade_date()` 有 9:15 分界（交易日 9:15 后返回当天，9:15 前/周末/节假日返回
> 上一个交易日），a-trade-calendar 自带的 `get_latest_trade_date()` 没有这个分界。

### 解码链（纯 Python，无 unicorn 依赖）

hd3.1 批量响应（≥6 股）的解码链，移植自 hexin.exe 真实机器码（与 Unicorn 逐字节对照验证）：

```
hd3.1\0 + 头(10B) + 字段表(fc×4) + preamble(4B) + BitRLE 流
  → _decode_bitrle_0x13746d0 (BitRLE 解码)     → dc×hs 字节位平面
  → _transpose_bitplane_0x1763410 (位平面转置)  → dc 条行主序记录
  → _parse_hd_records (按字段表切分)            → {code, dt<N>...}
```

≤5 股走 hd1.0 明文格式（`parse_hd1_response`）。离线回归测试（无需账号）：

```bash
uv run python tests/test_list_quotes.py --offline
# 用 thspy 抓包真值验证解码链（s27_resp_hex.txt，6/6 BitRLE 帧解码成功）
```

## 自定义板块/自选股管理（`blocks`）

登录后（`connect()` 自动初始化板块功能）即可管理自定义分组和自选股。走标准
HTTPS（cookie 鉴权，`ugc.10jqka.com.cn` API），与行情 TCP 协议独立。

```python
with THSClient("账号", "密码") as client:
    client.connect()
    # 列出所有分组
    for g in client.list_groups():
        print(f"{g.name} ({len(g.items)}只)")
    # 我的自选
    sg = client.get_self_stocks()
    print([item.code for item in sg.items])
    # 增删股票
    client.add_stock("我的分组", ["600000", "000001"])
    client.remove_stock("我的分组", ["600000"])
    # 动态板块（选股表达式）
    codes = client.query_dynamic_plate("涨跌幅>5%")
```

门面方法：`list_groups / get_group / add_group / delete_group / share_group /
add_stock / remove_stock / get_self_stocks / query_dynamic_plate / list_dynamic_plates`。
高级用法可用 `client.blocks` 直接访问 `BlockManager`。

## 短线精灵（异动，`dxjl_*`）

登录 8901 后懒连 9601，查个股异动（大笔买卖/涨跌停/封板等）。盘中（9:25-15:00）
有数据，非交易时段返回空列表。

```python
with THSClient("账号", "密码") as client:
    client.connect()
    # 最新一页异动（沪深，按时间倒序）
    for r in client.dxjl_latest():
        print(f"{r['代码']} {r['异动类型']} 金额={r['金额']} 涨跌幅={r['涨跌幅']}%")
    # 翻页历史（5 页）
    history = client.dxjl_history(pages=5)
```

每条记录：`时间`(微秒戳) / `市场`(32深 16沪) / `代码` / `异动类型`(中文) /
`异动编码` / `金额` / `涨跌幅`。普通账号和 Level2 的可选异动集合不同；
`STANDARD_REALORDER_CATEGORY_IDS` 是普通账号 23 类，
`ALL_REALORDER_CATEGORY_IDS` 是 Level2 全选抓到的 53 类。

### 自定义异动过滤（`datatype`）

短线精灵的 `datatype` 参数控制查哪些异动类型 + 阈值。默认 `DXJL_DATATYPE` 只查
大笔买卖 + 打开涨跌停。要查其他类型（如特大主动买卖），用 `build_datatype` 生成表达式：

```python
from thspypc import build_datatype, build_qurealorder_query

# 只查特大主动买卖（0xbc/0xbe），手数≥2千 OR 金额≥50万
dt = build_datatype([0xbc, 0xbe], volume_min=2000, amount_min=500000)
# 普通账号 UI 支持的全部 23 类
dt_standard = build_datatype("standard")
# Level2 UI “全选”抓到的 53 类；普通账号不要发送这一组
dt_all = build_datatype("all")

# 通过底层 API 传入（dxjl_page/dxjl_latest 目前用固定 DXJL_DATATYPE，
# 如需自定义，直接调 build_qurealorder_query + parse_qurealorder_response）
```

类别 ID 规则：`组前缀 | 异动字节`（见 `ANOMALY_GROUP_PREFIX`）。字段19=成交手数(手)，
字段17=成交金额(元)，`|`=OR。完整规则见
[`docs/handoffs/HANDOFF.md`](docs/handoffs/HANDOFF.md) §1.4。

### 实时推送（`subscribe_realtime` + `receive_pushes`）

订阅异动推送后，服务器在盘中主动推送 pushrealorder 帧（实测约 1500 条异动/分钟）：

```python
client.connect()
client.subscribe_realtime()              # 9601 订阅 market=16/32/151/48
client.receive_pushes(timeout=60, callback=lambda r: print(r["代码"]))
```

订阅用 9601 的 `method=subrealorder`（按数字市场代码 16=沪/32=深/151=北交所/48=板块
订阅，抓包确认 hexin 同协议）。推送帧 `pushrealorder` 由服务器主动 S→C 下发，
解析器提取股票代码（格式 A `!+代码` / 格式 B `-+长度+代码`），数值字段保留
`raw_bytes` 待逆向。实测盘中 20 秒收到 507 条异动（2026-07-17）。

## 心跳保活（自动）

`connect()` 成功后自动启动后台心跳线程，维持 8901/9601 长连接，`disconnect()` 自动停止。
无需手动管理——调用方完全无感知。

| 端口 | 心跳间隔 | 作用 |
|------|---------|------|
| 8901 | 每 3 秒 | 维持行情连接（内容：时间戳 + 流量统计 `tsi/tr/tc`） |
| 9601 | 每 30 秒 | 维持短线精灵连接（连接后自动覆盖） |

心跳协议（2026-07-17 抓包确认）：8901 心跳是 `cmd=0x09` + subtype `12 00 03 00` 的
状态帧（含 hex 时间戳和本机 IP）；9601 心跳是 5 字节极简帧。线程是 daemon，主进程
退出时自动结束；socket send 加锁避免与查询交错。

实测：connect → 静置 10 秒（发 3 次心跳）→ 再次 list_quotes 成功（连接未被断开）。

```python
with THSClient("账号", "密码") as client:
    client.connect()
    # 心跳后台自动运行，可随时查询
    time.sleep(60)  # 静置 1 分钟
    client.list_quotes(["600056"])  # ✓ 仍可用（心跳维持了连接）
```

## 集合竞价（`auction`）

查 9:15-9:25 集合竞价的逐 tick 撮合数据（虚拟开盘价/累计量/买卖未匹配量）。
普通账号当天使用 MAIN `pageid=9354/period=7176`，历史日使用
`pageid=9355/period=6144`；Level2 账号保留 4214 路径。

```python
from datetime import date
records = client.auction("603118", trade_date=date(2026, 7, 27))
# records[0] = {"time": datetime(2026,7,27,9,15,1), "dt10": 14.19, "dt49": 600.0,
#               "dt27": None, "dt33": 11500.0}
```

沪深指数仍使用同一个入口，但底层改走 `pageid=6240` 的 `T_URL` JSON 接口，
并且只提供当前交易日：

```python
index_records = client.auction("1A0001")  # 399001/399006 同形，市场码自动推断
# index_records[-1] = {
#     "time": datetime(...), "dt10": 3962.208523,
#     "newprice": 3962.208523, "lead_price": 3965.410889,
#     "leadprice": 3965.410889, "volume": 107894820,
#     "auction_type": "opening",
# }
```

同花顺 PC 客户端在竞价时段约每 10 秒重新请求一次 `T_URL` 后重绘曲线；这不是
主动推送。`client.auction()` 只执行一次查询并返回当前已有的全部点，需要实时追踪
时可由调用方按约 10 秒周期重复调用，并按 `markettime` 去重。

### 五字段语义（全部已确定，六股 × thsdk oracle 全量验证）

| 字段 | 含义 | 单位 | 验证状态 |
|------|------|------|---------|
| `time` (dt1) | unix 时间戳 | 秒 | ✅ 六股 ±2s 全命中 |
| `dt10` | 集合竞价撮合价 | 元 | ✅ 六股 100% 精确 |
| `dt49` | 累计竞价成交量 | 股（÷100=手）| ✅ 六股 100% 命中 |
| `dt27` | **买方**未匹配委托量 = thsdk buy2 | 股 | ✅ 六股 ~100% 命中 |
| `dt33` | **卖方**未匹配委托量 = thsdk sell2 | 股 | ✅ 六股 ~100% 命中 |

`dt27` / `dt33` 的「无值」哨兵（`0x80000000`）归一化为 `None`，与真实 `0.0` 区分。
集合竞价撮合时被动方总被吃光，故每条 tick 恰好一侧为 `None`。

### ⚠ dt 号跨接口语义不同（极易混淆）

同一 dt 号在不同接口含义完全不同——dt 号是协议槽位号，语义由字段表定义：

| dt 号 | 竞价（本接口）| 分时（`timeline`）| `list_quotes` |
|------|--------------|------------------|---------------|
| dt27 | 买方未匹配量 | — | — |
| dt33 | **卖方未匹配量** | **成交额** | **注册制上市日** |

**不要把竞价的 `dt33`（卖方未匹配量）和分时的 `dt33`（成交额）混为一谈。**

### 沪市响应的两层算法（逆向难点，已破解）

沪市 `auction()` 的原始响应走 `cmd=0x0a` 外层压缩，不是明文：

```
网络原始字节（cmd=0x0a 压缩流）
  → normalize_8901_response()：解开自研 LZ77 变体（位控制字 + 64K 哈希字典）
  → hd1.0 固定头 + 字段表 + 定长记录区（5 字段 × 4B = 20B/行）
  → parse_auction_response()：按字段表解码
```

**99% 的逆向难度在外层 LZ**：它自研无格式签名、控制位序非标准、用非标准哈希函数。
早期会话曾把外层压缩的字典引用表象误判为"内层参数化变长编码"，走了大量弯路。
外层算法移植自 hexin.exe RVA `0xf74260`（Unicorn 模拟逐字节对照纯 Python），
详见
[`docs/handoffs/HANDOFF_SUPERORDER_20260726.md`](docs/handoffs/HANDOFF_SUPERORDER_20260726.md)
第十七~二十章。
后续逆向建议先阅读[同花顺协议逆向方法论与实战复盘](docs/guides/THS_REVERSE_ENGINEERING_PLAYBOOK.md)，
其中总结了本次分层判定、语料设计、DMP 加载映像重建、Unicorn 原生 oracle 和
回归验收方法。

深市响应格式与沪市**同构**。普通账号历史竞价返回 9355 伴随表，解析器会从
组合响应中选择 9:15-9:25 段。

尾盘集合竞价使用独立方法：

```python
closing = client.closing_auction("603118", trade_date=date(2026, 7, 29))
whole_day = client.intraday("603118", trade_date=date(2026, 7, 29))
# whole_day 每条记录有 phase:
# opening_auction / continuous / closing_auction
```

尾盘协议为 `period=7424`，字段为时间、价格、累计量和伴随字段；它与早盘
买卖未匹配量字段集不同，因此底层保持独立解析，高层由 `intraday()` 合并显示。
普通账号使用 MAIN 9354/9355；Level2 账号严格使用对应市场连接，当天用 4214、
历史日用 4417，并先完成该股票的订阅注册，不会回退或混用普通账号请求。
Level2 历史尾盘（pageid=4417）已端到端打通：fresh login 重放即可拿到
`603118 / 2026-07-24` 的 61 个 14:57:00–15:00:00 尾盘点（价 15.79→15.77），
沪深多股活网回归通过（603118/688981/601318=61 点；600519/600276 因首tick
无成交为 60 点）。早期"独立客户端只收到空 ACK"是解析器假象——服务器一直正常
返回 `hd1.0` 帧，但该帧最后一条记录被服务器截断 1 字节，旧 `_decode_closing_rows`
遇到末条不完整会丢弃全部已解记录；修复为容错补零 + 越界停止后即解出全部点。
无需复刻 `verify3/pwd_login` SID 链路（详见 HANDOFF §7.6）。
深市历史尾盘同样已打通：请求参数与沪市同构（`33(000001,)` + `10,49,287`
+ `7424` + `4417`），但深市连 szlv2 节点、tick 间隔 9 秒（≈20-21 点，
沪市为 3 秒 ≈61 点）。早期"深市返回 ServerCost 拒绝"是探测脚本收帧 bug，
真实数据帧一直能解出。

## 安装

```bash
uv sync
# 二维码登录额外需要（终端渲染，非必需）：
uv pip install qrcode
```

可选原生解压加速：`_compression_native`（stable-ABI C 扩展，仅加速
BitRLE 解码与位平面转置两个纯函数）由 `.github/workflows/wheels.yml`
跨平台构建；仓内附 Windows 预编译 `.pyd`，未编译平台自动回退纯 Python，
一致性由 `tests/test_native_compression.py` 契约测试保证。

## 看盘前端

仓库自带一套 React 看盘前端（`web/`，vite + echarts），由 `thspypc.server`
（默认 `127.0.0.1:8765`）提供数据，三个视图经顶栏或 URL `?view=` 切换：

- **看盘**：三栏布局——左栏（同花顺板块涨幅/涨速/主力榜、自定义板块/自选股、
  全市场搜索与排序榜）、中栏（分时·大单金额 + 日K/分钟K，含均线开关、
  前后复权、缩放范围按周期记忆、分钟K真实日期轴与日分隔线）、右栏
  （个股概览 + 五档盘口、短线精灵实时流）。看盘页常驻保活：切到分时/
  超级盘口再切回即时恢复，K 线缩放状态不丢。
- **分时**：当日分时（含竞价三阶段）、光标时刻十档、逐笔成交明细
  （7169 回放 + WS 实时推送合并去重）。
- **超级盘口**：沪深（Level2）为 4096 盘口回放曲线 + 光标十档快照 +
  买一/卖一委托队列 + 逐笔/挂单/撤单明细，实时模式跟随最新；
  **北交所**为官方形态——当日全日逐笔（每行含五档快照，点选任意逐笔
  查看当时盘口）+ 历史日竞价段（09:15-09:25）逐笔，十档/队列无通道。

接口概览（全部在 `/api/` 前缀下，单用户无鉴权）：

| 分组 | 端点 |
|------|------|
| 行情 | `quote` / `quotes_ext` / `depth/{code}` / `stocks2` |
| K线·分时 | `kline/{code}` / `timeline` / `history_timeline` / `auction` / `closing_auction` / `intraday` / `market_view(_fast)` |
| 超级盘口 | `superorder/{code}`（7169/BSE 竞价窗）/ `superorder-bse/{code}`（BSE 全日+五档）/ `superorder-replay*`（4096）/ `superorder-window` / `order-queues` / `order-details` |
| 榜单·板块 | `stock_list_ranked` / `dde_rank` / `boards*` / `hot_boards` |
| 自选·异动 | `groups*` / `self_stocks` / `dynamic_plate*` / `dxjl*` |
| 实时流 (WS) | `stock-stream/{code}`（逐笔/十档/队列）、`dxjl/stream`（短线精灵） |

盘中轮询按交易时段自动降频（竞价/连续/盘后不同周期），页面隐藏或休市时
跳过；前端对各接口带 TTL 缓存与在途去重，避免快速切股时打爆通道。

### 一键启动

仓库根目录提供两个启动脚本：

```bash
dev.bat   # Windows cmd
./dev.sh  # macOS / Linux / Git Bash
```

两者行为对齐：

- 检查 Python 3.14 与后端依赖、pnpm 与 `web/node_modules`；
- 若 8765 端口已有旧后端，自动停止后重启；
- 分别打开后端和前端两个终端窗口，日志分离；
- `--backend` / `--frontend` 可只启动一侧，`--check` 只检查依赖。

`dev.sh` 在 macOS 上使用 Terminal 窗口，Windows Git Bash 使用 cmd 窗口，
无图形终端时回退到 `.dev-logs/` 日志文件。

首次启动会自动：

- `pnpm install`（如缺少 `web/node_modules`）；
- 全量拉取股票代码表并写入 `~/.ths_stock_codes.json`（自然日缓存）；
- 从 `cloud.10jqka.com.cn` 下载系统板块 ZIP 到 `~/.thspypc/blockupdate`
  （之后每日在后台检查更新）。

## 项目结构

```
thspypc/
├── pyproject.toml
├── dev.bat / dev.sh          # 看盘前后端一键启动
├── docs/                     # 手册/架构/路线图/调查/交接文档（见 docs/README.md）
├── src/thspypc/
│   ├── __init__.py             # 包入口
│   ├── client.py               # THSClient 公开门面与旧调用兼容
│   ├── _client/                # 连接原语、服务门面、股票代码缓存
│   ├── _transport/             # 按角色管理的 socket、会话和请求锁
│   │                            #  （MAIN / SH_L2 / SZ_L2 / BSE_MAIN / REALORDER）
│   ├── codecs/                 # 帧、压缩（含可选 C 加速）、hd1/hd3、数值编码
│   ├── features/               # 各业务纯协议 builder/parser
│   ├── services/               # 能力校验、连接选择与完整业务工作流
│   ├── protocol.py             # 历史 API 兼容导出 + HTTP 鉴权/主机解析
│   ├── transport.py            # 旧 transport API 兼容导出
│   ├── blocks.py               # 自定义板块/自选股管理（HTTPS）
│   ├── qr_login.py             # 二维码扫码登录 + 凭证缓存
│   ├── parse_hfd1.py           # hfd1.0 名称锚点解析
│   ├── testing.py              # 测试/诊断脚本并发登录与客户端复用 helper
│   └── server/                 # FastAPI 单用户 REST + WebSocket 接口
├── web/                       # React 看盘前端（vite + echarts）
└── tests/
    ├── test_*.py               # pytest 离线/在线回归
    ├── verify_*.py             # 活网验证脚本
    ├── capture_*.py            # 抓包工具
    ├── probe_*/analyze_*/_*    # 一次性逆向与诊断脚本
    ├── archive/                # 已完成使命的历史诊断脚本
    ├── fixtures/               # 脱敏协议样本（金样本回归）
    └── native/                 # 逆向辅助 C/C++ harness
```

## 已知限制
文档目录：[docs/README.md](docs/README.md)，按「手册指南 / 架构解析 / 规划路线图 / 调查记录 / 交接记录」分类。

- hd3.1 变体（unk=0x36/0x42/0x4a 等非 BitRLE 编码）暂不支持，`parse_hd3_response`
  自动跳过。
- hq1.0 字段表 TLV 格式未破解（字段表签名跨帧固定但 TLV 切分方式未对齐）。
  当前推送帧的数值解码通过**异动字节锚定 + THS float 扫描**绕过，已知类别名
  按抓包和官方客户端配置匹配（金额/涨幅 100% 精确）。解出 TLV 能实现通用 schema 驱动解析，但
  实际收益有限（需 Ghidra 逆向 hexin.exe）。
- A 股名称的 `name_16_16` 块状编码已解：走 `0x001c StockNameVer` 网络全量同步
  填充名称（纯网络跨平台，**无需安装同花顺客户端**；按服务器分组并发登录拉取）。
- **北交所通道边界**（2026-09-08 活网+抓包确认）：无十档回放/委托队列/挂撤单
  明细等沪深式 L2 通道；当日超级盘口 = 全日逐笔+五档（4096 全日窗），历史日期
  官方无超级盘口页、仅 6144 竞价段（09:15-09:25）逐笔；7176 只服务竞价窗，
  连续竞价时段窗口无响应。北交所请求必须走 main.123ths.com 组的 `BSE_MAIN`
  车道，且 init MarketDate 需含 `32(0)`。
- 全市场快照 `market_snapshot()`（hfd1.0）只覆盖沪市，深市不支持；
  用 `market_snapshot_with_quotes()`（stock_list + list_quotes 混合方案）覆盖全市场。
- 终端 ASCII 二维码可能因字体宽高比扫不了，用 `qr_login.png` 图片扫更可靠。
- passport 的 signdate/signvalid 用本地时间，和服务器时区可能差 1 小时（不影响登录）。
- VerifyCode=-1 有**两种**（2026-07-23）：
  - **A. login 帧内容错误**（已修复）：check 字节硬编码 / sk/sv 缺失。正常使用不再触发。
  - **B. 同 IP 短时间重复 login 的会话冲突**：level2 账号同一时刻只允许一个活跃会话。
    **对相同 IP 短时间重复 login** 会触发服务器 -1 保护（实测：反复 connect 同一批 IP
    几次即触发；IP 充分分散则不触发——`test_repeated_connect.py` 验证 interval=0 连 5 次
    不同 IP 全部成功）。**这不是账号封禁**——同花顺客户端用同账号始终能登录。thspypc
    的 IP 轮换（`_login_rr_offset`）让每次 login 打不同 IP，规避此问题；连续 5 个 -1
    提前返回 `error="session_conflict"`。
  - 仍建议长连接复用（connect 一次反复查），但反复 connect 在 IP 分散时也安全。
  - 确保同花顺客户端已退出（同账号不能两个客户端同时在线）。
- **L2 连接的 Passport64 时效**：同一票据被重复用于新 TCP 登录时，服务端可能返回
  “登录通行证有被修改的痕迹”。这不是 `signvalid` 到期，而是会话级重复登录保护。
  `_open_manual_push_connection` 是保留的兼容方法名；生产路径已按抓包使用
  `thsuser` 标准行情登录壳，并在检测到票据失效后立即重新 HTTP 鉴权。

## 连接治理（长连接复用 + 防 -1）

`THSClient` 复刻 hexin 客户端的长连接模式——**一条连接反复查询**（hexin 抓包零 FIN）：

- **建议**：`connect()` 成功后保持长连接反复查询。反复 connect 在 IP 分散时也安全
  （IP 轮换保证），但长连接仍是推荐用法（hexin 抓包零 FIN）。
- `connect()` 冷却复用：连接还活着时重复调用自动复用（冷却期内不重新 login，
  `error="reused_existing_connection"`）。
- `is_connected` 属性：探测 8901 主连接是否仍活着（MSG_PEEK 非阻塞）。
- `ensure_connected()` 方法：查询前健康检查，连接断了返回 False（不自动重连）。
- `enable_heartbeat=True`（默认）：后台心跳维持长连接（8901 每 3s、9601 每 30s）。

**测速缓存 + IP 轮换**（规避同 IP 重复 login 的 -1）：
- 测速结果在进程内缓存 5 分钟（`_PROBE_CACHE_TTL`），反复 connect 不重复测速。
- login 从测速排序的 IP 池里**轮换取 7 个**（`_login_rr_offset` 每次推进），让每次
  login 打不同 IP。实测：反复 connect 5 次（interval=0）连 5 个不同 IP 全部成功
  （`test_repeated_connect.py`），IP 轮换有效规避同 IP 重复 login 的 -1。
- 测速纯 TCP 握手不发 login，**不触发 -1**——可以放心跑（`_probe_fastest_hosts`）。

## 服务器 IP 动态获取 + 测速选最优

thspypc 不硬编码服务器 IP——HTTP 鉴权返回的 passport 里有 `M_hqdns` 字段
（域名列表）。A 股 MAIN 连接优先解析普通客户端实际使用的
`main.123ths.com`；旧 passport 缺少该域名时回退到已验证的
`ifindhq.123ths.com`。`fu4`、`hkus`、`euhq` 等条目不混入 MAIN。L2 连接分别解析
`shlv2.123ths.com` / `szlv2.123ths.com`。硬编码的 `MARKET_HOSTS` 仅作 MAIN DNS
解析失败时的回退。

拿到当前 MAIN IP 后，`connect()` 会并发 TCP 握手测延迟，再从排序后的
IP 池轮换选择最多 7 个 login。测速缓存只在缓存 IP 仍属于当前 DNS 候选时复用，
避免旧域名分组或过期 DNS 结果重新混入 MAIN。纯 TCP 握手不发 login，不触发
VerifyCode=-1。

## L2 分服 init

MAIN 普通登录连接在 `VerifyCode=0` 后发送标准 MAIN init，收到服务器配置帧后
才进入 ready；MAIN 不发送 L2 市场初始化流程。

带市场配置的 init 属于 L2 市场通道：

- 沪市：连接 `shlv2`，发送 `MarketCode=16;144;`
- 深市：连接 `szlv2`，发送 `MarketCode=32;`

`stock_list()` 复用 MAIN，并且不发送 L2 init。它只发送一个最小
`DataType=[5],[55]` 请求；详细路由见
[行情服务器矩阵](docs/architecture/SERVER_MATRIX.md)。

修正后的活网 A/B 验证共 4 轮：关闭心跳 2 轮、开启心跳 2 轮，四轮均完成登录、
立即查询和等待后二次查询；开启心跳的两轮各发送 2 次心跳后连接仍正常。

## License

MIT
