# thspypc — 同花顺 Windows PC 远航版行情协议纯 Python 实现

模仿 [thspy](https://github.com/djj45/thspy)（Mac 版逆向）的登录实现，改成 **Windows PC 远航版协议**，连 **8901** 端口。**已实测登录成功（VerifyCode=0），含 Level2 账号。行情查询已打通（个股列表实时行情）。**

> 本项目源自对真实 hexin.exe（PC 远航版）的抓包分析。协议参考见 `D:\code\ths_takehome\ths\PROTOCOL.md`。

## ✅ 已实现

- HTTP 三步鉴权（RSA 公钥 → unified_login → mainverify）
- head128 + passport64 构造（PC 版 ACCOUNT_TYPE 前缀）
- PC 远航版 login 帧构造（8901 端口）+ **login 后自动 init 握手**激活行情通道
- **M_hqdns 动态域名解析**：从 passport 解析服务器域名 → DNS 查询拿最新 IP（不硬编码）
- 多 IP 冗余连接 + 失败诊断
- **设备指纹全自动生成**：`generate_imei()` + `generate_mac64()`（算法已逆向，无需抓包）
- **二维码扫码登录**：终端显示二维码，手机同花顺扫码即登录（无需账号密码）
- **30天免登录凭证缓存**：扫码一次，30天内重启免扫码秒登录
- **实测**：Level2 账号成功登录 8901，拿到带 level2/sid 权限的 passport
- **个股列表行情查询**（`list_quotes`）：hd1.0/hd3.1 响应解析，纯 Python 移植
  hexin.exe 真实机器码（BitRLE 解码 + 位平面转置），无 unicorn 依赖。实测解出
  600056 等股票的 现价/昨收/开盘/涨幅/竞价金额
- **全市场股票列表**（`stock_list`）：重放 hexin 启动序列，~6 秒拿全市场 7400+ 代码
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
  全部解码（异动字节锚定 + THS float，30 种异动全覆盖，历史对照 100% 精确）。
- **K线查询**（`kline`）：日/周/月/5分/15分/30分/60分K线，hd3.1 flag=0x0042/0x0046
  响应解析，连接复用（一次 connect 查多只多周期）。
- **沪深 L2 分时查询**（`timeline`）：当日逐点分时（现价/量/额/均价，241 根），
  level2 账号走 pageid=4214 推送通道，hd3.1 flag=0x00b4 响应解析。
  ★ **沪深分服**：shlv2（沪）/szlv2（深）是两套独立 L2 服务器（IP 0 重叠），
  按股票市场选对应 IP + 配套 init MarketCode（沪 16;144 / 深 32）。
  ★ **后台预热**：首次建好某市连接后异步预热另一市，跨市切换 0.44s（复刻 hexin 秒加载）。

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
| 4 | head128 ACCOUNT_TYPE | `44 04 2d 80 00` | `be 06 06 80 00` | head128 校验失败（-300:） |

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

> 封单额/首次涨停时间/主力净额 → 从推送帧本地计算，不走列表请求。

## 全市场股票列表（`stock_list`）

获取沪深+北交所+新三板+基金全市场代码表（约 7400 条），用于批量行情查询。

```python
with THSClient("账号", "密码") as client:
    client.connect()
    # 拉取全市场代码表（重放 hexin 启动序列，~6 秒）
    stocks = client.stock_list()  # [{code:"600000", name:""}, ...]
    print(f"共 {len(stocks)} 只")

    # 拿到代码后批量查行情
    codes = [s["code"] for s in stocks if s["code"].startswith("6")][:50]
    recs = client.list_quotes(codes, market=17)
```

**机制**：重放 hexin 启动序列的关键请求段（subreal×8 + 特殊 CodeList 订阅 + init），
触发服务器在登录连接上推送 dc≈7422 的全量 hd3.1 帧（unk=0x18 BitRLE 编码）。
重放模板固化在 `src/thspypc/data/stock_list_replay.bin`（提取自 cold_start.pcap）。

⚠️ **限制**：
- 默认 `with_names=False` 时 `name` 恒为 `""`；`stock_list(with_names=True)` 会自动
  从同花顺本地缓存填充名称（需安装同花顺 PC 客户端）
- 覆盖全市场（沪 600/601/603/688 + 深 + 北交所 870-875/920 + 新三板 830-839 + 基金 430/400）
- 非交易日也可用（实测周日正常拉取代码表）

### 带本地缓存的代码表（`stock_list_cached`）

`stock_list()` 每次都要重放启动序列拉取（~6 秒）。如果一天内要多次用全量代码表，
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
- 失效口径：**按自然日**——写入的日期与查询日不同即失效（隔夜自动刷新）
- 仅在拉取到有效结果（非空）时写盘，避免失败拉取被缓存一整天
- 缓存与账号无关（全市场代码表共享一个文件），换账号无需清缓存

底层缓存函数（无需登录即可独立使用）：`save_stock_codes` / `load_stock_codes` /
`is_stock_cache_expired` / `market_from_code` / `default_stock_cache_path`。

### Passport64 生成 + login 帧校验（已复刻 hexin，无需抓包）

`build_passport64` 自动从服务端返回的 `passport_bytes`（53 字段）里**过滤掉 10 个路由
字段**（M_hq/M_hqdns/M_wg/M_zx/UpdateSvr/download/Foss_url/DownloadSelfStock/
UploadSelfStock/signlength），保留含 sk/sv 的 **43 个身份/会话字段**（2304 字符）。

`build_login_body_pc` 的帧头校验字节**动态计算**（非固定值）：
`check = (固定文本长度 + 1) & 0xFF`，其中固定文本 = `Ask=login\n...Passport64=`。

> **login 失败的两个独立根因**（2026-07-23 完整逆向 + 三变体实测）：
> - **0 字节 FIN**：校验字节错（曾硬编码 0xaa）。修为动态计算后解决。
> - **PromptText=-6**：sk/sv 被误过滤。抓包显示 hexin 不发 sk/sv 明文，但它的 head128
>   把 sk/sv 编码进了 signature；thspypc 的 head128（移植自 thspy Mac 版）没这能力，
>   故**必须保留 sk/sv 明文字段**。回退过滤到 10 字段后解决。
> - 两者都修后 VerifyCode=0，cli_ticker 活网验证通过。

`THSClient.connect()`（账号密码 HTTP 鉴权）已内置，直接可用，无需抓包。
`connect_with_passport64()` 仍保留，用于直接传入外部 Passport64（如抓包调试）。

诊断工具：
- `tests/capture_login_compare.py`（抓 hexin 8901 login 帧 4 维度对比）
- `tests/compare_login_frame_bytes.py`（逐字节对比，定位校验字节差异）
- `tests/test_passport_variants.py`（三变体实测字段集，定位 sk/sv 缺失）

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
`异动编码` / `金额` / `涨跌幅`。异动类型见 `ANOMALY_MAP_DXJL`（30 种，抓包确认）。

### 自定义异动过滤（`datatype`）

短线精灵的 `datatype` 参数控制查哪些异动类型 + 阈值。默认 `DXJL_DATATYPE` 只查
大笔买卖 + 打开涨跌停。要查其他类型（如特大主动买卖），用 `build_datatype` 生成表达式：

```python
from thspypc import build_datatype, build_qurealorder_query

# 只查特大主动买卖（0xbc/0xbe），手数≥2千 OR 金额≥50万
dt = build_datatype([0xbc, 0xbe], volume_min=2000, amount_min=500000)
# 查全部已知异动类型（匹配推送帧时推荐）
dt_all = build_datatype("all")

# 通过底层 API 传入（dxjl_page/dxjl_latest 目前用固定 DXJL_DATATYPE，
# 如需自定义，直接调 build_qurealorder_query + parse_qurealorder_response）
```

类别 ID 规则：`组前缀 | 异动字节`（见 `ANOMALY_GROUP_PREFIX`）。字段19=成交手数(手)，
字段17=成交金额(元)，`|`=OR。完整规则见 `HANDOFF.md` §1.4。

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

## 安装

```bash
cd D:\code\ths_takehome\thspypc
uv sync
# 二维码登录额外需要（终端渲染，非必需）：
uv pip install qrcode
```

## 项目结构

```
thspypc/
├── pyproject.toml
├── src/thspypc/
│   ├── __init__.py     # 包入口
│   ├── protocol.py     # 帧编解码 + HTTP 鉴权 + generate_imei/mac64 + 行情查询
│   │                   #   （list_quote）+ 短线精灵（qurealorder）
│   ├── blocks.py       # 自定义板块/自选股管理（HTTPS，移植自 thspy）
│   ├── qr_login.py     # 二维码扫码登录 + 凭证缓存（save/load_credentials）
│   └── client.py       # THSClient：connect() / connect_with_qrcode() / connect_cached()
│                        #   / connect_with_passport64() / list_quotes()
│                        #   / blocks 门面方法 / dxjl_*（短线精灵）
└── tests/
    ├── test_login.py           # 账号密码端到端测试
    ├── test_qr_login.py        # 二维码扫码端到端测试
    ├── test_list_quotes.py     # 个股列表行情测试（--offline 离线 / 默认活网）
    ├── test_blocks.py          # 自定义板块/自选股测试
    ├── test_dxjl.py            # 短线精灵（异动）测试
    ├── test_push.py            # 短线精灵实时推送测试（框架就绪待调试）
    ├── test_heartbeat.py       # 心跳保活测试（静置后连接仍可用）
    ├── diag_fresh_passport.py  # 抓包提取 hexin Passport64 + 行情验证（调试用）
    └── compare_remember.py     # 「30天免登录」勾选/不勾选对比工具
```

## 已知限制

- hd3.1 变体（unk=0x36/0x42/0x4a 等非 BitRLE 编码）暂不支持，`parse_hd3_response`
  自动跳过。
- hq1.0 字段表 TLV 格式未破解（字段表签名跨帧固定但 TLV 切分方式未对齐）。
  当前推送帧的数值解码通过**异动字节锚定 + THS float 扫描**绕过，30 种异动
  全覆盖（金额/涨幅 100% 精确）。解出 TLV 能实现通用 schema 驱动解析，但
  实际收益有限（需 Ghidra 逆向 hexin.exe）。
- upstockname A 股名称的块状编码未解（纯文本段已解），默认走同花顺本地缓存
  填充名称（需安装同花顺 PC 客户端）。
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
- **`__manual` 登录的 Passport64 时效**（分时/推送通道专用）：主连接 login 已"消费"
  Passport64（服务器记录会话），`__manual` 再用同一票据登录会被拒——PromptText
  "我们发现您的登录通行证有被修改的痕迹"。**这不是过期**（signvalid 有效期一周），
  是同一票据被重复用于新登录触发的保护。主连接已建立的不受影响，只有新的
  `__manual` 登录会被拒。`_open_manual_push_connection` 检测到此类 PromptText 会
  **立即重新 `full_http_auth`** 拿新鲜 Passport64 重试（16s→1s），用户无感。

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
（域名列表），`resolve_market_hosts()` 解析这些域名拿到当前可用的 8901 IP
（DNS 轮询，每次可能不同）。hexin 客户端也是这么做的（抓包确认：它并发 DNS 查询
`shlv2.123ths.com`/`szlv2.123ths.com` 等域名拿 IP，按运营商分组）。硬编码的
`MARKET_HOSTS` 仅作 DNS 解析失败时的回退。

拿到 ~70 个 IP 后，`connect()` 会**并发 TCP 握手测延迟**（`_probe_fastest_hosts`），
选最快的 7 个 login——复刻同花顺「测试 IP」功能的机制（抓包确认：同花顺并发 TCP
连多个 IP 测 SYN→SYN-ACK 往返时间，最快 122.9.115.201=28ms）。纯 TCP 握手不发 login，
不触发 VerifyCode=-1。测速整体 ~1s（70 个 IP 并发），login 稳定 ~2s。

## init 握手激活行情通道

login 成功后 `connect()` 自动发 init 请求（`_send_init_handshake`）激活行情查询通道——
不发 init 直接 `list_quotes` 会超时（抓包确认 hexin 每条连接 LOGIN→INIT→行情查询）。

init 响应是**服务器配置帧**（~49KB，含 S-OS/S-Version 等元数据），不是全量代码表
（代码表是 `stock_list()` 重放序列才触发）。实测稳定返回 1 帧，读 1 帧即激活通道，
`list_quotes` 立即可用。

## License

MIT
