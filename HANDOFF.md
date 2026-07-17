# thspypc 开发交接文档

> 会话日期：2026-07-16 ~ 2026-07-17
> 项目路径：`D:\code\ths_takehome\thspypc`
> 参考项目：`D:\code\thspy`（Mac 版逆向，本地）、`D:\code\ths_takehome\ths`（PC 版协议文档）

---

## 一、本次会话完成的功能

### 1. hd3.1 个股列表行情解码（纯 Python，无 unicorn 依赖）

从 thspy 移植了 hd3.1 压缩响应的完整解码链到 thspypc，用纯 Python 替代 Unicorn 模拟：

- **`_decode_bitrle_0x13746d0`**：BitRLE 解码器，忠实翻译 hexin.exe 的 283 条指令决策树
- **`_transpose_bitplane_0x1763410`**：位平面转置，LSB-first 列主序读取
- **`parse_hd3_response` / `parse_hd1_response`**：≥6 股走 hd3.1，≤5 股走 hd1.0
- **`decode_ths_float`**：THS 定点浮点解码（bit31=除法, bit30-28=指数, bit27=符号, bit26-0=尾数）
- **`build_list_quote_query`**：行情请求构造（单子帧 cmd=0x09，hdr[19:21]=文本长度+1）

**关键发现**：
- BitRLE 决策树中 `0x137485b` 处有一次**无条件 emit bl**（容易遗漏，是解码正确的关键）
- 位平面转置用 **LSB-first** 读取（`bl & src`，不是 `edi & 0x80` MSB-first）
- 请求帧每帧尾随 `\n`（抓包确认 hexin 每帧都有 trailing 0x0a）

**实测**：`list_quotes(['600056',...])` 解出 5 条实时行情（现价/昨收/开盘/涨幅/竞价金额）

### 2. Passport64 生成复刻

**问题**：HTTP 鉴权生成的 passport 能登录（VerifyCode=0）但**无行情查询权限**

**根因**：服务端返回的 passport_bytes 含 53 个字段，其中 10 个是客户端路由/配置字段（`M_hq`/`M_hqdns`/`M_wg`/`download`/`signlength` 等）。hexin 缓存的 passport 会**过滤掉这 10 个字段**（剩 43 个）。带配置字段的 passport 能登录但行情网关校验不通过。

**修复**：`build_passport64` 自动过滤 `_PASSPORT_DROP_FIELDS`（10 个字段），过滤后 b64 长度与 hexin 缓存逐字符一致（2304 字符），行情权限恢复。**无需抓包，账号密码直接可用**。

### 3. 自定义板块管理（移植自 thspy）

- 整文件复制 `blocks.py`（1091 行），纯 HTTPS、零内部依赖
- 凭证链：`full_http_auth` → userid/sessionid + passport_bytes 里的 signvalid → `BlockAuth.docookie2()` → cookies → `BlockManager`
- `connect()` 时自动初始化（`_init_blocks()`），失败不影响登录
- 门面方法：`list_groups` / `get_group` / `add_group` / `delete_group` / `add_stock` / `remove_stock` / `get_self_stocks` / `query_dynamic_plate` 等

**实测**：`list_groups()` 返回 95 个分组

### 4. 短线精灵（异动）

**历史查询**（9601 qurealorder，已完整解码）：
- `dxjl_page` / `dxjl_latest` / `dxjl_history`
- 每条记录含：时间/市场/代码/异动类型/金额/涨跌幅
- 异动类型映射 `ANOMALY_MAP_DXJL`（30 种）

**datatype 过滤表达式**（控制查哪些异动类型，2026-07-17 全选抓包确认）：
- 类别 ID 结构：`category_id = group_prefix | anomaly_byte`
  - 高 3 字节 = 组前缀（异动按字节范围分组）
  - 低 1 字节 = 异动字节（同 `ANOMALY_MAP_DXJL` 的 key）
- 组前缀表（6 组，覆盖全部 53 个类别）：

  | 前缀 | 字节范围 | 含义 |
  |------|---------|------|
  | `0x40080c00` | 0xd1~0xf8 | 核心异动（大笔/涨跌停/急速/放量/封板） |
  | `0x00090a00` | 0xbc~0xbf | 特大主动/被动买卖 |
  | `0x00020b00` | 0x66~0x6f | 挂单/撤单 |
  | `0x00020a00` | 0xa2~0xa5 | 拖拉机/远价位 |
  | `0x003f0d00` | 0xab~0xb0 | 新版异动（含义未知） |
  | `0x000b0b00` | 0x99~0x9a | 新版异动（含义未知） |

- 阈值表达式 `{字段[下限~上限]|字段[下限~上限]}`：
  - 字段19 = 成交手数（单位：手）
  - 字段17 = 成交金额（单位：元）
  - `|` = OR（满足任一，实测确认，非 AND）
  - `~` = 范围，`-` = 无限
- 用 `build_category_id(0xd6)` 生成类别 ID，`build_datatype([0xd6,0xd7], volume_min=10000, amount_min=5000000)` 生成表达式
- 默认 `DXJL_DATATYPE` = 大笔买卖+打开涨跌停（4 类）
  - 大笔买卖阈值：成交手数≥1万手 **OR** 金额≥500万（对齐同花顺客户端默认）
  - 打开涨跌停无阈值
- `datatype=""` 查全部类型（匹配推送帧时推荐用这个）
- ⚠️ 同花顺客户端实测 `maxcount=80~120`，代码默认已改为 80（旧默认 5 太小会漏数据）

**实时推送**（9601 subrealorder + pushrealorder）：
- `subscribe_realtime()`：在 9601 发 `method=subrealorder`（market=16/32/151/48）
- `receive_pushes(timeout, callback)`：接收 pushrealorder 帧
- `parse_pushrealorder_response`：提取股票代码（格式 A `0x21+6BASCII` / 格式 B `0x2d+len+代码`）
- **实测**：盘中 20 秒收到 507 条异动推送

**⚠️ 推送数值字段（金额/涨幅）待逆向**：推送帧用自定义变长编码（不是标准 THS 定点数，也不是 LEB128），当前保留 `raw_bytes`。详见下文「待办」。

### 5. 心跳保活

- 8901 每 3 秒、9601 每 30 秒，后台 daemon 线程自动发送
- `connect()` 成功自动启动，`disconnect()` 自动停止
- socket send 加锁（`_sock_lock` / `_realorder_lock`）避免与查询交错
- `enable_heartbeat=False` 可禁用（对比测试用）
- **实测**：不发心跳静置 15 分钟连接仍不断（8901 空闲超时极长）；心跳对超长连接/实时推送有价值

### 6. 登录多 IP 重试

- VerifyCode=-1 是**特定服务器实例的临时状态**（不是账号级限流）
- 实测同账号连不同 IP，第2次 -1 但第3次又 0
- **修复**：`_do_tcp_login_raw` 遇到 -1 自动换下一个 host 重试（`continue`），不再直接失败
- hexin 不限流是因为连 7 个 IP 并发；thspypc 遍历多 host 同样有效
- **修复后连续 5 次完整 connect() 全部成功**

---

## 二、项目结构

```
thspypc/
├── pyproject.toml              # 依赖：pycryptodome, requests；可选：qrcode
├── .env                        # THS_USERNAME / THS_PASSWORD / THS_IMEI
├── data/                       # ★持久数据（gitignore，不被清）
│   ├── push_frames.jsonl       # 226 个完整推送帧（含 hq1.0 头，核心逆向数据）
│   ├── history_full.jsonl      # 271 条历史异动（完整字段）
│   ├── ANALYSIS_NOTES.md       # 推送帧逆向分析笔记
│   └── matched.csv             # 推送↔历史对照样本（collect_push_samples 产出）
├── src/thspypc/
│   ├── __init__.py             # 包入口，导出所有公开符号
│   ├── protocol.py             # 帧编解码 + HTTP 鉴权 + 行情查询 + 短线精灵 + 心跳
│   ├── blocks.py               # 自定义板块/自选股（HTTPS，移植自 thspy）
│   ├── qr_login.py             # 二维码扫码登录 + 凭证缓存
│   └── client.py               # THSClient：connect/list_quotes/blocks/dxjl_*/pushes/heartbeat
└── tests/
    ├── test_login.py           # 账号密码登录
    ├── test_qr_login.py        # 二维码登录
    ├── test_list_quotes.py     # 个股列表行情（--offline 离线 / 默认活网）
    ├── test_blocks.py          # 自定义板块
    ├── test_dxjl.py            # 短线精灵历史查询
    ├── test_push.py            # 短线精灵实时推送
    ├── test_heartbeat.py       # 心跳保活
    ├── collect_push_samples.py # ★采集推送+历史对照样本（带锁交替，盘中用）
    ├── analyze_matched.py      # ★离线逆向 matched.csv 的数值编码
    ├── capture_hexin_start.py  # 抓 hexin 启动序列（subreal/push 定位）
    ├── capture_dxjl_settings.py# 抓短线精灵阈值设置（datatype 逆向）
    ├── diag_fresh_passport.py  # 抓包提取 hexin Passport64（调试用）
    └── archive/                # 已完成使命的一次性诊断脚本
        ├── diag_no_heartbeat.py    # 心跳必要性实验（结论已沉淀到 test_heartbeat）
        └── compare_remember.py     # 30天免登录差异（结论：expireTime 字段）
```

---

## 三、用法速查

```python
from thspypc import THSClient

with THSClient("账号", "密码") as client:
    client.connect()

    # 个股列表行情
    recs = client.list_quotes(["600056", "600057", ...], market=17)

    # 自定义板块
    for g in client.list_groups():
        print(g.name, len(g.items))
    client.add_stock("我的分组", ["600000"])

    # 短线精灵历史
    for r in client.dxjl_latest():
        print(r["代码"], r["异动类型"], r["金额"])

    # 短线精灵实时推送（盘中）
    client.subscribe_realtime()
    client.receive_pushes(timeout=60, callback=lambda r: print(r["代码"]))
```

---

## 四、待办（优先级排序）

### ★1. 破解 pushrealorder 推送帧的数值字段编码

**现状**：实时推送能收到异动代码，但金额/涨幅/异动类型是自定义变长编码，未破解。
框架结构已摸清（字段表位置、字段编号、方向标记、时间戳），但数值字段精确解码待逆向。

**已完成（本会话）**：
- ✅ datatype 过滤表达式完全破解（字段19=成交手数, 字段17=成交金额, 类别ID=前缀|异动字节）
  见 `protocol.py` 的 `DXJL_DATATYPE` / `ANOMALY_GROUP_PREFIX` / `build_category_id` / `build_datatype`
- ✅ 推送帧内部时间戳定位：首条记录 `b[152:160]` 是 8字节 LE64 微秒戳（=15:00:00，异动发生时刻）
- ✅ matched.csv=0 根因定位：①默认 datatype 过滤掉"特大被动买"等类型；②收盘后时间窗口错开
- ✅ `receive_pushes_locked` 修复并发 bug（持锁交替读，不与心跳/dxjl 抢 socket）
- ✅ `analyze_matched.py` 离线逆向工具就绪（滑动窗口+多解码假设暴力搜索）

**下一步**：
1. **盘中（9:30-15:00）**跑 `collect_push_samples.py` 采集时间窗口重叠的对照样本
   （用 `datatype=""` 查全部类型 + maxcount=80 + 推送内部时间戳请求历史）
2. 跑 `analyze_matched.py` 对 `matched.csv` 做暴力搜索，定位金额/涨幅字段的 offset+encoding
3. 解析 hq1.0 字段表 TLV 格式（字段编号已识别：199时间/5代码/17金额/61异动/64方向/18涨幅）
4. 补全 `parse_pushrealorder_response` 的数值字段解码

### 2. subreal（8901 异动通道订阅）的效果确认

8901 上 hexin 发 `method=subreal`（URS/UCT/UNX/UCX/UME 通道），但实测 8901 subreal 后服务器不推送。推送实际来自 9601 的 `subrealorder`。8901 的 subreal 可能是另一种订阅（推送行情数据而非异动），待确认。

### 3. hd3.1 变体支持

unk=0x36/0x42/0x4a 等非 BitRLE 编码的 hd3.1 帧暂不支持（`parse_hd3_response` 自动跳过）。

### 4. 8901 推送（init 数据 / 行情推送）

文档 §4.2 说 login 成功后服务端主动推送 init 数据。thspypc 目前只做请求-响应模式，未处理 8901 的主动推送。

---

## 五、关键协议细节备忘

### 8901 行情请求帧格式
- 单子帧 cmd=0x09，header 23B（subtype=`12 00 09 00`，hdr[19:21]=文本长度+1）
- 文本：`CodeList=17(600056,);\r\nDataType=7,49,...\r\nDateTime=0(0-0)\r\nLackTime=...\r\npageid=1335\r`
- 行分隔 `\r\n`，末尾仅 `\r`（无 `\n`）
- 每帧尾随 `\n`（encode_frame 后加 `b"\n"`）

### 8901 心跳帧格式
- cmd=0x09，subtype=`12 00 03 00`（区别于行情的 `12 00 09 00`）
- 文本：`10,<hex时间戳>,0000;st=<本机IP>;tsi0=<ts>:0;...;tr=<ts>:0;tc=<ts>:0`
- 时间戳 = Unix 秒 hex 编码

### 9601 subrealorder 订阅帧
- `method=subrealorder\naction=add\nmarket=16\naccept_ziptype=snappy\nrettype=hqfile`
- market: 16=沪 32=深 151=北交所 48=板块

### 9601 心跳帧
- 5 字节 body: `09 <3字节序号 big-endian> 07`，hexlen=00000004

### Passport64 字段过滤
- 过滤 10 个字段：`M_hq`/`M_hqdns`/`M_wg`/`M_zx`/`UpdateSvr`/`download`/`Foss_url`/`DownloadSelfStock`/`UploadSelfStock`/`signlength`
- 过滤后才有行情查询权限

### MARKET_HOSTS（实测 2026-07-17）
- `122.9.202.190` / `122.9.125.190`：登录+行情均可（推荐）
- `116.63.108.136`：登录可用，行情可能 timeout
- 其他：备用

---

## 六、测试命令速查

```bash
cd D:\code\ths_takehome\thspypc

# 离线测试（无需账号）
py tests/test_list_quotes.py --offline

# 活网测试（需 .env 账号）
py tests/test_login.py              # 登录
py tests/test_list_quotes.py        # 行情查询
py tests/test_blocks.py             # 板块管理
py tests/test_dxjl.py               # 短线精灵历史（盘中有数据）
py tests/test_push.py --timeout 20  # 短线精灵实时推送（盘中）
py tests/test_heartbeat.py          # 心跳保活
py tests/collect_push_samples.py    # 采集推送+历史对照（盘中，用于逆向）
```
