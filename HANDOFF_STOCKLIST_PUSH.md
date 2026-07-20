# thspypc 开发交接文档（stock_list + 推送采集）

> 会话日期：2026-07-19 ~ 2026-07-20
> 项目路径：`D:\code\ths_takehome\thspypc`（GitHub: `djj45/thspypc`，分支 `feat/stock-list-full`）
> 参考抓包：`D:\code\thspy\captures\cold_start.pcap`（Windows 冷启动，含 dc=7526 全量帧）

本会话在 `HANDOFF.md` 已有功能基础上，完成了 **stock_list 全量代码表**和**短线精灵推送对照样本采集**。
原 `HANDOFF.md` 的 §1.5 stock_list 章节已被本次会话更新（机制纠正）。

---

## 一、本次会话完成的功能

### 1. stock_list 全量代码表（✅ 已工作，已推送 GitHub）

**`client.stock_list()` 拿全市场 ~7400 条代码**（沪 600/601/603/688 + 深 + 北交所 870-875/920 + 新三板 830-839 + 基金 430/400）。

**机制（2026-07-19 三次抓包 + Windows cold_start.pcap 彻底澄清）：**

hexin 拉股票列表有**两条路径**，用途完全不同：

| 路径 | 请求 | 能拿全量？ | 实现状态 |
|------|------|-----------|---------|
| **A：DataType=199112 排序查询** | `build_stock_list_query` (空 CodeList + SortCount 递增) | ❌ 小帧只返回 29 条热门票（重复），大帧只返回 2 位前缀 | `_parse_stock_list_hd31_variant`（保留，解 199112 响应） |
| **B：init 全量帧**（启动序列） | 重放 4 个请求段（subreal×8 + CodeList 1B0987 + init） | ✅ dc≈7422 全量 | `client.stock_list()`（重放路径） |

**路径 B 的关键发现**（颠覆了任务描述的前提）：
- 单独发 `build_init_query()` **不会**触发全量下发（服务器只返回 49KB 配置帧）
- 必须重放完整启动序列：`subreal×8(URS/UCT/UNX/UCX/UME/UGF/UGFO/UNS)` +
  `CodeList=16(1B0987,)`（特殊订阅，`1B0987` 是"全市场代码表"特殊标的，subtype=0x0002 route=0x0001）+ init
- 重放模板固化在 `src/thspypc/data/stock_list_replay.bin`（27KB，提取自 cold_start.pcap stream 44 帧1619/1965/2308/2481）
- 重放后服务器在登录连接上推送 `dc≈7422, unk=0x18, hs=71, fc=2` 的 hd3.1 全量帧

**响应解码**（hd3.1 标准 BitRLE）：
- 字段：`dt5(code, w7) + dt55(w64)`
- 纯 Python BitRLE 100% 正确（7422/7526 条完整 6 位 ASCII 代码，与 unicorn 逐字节一致）
- **dt55 在 init 帧里全 0**（init 不填名称），返回 stocks 里 name 恒 ""

**实测**：活网 5.7s 拿到 7422 条；离线 cold_start.pcap 解出 7526 条。

### 2. 名称获取的两条路径（dt55 = 名称字段，已确认）

mac 版字段表 `D:/code/thspy/client.py:143` 明确定义 `55: '名称'`。活网实验验证：`list_quotes` 的 DataType 加 `55`，响应 dt55 含 GBK 名称（600000→`c6d6b7a2d2f8d0d0`→"浦发银行"）。

| 方案 | 状态 | 效率 |
|------|------|------|
| **A：list_quotes 带 DataType=55** | ✅ 已可用 | 慢（7000 只 / 每批 30 ≈ 250 请求） |
| **B：upstockname 全量同步** | ⚠️ 待逆向 | 快（1 请求拿全量） |

**upstockname 逆向进展**：
- 请求格式已对齐 hexin（字节级一致）：`\x09instid=65536\nmethod=upstockname\nmarket=URS\nStockNameVer=;;\nprototype=kvproto\npageid=5716\n`
- 单独发服务器**不响应**；追加在 stock_list 重放序列末尾能收到 1 个名称帧（4862B 增量）
- 名称帧格式是**混合文本+位平面编码**（骨架可读 `[name_16_16]\nConfigVer=...\n600000=浦发银行|浦发银行@f`，但字节被位平面转置破坏），未破解
- 样本存 `captures_live/upstockname_name_frame_sample.bin`（4862B，gitignored）
- hexin 落盘格式：`C:/同花顺软件/同花顺/stockname/stockname_<市场>_0.txt`（`<代码>=<名称>|<别名>@<标志>`，如 `600000=浦发银行|浦发银行@f`）

### 3. 短线精灵推送对照样本采集（✅ 已拿到 245 条匹配）

**2026-07-20 13:00 盘中双窗口采集**（账号 mx_***，IP `122.9.202.190`）：

| 窗口 | 工具 | 产物 | 结果 |
|------|------|------|------|
| 1（抓包） | `capture_hexin_start.py` | `captures_live/hexin_full.pcap`（4.19MB） | 3452 个 pushrealorder 帧（738 帧/分钟） |
| 2（SDK） | `collect_push_samples.py --rounds 30` | `data/*.jsonl` + `matched.csv` | **245 条匹配对照**（核心逆向数据） |

**matched.csv 结构**（逆向数值字段的金矿）：
```
code, hist_type, hist_code_byte, hist_amount, hist_change, hist_time,
push_market, push_ts, time_diff_s, push_raw_bytes
```
每行把推送的 `raw_bytes`（二进制）和历史的真值（金额/涨跌幅/异动类型）配对。

**匹配样本异动类型分布**：
- 大笔买入: 114
- 大笔卖出: 107
- 打开跌停板: 23
- 打开涨停板: 1

**样本观察**（来自 matched.csv 头几行）：
- `601668` 大笔买入 0xd6，金额 17909250，涨幅 2.43%，推送 `2d 18 11 36 30 31 36 36 38 01 27 09 01 50 d6 0c 08 40 ff 32 32 00 0c 3a 4e 92 02 46 11 01 f3 00 00 a0 86 0d`
- `002281` 打开跌停板 0xdb，金额 0，涨幅 -10%，推送 `2d 18 21 30 30 32 32 38 31 01 27 09 01 0c da 0c 08 40 01 2d 30 9b 42...`
- 异动字节 `d6`=大笔买入、`db`=打开跌停板，与 `ANOMALY_MAP_DXJL` 一致

---

## 二、下一步（优先级排序）

### ★1. 用 analyze_matched.py 暴力破解推送帧数值字段

**目标**：定位 `push_raw_bytes` 里金额、涨跌幅、异动类型的 offset + encoding。

**已就绪**：
- `data/matched.csv`（245 条对照，4 种异动类型）
- `tests/analyze_matched.py`（离线逆向工具，滑动窗口+多解码假设暴力搜索）
- HANDOFF.md §4.1 记录的已知框架：字段表位置、字段编号（199时间/5代码/17金额/61异动/64方向/18涨幅）、首条记录时间戳在 `b[152:160]`（8字节 LE64 微秒戳）

**方法**：对 matched.csv 每条，把 hist_amount/hist_change 转成多种编码（THS 定点 LE32、LEB128、zigzag、raw int/float），在 push_raw_bytes 里滑窗搜索匹配 offset。多个样本 offset 一致即定位成功。

### 2. 完善 stock_list 名称（路径 B 逆向 upstockname）

清掉 hexin 的 `stockname/` 缓存重新抓包，拿真正的全量名称响应帧（760KB，不是增量 4862B）。
格式是混合文本+位平面，需要专门逆向（参考 hd3.1 BitRLE 解码链）。

### 3. 完善 stock_list（路径 A 的 DataType=199112）

虽然拿不到全量，但已正确实现 `_parse_stock_list_hd31_variant`（16-bit dc 变体）。
可作为"拿最近活跃 29 只"的轻量 API 保留。

---

## 三、关键文件变更

| 文件 | 变更 |
|------|------|
| `src/thspypc/client.py` | `stock_list()` 重写为重放路径（init 全量帧） |
| `src/thspypc/protocol.py` | `parse_init_response`（直接用 parse_hd3_response）+ `_parse_stock_list_hd31_variant`（199112 变体）+ 常量修正（市场码 22、去 55） |
| `src/thspypc/data/stock_list_replay.bin` | 重放模板（27KB，4 个请求段，已加 .gitignore 例外） |
| `tests/test_stock_list.py` | 离线（dc=7526）+ 活网（dc=7422）双模式测试 |
| `tests/capture_hexin_start.py` | 重写（时长可调、聚焦 pushrealorder 统计） |
| `tests/capture_stock_list.py` | 重写（聚焦 stock_list 请求/响应分析） |
| `tests/analyze_pcap_pagination.py` | 新增（离线分页分析工具） |
| `tests/collect_push_samples.py` | 加 CLI（`--user/--pwd/--rounds`，默认读 .env） |
| `pyproject.toml` | `package = false`（绕过 uv_build 被 AppLocker 拦截） |

**采集数据**（gitignored）：
- `data/push_frames.jsonl`（2162 完整推送帧，含 hq1.0 头）
- `data/pushes.jsonl`（3723 推送记录）
- `data/history.jsonl`（9600 历史异动）
- `data/matched.csv`（★245 条对照样本）
- `captures_live/hexin_full.pcap`（4.19MB，3452 推送帧）

---

## 四、关键认知（避免重复踩坑）

- **DataType=199112 不是启动拉代码表的路径**（是用户打开 A 股列表时的排序查询，拿不到全量）
- **init 请求单独发不会触发全量**（必须重放完整 subreal+CodeList 1B0987+init 序列）
- **dt55 = 名称字段**（mac 字段表确认 + 活网验证），但 init 全量帧的 dt55 全 0
- **upstockname 全量名称帧是混合文本+位平面编码**（不是纯文本，不是标准 hd3.1）
- **uv_build 被 Windows AppLocker 拦截**（WinError 4551），`pyproject.toml` 设 `package = false` 绕过
- **collect_push_samples 必须盘中跑**（9:30-15:00），否则 matched.csv=0
- **同账号多端登录会互踢**（用 collect 时确保账号和 hexin 客户端不同，或先退出 hexin）

---

## 五、测试命令速查

```bash
cd D:\code\ths_takehome\thspypc

# stock_list（离线 + 活网）
py tests/test_stock_list.py --offline    # 离线解码 dc=7526
py tests/test_stock_list.py              # 活网重放拿 dc=7422（~6s）

# 短线精灵（盘中）
py tests/capture_hexin_start.py                   # 抓包 5 分钟（hexin 流量）
py tests/capture_hexin_start.py --duration 600    # 抓 10 分钟
py tests/collect_push_samples.py --rounds 30      # SDK 采集对照样本（默认读 .env）
py tests/collect_push_samples.py --user X --pwd Y # 指定另一个账号

# 离线分析
py tests/analyze_pcap_pagination.py               # stock_list 分页分析
# 用 analyze_matched.py 暴力破解推送数值字段（下一步）
```
