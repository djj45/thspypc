# thspypc 开发交接文档（stock_list + 推送采集）

> 会话日期：2026-07-19 ~ 2026-07-23
> 项目路径：`D:\code\ths_takehome\thspypc`（GitHub: `djj45/thspypc`，分支 `feat/stock-list-full`）
> 参考抓包：`D:\code\thspy\captures\cold_start.pcap`（Windows 冷启动，含 dc=7526 全量帧）

本会话在 `HANDOFF.md` 已有功能基础上，完成了 **stock_list 全量代码表**、**短线精灵推送对照样本采集**、
**推送帧数值字段解码**、**名称加载**、**upstockname 协议抓包分析**、**hfd1.0 全市场快照解析**。
原 `HANDOFF.md` 的 §1.5 stock_list 章节已被更新（机制纠正）。

---

## 2026-07-23 新增（全市场快照 hfd1.0——解析器实现 + 混合行情 API）

### 11. 全市场快照（✅ hfd1.0 解析器 + market_snapshot API + 混合行情）

**背景**：同花顺客户端打开 A 股列表"瞬间"拿全市场行情，靠的是**空括号全市场订阅**
（`CodeList=16();17();...`，frame 1046）。单请求 ~0.13s 返回 326KB 全市场数据。

**已实现的三个 API**（2026-07-23 限流修复后）：

| API | 覆盖 | 速度 | 行情精度 | hfd1.0 依赖 |
|-----|------|------|---------|:-----------:|
| `market_snapshot()` | 沪市 ~1200 条 | ~1s | 实验性 | ✅ 主连接单次发 |
| `market_snapshot_with_quotes()` | **沪深全市场 ~7400 条** | ~10-30s | **准确** | ❌ 已移除 |
| `stock_list_cached()` | 沪深全部 ~7400 条 | ~瞬时(缓存) | 无行情 | ❌ |

> **2026-07-23 限流修复**：`market_snapshot_with_quotes` 去掉了 hfd1.0 调用——
> 旧实现 `_try_market_snapshot_on_host` 循环 connect/disconnect 最多 5 次 × 每次
> 并发 7 IP = 短时间 35 次 login 打同一批 IP，**必然触发 VerifyCode=-1**
> （限流根因，见 §7）。且 hfd1.0 名称覆盖（1209 锚点）不如 hexin 本地缓存
> （~8000 条），故移除。code+name 现完全由 `stock_list_cached(with_names=True)`
> 提供。`market_snapshot()` 改为在主连接 `self._sock` 上单次发（新方法
> `_market_snapshot_on_main_sock`），host 不支持时返回空，不再重连。
> 详见 §7a。

#### 11a. 名称锚点扩采（✅ 1409 个锚点）

**问题**：原始只采了 21 个锚点（沪市前 60 只），不足以做模式分析。

**解法**：用 hexin 本地缓存 118K 名称在 hfd1.0 密文中全量匹配 GBK 字节。

**工具**：`tests/expand_hfd1_anchors.py`（v2，零网络依赖）
```bash
py tests/expand_hfd1_anchors.py
```

**结果**：
- 原始 21 锚点 → **1409 个唯一锚点**
- 过滤后（`pre[-1] == code[-1]` + 数字开头）：**1209 个可靠锚点**
- 覆盖：沪 A(6xx)、新三板(8xx)、北交所(87x)、基金(4xx)、指数(1A/1B)
- **深市 A 股（000/002/300）：hfd1.0 不支持**（市场码 32/33 返回空）

#### 11b. 代码压缩分析（07 控制字节 + 增量编码）

**核心发现**：hfd1.0 与 mac 版 `_parse_one_record_200`（id=200 格式）共享同一套 LZ 压缩原理。

**记录结构**：
```
[07 00 XX YY ZZ] [GBK_name] [numeric_data]
  └─ 07 = 记录标记（mac 版用 01）
  └─ 00 = 固定
  └─ XX YY = 代码前缀的增量编码
  └─ ZZ = 代码末位 ASCII 数字（紧贴名称前）
```

**验证统计**（1209 锚点）：
- `pre[-1] == code[-1]`：85% 匹配（剩余 15% 为 07 控制字节正好在末位位置）
- 记录间距：avg=230B, median=64B（含多个未匹配的记录）
- 控制字节：`0x07`(166次)、`0x00`(720, 普遍)、`0x0f`(142)、`0x1f`(134)

**解析策略**：**不逆向代码压缩**——直接用名称锚点 + oracle 映射（名称→code）跳过解码。
名称在响应中是明文 GBK，可做可靠锚点。

#### 11c. 解析器实现（✅ `parse_hfd1_response`）

**文件**：`src/thspypc/parse_hfd1.py`

**架构**：
```
parse_hfd1_response(raw)
  1. load_anchors() → 从 hfd1_0_name_anchors.json 加载 1209 个已验证锚点
  2. 遍历锚点 → 名称处截取 code+name
  3. _parse_numeric(raw, name_end) → 名称后扫描 THS float（实验性）
  4. 返回 [{code, name, price?, change_pct?, ...}]
```

**数值字段（❌ 实验性，准确度有限）**：
- THS float 编码过于宽泛——几乎所有 4B 序列都能解码出"合理"值
- 字段偏移因记录类型（指数/股票）而异，且数值区混入 ASCII 数字文本
- 无法靠值范围扫描区分真实数据与随机字节
- **需 x32dbg/ScyllaHide 或 Ghidra 动态/静态逆向解码函数**才能可靠破解
  （hexin 反调试之前尝试已失败，需装 ScyllaHide 插件）
- 当前实现返回近似值，不保证准确性

#### 11d. client.market_snapshot（✅ 活网验证通过）

**host 兼容性**：部分服务器 host 支持 hfd1.0（122.9.202.190），部分不支持
（122.9.125.190）。`_try_market_snapshot_on_host()` 自动重试 5 次直到命中。

**活网测试**（`tests/test_market_snapshot.py`）：
```
服务器: 122.9.202.190:8901
耗时: 1076ms（含 host 重试）
记录: 1209 条
覆盖: 沪 A(6xx=278) + 新三板(8xx) + 北交所(87x) + 基金(4xx) + 指数
```

#### 11e. 深市覆盖结论（❌ hfd1.0 不支持）

通过 hexin 缓存文件名推断市场码映射：

| 市场码 | 品种 | hfd1.0 支持 |
|--------|------|:---------:|
| 16 | 沪市 A 股 (6xx) | ✅ |
| 32 | **深市 A 股 (000/002/300)** | **❌** |
| 144 | 新三板/基金 (8xx/4xx) | ✅ |

**验证**：市场 32/33 单独请求返回 26B 错误；启动重放序列（`stock_list_replay.bin`）中
`MarketCode=16;144;` 不含深市。

**同花顺客户端秒加载深市的原理**：通过 `subreal` 订阅推送（非请求-响应），
数据在后台持续流入。thspypc 无法复现此机制。

**混合方案**：`market_snapshot_with_quotes()` 先用 stock_list 拿全量代码（含深市），
再用 list_quotes 批量回填行情。

### 12. stock_list 代码表本地缓存（✅ 已实现）

`stock_list_cached()` 给全量代码表加了本地缓存（有效期一天=自然日），当天重复查询直接
读盘不重复发网络请求。详见 README「带本地缓存的代码表」章节 + `tests/test_stock_cache.py`。

---

## 2026-07-22 晚新增（推送帧数值字段逆向突破）

### 8. 推送帧记录结构 + 数值解码（✅ 完全破解，100% 验证）

系统性字节 dump + 历史对照（翻页到推送时间窗口 13:00-13:03）100% 验证。

**记录结构**：
```
[marker 0x11/0x21] [代码 6B ASCII] [01 25 09 01 50 ...]  ← 记录头
  └─ 每条异动子记录（同一代码可有多条）:
     [异动字节 d6/d7/66...] [0c 08 40 头] [方向标记?]
     [变长中间字段] [金额 THS float 4B] [涨幅 THS float 4B]
```

**数值字段解码（100% 精确验证，20/20 样本）**：
- **金额 = 标准 THS float（LE32）**，紧跟**涨幅前 4 字节**
- **涨幅 = 标准 THS float（LE32）**，高字节 `a0`=正/`a8`=负，值在 ±50 范围
- 定位算法：异动字节 + `0c 08 40` 头 → 扫描首个 `a0`/`a8` 结尾 THS = 涨幅 → 前 4B = 金额
- ⚠️ **之前所有"金额不是 THS float"的判断都是错的**——根因是 matched.csv 截断 + 时间错位 + 4B 对齐错误

**异动类型**：
- 主映射 `ANOMALY_BYTE_MAP`：仅按异动字节（d6=大笔买入、d7=大笔卖出...），30 种
- 精确映射 `ANOMALY_MAP_DXJL`：`(异动字节, 方向标记 ff323200/00e60000)` 区分 bc/bd/be/bf
- 推送帧常无方向标记，用字节回退（d6/d7 等由字节唯一确定）

**推送帧内部时间戳**：`b[64:72]`（相对 hq1.0）= LE64 微秒戳（帧级，整秒附近）

**已实现**：`parse_pushrealorder_response` 完全重写（见 §三 文件变更）
- 旧版正则截断 48B + 暴力搜索 → 金额 17%、涨幅 83%
- 新版异动字节锚定 + THS float 精确解码 → 金额/涨幅 100%（对照验证）

### 9. 历史对照验证方法（✅ 无需开盘）

推送帧时间窗口 2026-07-22 13:00:04 ~ 13:02:38。用 `dxjl_history` 翻页到该窗口，
拿到 409 条历史真值（404 条带金额）。关键：**历史查询任何时候都能用**（服务器保留历史）。

```bash
# 翻历史到推送时间窗口（不需开盘，历史数据常驻）
# 见 tests/analyze_push_fields.py 的验证逻辑

# 数据产物
data/history_1300_window.jsonl  # 409 条 13:00-13:03 窗口历史真值
```

**验证结果**（解析器输出 vs 历史三元组）：
- (代码, 金额, 涨幅) 三元组精确匹配：61 条（覆盖率受推送帧 2.5min vs 历史 3min 限制）
- 异动类型一致率：82%（14/77 不一致）
- 算法正确性已由 20/20 干净样本 100% 匹配确认

**14 个类型不一致的根因**（已诊断，非解析器 bug）：
- 全部是 **d6/d7 买卖方向搞反**（如解析=大笔卖出 d7，历史=大笔买入 d6）
- 金额也略有差异（如 15091000 vs 15675000，差 4%）——是**不同的异动事件**
- 根因：**同一代码在同一秒内既有大笔买入又有大笔卖出**，帧级时间戳（整秒）无法区分
- 三元组匹配时金额接近（±5%）就误配到了另一条异动
- **需明天开盘用实时推送 + 紧邻历史查询**（时间差 < 0.5s）验证 d6/d7 是否正确

### 10. hexin_unpacked.exe 逆向（⏸️ 需 Ghidra 完整分析）

- 路径：`D:\code\ths_takehome\ths\hexin_unpacked.exe`（46MB，PE32，脱壳后）
- 字符串定位：`hq1.0`@VA 0x1e7d05c、`pushrealorder`@0x1e34a78、`hqfile`@0x1de219c
- hq1.0 唯一 xref @ VA 0x176b0d0（容器初始化函数，非解析函数）
- **脚本线性反汇编误判太多**（脱壳 PE 无重定位，字节级 `cmp al,0xa0` 搜索全是噪声）
- **需 Ghidra/IDA 完整分析**（函数识别 + 控制流恢复）才能定位字段表解析函数
- 参考：mac 版用 lldb hook `InitBuffer` 拿到字段表 + 偏移规则（SUMMARY 教训1）

---

## 2026-07-22 新增

### 6. upstockname 全量名称抓包分析（✅ 协议已确认）

清空 hexin 的 `stockname/` 缓存后冷启动抓包，确认 upstockname 协议的完整链路。

**抓包产物**：`captures_live/upstockname_capture_20260722_123533.pcap`（4638 包，5.7MB）

**TCP 流分布**（名称数据分布在不同流）：

| 流 | 大小 | 内容 |
|----|------|------|
| Stream 35 | 1.6MB | `[name_16_16]` — 沪市 A 股全量名称 |
| Stream 37 | 138KB | `[name_48]`, `[name_88]`, `[name_96]`, `[name_128]`, `[name_216]` — 板块/外汇/期货 |
| Stream 38 | 831KB | `[name_168_16]` — 混合市场 |
| Stream 40 | 868KB | `[name_64_*]` — 北交所/商品 |
| Stream 41 | 7.6KB | `[name_UNS]`, `[name_UHI]` — 纳斯达克/港交所 |

**协议格式**：

请求（hexin → 服务器，8901 端口）：
```
\x09 + instid=65536\nmethod=upstockname\nmarket=<CHANNEL>\nStockNameVer=;;\nprototype=kvproto\npageid=392\n
```
- `StockNameVer=;;` 表示本地无缓存，触发全量下发
- 不同 market channel 分别请求（UNS/UHI/UCX…）

响应（服务器 → hexin）：
```
<binary_header>instid=65536\nmethod=upstockname\nmarket=<DECIMAL_ID>\nupnametype=base:none;real:full;history:none\nerrorcode=0\nrettype=ini\n<binary>[name_<MARKET>]\nConfigVer=<YYYYMMDD_version>\n<name_data>
```
- `real:full` = 全量模式（区别于增量）
- `market` 在响应中是十进制 ID（非 ASCII 市场码）

**名称数据格式**（与本地 `.txt` 缓存完全一致）：
```
[name_16_16]
ConfigVer=20260722_2552009064
1A0001=上证指数|000001@s
600000=浦发银行|600000@f
...
```

**位平面编码**（2026-07-22 修正，详见 §6a）：
- ~~传输层中文 GBK 字节被位平面转置破坏~~ —— 实为**按市场分段编码**：
  绝大多数段（外汇/期货/北交所/外盘）是**纯文本 GBK**，已解（24K+ 条）；
  仅沪深 A 股 `name_16_16` 用**块状变长 LZ 编码**（17 字节单元，部分解）
- hexin 客户端本地解码后写入 `stockname_<market>_0.txt`（明文 GBK）
- 当前实用方案：直接读 `.txt` 文件（`load_hexin_names()`），无需逆向传输层编码

**thspypc 探针结论**（`tests/probe_upstockname.py`）：
- thspypc 发送 upstockname 请求，服务器仅返回增量（~12 条/次）
- 因为服务器按账号追踪版本状态，thspypc 无法触发全量下发
- 单独发不响应；追加在 stock_list 重放序列末尾能收到增量名称帧

### 6a. upstockname 编码逆向 + 协议封装（默认用本地缓存 / 块状段未解）

> **名称获取策略（当前默认）**：用同花顺本地缓存 `load_hexin_names()`（瞬时、~8K 条
> 沪深北 A 股名称、零网络依赖）。upstockname 网络协议仅作探索性能力保留——纯文本段
> 虽已解，但 thspypc 实际能拿到的增量恰好是未解的块状段，对主用途（A 股名称）无增益。

2026-07-22 系统逆向 name 帧编码，确认**不同市场段用不同编码**，并实现协议层封装。

**段编码分类**（stream35/37/38/40/41 全量样本验证）：

| 段 | 编码 | 可解 | 条数(样本) |
|----|------|------|-----------|
| `name_96_*`（外汇）、`name_88_*`、`name_128_*`、`name_216_*`、`name_48_48` | **纯文本 GBK** | ✅ | ~25K |
| `name_64_*`（期货/北交所/商品，`64_68/69/70`） | **纯文本 GBK** | ✅ | ~20K |
| `name_UNS*`（纳斯达克）、`name_UHI*`（港交所） | **纯文本 GBK** | ✅ | ~260 |
| `name_16_16`（沪深 A 股）、`name_168_16`（混合） | **块状自定义编码** | ❌ 未解 | — |

**纯文本段**：直接 `decode('gbk')`，行格式 `CODE=NAME|ALIAS@FLAG`（CODE 前可有 `@`，
行分隔 `\r\n`/`\n`）。14/14 共同条目与本地缓存 100% 匹配。

**块状编码**（`name_16_16`，沪深 A 股名称）—— 2026-07-22 晚穷举证伪了所有简单模型：
- ✅ **已确认**：结构 = 每 16 字节明文数据后插入 1 个 ctrl 字节（ConfigVer 的 29 字节
  在密文中的位置精确验证：27 个间隔=1，1 个间隔=2 正好是 ctrl 插入点）。
- ✅ **已确认**：`ctrl=0x00` → 16 字节全 literal（组 0-2 同版本明文 100% 匹配）。
- ❌ **已证伪**：固定/动态 offset + bit 控 2 位复制模型。组 4 曾巧合符合 off=26 复制
  （其内容恰好与历史高度相似），误导性结论；逐组穷举 30 组中 25 组**完全无 offset 解**。
- ❌ **已证伪**：标准 LZSS（8 token/ctrl）、简单 RLE、位转置。
- **结论**：块状段是 hexin 自定义的多状态算法（疑似含字典/哈希），纯靠密文+明文
  对照无法归纳。需动态调试或 Ghidra 才能继续。详见 §6b。

**已实现**（`src/thspypc/protocol.py` + `client.py`，探索性保留）：
- `build_upstockname_request(market, stock_name_ver)` — 请求帧构造（字节级对齐 hexin）
- `decode_name_frame(body)` — 解析响应，自动识别纯文本/块状段，纯文本段解出
  `{code:name}`，块状段记录到 `skipped`。实测解出 24,361 条名称（外汇/期货/北交所/外盘）
- `THSClient.fetch_stock_names(market)` — 发请求 + 解析的封装 API（探索性，A 股名称拿不到）

**工具**：
- `tests/analyze_name_frame.py --decode-block N` — oracle 逐组解码对照明文
  （`--dump-blocks`/`--probe` 看块结构/ctrl 分布）

**结论**：名称获取**默认走本地缓存** `load_hexin_names()`（A 股名称，稳定可靠）。
upstockname 网络协议已封装但仅能解非 A 股的纯文本段；沪深 A 股 `name_16_16` 块状
编码未解，且 thspypc 增量帧恰好是该段，故网络路径对 A 股名称无增益。

### 6b. 块状编码攻坚记录（❌ 纯静态/动态均受阻，暂搁置）

2026-07-22 晚集中攻坚 `name_16_16` 块状编码，三条路径全部受阻，记录如下避免重复踩坑。

**路径 1：纯密文+明文对照暴力破解（方案 E）—— 证伪**
- 同版本明文样本（`stockname_16_0.txt` ConfigVer=20260722）+ 密文（stream35）精确对照。
- 确认结构：每 16 字节明文后插 1 个 ctrl 字节；`ctrl=0x00`→16B 全 literal（组 0-2 100% 验证）。
- **穷举证伪所有简单模型**：固定 off=26 + bit 控 2 位（全段 29.9%，0 组完全对）；
  动态 offset 逐组穷举（30 组中 25 组完全无解）；标准 LZSS、RLE、位转置均不符。
- 组 4 曾巧合符合 off=26 复制（内容恰好与历史相似），是误导性结论。
- **结论**：块状段是 hexin 自定义多状态算法（疑似含字典/哈希），纯对照归纳无法破解。

**路径 2：x32dbg 动态调试 —— 被反调试阻断**
- hexin.exe 含完整反调试：`IsDebuggerPresent` + `CheckRemoteDebuggerPresent` +
  `NtQueryInformationProcess` + `fs:[30h]` 直读 PEB BeingDebugged（2 处）。
- attach 后同花顺 GUI 卡死、登录界面无响应（反调试触发，非单纯断点频繁）。
- x32dbg 未装 ScyllaHide 插件（`D:\software\x64dbg\release\x32\` 无），不能一键绕过。
- 操作手册已写好：`docs/x32dbg_变体A调试手册.md`（含 VA→运行时换算 delta=-0x2a0000、
  下断坐标、dump 步骤）。装 ScyllaHide 后手册可直接用。

**路径 3：Unicorn 静态定位 —— C++ 对象层太厚**
- mac 版 `disasm_17632f0.txt`（变体A 位运算函数）需字段表 widths 数组，name 段无字段表，不适用。
- 静态扫 call 图：name 处理区（`ProcessStockName_Step1/2` @ VA 0xb00240/0xb00500、
  `NEW_UpdateStockName` @ 0xa86000）全是 C++ 对象方法（vtable+SEH），无"位运算密集"的
  纯算法函数（最高 14%），无法快速定位底层解码器。
- 源码路径线索：`diskserver.cpp` 的 `CDiskServer::HandleAllData`（所有数据帧分发入口）。

**已定位的确定性坐标**（供下次攻坚用，均经字符串 xref 交叉验证）：
- `ProcessStockName_Step1` 日志 xref @ VA 0xb003c1（运行时 0x860240）
- `upstockname` 字符串比较 @ VA 0xa85ab4（运行时 0x7e5ab4）
- `stockname_%s_%d.txt` 写文件 @ VA 0x167ae72（运行时 0x13dae72）← 解码完成、写盘瞬间
- hexin 反调试 API：`IsDebuggerPresent`@file 0x1e990c2 等

**搁置决策**：A 股名称已由本地缓存稳定覆盖，块状编码攻坚投入产出比低，暂搁置。
若需重启：首选装 ScyllaHide 复活 x32dbg（用 `stockname_%s_%d.txt` 写文件断点抓明文缓冲区，
倒推解码函数），次选装 Ghidra 静态硬啃调用链。

---

## 2026-07-21 新增

### 4. 推送帧数值字段解码（✅ 涨幅 83%，金额 ⚠️ ~17%）

通过 480 条对照样本（`data/matched.csv`，2026-07-22 盘中补充至 480 条）暴力搜索 + 编码假设验证，确认推送帧数值字段使用**同花顺 THS 定点浮点编码（LE32）**。

**涨幅（变化率）**：
- THS LE32，高字节 `0xa0`（正）/ `0xa8`（负）同时作为 tag 标记和 THS 参数
- exp=2（÷100），低 3 字节 = abs(涨幅%) × 100
- 例：`f3 00 00 a0` → 243 ÷ 100 = 2.43%
- 检测率：83%（204/244，容忍 15% 误差）。剩余 17% 多为格式 A 多记录帧，涨幅在子记录中。

**金额（成交金额）**：
- THS 定点 LE32 或纯整数 LE32，编码已确认
- **检测率仅 ~17%**（480 条样本后仍未显著提升）
- **根因**：金额在 payload 中的偏移随**子类型**变化（即使同前缀组），纯暴力搜索已到天花板
- **正确解法**：逆向 hq1.0 字段表 TLV 格式，从字段编号直接定位（字段 17=金额、字段 18=涨幅）
- 当前折中：在涨幅标记前 30 字节搜索 THS LE32 + plain LE32，取最大值

**文件变更**：`src/thspypc/protocol.py`
- 新增 `_extract_push_payload(raw)` — 从 Format B/A 壳提取纯数据
- 新增 `_decode_push_single(raw)` — 解码单条推送记录的涨幅+金额
- 更新 `parse_pushrealorder_response` — 返回 `金额`/`涨幅` 字段

### 5. stock_list 名称填充（✅ 已工作）

**方案变更**：逆向 upstockname 协议 → 改用**同花顺本地缓存文件**。

upstockname 协议发现：服务器按账号追踪版本状态，只下发增量（12 条名称）。
即使发送 `StockNameVer=0;;`，服务器仍然只返回增量。

**最终方案**：直接读取同花顺 PC 客户端本地缓存：
- 路径：`C:\同花顺软件\同花顺\stockname\stockname_*_0.txt`
- 格式：GBK 文本，`CODE=NAME|ALIAS@FLAG`
- 共 ~60,000 条名称（覆盖沪深北+新三板+基金+期货+外盘）

**API**：
```python
# 方式 1：自动填充
stocks = client.stock_list(with_names=True)  # 7458 条含名称，~6s

# 方式 2：单独加载
names = THSClient.load_hexin_names()         # → {"600000": "浦发银行", ...}
```

### 7. list_quotes / stock_list_hot 超时根因（✅ 2026-07-23 已解决）

行情查询（list_quotes / stock_list_hot/199112）超时无响应。经多轮抓包 + A/B
测试，**真正根因是 login 后缺少 init 握手帧**。

**调查历程（三轮，逐步逼近真凶）**：

1. ~~第一轮：归因 login 帧缺 UserName/Password + 校验字节 0xc9~~（后被推翻）
2. ~~第二轮：归因 IP 集群迁移（旧 IP 退化为纯登录网关）~~（后被推翻）
3. **第三轮（最终结论）**：2026-07-23 多次抓包对比 hexin 客户端的连接序列，
   发现 hexin 每条 8901 连接的顺序是 `LOGIN → INIT → 行情查询`。thspypc 的
   `connect()` 跳过了 INIT，直接发行情查询 → 服务器不激活该连接的行情通道 → 超时。

**最终修复**（2026-07-23）：
- `client.py:_send_init_handshake()` — login 成功后自动发 init 请求 + 排空响应，
  激活行情通道。在 `_do_tcp_login_raw` 的 VerifyCode=0 分支调用。
- `protocol.py:resolve_market_hosts()` — 从 passport `M_hqdns` 动态解析域名拿
  最新 IP（不再依赖硬编码 MARKET_HOSTS 快照）。`build_login_body_pc` 维持
  0xaa 无 UserName（抓包确认 hexin 多数时候也不带）。

**验证**（2026-07-23 13:00，同花顺客户端已退出、干净连接）：
- ✅ 连 122.9.202.190（之前认为"退化"的旧 IP），init 握手后
  `list_quotes` 成功：600000 现价 9.03 涨幅 0.22%、600004 涨幅 0.51%
- → 证明旧 IP 没退化，之前超时纯粹因为没发 init

**关于 VerifyCode=-1 的澄清**（2026-07-23 抓包分析 hexin 登录模式）：
- 不是账号限流，而是**同账号同 IP 短时间重复 login 的会话冲突**。
- hexin 客户端的登录策略（抓包确认）：每 ~20s 重新登录一波，每波**并发连
  7 个不同 IP**，28 次 login 分布在 18 个 IP 上。同一 IP 重复登录间隔 ≥20s。
  因此 hexin 从不对同一 IP 短时间狂发 login，不触发冲突。
- thspypc 的 `connect()` 串行遍历 IP 列表，对每个 IP 发 login——如果测试时
  反复 connect/disconnect（如调试），几十秒内对同一批 IP 发几十次 login，
  服务器返回 VerifyCode=-1（会话冲突保护）。
- **测试要点**：① 确保同花顺客户端已退出（同账号不能两个客户端同时在线）；
  ② 不要短时间（<20s）内反复 connect；③ 失败后等 30s 再重试。

**199112/stock_list_hot 的 hd1.0 解析**：
- `_parse_stock_list_hd10_variant` 已实现（199112 小批量响应走 hd1.0 明文变体）
- `stock_list_hot` 已修复（加 `\n` + 多帧读循环 + 市场码改 33）

**相关文件**：
- `src/thspypc/client.py:_send_init_handshake` — init 握手（login 后自动调用）
- `src/thspypc/protocol.py:resolve_market_hosts` — M_hqdns 动态域名解析
- `src/thspypc/protocol.py:_parse_stock_list_hd10_variant` — 199112 hd1.0 解析
- `tests/probe_stock_list_hot.py` — A/B 测试探针

### 7a. 连接治理 + 性能优化（✅ 2026-07-23）

> ⚠ **纠正**：本节原标题"VerifyCode=-1 限流根治"是**错误归因**。后续抓包 + 三变体实测
> 证明 -1 的真正根因是 login 帧内容（check 字节硬编码 + sk/sv 误过滤，见 §2），
> 与连接频率无关（同账号反复登录退出 hexin 毫无问题）。本节的代码改进（连接治理、
> market_snapshot 改造）仍有价值（避免无谓重连、防选慢 IP），但**不是防 -1 的手段**。

**代码改进**（虽然不是 -1 解法，但都是好实践）：

| 改进 | 实现 | 价值 |
|------|------|------|
| market_snapshot 不再反复 connect | `_try_market_snapshot_on_host` 删除 → `_market_snapshot_on_main_sock`（主连接单次发） | 避免无谓重连 |
| market_snapshot_with_quotes 去 hfd1.0 | code+name 走 `stock_list_cached` | 简化 + 名称更全 |
| `connect()` 冷却复用 | 连接活着 + <20s 直接复用（`error=reused_existing_connection`） | 避免重复 login |
| `is_connected` 属性 + `ensure_connected()` | MSG_PEEK 探测连接活性 | 健康检查 |

**真正的性能优化**（本次会话后期完成）：

| 优化 | 效果 |
|------|------|
| **测速选 IP**（`_probe_fastest_hosts`） | 并发 TCP 握手测 70 个 IP 延迟（复刻同花顺「测试 IP」），选最快 7 个 login。connect 从 2~46s（盲选）降到稳定 ~2s |
| **init 握手优化** | init 响应只是 1 帧 49KB 配置（非代码表），读 1 帧 + 0.2s peek 即可。从 8s 降到 0.3s |
| **并发登录提前退出** | `_concurrent_login` 用 `all_done` 计数器，所有 IP 都完成即退出（不必等满 timeout） |
| **连续 -1 提前放弃** | 串行 fallback 连续 5 个 -1 判定全局封禁，停止重试（避免傻试 60 个 IP 拖几十秒） |

**测速选 IP 机制**（抓包复刻同花顺，2026-07-23）：
- `tests/capture_ip_test.py` 抓同花顺「获取/测试 IP」功能，确认机制：
  ① DNS 解析 `*.123ths.com` 域名拿 IP（thspypc 的 `resolve_market_hosts` 同此）
  ② 并发 TCP 握手测延迟（SYN→SYN-ACK），选最快的（最快 122.9.115.201=28ms）
- thspypc 的 `_probe_fastest_hosts` 做同样的事：纯 TCP 握手不发 login，不触发 -1，70 个 IP 并发测完 ~1s

**⚠ VerifyCode=-1 的两种类型（2026-07-23 最终澄清）**：
- **A. login 帧内容**（已修复）：check 字节硬编码（0 字节 FIN）/ sk/sv 缺失（-6）。
  正常使用不再触发。
- **B. 账号级临时封禁**（无法绕过）：同账号短时间反复 connect，尤其集中撞同一批 IP，
  触发服务器保护——所有 IP 秒回 -1，持续几分钟~十几分钟。**这是服务器行为，代码无法
  绕过，只能等释放**。实测：反复 connect 同一批快 IP 几次即触发。
- 应对 B 的措施：① connect 冷却复用（同进程内不重复 login）；② **测速缓存 + IP 轮换**
  （`_probe_cache` 5 分钟复用测速结果；`_login_rr_offset` 每次推进，login 从快 IP 池
  轮换取 7 个，分散到不同子集，避免集中撞同一批）；③ 连续 5 个 -1 提前返回
  `error="global_rate_limited"` 提示等待，不傻试 60 个 IP。
- **根本对策**：connect 一次保持长连接反复查，不要反复 connect。

**仍需用户注意**：
- 确保同花顺客户端已退出（同账号不能两个客户端同时在线）
- 短时间反复 connect 会触发 B 类型 -1，等几分钟释放；测速（`_probe_fastest_hosts`）
  纯 TCP 握手不发 login，可以放心跑

**相关文件**：
- `src/thspypc/client.py` — `_probe_fastest_hosts`（含缓存）/ `_do_tcp_login_raw`（IP 轮换）/ `_market_snapshot_on_main_sock` / `is_connected` / `ensure_connected` / `connect`（冷却）/ `_send_init_handshake`（优化）/ `_concurrent_login`（提前退出）
- `src/thspypc/protocol.py` — `MARKET_HOSTS` 注释纠正 / `_PASSPORT_DROP_FIELDS`（见 §2）
- `tests/cli_ticker.py` — 去掉冗余 `time.sleep(2)`

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
| **B：upstockname 全量同步** | ✅ 协议已确认 | 仅 hexin 客户端可用（服务器按账号追踪版本） |
| **C：hexin 本地缓存** | ✅ 推荐方案 | 瞬时（读 `stockname/*_0.txt`，~60K 条） |

**upstockname 逆向进展**：
- 请求格式已对齐 hexin（字节级一致）：`\x09instid=65536\nmethod=upstockname\nmarket=URS\nStockNameVer=;;\nprototype=kvproto\npageid=5716\n`
- 单独发服务器**不响应**；追加在 stock_list 重放序列末尾能收到 1 个名称帧（4862B 增量）
- 名称帧格式按市场分段（详见 §6a）：A 股 `name_16_16` 是**块状自定义编码**（每 16 字节数据后插 1 ctrl 字节，ctrl≠0 时算法未解）；其余市场段是纯文本 GBK
- 样本存 `captures_live/upstockname_name_frame_sample.bin`（4862B，gitignored）
- hexin 落盘格式：`C:/同花顺软件/同花顺/stockname/stockname_<市场>_0.txt`（`<代码>=<名称>|<别名>@<标志>`，如 `600000=浦发银行|浦发银行@f`）

### 3. 短线精灵推送对照样本采集（✅ 已拿到 480 条匹配）

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

**2026-07-22 盘中补充**：从 245 条扩至 480 条（大笔卖出 286 + 大笔买入 188 + 打开涨停板 6）。

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

### ✅ 1. ~~用 analyze_matched.py 暴力破解推送帧数值字段~~（已完成 2026-07-21）

涨幅 83%、金额 ~17%。见上文 §4。金额提升需逆向 hq1.0 字段表 TLV（见 §3）。

### ✅ 2. ~~完善 stock_list 名称~~（已完成 2026-07-21）

改用同花顺本地缓存（`stockname/*_0.txt`），~60K 名称。见上文 §5。

### ✅ 3. ~~推送帧记录结构 + 数值解码~~（已完成 2026-07-22 晚，见 §8/§9）

金额/涨幅 100% 精确解码（THS float），异动类型 30 种全覆盖。
`parse_pushrealorder_response` 已重写。历史对照验证通过（无需开盘）。

### ✅ 3a. 开盘验证 d6/d7 异动方向（已验证 2026-07-23，解析器无需修改）

**结论：方向判定正确，无 bug。** §8 中 14/77（旧数据）"d6/d7 买卖搞反"
的现象，已用 2026-07-23 开盘新鲜数据证实是**历史对照的时间配对错位**，
不是解析器问题。

**验证数据**（2026-07-23 盘中 `collect_push_samples.py --rounds 30`）：

| 指标 | 结果 |
|------|------|
| 样本总数 | 101（含完整帧 101） |
| 整体类型一致率 | **94/101 = 93.1%** |
| 方向标记命中的干净子集 | **36/39 = 92.3%** |

7 条不一致全部是**同代码短时间内多条异动**导致三元组匹配误配：
- `002432` 在 0.92s~4.79s 内出现 3 种异动（0xd7 卖出 / 0xda 跌停封板 / 0xd7），
  matched.csv 把不同事件配到了一起
- `603986` 4 秒内 0xd6→0xd7→0xd7 买卖翻转
- `300285`(Δt=9.24s)、`000636`(Δt=3.96s)——时间差大，明显配到了另一条异动

**根因**：异动字节 0xd6 本身判"买入"、0xd7 判"卖出"，和方向标记
`ff323200`(买)/`00e60000`(卖) 组合后类型完全正确。大单买卖在同一只股票
短时间内同时出现是常态，帧级时间戳（整秒）无法区分，三元组匹配就会误配
到相邻事件。这是**对照方法的局限**，解析器无需修改。

**对比旧数据**：

| | §8 旧数据 | 2026-07-23 验证 |
|---|---|---|
| 不一致率 | 14/77（18%） | 7/101（7%） |
| 时间差 | 整秒窗口（粗） | 0.69~1.5s（更紧邻） |
| 根因 | 推测同秒多异动 | **已证实**：时间配对错位 |

**验证命令**（如需复现）：
```bash
# 1. 盘中采集（9:30-15:00，matched.csv 带 push_raw_bytes/push_frame_hex）
uv run python tests/collect_push_samples.py --rounds 30

# 2. 离线分析（只看时间紧邻样本，排除同秒多异动干扰）
uv run python tests/analyze_push_fields.py --input data/matched.csv --max-diff 1 --verbose

# 3. 方向验证（异动字节+方向标记 vs 历史真值，对照 hist_type/hist_code_byte）
#    见本节验证逻辑：从 push_raw_bytes 提取 (异动字节,方向标记) 组合判定类型，
#    与 matched.csv 的 hist_type 对照，统计一致率
```

### ✅ 4. stock_list_hot()（已解决 2026-07-23，见 §7）

根因：connect() 缺 init 握手 + 199112 的 hd1.0 解析缺失。
已修复（init 握手 + M_hqdns 动态 IP + hd1.0 解析 + stock_list_hot 读帧 bug）。

### 5. hq1.0 字段表 TLV 格式（中优先级，见 §10）

字段表签名跨帧固定但 TLV 切分未破解（8B/条、4B/条、varint 都不对齐）。
PROTOCOL.md §5.2 揭示推送异动用字段 **203/204(量) + 225/226(金额)**，与 qurealorder 的 17 不同。
需 Ghidra 完整分析 `hexin_unpacked.exe` 定位字段表解析函数。

### 5. 其他待办（来自 HANDOFF.md §4）

- subreal（8901 异动通道订阅）效果确认
- hd3.1 变体支持（unk=0x36/0x42/0x4a）
- 8901 主动推送处理
- ~~MarketTime 握手 → 解锁 stock_list_hot()~~（2026-07-23 已证伪：根因是 login 帧
  缺 UserName/Password + 校验字节，非 MarketTime。见 §7）

---

## 三、关键文件变更

| 文件 | 变更 |
|------|------|
| `src/thspypc/client.py` | `stock_list()` 重写为重放路径 + `load_hexin_names()` 名称加载 + `with_names` + `fetch_stock_names()` + **`market_snapshot()`**（hfd1.0 全市场快照）+ **`market_snapshot_with_quotes()`**（混合行情：hfd1.0 + stock_list + list_quotes） |
| `src/thspypc/parse_hfd1.py` | **新增**：hfd1.0 响应解析器（名称锚点驱动，THS float 数值扫描实验性） |
| `src/thspypc/protocol.py` | `parse_pushrealorder_response` **完全重写** + `ANOMALY_BYTE_MAP` + `parse_init_response` + `_parse_stock_list_hd31_variant` + 常量修正 + `build_upstockname_request()` + `decode_name_frame()` |
| `src/thspypc/data/stock_list_replay.bin` | 重放模板（27KB，4 个请求段） |
| `tests/test_stock_list.py` | 离线+活网双模式 + `--with-names` |
| `tests/probe_upstockname.py` | **新增**：upstockname 探针（确认服务器只发增量） |
| `tests/capture_upstockname.py` | **新增**：upstockname 冷启动抓包（dumpcap + tshark 自动分析） |
| `tests/analyze_matched.py` | **重写 v2**：Format B/A 壳解析 + 前缀分组 + 编码搜索 |
| `tests/capture_hexin_start.py` | 重写（时长可调、聚焦 pushrealorder 统计） |
| `tests/capture_stock_list.py` | 重写（聚焦 stock_list 请求/响应分析） |
| `tests/analyze_pcap_pagination.py` | 新增（离线分页分析工具） |
| `tests/collect_push_samples.py` | 加 CLI + `match_pushes_with_history` 新增 `full_frames` 参数（matched.csv 带 `push_frame_hex` 完整帧） |
| `tests/analyze_push_fields.py` | **新增**：基于完整帧的数值字段逆向工具（异动字节锚定 + THS float 验证 + 偏移统计） |
| `tests/analyze_name_frame.py` | **新增**：upstockname 名称帧编码逆向工具（密文↔明文对照、`--dump-blocks`/`--probe`/`--decode-block` oracle 解码） |
| `docs/x32dbg_变体A调试手册.md` | **新增**：块状编码动态调试操作手册（VA→运行时换算、下断坐标、dump 步骤；装 ScyllaHide 后可用） |
| `pyproject.toml` | `package = false`（绕过 uv_build 被 AppLocker 拦截） |
| `tests/expand_hfd1_anchors.py` | **新增**：hfd1.0 锚点扩采（v2，零网络依赖，hexin 缓存匹配 ~60K 名称） |
| `tests/analyze_hfd1_compression.py` | **新增**：代码压缩模式分析（07 控制字节 + 增量编码） |
| `tests/analyze_hfd1_raw_layout.py` | **新增**：原始记录布局分析（记录边界、数值区偏移） |
| `tests/analyze_hfd1_numeric_v2.py` | **新增**：数值字段校准（THS float 偏移统计 + 指数/股票分类） |
| `tests/analyze_hfd1_scanrecords.py` | **新增**：记录边界字节模式扫描 |
| `tests/analyze_hfd1_code_pattern.py` | **新增**：代码模式精分析（pre_30 窗口 + 07 位置统计） |
| `tests/calibrate_hfd1_numeric.py` | **新增**：list_quotes 真值对照校准数值偏移 |
| `tests/probe_sz_snapshot.py` | **新增**：深市市场码探针（验证 32/33/144-151 各市场的快照支持） |
| `tests/test_market_snapshot.py` | **新增**：market_snapshot 离线/活网测试 |

**采集数据**（gitignored）：
- `data/push_frames.jsonl`（2357 完整推送帧，含 hq1.0 头，核心逆向数据）
- `data/pushes.jsonl`（4608 推送记录）
- `data/history.jsonl`（9440 历史异动）
- `data/matched.csv`（★480 条对照样本，2026-07-22 盘中补充）
- `data/hfd1_0_response.bin`（326KB，hfd1.0 全市场快照原始响应）
- `data/hfd1_0_name_anchors.json`（★1409 个名称锚点，核心解析数据）
- `data/oracle_code_names.json`（1528 条名称→code 映射）
- `data/hfd1_0_parsed.json`（解析结果缓存）
- `data/snapshot_*.bin`（各市场码快照探针存盘）
- `captures_live/hexin_full.pcap`（4.19MB，3452 推送帧）
- `captures_live/upstockname_capture_20260722_123533.pcap`（5.7MB，4638 包，冷启动全量名称抓包）
- `captures_live/upstockname_stream35_server.bin`（1.6MB，沪A 全量名称原始帧）
- `captures_live/upstockname_stream37_server.bin`（138KB，外汇/期货名称）
- `captures_live/upstockname_stream40_server.bin`（868KB，北交所名称）
- `captures_live/upstockname_stream41_server.bin`（7.6KB，纳斯达克/HK 名称）
- `captures_live/upstockname_*.bin`（thspypc 探针增量名称帧，4.5KB）

---

## 四、关键认知（避免重复踩坑）

- **DataType=199112 不是启动拉代码表的路径**（是用户打开 A 股列表时的排序查询，拿不到全量）
- **init 请求单独发不会触发全量**（必须重放完整 subreal+CodeList 1B0987+init 序列）
- **dt55 = 名称字段**（mac 字段表确认 + 活网验证），但 init 全量帧的 dt55 全 0
- **名称获取默认用本地缓存** `load_hexin_names()`（A 股名称，瞬时、稳定、零依赖）。upstockname 网络协议仅探索性保留，纯文本段已解但 A 股 `name_16_16` 块状编码未解（详见 §6a/§6b）
- **upstockname 名称帧按市场分段编码**：外汇/期货/北交所/外盘段是**纯文本 GBK**（已解，24K+ 条）；沪深 A 股 `name_16_16` 是**块状自定义编码**（未解，简单模型已穷举证伪）
- **upstockname 全量名称走冷启动触发**（服务器按账号追踪版本，thspypc 只能拿增量；且增量恰好是未解的 `16_16` 块状段，故网络路径对 A 股名称无增益）
- **名称本地缓存在 `C:\同花顺软件\同花顺\stockname\stockname_<market>_0.txt`**（GBK 明文，~60K 条）
- **推送帧记录结构 = marker(11/21) + 代码(6 ASCII) + [异动字节 + 0c0840头 + 变长字段 + 金额THS + 涨幅THS]×N**（见 §8）
- **推送帧金额 = 标准 THS float**（LE32），紧跟涨幅前 4 字节（100% 验证）
- **推送帧涨幅 = 标准 THS float**（`a0`=正/`a8`=负 高字节），异动字节后扫描首个 a0/a8 标记定位
- **推送帧异动字节后紧跟 `0c 08 40` 头**（0x40=64=方向字段，用作异动记录锚点）
- **~~推送帧金额不是 THS float~~** ← 此前错误结论！根因：matched.csv 48B 截断 + 时间错位 + 4B 对齐错误
- **历史查询任何时候都能用**（服务器保留历史异动），翻页到推送时间窗口即可对照（见 §9）
- **encode_ths_float 浮点精度 bug**：`8.72*100=871.9999`，必须用 `round()` 容差（见 §8）
- **uv_build 被 Windows AppLocker 拦截**（WinError 4551），`pyproject.toml` 设 `package = false` 绕过
- **collect_push_samples 必须盘中跑**（9:30-15:00），否则 matched.csv=0
- **同账号多端登录会互踢**（用 collect 时确保账号和 hexin 客户端不同，或先退出 hexin）
- **hfd1.0 = mac 版 id=200 的 PC 变体**：代码用 07 控制字节压缩（mac 用 01），名称明文 GBK，数值区 THS float。无 mac 版的 `fe0100` 锚点和 `05800000` 尾标记
- **hfd1.0 解析用名称锚点驱动**：名称 GBK 在响应中明文出现，直接匹配 hexin 缓存拿 code，不依赖代码压缩逆向
- **hfd1.0 数值字段扫描不可靠**：THS float 编码过于宽泛，几乎所有 4B 都能解码出"合理"值，无法靠范围区分真伪。正确解法需动态逆向（反调试限制大）
- **hfd1.0 只覆盖沪市/三板/基金**（市场 16/144-151），**深市 A 股（市场码 32/33）不支持快照**。hexin 客户端靠 subreal 订阅推送拿深市行情
- **list_quotes 不支持全量（~7000 只）单请求**，服务器超时；合理 batch=30，盘中可用
- **市场码映射**：16=沪A, 32=深A, 33=深A(list_quotes用), 144=新三板+基金

---

## 五、测试命令速查

```bash
cd D:\code\ths_takehome\thspypc

# stock_list（离线 + 活网）
py tests/test_stock_list.py --offline    # 离线解码 dc=7526
py tests/test_stock_list.py              # 活网重放拿 dc=7458（~6s）
py tests/test_stock_list.py --with-names # 活网 + 自动填充名称

# 名称加载（独立使用）
py -c "from thspypc.client import THSClient; n=THSClient.load_hexin_names(); print(len(n))"

# 短线精灵（盘中）
py tests/capture_hexin_start.py                   # 抓包 5 分钟（hexin 流量）
py tests/capture_hexin_start.py --duration 600    # 抓 10 分钟
py tests/collect_push_samples.py --rounds 30      # SDK 采集对照样本（默认读 .env）
py tests/collect_push_samples.py --user X --pwd Y # 指定另一个账号

# 离线分析
py tests/analyze_matched.py              # 推送字段编码逆向（按前缀组分析，旧版暴力搜索）
py tests/analyze_matched.py --verbose    # 详细解码输出
py tests/analyze_push_fields.py --input data/matched.csv --offset-stats  # ★新版：基于完整帧 + 异动字节锚定
py tests/analyze_push_fields.py --verbose --max-diff 2                   # 只看时间紧邻样本（最可靠）

# 全市场快照 hfd1.0
py tests/test_market_snapshot.py --offline          # 离线解析 hfd1_0_response.bin
py tests/test_market_snapshot.py                    # 活网测试（自动重试 host）
py -m src.thspypc.parse_hfd1                        # 解析器独立测试
py tests/expand_hfd1_anchors.py                     # 锚点扩采（零网络依赖，hexin 缓存匹配）
py tests/analyze_hfd1_compression.py                # 代码压缩模式分析
py tests/analyze_hfd1_raw_layout.py                 # 原始记录布局
py tests/analyze_hfd1_numeric_v2.py                 # 数值字段校准
py tests/probe_sz_snapshot.py                       # 深市市场码探针
py tests/analyze_pcap_pagination.py      # stock_list 分页分析

# upstockname 抓包（需清空 stockname 缓存 + 冷启动同花顺）
py tests/capture_upstockname.py                   # 交互式抓包 30s
py tests/capture_upstockname.py --duration 60     # 抓 60s
py tests/capture_upstockname.py --pcap xxx.pcap   # 分析已有 pcap
py tests/probe_upstockname.py                     # thspypc 探针（仅增量）

# upstockname 名称解码（离线样本 + 编码逆向）
py tests/analyze_name_frame.py                    # 纯文本段解码 + 对照明文
py tests/analyze_name_frame.py --dump-blocks 8    # 块状段 17 字节组对照
py tests/analyze_name_frame.py --decode-block 5   # oracle 逐组解码（组0-3可解）
py -c "from thspypc.protocol import decode_name_frame as d; r=d(open('captures_live/upstockname_stream40_server.bin','rb').read()); print(len(r['names']),'条')"  # 解 stream40 期货/北交所名称
```
