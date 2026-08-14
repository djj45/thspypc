# 排序榜账号分流 + 北交所补全 / 排序值三编码归一化（2026-08-14 晚）

> 本次会话收口三组问题：Level2/普通账号排序榜缺北交所（920083 等）、10~20% 区间
> "缺条目"、排序值混用三种编码导致前端显示错乱。核心是两次抓包（Level2 拆沪深、
> 普通账号 MAIN 单请求）+ 活网 A/B 验证。

## 核心结论

| 问题 | 根因 | 修复 |
|---|---|---|
| Level2 排序榜缺北交所/10~20% 缺条目 | MAIN 单请求不返回 151（北交所）；旧 ranked() 不分账号 | ranked() 分账号：Level2 拆 SH_L2(17/22/151)+SZ_L2(33) pageid=1341，SortCount 放大；普通走 MAIN 单请求 17/22/33/151 pageid=1334 |
| 普通账号排序榜无北交所 | MAIN 连接连到 ifindhq（不支持 151），而非 main.123ths.com | resolve_market_hosts 恢复 main 优先；测速/batch 按 main 优先分组轮换 |
| 排序值显示错乱（+884720000%） | 同一字段混用三种编码：除法 float（直接真值）/乘法 float（×1e8）/裸 mantissa（×10000） | `_normalize_rank_value` 按量级统一为 mantissa/10000；前端去掉 raw/1e8 |

## 1. 客户端抓包事实（2026-08-14 两次抓包）

### Level2 账号（rank_sort_20260814_154552.pcap）

- **拆两条 L2 连接**：沪 `8.134.98.163` 发 `CodeList=17();22();151();`、深 `8.134.112.142` 发 `CodeList=33();`
- pageid=**1341**、SortCount=**20** 起、SortBegin 恒 0；滚动时 SortCount 放大（20→160→2897→4541→5191）
- 第一页响应即含北交所（151:3，920083 金戈新材 29.97%）；最终全榜：沪 dc=2048（335 只北交所）、深 dc=1770
- 中间穿插的 `CodeList=17(具体代码);DataType=7,49,13,...` 是已见行行情刷新，不是翻页

### 普通账号（rank_sort_20260814_154833.pcap）

- **MAIN 单请求** `CodeList=17();22();33();151();` pageid=**1334**，SortCount=20，SortBegin 递增（0→100→220→320→340→440→3102）
- 服务器 `8.134.108.168`（**main.123ths.com**）响应含北交所（151:2，920083）
- 注意：ifindhq.123ths.com 的 IP（如 8.134.121.153/8.134.123.179）对同一请求**不返回 151**

## 2. 排序值三种编码（真值 = mantissa/10000）

同一排序响应字段混用三种 THS float 编码，解码值量级可区分：

| 编码 | 例 | 解码值 | 还原 |
|---|---|---|---|
| 除法 float（bit31=1） | 0xc000431c → 1.718 | 直接真值 | 不处理 |
| 乘法 float（bit31=0） | 0x40001536 → 54300000 | ×1e8 | ÷1e8 |
| 裸 mantissa | 0x431c → 17180（L2 涨速榜） | ×10000 | ÷1e4 |

统一规则（`_normalize_rank_value`）：|v| ≥ 1e7 → ÷1e8；1e3 ≤ |v| < 1e7 → ÷1e4；否则原样。
只作用于百分比类排序键（涨幅 199112/涨速 48/换手 1968584/量比 1771976/竞价涨幅 68762）；
金额类（竞价额 dt150/封单额 dt44/主力 dt250）是原始元不缩放。

## 3. 实现改动

### services/stock_list.py（核心）

- `ranked()` 按 `profile.kind` 分流：
  - **LEVEL2** → `_ranked_l2`：SH_L2（17/22/151）+ SZ_L2（33）各自 pageid=1341、SortCount 从 20 放大，`_merge_ranked_rows` 按排序值本地归并（对齐 dde_ranked 模式）；fetch 时就地归一化排序字段
  - **STANDARD** → `_ranked_main`：MAIN 单请求 17/22/33/151、pageid=1334、SortBegin 递增翻页（客户端确认的模式）
- 新增 `_normalize_rank_value`（模块级）与 `_normalize_ranked_values` 兜底

### _client/service_facade.py

- `stock_list_hot` 按账号类型授权 capability：LEVEL2 → `L2_MARKET_ACCESS`（同 dde_rank），普通 → `BASIC_QUOTE`

### protocol.py + _client/connection_primitives.py（普通账号连 main）

- `resolve_market_hosts` 恢复 **main 优先**（支持北交所 151），ifindhq 仅回退；passport 无 M_hqdns 时硬编码 main（之前硬编码 ifindhq）
- `_probe_fastest_hosts` 增加 `priority_hosts` 分组：main 域名的 IP 恒排前、组内按延迟序；**缓存命中同样应用分组**（否则旧延迟序缓存绕过优先级）
- `_do_tcp_login_raw` batch 构造：**main 组内轮换取满、ifindhq 仅补齐**（原逻辑轮换偏移会把 main 全部跳过）
- 2026-08-12 观察到的 "main 全 IP VerifyCode=-1" 是 passport 过期/被消费的临时状态（重新 HTTP 鉴权即恢复，AGENTS.md 规则 4），非 main 节点封禁

### web/src/components/left/RankPanel.tsx

- 去掉 `raw / 1e8`：后端 with_values 已统一真值，前端直接使用

## 4. 活网验证

| 账号 | 结果 |
|---|---|
| Level2（.env） | 涨幅榜 920083 金戈新材 29.97% 居首、北交所 3 条（前30）/14 条（前400）、涨速榜 1.718% 等、封单额不缩放 |
| 普通（.env.normal） | MAIN peer=8.134.108.168（与抓包一致）、920083 居首、北交所 14 条、10~20% 区间 46 条与 Level2 完全一致 |

⚠ 10~20% 区间的"跳跃"（19.9x→18.4x→16.1x...）是**市场真实分布**（当天 17.x/15.x 涨幅的股票不存在），
两条独立路径（普通 MAIN + Level2 拆分）值序列完全一致，非解析/翻页问题。

## 5. 关键文件

- src/thspypc/services/stock_list.py（ranked 分账号 + 归一化）
- src/thspypc/protocol.py（resolve_market_hosts main 优先）
- src/thspypc/_client/connection_primitives.py（测速/batch main 优先分组）
- src/thspypc/_client/service_facade.py（capability 按账号）
- web/src/components/left/RankPanel.tsx（去 ÷1e8）

## 6. 诊断/验证脚本（tests/，保留）

- capture_rank_sort.py：抓包脚本（--account level2/normal，含滚动翻页提示）
- verify_rank_fix_live.py：Level2 分账号修复活网验证
- verify_rank_normal_live.py：普通账号（.env.normal）活网验证
- diag_ranked_gaps.py / verify_l2_rank.py / compare_rank_l2_vs_main.py：诊断过程
- verify_speed_dt48_live.py / verify_speed_dt48_truth.py：dt48/dt200 缩放交叉验证

## 7. 测试

- 600 passed + 19 skipped（test_market_snapshot_service::test_captured_hfd1_snapshot_contract 为既有失败，与本次无关）
- test_stock_list_service.py：Level2 断言更新（拆 L2 连接/pageid=1341/含北交所）+ _normalize_rank_value 单元测试
- test_market_host_resolution.py：重写为 main 优先（6 个测试）