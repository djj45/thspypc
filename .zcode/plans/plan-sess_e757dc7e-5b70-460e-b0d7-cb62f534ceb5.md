## 目标
给 `stock_list()` 的全量代码表（~7400 条）做一个本地缓存，有效期一天（按自然日），让调用方当天重复查询直接读盘、不重复发网络请求。缓存按市场分好类（沪/深/北交所）并带名称，方便直接喂给 `list_quotes()`。

## 文件格式与存放

- **路径**：`~/.ths_stock_codes.json`（仿 `qr_login.default_cache_path` 的 home 目录风格）
- **JSON 结构**（含校验字段，自然日失效）：
```json
{
  "saved_date": "2026-07-22",      // 自然日字符串，用于判断是否当天
  "saved_at": 1784620800,          // Unix 时间戳（调试用）
  "count": 7422,
  "stocks": [
    {"code": "600000", "name": "浦发银行", "market": 17},
    ...
  ]
}
```

## 市场码派生（核心逻辑）

`stock_list()` 的 `market` 字段恒为 0（protocol.py:917，dt5 首字节在解码中丢失），无法直接用。新增一个模块级函数 `_market_from_code(code) -> int | None`，按代码前缀派生 `list_quotes` 能认的市场码：

```python
# 17=沪、33=深（build_list_quote_query docstring protocol.py:527 确认）
def market_from_code(code: str) -> int | None:
    if code[:3] in ("600","601","603","605") or code[:3] == "688":  # 沪市 A 股 + 科创板
        return 17
    if code[:3] in ("000","001","002","003","300","301"):           # 深市 A 股 + 创业板
        return 33
    # 北交所/新三板/基金等：list_quotes 用 17/33 两个市场码覆盖不到，返回 None
    return None
```
北交所（8xxxxx/920xxx）、新三板（830-839）、基金（430/400）这些 `list_quotes` 当前不支持，缓存里仍保留 code+name，但 market=None（调用方自处理）。

## API 设计（新增 4 个函数 + 1 个便捷方法）

**新增独立函数**（放 `client.py` 底部，静态/模块函数，仿 qr_login 风格，不登录也能用）：

```python
def default_stock_cache_path() -> str          # ~/.ths_stock_codes.json
def market_from_code(code) -> int | None       # 前缀→市场码（也独立导出，调用方常用）
def save_stock_codes(stocks, path=None) -> str # 写盘（覆盖 market 字段为派生值）
def load_stock_codes(path=None) -> tuple[list[dict], str] | None
                                               # 返回 (stocks, saved_date)，过期/损坏返回 None
def is_stock_cache_expired(path=None, now=None) -> bool  # 按自然日判断（跨天即失效）
```

**THSClient 便捷方法**（核心入口，缓存优先）：
```python
def stock_list_cached(self, *, cache_path=None, refresh=False,
                      with_names=True, timeout=30.0) -> list[dict]
```
逻辑：
1. `refresh=False` 时先试 `load_stock_codes()` → 当天有效 → 直接返回（0 网络请求，~瞬时）
2. 过期/不存在/`refresh=True` → 调 `self.stock_list(with_names=True)` 拿全量 → `save_stock_codes()` 写盘 → 返回
3. `with_names=True` 默认开（缓存场景几乎都要名称，且只写盘一次）

**自然日失效口径**：`saved_date` 字符串 `datetime.date.today().isoformat()` 与读盘当日比较，不等即过期。简单、无时区歧义。

## 导出
在 `__init__.py` 导出新函数（仿现有 qr_login 导出，line 41-44 / `__all__` line 65）：
`market_from_code, default_stock_cache_path, save_stock_codes, load_stock_codes, is_stock_cache_expired`

## 测试（tests/test_stock_cache.py，可运行脚本风格，仿 test_stock_list.py）

- **离线单测**（无需账号/网络）：`market_from_code` 各前缀映射正确；`save_stock_codes` → `load_stock_codes` 往返完整；过期判断（写昨天的日期 → 判过期）。
- **活网测试**（读 .env）：连真账号 → `stock_list_cached()` 第一次走网络拉取并写盘 → 第二次调用验证直接命中缓存（打印是否发网络，可通过计时区分：缓存命中 <0.1s vs 网络拉取 ~6s）→ 断言 `len >= 7000`。

## 文档
- 更新 README.md「全市场股票列表」章节：补充 `stock_list_cached()` 用法 + 缓存说明（自然日失效、路径、刷新方式）。
- 不改 HANDOFF（那是开发交接文档，非用户文档）。

## 不做的事（避免范围蔓延）
- 不动 `stock_list()` 本身（保持纯网络查询）
- 不支持自定义 TTL（用户明确要"一天"，自然日口径已满足；后续需要再加参数）
- 不做多账号隔离（缓存是全市场代码表，与账号无关，共享一个文件合理）
