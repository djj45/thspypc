"""Local daily cache for the discovered stock universe."""
from __future__ import annotations

import datetime
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

# 缓存格式版本：股票表增加北交所全量后 bump；旧格式读取时视为过期，
# 下一次 /api/stocks2 会自动全量刷新并写回新格式。
CACHE_VERSION = 2


def default_stock_cache_path() -> str:
    """股票代码表缓存的默认路径（用户 home 目录，跨平台）。"""
    return os.path.join(os.path.expanduser("~"), ".ths_stock_codes.json")

def market_from_code(code: str) -> int | None:
    """按股票代码前缀派生 ``list_quotes`` 的市场码。

    ``stock_list()`` 返回的 market 字段恒为 0（dt5 首字节在解码中丢失，
    见 ``protocol._dt5_market``），无法直接用。本函数按 A 股代码前缀规则
    派生 ``list_quotes`` 能认的市场码（17=沪 33=深，见
    ``build_list_quote_query`` docstring）。

    Args:
        code: 6 位数字股票代码（如 "600000"、"000001"、"300750"）。

    Returns:
        17（沪市 A 股/科创板）、33（深市 A 股/创业板），或 None（北交所/
        新三板/基金等 list_quotes 当前不支持的市场）。
    """
    if len(code) < 3:
        return None
    p = code[:3]
    # 沪市 A 股（600/601/603/605）+ 科创板股票/CDR（688/689）
    if p in ("600", "601", "603", "605", "688", "689"):
        return 17
    # 深市 A 股（000/001/002/003）+ 创业板（300/301）
    if p in ("000", "001", "002", "003", "300", "301"):
        return 33
    # 北交所（8xxxxx/920xxx）、新三板（830-839）、基金（430/400）等：list_quotes 不支持
    return None

def save_stock_codes(stocks: list[dict], path: str | None = None) -> str:
    """把全量股票代码表写盘缓存（覆盖写）。

    每条记录保留 ``code/name/market``，并写入 ``saved_date``（自然日，用于失效判断）
    和 ``saved_at``（Unix 时间戳，调试用）。

    Args:
        stocks: ``stock_list()`` 的返回值，每项含 ``code``（其余字段如 name/market
            有则保留，market 会用 :func:`market_from_code` 重新派生覆盖）。
        path: 缓存路径，None 用 :func:`default_stock_cache_path`。

    Returns:
        实际写入的文件路径。
    """
    path = path or default_stock_cache_path()
    # 规范化：确保每条有 name/market 字段，market 用派生值覆盖
    records = []
    for s in stocks:
        code = s.get("code", "")
        if not code:
            continue
        records.append({
            "code": code,
            "name": s.get("name", ""),
            "market": market_from_code(code),
        })
    data = {
        "version": CACHE_VERSION,
        "saved_date": datetime.date.today().isoformat(),
        "saved_at": int(time.time()),
        "count": len(records),
        "stocks": records,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("股票代码表已缓存: %s (%d 条)", path, len(records))
    except OSError as e:
        logger.warning("股票代码表写盘失败（不影响本次返回）: %s", e)
    return path

def load_stock_codes(
    path: str | None = None,
) -> tuple[list[dict], str] | None:
    """读取缓存的股票代码表（已过期或损坏时返回 None）。

    Args:
        path: 缓存路径，None 用 :func:`default_stock_cache_path`。

    Returns:
        ``(stocks, saved_date)``：stocks 为 ``[{code, name, market}, ...]``，
        saved_date 为缓存写入的自然日（如 "2026-07-22"）。
        文件不存在、已过期（跨自然日）或格式错误时返回 None。
    """
    path = path or default_stock_cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
            logger.info(
                "股票代码表缓存版本过旧（version=%s），忽略并重新拉取",
                data.get("version") if isinstance(data, dict) else None,
            )
            return None
        saved_date = data["saved_date"]
        stocks = data["stocks"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("股票代码表缓存读取失败（将忽略）: %s", e)
        return None
    # 按自然日判断：saved_date 与今天不同即过期
    today = datetime.date.today().isoformat()
    if saved_date != today:
        logger.info("股票代码表缓存已过期 (saved_date=%s, today=%s)",
                    saved_date, today)
        return None
    return stocks, saved_date

def is_stock_cache_expired(path: str | None = None,
                           now: datetime.date | None = None) -> bool:
    """判断股票代码表缓存是否已过期（按自然日）。

    与 :func:`load_stock_codes` 的内置判断一致：缓存写入的自然日与查询日不同
    即视为过期。文件不存在或损坏也返回 True。

    Args:
        path: 缓存路径，None 用默认路径。
        now: 指定查询日（调试用），None 用 datetime.date.today()。

    Returns:
        True 表示缓存已过期/不存在/损坏（需重新拉取）。
    """
    loaded = load_stock_codes(path)
    if loaded is None:
        return True
    _, saved_date = loaded
    today = (now or datetime.date.today()).isoformat()
    return saved_date != today
