"""A-share trading-date selection used by live market-data workflows."""
from __future__ import annotations

import csv
import datetime as dt
import importlib
import json
import logging
import os
import random
import threading
from bisect import bisect_right
from urllib.parse import urlencode
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)

_trade_days_cache: list[dt.date] | None = None
_trade_days_loaded = False
_trade_days_lock = threading.Lock()


def _load_trade_days_from_csv() -> list[dt.date] | None:
    """Load the optional ``a-trade-calendar`` package without pandas."""
    try:
        package = importlib.import_module("a_trade_calendar")
        csv_path = os.path.join(
            os.path.dirname(package.__file__),
            "a_trade_calendar.csv",
        )
        if not os.path.isfile(csv_path):
            return None
        with open(csv_path, newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            next(reader, None)
            days = [
                dt.date.fromisoformat(row[0].strip())
                for row in reader
                if row and row[0].strip()
            ]
        return sorted(days) or None
    except Exception:  # noqa: BLE001 - optional local data source
        return None


def _fetch_month_from_szse(year: int, month: int) -> list[dt.date]:
    key = f"{year:04d}-{month:02d}"
    params = urlencode({"month": key, "random": random.random()})
    request = Request(
        "https://www.szse.cn/api/report/exchange/onepersistenthour/"
        f"monthList?{params}",
        headers={
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://www.szse.cn/",
        },
    )
    with urlopen(request, timeout=5) as response:
        payload = json.load(response)
    return [
        dt.date.fromisoformat(row["jyrq"])
        for row in payload.get("data", [])
        if row.get("jybz") == "1"
    ]


def _load_trade_days_from_szse(today: dt.date) -> list[dt.date]:
    previous_month = today.replace(day=1) - dt.timedelta(days=1)
    days = [
        *_fetch_month_from_szse(previous_month.year, previous_month.month),
        *_fetch_month_from_szse(today.year, today.month),
    ]
    return sorted(set(days))


def _load_trade_days(today: dt.date | None = None) -> list[dt.date]:
    """Load and cache a holiday-aware calendar, preferring local data."""
    global _trade_days_cache, _trade_days_loaded
    if _trade_days_loaded:
        return _trade_days_cache or []
    with _trade_days_lock:
        if _trade_days_loaded:
            return _trade_days_cache or []
        days = _load_trade_days_from_csv()
        source = "a-trade-calendar"
        if days is None:
            try:
                days = _load_trade_days_from_szse(today or dt.date.today())
                source = "SZSE"
            except Exception as exc:  # noqa: BLE001 - weekend fallback below
                logger.warning("trading calendar unavailable: %s", exc)
                days = []
        _trade_days_cache = days or []
        _trade_days_loaded = True
        if days:
            logger.debug(
                "loaded %d trading dates (%s..%s) from %s",
                len(days),
                days[0],
                days[-1],
                source,
            )
        return _trade_days_cache


def latest_trade_date(now: dt.datetime | None = None) -> dt.date:
    """Return the date displayed by a default intraday request.

    From 09:15 on an actual trading day the result is today.  Before 09:15,
    on weekends, and on exchange holidays it is the preceding trading day.
    """
    current = now or dt.datetime.now()
    cutoff = (
        current.date()
        if current.time() >= dt.time(9, 15)
        else current.date() - dt.timedelta(days=1)
    )
    days = _load_trade_days(current.date())
    if days:
        index = bisect_right(days, cutoff)
        if index:
            return days[index - 1]

    # Last-resort behavior when neither the local calendar nor SZSE is
    # available.  It preserves the important pre-open/weekend semantics.
    target = cutoff
    while target.weekday() >= 5:
        target -= dt.timedelta(days=1)
    return target


__all__ = ["latest_trade_date"]
