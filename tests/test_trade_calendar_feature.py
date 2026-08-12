"""Production trading-date selection contracts."""
from __future__ import annotations

import datetime as dt

import thspypc.features.trade_calendar as calendar


TRADE_DAYS = [
    dt.date(2026, 8, 10),
    dt.date(2026, 8, 11),
    dt.date(2026, 8, 14),
]


def test_before_0915_uses_previous_trading_day(monkeypatch):
    monkeypatch.setattr(calendar, "_load_trade_days", lambda _today=None: TRADE_DAYS)

    assert calendar.latest_trade_date(
        dt.datetime(2026, 8, 11, 9, 14, 59)
    ) == dt.date(2026, 8, 10)


def test_from_0915_uses_current_trading_day(monkeypatch):
    monkeypatch.setattr(calendar, "_load_trade_days", lambda _today=None: TRADE_DAYS)

    assert calendar.latest_trade_date(
        dt.datetime(2026, 8, 11, 9, 15)
    ) == dt.date(2026, 8, 11)


def test_holiday_and_weekend_use_last_trading_day(monkeypatch):
    monkeypatch.setattr(calendar, "_load_trade_days", lambda _today=None: TRADE_DAYS)

    # 8/12 and 8/13 are omitted to model an exchange holiday.
    assert calendar.latest_trade_date(
        dt.datetime(2026, 8, 13, 14, 0)
    ) == dt.date(2026, 8, 11)
    assert calendar.latest_trade_date(
        dt.datetime(2026, 8, 15, 14, 0)
    ) == dt.date(2026, 8, 14)
