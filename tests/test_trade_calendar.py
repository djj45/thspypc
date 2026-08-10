"""Unit tests for latest_trade_date() trading calendar logic."""
from __future__ import annotations

import datetime as dt

import pytest

import thspypc.testing as testing
from thspypc.testing import latest_trade_date


def _mock_calendar(monkeypatch, days: list[dt.date]):
    """Replace _load_trade_days with a static list (resets cache)."""
    monkeypatch.setattr(testing, "_trade_days_cache", days)
    monkeypatch.setattr(testing, "_load_trade_days", lambda: days)


# ── 2026-07 ~ 08 完整交易日列表（8/10 是周一）──
AUG_JUL = (
    [dt.date(2026, 7, d) for d in [1, 2, 3, 6, 7, 8, 9, 10, 13, 14,
                                   15, 16, 17, 20, 21, 22, 23, 24,
                                   27, 28, 29, 30, 31]]
    + [dt.date(2026, 8, d) for d in range(3, 8)]      # 8/3-8/7
    + [dt.date(2026, 8, d) for d in range(10, 15)]     # 8/10-8/14
    + [dt.date(2026, 8, d) for d in range(17, 22)]     # 8/17-8/21
    + [dt.date(2026, 8, d) for d in range(24, 29)]     # 8/24-8/28
    + [dt.date(2026, 8, 31)]
)


class TestLatestTradeDate:
    def test_trading_day_after_915_returns_today(self, monkeypatch):
        """交易日 9:15 后 → 当天。"""
        _mock_calendar(monkeypatch, AUG_JUL)
        now = dt.datetime(2026, 8, 11, 14, 30)  # 周二下午
        assert latest_trade_date(now) == dt.date(2026, 8, 11)

    def test_trading_day_before_915_returns_previous(self, monkeypatch):
        """交易日 9:15 前 → 上一个交易日。"""
        _mock_calendar(monkeypatch, AUG_JUL)
        now = dt.datetime(2026, 8, 11, 8, 0)  # 周二早上
        assert latest_trade_date(now) == dt.date(2026, 8, 10)  # 周一

    def test_trading_day_at_915_boundary_returns_today(self, monkeypatch):
        """9:15 整点 → 当天（>= 9:15 含当天）。"""
        _mock_calendar(monkeypatch, AUG_JUL)
        now = dt.datetime(2026, 8, 11, 9, 15, 0)
        assert latest_trade_date(now) == dt.date(2026, 8, 11)

    def test_weekend_returns_friday(self, monkeypatch):
        """周六/周日 → 上周五。"""
        _mock_calendar(monkeypatch, AUG_JUL)
        # 周六 8/15
        assert latest_trade_date(dt.datetime(2026, 8, 15, 10, 0)) == dt.date(2026, 8, 14)
        # 周日 8/16
        assert latest_trade_date(dt.datetime(2026, 8, 16, 20, 0)) == dt.date(2026, 8, 14)

    def test_holiday_returns_last_trading_day(self, monkeypatch):
        """节假日（不在交易日列表里）→ 放假前最后交易日。"""
        # 去掉 8/12-8/14 模拟假期
        holiday_days = [d for d in AUG_JUL if d.day not in (12, 13, 14) or d.month != 8]
        _mock_calendar(monkeypatch, holiday_days)
        # 8/13（假期中）14:00 → 应返回 8/11
        assert latest_trade_date(dt.datetime(2026, 8, 13, 14, 0)) == dt.date(2026, 8, 11)

    def test_month_boundary_before_915(self, monkeypatch):
        """月初跨月：9/1 周二 9:15 前 → 8/31 周一（上月最后交易日）。"""
        sep = AUG_JUL + [dt.date(2026, 9, d) for d in [1, 2, 3, 4, 7, 8, 9]]
        _mock_calendar(monkeypatch, sep)
        now = dt.datetime(2026, 9, 1, 8, 0)
        assert latest_trade_date(now) == dt.date(2026, 8, 31)

    def test_month_boundary_after_915(self, monkeypatch):
        """月初跨月：9/1 周二 9:15 后 → 9/1 当天。"""
        sep = AUG_JUL + [dt.date(2026, 9, d) for d in [1, 2, 3, 4, 7, 8, 9]]
        _mock_calendar(monkeypatch, sep)
        now = dt.datetime(2026, 9, 1, 10, 0)
        assert latest_trade_date(now) == dt.date(2026, 9, 1)

    def test_fallback_skips_weekend_when_calendar_fails(self, monkeypatch):
        """日历不可用 → 退化到跳周末。"""
        monkeypatch.setattr(testing, "_trade_days_cache", None)
        monkeypatch.setattr(testing, "_load_trade_days",
                            lambda: (_ for _ in ()).throw(ConnectionError("down")))
        now = dt.datetime(2026, 8, 15, 10, 0)  # 周六
        assert latest_trade_date(now) == dt.date(2026, 8, 14)  # 周五

    def test_fallback_before_915_trading_day(self, monkeypatch):
        """日历不可用 + 交易日 9:15 前 → 前一天（fallback 只跳周末）。"""
        monkeypatch.setattr(testing, "_trade_days_cache", None)
        monkeypatch.setattr(testing, "_load_trade_days",
                            lambda: (_ for _ in ()).throw(OSError("timeout")))
        now = dt.datetime(2026, 8, 11, 8, 0)  # 周二 8 点
        assert latest_trade_date(now) == dt.date(2026, 8, 10)  # 周一

    def test_fallback_weekend_before_915(self, monkeypatch):
        """日历不可用 + 周六 9:15 前 → 周五。"""
        monkeypatch.setattr(testing, "_trade_days_cache", None)
        monkeypatch.setattr(testing, "_load_trade_days",
                            lambda: (_ for _ in ()).throw(OSError("timeout")))
        now = dt.datetime(2026, 8, 15, 8, 0)  # 周六 8 点（< 9:15）
        assert latest_trade_date(now) == dt.date(2026, 8, 14)

    def test_csv_data_source_live(self, monkeypatch):
        """活网：用真实 CSV/API 数据源验证当前日期合理（不 mock）。"""
        monkeypatch.setattr(testing, "_trade_days_cache", None)  # 清缓存走真实加载
        result = latest_trade_date()
        # 结果必须是工作日（周一~周五）
        assert result.weekday() < 5
        # 结果不能是未来
        assert result <= dt.date.today()

