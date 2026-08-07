#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""盘中实时功能冒烟测试（2026-08-04 下午盘）。

覆盖：
  1. 指数分时（上证指数/深证成指）
  2. 个股分时（600519 / 000938）
  3. 短线精灵最新异动 dxjl_latest
  4. 热门股排序 stock_list_hot（涨幅榜）
  5. 板块指数行情 board_quotes（全量，按涨幅本地排序）
  6. 短线精灵实时推送 subscribe_realtime + receive_pushes

用法：
    uv run python live_check.py [--push 20]
"""
from __future__ import annotations

import datetime
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from thspypc import THSClient


def load_dotenv() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def _fmt(value, ndigits: int = 3) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.{ndigits}f}"
    except (TypeError, ValueError):
        return str(value)


def _pct(value) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):+.2f}%"
    except (TypeError, ValueError):
        return str(value)


def _section(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def check_timeline(client, label: str, code: str, market: int = 0) -> None:
    t0 = time.time()
    try:
        recs = client.timeline(code, market=market)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! {label} ({code}, mkt={market}) 失败: {exc}")
        return
    dt = time.time() - t0
    print(f"  {label} {code}: {len(recs)} 点, 耗时 {dt:.2f}s")
    if not recs:
        print("     (无数据)")
        return
    first, last = recs[0], recs[-1]
    for key in ("time", "minute_index", "dt10", "dt13", "dt19", "dt14", "bar_index"):
        if key in last:
            print(f"    最新 {key}={last[key]}", end="")
    print()
    print(f"    首点: {first}")
    print(f"    末点: {last}")


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    push_timeout = 20.0
    if "--push" in sys.argv:
        i = sys.argv.index("--push")
        if i + 1 < len(sys.argv):
            push_timeout = float(sys.argv[i + 1])

    now = datetime.datetime.now()
    print("=" * 64)
    print(f"盘中实时功能冒烟测试 @ {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"推送接收时长: {push_timeout:.0f}s")
    print("=" * 64)

    client = THSClient(username, password, imei)
    t0 = time.time()
    try:
        result = client.connect()
    except Exception as exc:  # noqa: BLE001
        print(f"!! 登录异常: {exc}")
        return 1
    if not result.success:
        print(f"!! 登录失败 (error={result.error}): {result.detail}")
        return 1
    print(f"  登录成功: {result.server} ({(time.time() - t0):.1f}s)")

    # 1. 指数分时
    _section("1. 指数分时")
    check_timeline(client, "上证指数", "1A0001", market=16)
    check_timeline(client, "深证成指", "399001", market=32)

    # 2. 个股分时
    _section("2. 个股分时")
    check_timeline(client, "贵州茅台", "600519", market=17)
    check_timeline(client, "紫光股份", "000938", market=33)

    # 2b. 板块指数分时/竞价（默认当日）
    _section("2b. 板块指数分时/竞价")
    for label, fn in (
        ("板块指数分时 881121", lambda: client.board_timeline("881121", timeout=15.0)),
        ("板块指数竞价 881121", lambda: client.board_auction("881121", timeout=15.0)),
    ):
        t0 = time.time()
        try:
            recs = fn()
            print(f"  {label}: {len(recs)} 条, 耗时 {time.time() - t0:.2f}s")
            if recs:
                last = recs[-1]
                print(f"    末点: {last}")
        except Exception as exc:  # noqa: BLE001
            print(f"  !! {label} 失败: {exc}")

    # 3. 短线精灵最新异动
    _section("3. 短线精灵最新异动 (dxjl_latest)")
    t0 = time.time()
    try:
        dxjl = client.dxjl_latest()
    except Exception as exc:  # noqa: BLE001
        print(f"  !! dxjl_latest 失败: {exc}")
        dxjl = []
    print(f"  返回 {len(dxjl)} 条, 耗时 {time.time() - t0:.2f}s")
    for rec in dxjl[:8]:
        keys = rec.keys()
        time_v = rec.get("时间") or rec.get("time") or ""
        code_v = rec.get("代码") or rec.get("code") or ""
        mkt_v = rec.get("市场") or ""
        typ = rec.get("异动类型") or rec.get("type") or ""
        amt = rec.get("金额") or ""
        pct = rec.get("涨跌幅") or ""
        print(f"    {time_v} mkt={mkt_v} {code_v} {typ} 金额={amt} 涨跌幅={pct}")

    # 4. 热门股排序（涨幅榜）
    _section("4. 热门股排序 (stock_list_hot, sort_by=199112 涨幅)")
    t0 = time.time()
    try:
        hot = client.stock_list_hot(count=29, sort_by=199112)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! stock_list_hot 失败: {exc}")
        hot = []
    print(f"  返回 {len(hot)} 条, 耗时 {time.time() - t0:.2f}s")
    for stock in hot[:10]:
        print(f"    {stock.get('code', '')} {stock.get('name', '')} {stock}")

    # 5. 板块指数行情（全量，按涨幅排序）
    _section("5. 板块指数行情 (board_quotes 全量, 本地按涨幅排序)")
    t0 = time.time()
    try:
        boards = client.board_quotes(None, timeout=50.0)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! board_quotes 失败: {exc}")
        boards = []
    print(f"  返回 {len(boards)} 个板块, 耗时 {time.time() - t0:.2f}s")
    valid = [b for b in boards if b.get("chg_pct") is not None]
    valid.sort(key=lambda b: float(b["chg_pct"]), reverse=True)
    print("  涨幅榜 Top 10:")
    for b in valid[:10]:
        print(
            f"    {b.get('code', '')} {b.get('name', '')} "
            f"{_pct(b.get('chg_pct'))} 价格={_fmt(b.get('price'))} "
            f"主力净流入={b.get('main_inflow')}"
        )
    print("  跌幅榜 Top 5:")
    for b in valid[-5:]:
        print(
            f"    {b.get('code', '')} {b.get('name', '')} {_pct(b.get('chg_pct'))}"
        )

    # 6. 短线精灵实时推送
    _section(f"6. 短线精灵实时推送 (subscribe + receive {push_timeout:.0f}s)")
    try:
        client.subscribe_realtime()
        print("  订阅已发送")
    except Exception as exc:  # noqa: BLE001
        print(f"  !! subscribe_realtime 失败: {exc}")
        client.disconnect()
        return 1

    push_count = [0]
    samples: list[str] = []

    def on_push(rec) -> None:
        push_count[0] += 1
        if len(samples) < 10:
            code = rec.get("代码") or rec.get("code") or ""
            mkt = rec.get("市场") or ""
            samples.append(f"{mkt} {code} {rec}")

    t0 = time.time()
    try:
        client.receive_pushes(timeout=push_timeout, callback=on_push)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! receive_pushes 失败: {exc}")
    elapsed = time.time() - t0
    n = push_count[0]
    print(f"  {elapsed:.1f}s 内收到 {n} 条推送 "
          f"(约 {n / elapsed:.1f} 条/秒)")
    for s in samples:
        print(f"    {s}")
    if n == 0:
        print("  (无推送：可能非交易时段或通道未就绪)")
    else:
        print("  -> 实时推送链路正常")

    client.disconnect()
    print("\n完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
