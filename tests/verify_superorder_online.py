#!/usr/bin/env python
"""在线验证 client.superorder() 生产链路（period=7169 逐笔成交回放）。

确认仅凭 .env 的 level2 账号 + 网络，即可在线拿到逐笔成交回放记录。
覆盖沪深两市：深市 000938、沪市 603118。

默认查最近交易日尾盘 14:30-15:00（半小时，活跃度高，数据量适中）。
2026-08-06 活网验证通过：深市 48858 条、沪市 12010 条，价/方向/seq 全合理。

用法:
    py tests/verify_superorder_online.py                          # 默认 000938+603118 @ 最近交易日 14:30-15:00
    py tests/verify_superorder_online.py 000938                   # 只查深市
    py tests/verify_superorder_online.py 000938 2026-08-05        # 指定日期
    py tests/verify_superorder_online.py 603118 2026-08-05 14:00  # 指定日期 + 起点 14:00
"""
from __future__ import annotations

import os
import sys
import time
from datetime import date, datetime, time as dtime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402
from thspypc.features.auction_protocol import resolve_trade_date  # noqa: E402


def _summarize(tag: str, records: list[dict]) -> None:
    if not records:
        print(f"  [{tag}] ✗ 空（无逐笔数据）")
        return
    first = records[0]
    last = records[-1]
    prices = [r["price"] for r in records if isinstance(r.get("price"), (int, float))]
    dirs = {}
    for r in records:
        d = r.get("direction")
        dirs[d] = dirs.get(d, 0) + 1
    pmin = min(prices) if prices else 0
    pmax = max(prices) if prices else 0
    main_dirs = {k: v for k, v in dirs.items() if k in (1, 5)}
    other_n = sum(v for k, v in dirs.items() if k not in (1, 5))
    print(f"  [{tag}] n={len(records)}")
    print(f"    首: {first.get('time')} 价={first.get('price')} 量={first.get('volume')} 方向={first.get('direction')}")
    print(f"    末: {last.get('time')} 价={last.get('price')} 量={last.get('volume')} 方向={last.get('direction')}")
    print(f"    价区间: {pmin:.2f}-{pmax:.2f}  方向: {main_dirs} (其它 {other_n})")
    seqs = [r.get("seq", 0) for r in records]
    mono = sum(1 for i in range(1, len(seqs)) if seqs[i] == seqs[i - 1] + 1)
    print(f"    seq 相邻+1: {mono}/{len(seqs)-1}")


def main():
    args = sys.argv[1:]
    codes = ["000938", "603118"]
    trade_day = resolve_trade_date()   # 默认最近已收盘交易日
    start_hm = (14, 30)
    end_hm = (15, 0)
    # 解析命令行：code [date YYYY-MM-DD] [start HH:MM]
    if args:
        codes = [args[0]]
    if len(args) >= 2:
        trade_day = date.fromisoformat(args[1])
    if len(args) >= 3:
        h, m = args[2].split(":")
        start_hm = (int(h), int(m))

    username = os.environ.get("THS_USERNAME")
    password = os.environ.get("THS_PASSWORD")
    imei = os.environ.get("THS_IMEI")
    if not username or not password:
        envpath = ROOT / ".env"
        if envpath.exists():
            for ln in envpath.read_text().splitlines():
                if "=" in ln and not ln.strip().startswith("#"):
                    k, _, v = ln.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())
            username = os.environ.get("THS_USERNAME")
            password = os.environ.get("THS_PASSWORD")
            imei = os.environ.get("THS_IMEI")
    if not username or not password:
        print("✗ 缺少 THS_USERNAME / THS_PASSWORD（.env 或环境变量）")
        sys.exit(1)

    start = datetime.combine(trade_day, dtime(*start_hm))
    end = datetime.combine(trade_day, dtime(*end_hm))
    print(f"登录 level2 账号 {username[:4]}***")
    print(f"交易日 {trade_day}  区间 {start.strftime('%H:%M')}-{end.strftime('%H:%M')}")
    print()

    with THSClient(username, password, imei=imei) as client:
        for code in codes:
            print(f"{'='*60}")
            print(f"client.superorder({code!r}, {start.strftime('%m-%d %H:%M')}, {end.strftime('%H:%M')})")
            print(f"{'='*60}")
            t0 = time.time()
            try:
                records = client.superorder(code, start, end, timeout=25.0)
            except Exception as exc:
                print(f"  ✗ 失败: {type(exc).__name__}: {exc}")
                print()
                continue
            elapsed = time.time() - t0
            print(f"  耗时 {elapsed:.1f}s")
            _summarize(code, records)
            if records:
                print("  前 3 条:")
                for r in records[:3]:
                    print(f"    {r.get('time')} 价{r.get('price')} 量{r.get('volume')} 方向{r.get('direction')} seq{r.get('seq')}")
            print()


if __name__ == "__main__":
    main()
