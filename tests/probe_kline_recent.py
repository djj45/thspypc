#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""打印指定股票最近 N 根 K线（日/周/月），供与同花顺客户端对比校准复权。

用法:
    py tests/probe_kline_recent.py --code 000938
    py tests/probe_kline_recent.py --code 000938 --periods week month --n 10
"""
from __future__ import annotations
import argparse, os, sys
from decimal import Decimal, ROUND_HALF_UP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient


def r2(v) -> str:
    """价格格式化：四舍五入到2位（Python 默认 :.2f 是银行家舍入，会和同花顺差 0.01）。"""
    if v is None:
        return "?"
    return str(Decimal(str(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def r0(v) -> str:
    """量额格式化：四舍五入到整数。"""
    if v is None:
        return "?"
    return str(int(Decimal(str(v)).quantize(Decimal("1"), rounding=ROUND_HALF_UP)))


def load_dotenv():
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(p): return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'").strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--code", default="000938")
    ap.add_argument("--periods", nargs="*", default=["day", "week", "month"])
    ap.add_argument("--n", type=int, default=10, help="打印最近N根")
    ap.add_argument("--count", type=int, default=336, help="请求的总根数")
    args = ap.parse_args()
    load_dotenv()
    u = os.environ.get("THS_USERNAME", "").strip()
    p = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    if not u or not p:
        print("✗ 缺少 THS_USERNAME/THS_PASSWORD"); return 1
    c = THSClient(u, p, imei)
    print(f"K线对比 {args.code}（最近 {args.n} 根，与同花顺客户端对照）\n")
    for period in args.periods:
        try:
            recs = c.kline(args.code, period=period, count=args.count)
        except Exception as e:
            print(f"{period:6s}: FAIL {e}\n"); continue
        recent = recs[-args.n:]
        print(f"=== {period}（共 {len(recs)} 根，显示末 {len(recent)} 根）===")
        for r in recent:
            t = r.get("time")
            ts = t.strftime("%Y-%m-%d") if hasattr(t, "year") else f"bar#{r.get('bar_index')}"
            print(f"  {ts}  O={r2(r.get('open'))}  H={r2(r.get('high'))}  "
                  f"L={r2(r.get('low'))}  C={r2(r.get('close'))}  "
                  f"量={r0(r.get('volume'))}  额={r0(r.get('amount'))}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
