#!/usr/bin/env python
"""批量导出 thsdk oracle JSON，供 verify_auction_corpus.py 做逐点对照。

probe_thsdk_auction.py 一次只查一只；本脚本对六股各查一次，统一落盘到
captures_live/_thsdk_auction_<code>_<ts>.json。

字段名在本机是 mojibake，但列序稳定：time, price, unmatched-buy,
unmatched-sell, current-volume（verify_auction_corpus.oracle_rows 按位置取）。

用法:
    py tests/probe_thsdk_auction_batch.py
    py tests/probe_thsdk_auction_batch.py USHA603118 USHA600276
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from thsdk import THS

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "captures_live"

DEFAULT_CODES = [
    "USHA600276", "USHA600519", "USHA601318",
    "USHA603118", "USHA688825", "USHA688981",
]


def main() -> int:
    codes = sys.argv[1:] or DEFAULT_CODES
    ts = int(time.time())
    print(f"导出 thsdk oracle：{codes}\n")

    results = {}
    with THS() as ths:
        for code in codes:
            t0 = time.perf_counter()
            try:
                resp = ths.call_auction(code)
            except Exception as e:
                print(f"  {code}: 异常 {type(e).__name__}: {e}")
                results[code] = None
                continue
            elapsed = time.perf_counter() - t0
            data = resp.data if resp.error == "" else []
            n = len(data) if isinstance(data, list) else 0
            print(f"  {code}: n={n}  {elapsed:.2f}s  error={resp.error!r}")
            results[code] = data if n else None

    print()
    saved = []
    for code, data in results.items():
        if not data:
            print(f"  {code}: 跳过（无数据）")
            continue
        out = CAPTURES / f"_thsdk_auction_{code}_{ts}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"code": code, "data": data}, f, ensure_ascii=False, indent=2)
        print(f"  ✓ {out.name}  ({len(data)} 条)")
        saved.append(code)

    print(f"\n完成：{len(saved)}/{len(codes)} 只导出成功")
    return 0 if saved else 1


if __name__ == "__main__":
    raise SystemExit(main())
