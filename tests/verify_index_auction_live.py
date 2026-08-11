#!/usr/bin/env python
"""Live-check current-day index auction queries during 09:15-09:25.

This diagnostic deliberately calls ``get_client()`` once and reuses the same
``THSClient`` for every index and polling round.  Run it during the opening
auction; outside that window the endpoint may return an empty or completed
series and cannot validate live growth.

Usage::

    uv run python tests/verify_index_auction_live.py
    uv run python tests/verify_index_auction_live.py --repeat 3 --interval 10
    uv run python tests/verify_index_auction_live.py --env .env.normal
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.testing import close_all_clients, get_client  # noqa: E402


INDEX_CODES = ("1A0001", "399001", "399006")


def _summary(code: str, records: list[dict]) -> tuple[bool, set[str]]:
    if not records:
        print(f"  {code}: EMPTY")
        return False, set()
    markettimes = [str(record.get("markettime", "")) for record in records]
    unique_times = {value for value in markettimes if value}
    last = records[-1]
    ok = (
        len(unique_times) == len(markettimes)
        and last.get("auction_type") == "opening"
        and isinstance(last.get("dt10"), float)
        and isinstance(last.get("lead_price"), float)
        and isinstance(last.get("volume"), int)
    )
    mark = "OK" if ok else "BAD"
    print(
        f"  {code}: {mark} rows={len(records)} "
        f"time={markettimes[0]}..{markettimes[-1]} "
        f"newprice={last.get('dt10')} leadprice={last.get('lead_price')} "
        f"volume={last.get('volume')}"
    )
    return ok, unique_times


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=".env", help="credential env file")
    parser.add_argument("--repeat", type=int, default=2, help="polling rounds")
    parser.add_argument("--interval", type=float, default=10.0, help="seconds between rounds")
    parser.add_argument("--timeout", type=float, default=12.0, help="query timeout")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if not 0 <= args.interval <= 60:
        parser.error("--interval must be between 0 and 60 seconds")

    prior_times: dict[str, set[str]] = {}
    all_ok = True
    try:
        client = get_client(ROOT / args.env)
        for round_index in range(args.repeat):
            print(f"round {round_index + 1}/{args.repeat}")
            for code in INDEX_CODES:
                try:
                    records = client.auction(code, timeout=args.timeout)
                except Exception as exc:  # diagnostic: show every index failure
                    print(f"  {code}: ERROR {type(exc).__name__}: {exc}")
                    all_ok = False
                    continue
                ok, current_times = _summary(code, records)
                all_ok &= ok
                previous = prior_times.get(code)
                if previous is not None:
                    added = current_times - previous
                    print(f"         newly observed markettime values: {len(added)}")
                prior_times[code] = current_times
            if round_index + 1 < args.repeat:
                time.sleep(args.interval)
    finally:
        close_all_clients()
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
