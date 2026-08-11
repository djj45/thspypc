#!/usr/bin/env python
"""Live-check multi-market Level2 depth event delivery during market hours.

The script calls ``get_client()`` once, subscribes one Shanghai and one Shenzhen
stock on the same ``THSClient``, consumes the dedicated depth queue, then removes
both local subscriptions.  It never performs a second login.

Usage::

    uv run python tests/verify_depth_push_live.py
    uv run python tests/verify_depth_push_live.py --codes 600519,000001 --seconds 45
"""
from __future__ import annotations

import argparse
import collections
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.testing import close_all_clients, get_client  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=".env", help="credential env file")
    parser.add_argument("--codes", default="600519,000001", help="comma-separated stock codes")
    parser.add_argument("--seconds", type=float, default=30.0, help="collection window")
    args = parser.parse_args()
    codes = list(dict.fromkeys(code.strip() for code in args.codes.split(",") if code.strip()))
    if not codes:
        parser.error("--codes must contain at least one stock code")
    if not 1 <= args.seconds <= 300:
        parser.error("--seconds must be between 1 and 300")

    callback_counts: collections.Counter[str] = collections.Counter()
    queue_counts: collections.Counter[str] = collections.Counter()
    latest: dict[str, dict] = {}
    subscribed: list[str] = []

    def on_depth(record: dict) -> None:
        callback_counts[record["code"]] += 1

    try:
        client = get_client(ROOT / args.env)
        for code in codes:
            if not client.depth_subscribe(code, callback=on_depth):
                print(f"{code}: registration rejected")
                continue
            subscribed.append(code)
            print(f"{code}: registered")
        if not subscribed:
            return 2

        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            record = client.receive_depth(timeout=min(1.0, deadline - time.monotonic()))
            if record is None:
                continue
            code = record["code"]
            queue_counts[code] += 1
            latest[code] = record

        all_ok = True
        for code in subscribed:
            record = latest.get(code) or client.latest_depth(code)
            bids = record.get("bids", []) if record else []
            asks = record.get("asks", []) if record else []
            ok = queue_counts[code] > 0 and callback_counts[code] > 0 and bool(record)
            if record and record.get("phase") == "continuous":
                ok = ok and len(bids) == 10 and len(asks) == 10
            all_ok &= ok
            print(
                f"{code}: {'OK' if ok else 'BAD'} queue={queue_counts[code]} "
                f"callback={callback_counts[code]} phase={record.get('phase') if record else None} "
                f"bids={len(bids)} asks={len(asks)}"
            )
        return 0 if all_ok else 1
    finally:
        client = locals().get("client")
        if client is not None:
            for code in subscribed:
                client.depth_unsubscribe(code)
        close_all_clients()


if __name__ == "__main__":
    raise SystemExit(main())
