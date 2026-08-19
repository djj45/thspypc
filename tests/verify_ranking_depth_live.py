#!/usr/bin/env python
"""Market-hours verification for the page-982 ranking depth bucket.

IMPORTANT: the Level2 account allows only one client session.  Fully exit the
official hexin client before running this script.  The script calls
``get_client()`` exactly once and reuses its managed SH_L2/SZ_L2 socket for the
entire set -> push -> delta -> push -> clear lifecycle.

Examples::

    py tests/verify_ranking_depth_live.py --market 17 \
        --codes 600519,600000,600036 --add 600009 --remove 600000
    py tests/verify_ranking_depth_live.py --market 33 \
        --codes 000001,000002,000063 --add 000333 --remove 000002
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


def _codes(value: str) -> list[str]:
    return list(
        dict.fromkeys(code.strip() for code in value.split(",") if code.strip())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=".env", help="credential env file")
    parser.add_argument("--market", type=int, choices=(17, 33), required=True)
    parser.add_argument("--codes", required=True, help="initial comma-separated codes")
    parser.add_argument("--add", default="", help="delta AddCode values")
    parser.add_argument("--remove", default="", help="delta DelCode values")
    parser.add_argument("--seconds", type=float, default=40.0)
    parser.add_argument(
        "--no-query",
        action="store_true",
        help="send only CodeList management, omit the captured page-982 field query",
    )
    args = parser.parse_args()
    initial = _codes(args.codes)
    add = _codes(args.add)
    remove = _codes(args.remove)
    if not initial or any(not code.isdigit() for code in (*initial, *add, *remove)):
        parser.error("all code arguments must contain numeric stock codes")
    if not 10 <= args.seconds <= 300:
        parser.error("--seconds must be between 10 and 300")
    expected_prefix = "6" if args.market == 17 else ("0", "3")
    if any(not code.startswith(expected_prefix) for code in (*initial, *add, *remove)):
        parser.error("codes do not match --market 17(SH) / 33(SZ)")

    counts: collections.Counter[str] = collections.Counter()
    latest: dict[str, dict] = {}
    client = None
    registered = False
    try:
        client = get_client(ROOT / args.env)
        query_datatype = () if args.no_query else None
        kwargs = {} if query_datatype is None else {"query_datatype": query_datatype}
        size = client.ranking_depth_subscribe(
            initial,
            market=args.market,
            **kwargs,
        )
        registered = True
        print(f"SET acknowledged CodeListSize={size}: {','.join(initial)}")

        split_at = time.monotonic() + args.seconds / 2
        deadline = time.monotonic() + args.seconds
        delta_done = False
        active = set(initial)
        while time.monotonic() < deadline:
            if not delta_done and time.monotonic() >= split_at:
                if add or remove:
                    size = client.ranking_depth_update(
                        add=add,
                        remove=remove,
                        market=args.market,
                    )
                    active.difference_update(remove)
                    active.update(add)
                    print(
                        f"DELTA acknowledged CodeListSize={size}: "
                        f"add={add or '-'} remove={remove or '-'}"
                    )
                delta_done = True
            record = client.receive_depth(
                timeout=min(1.0, max(0.0, deadline - time.monotonic()))
            )
            if record is None:
                continue
            code = record.get("code", "")
            counts[code] += 1
            latest[code] = record

        all_ok = True
        for code in sorted(active):
            record = latest.get(code) or client.latest_depth(code)
            bids = record.get("bids", []) if record else []
            asks = record.get("asks", []) if record else []
            ok = counts[code] > 0 and record is not None
            if record and record.get("phase") == "continuous":
                ok = ok and len(bids) == 10 and len(asks) == 10
            all_ok &= ok
            print(
                f"{code}: {'OK' if ok else 'BAD'} pushes={counts[code]} "
                f"phase={record.get('phase') if record else None} "
                f"bids={len(bids)} asks={len(asks)}"
            )
        return 0 if all_ok else 1
    finally:
        if client is not None and registered:
            try:
                size = client.ranking_depth_clear(market=args.market)
                print(f"CLEAR acknowledged CodeListSize={size}")
            except Exception as exc:  # noqa: BLE001
                print(f"CLEAR failed during teardown: {exc}", file=sys.stderr)
        close_all_clients()


if __name__ == "__main__":
    raise SystemExit(main())
