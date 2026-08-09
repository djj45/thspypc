"""Live Level2 7173/7174 verification without consuming Passport64 on MAIN.

Examples:
    pytest is not used; run as a script in a fresh process:
    python tests/verify_order_queue_online.py --env .env --code 688693 \
        --trade-date 2026-08-07
    python tests/verify_order_queue_online.py --env .env.normal \
        --expect-denied

The script performs HTTP auth once and lets the requested market L2 connection
be the first and only successful 8901 login for that passport generation.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc import THSClient  # noqa: E402
from thspypc.errors import CapabilityUnavailableError
from thspypc.testing import load_env


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default=".env")
    parser.add_argument("--code", default="688693")
    parser.add_argument("--trade-date")
    parser.add_argument("--expect-denied", action="store_true")
    args = parser.parse_args()

    env_path = load_env(Path(args.env))
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError(f"THS_USERNAME/THS_PASSWORD missing in {env_path}")

    client = THSClient(username, password, enable_heartbeat=False)
    try:
        # Deliberately do not call connect()/get_client(): MAIN must not consume
        # this passport before the single target-market L2 login.
        client.authenticate()
        try:
            queues = client.order_queues(
                args.code,
                trade_date=args.trade_date,
                timeout=15.0,
            )
        except CapabilityUnavailableError:
            if args.expect_denied:
                print("PASS: standard account rejected before L2 socket login")
                return 0
            raise
        if args.expect_denied:
            raise AssertionError("expected standard-account capability denial")

        for side in ("buy", "sell"):
            queue = queues[side]
            print(
                side,
                f"empty={queue.get('empty')}",
                f"price={queue.get('price')}",
                f"orders={queue.get('total_order_count')}",
                f"visible={queue.get('visible_count')}",
                f"major_orders={queue.get('visible_major_order_count')}",
                f"major_hands={queue.get('visible_major_hands')}",
                f"total_hands={queue.get('total_hands')}",
            )
        if args.trade_date == "2026-08-07" and args.code == "688693":
            buy, sell = queues["buy"], queues["sell"]
            assert sell["empty"] is True
            assert buy["price"] == 93.38
            assert buy["total_order_count"] == 700
            assert buy["visible_count"] == 49
            assert buy["visible_major_order_count"] == 4
            assert buy["visible_major_shares"] == 123_093
            assert buy["total_hands"] == 10_698
            print("PASS: 688693 matches the 2026-08-07 client screenshot")
        if args.trade_date == "2026-08-07" and args.code == "000779":
            buy, sell = queues["buy"], queues["sell"]
            assert buy["empty"] is True
            assert sell["price"] == 12.85
            assert sell["total_order_count"] == 7756
            assert sell["visible_count"] == 49
            assert sell["visible_major_order_count"] == 3
            assert sell["visible_major_shares"] == 1_258_898
            assert sell["total_hands"] == 145_824
            print("PASS: 000779 matches the 2026-08-07 client screenshot")
        return 0
    finally:
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
