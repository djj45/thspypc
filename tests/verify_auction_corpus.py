#!/usr/bin/env python
"""Measure Shanghai auction parser changes against the local thsdk corpus.

This is deliberately an offline regression tool.  It groups byte-identical
responses, runs the production parser once per unique response, and compares
timestamps/prices with the corresponding thsdk JSON truth.  It does not assume
a fixed three-second cadence.

Usage:
    py tests/verify_auction_corpus.py
    py tests/verify_auction_corpus.py 600276 601318
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.protocol import parse_auction_response


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "captures_live"


def oracle_rows(code: str) -> dict[int, tuple[float, int]]:
    paths = sorted(CAPTURES.glob(f"_thsdk_auction_USHA{code}_*.json"))
    if not paths:
        return {}
    payload = json.loads(paths[-1].read_text(encoding="utf-8"))
    result: dict[int, tuple[float, int]] = {}
    for row in payload["data"]:
        # The local SDK emitted mojibake field names on this machine, but its
        # stable column order is time, price, unmatched-buy, unmatched-sell,
        # current-volume.  Avoid baking mojibake spellings into the verifier.
        values = list(row.values())
        result[int(values[0])] = (float(values[1]), int(values[-1]))
    return result


def parsed_rows(data: bytes) -> dict[int, dict]:
    result: dict[int, dict] = {}
    for row in parse_auction_response(data):
        value = row.get("time")
        if isinstance(value, datetime):
            timestamp = int(value.timestamp())
        elif isinstance(value, (int, float)):
            timestamp = int(value)
        else:
            continue
        result[timestamp] = row
    return result


def variant(payload: bytes) -> str:
    pos = payload.find(b"hd1.")
    if pos < 0:
        return "no-hd1"
    head = payload[pos:pos + 10]
    if head.startswith(b"hd1.M0"):
        return "B"
    if head.startswith(b"hd1.L0"):
        return "E"
    if len(head) > 6 and head[5] == 0x9B:
        return "C"
    if len(head) > 6 and head[5] == 0x99:
        return "D"
    if head.startswith(b"hd1.0"):
        return "A/other"
    return head.hex()


def fmt_time(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")


def verify(code: str) -> bool:
    truth = oracle_rows(code)
    paths = sorted(CAPTURES.glob(f"auction_raw_{code}_*.bin"))
    if not truth or not paths:
        print(f"{code}: skipped (truth={len(truth)}, captures={len(paths)})")
        return False

    unique: dict[str, tuple[Path, bytes, int]] = {}
    for path in paths:
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest in unique:
            old_path, old_data, count = unique[digest]
            unique[digest] = (old_path, old_data, count + 1)
        else:
            unique[digest] = (path, data, 1)

    print(
        f"{code}: truth={len(truth)} captures={len(paths)} "
        f"byte_variants={len(unique)}"
    )
    all_exact = True
    for index, (_, (path, data, repeats)) in enumerate(unique.items(), 1):
        parsed = parsed_rows(data)
        truth_times = set(truth)
        parsed_times = set(parsed)
        missing = sorted(truth_times - parsed_times)
        extra = sorted(parsed_times - truth_times)
        shared = sorted(truth_times & parsed_times)
        price_ok = sum(
            parsed[ts].get("dt10") is not None
            and abs(float(parsed[ts]["dt10"]) - truth[ts][0]) < 0.0005
            for ts in shared
        )
        exact = not missing and not extra and price_ok == len(truth)
        all_exact &= exact
        print(
            f"  V{index} family={variant(data):7} repeats={repeats:2} "
            f"size={len(data):4} parsed={len(parsed):3} "
            f"time={len(shared)}/{len(truth)} "
            f"extra={len(extra)} price={price_ok}/{len(shared)} "
            f"sha256={hashlib.sha256(data).hexdigest()[:12]}"
        )
        if missing:
            print("    missing:", " ".join(fmt_time(ts) for ts in missing[:12]))
        if extra:
            print("    extra:  ", " ".join(fmt_time(ts) for ts in extra[:12]))

    gaps = Counter(
        right - left
        for left, right in zip(sorted(truth), sorted(truth)[1:])
    )
    print("  truth gaps:", " ".join(f"{gap}s x{count}" for gap, count in sorted(gaps.items())))
    return all_exact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("codes", nargs="*")
    args = parser.parse_args()
    codes = args.codes or sorted({
        path.name.split("_")[2]
        for path in CAPTURES.glob("auction_raw_*.bin")
    })
    results = [verify(code) for code in codes]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
