#!/usr/bin/env python
"""Compare Shanghai auction hd1.0 wire variants record by record.

This is an offline reverse-engineering aid.  It deliberately does not call the
production parser: timestamps are used only as record anchors, then captures
of the same symbol are aligned by timestamp.  Bytes shared by two encodings
are likely payload; bytes unique to one encoding are likely control data.

Examples:

    py tests/reverse_auction_hd10.py 600519
    py tests/reverse_auction_hd10.py 603118 --limit 12
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path


TIME_KEY = "\u65f6\u95f4"
PRICE_KEY = "\u4ef7\u683c"
VOLUME_KEY = "\u5f53\u524d\u91cf"


@dataclass(frozen=True)
class Anchor:
    timestamp: int
    offset: int
    width: int


@dataclass
class Capture:
    path: Path
    body: bytes
    anchors: list[Anchor]
    records: dict[int, bytes]
    signature: str


def in_auction(ts: int, target_date: dt.date) -> bool:
    try:
        value = dt.datetime.fromtimestamp(ts)
    except (OSError, OverflowError, ValueError):
        return False
    seconds = value.hour * 3600 + value.minute * 60 + value.second
    return (
        value.date() == target_date
        and 9 * 3600 + 15 * 60 <= seconds <= 9 * 3600 + 25 * 60
    )


def timestamp_anchors(body: bytes, target_date: dt.date) -> list[Anchor]:
    """Find direct LE32 timestamps and the two observed one-byte insertions."""
    candidates: list[Anchor] = []
    for offset in range(len(body) - 3):
        raw = body[offset:offset + 4]
        ts = int.from_bytes(raw, "little")
        if in_auction(ts, target_date):
            candidates.append(Anchor(ts, offset, 4))

        # Observed shape: low0, control, low1, high0, high1.
        if offset + 5 <= len(body):
            raw = bytes((
                body[offset],
                body[offset + 2],
                body[offset + 3],
                body[offset + 4],
            ))
            ts = int.from_bytes(raw, "little")
            if in_auction(ts, target_date):
                candidates.append(Anchor(ts, offset, 5))

    # Real records are physically time ordered.  Pick the longest increasing
    # chain, which rejects accidental timestamp-looking payload bytes.
    candidates.sort(key=lambda item: (item.offset, item.width))
    best: list[list[Anchor]] = []
    for index, item in enumerate(candidates):
        chain = [item]
        for previous in range(index):
            prior = best[previous]
            if (
                prior[-1].offset + prior[-1].width <= item.offset
                and prior[-1].timestamp < item.timestamp
            ):
                proposal = prior + [item]
                if len(proposal) > len(chain):
                    chain = proposal
        best.append(chain)
    if not best:
        return []
    result = max(best, key=len)

    # A direct hit and an inserted hit can occasionally describe the same
    # timestamp at adjacent offsets.  Retain the narrower/direct form.
    dedup: dict[int, Anchor] = {}
    for item in result:
        old = dedup.get(item.timestamp)
        if old is None or (item.width, item.offset) < (old.width, old.offset):
            dedup[item.timestamp] = item
    return sorted(dedup.values(), key=lambda item: item.offset)


def split_records(body: bytes, anchors: list[Anchor]) -> dict[int, bytes]:
    records: dict[int, bytes] = {}
    for index, item in enumerate(anchors):
        start = item.offset + item.width
        end = anchors[index + 1].offset if index + 1 < len(anchors) else len(body)
        records[item.timestamp] = body[start:end]
    return records


def signature(body: bytes) -> str:
    pos = body.find(b"hd1.")
    if pos < 0:
        return "no-hd1"
    return body[pos:pos + 28].hex()


def load_capture(path: Path) -> Capture:
    body = path.read_bytes()
    match = re.search(r"_(\d{8})_\d{6}", path.name)
    if match is None:
        raise ValueError(f"cannot infer trading date from {path.name}")
    target_date = dt.datetime.strptime(match.group(1), "%Y%m%d").date()
    anchors = timestamp_anchors(body, target_date)
    return Capture(
        path=path,
        body=body,
        anchors=anchors,
        records=split_records(body, anchors),
        signature=signature(body),
    )


def lcs_parts(left: bytes, right: bytes) -> tuple[bytes, bytes, bytes]:
    matcher = SequenceMatcher(None, left, right, autojunk=False)
    common = bytearray()
    left_only = bytearray()
    right_only = bytearray()
    left_pos = right_pos = 0
    for match in matcher.get_matching_blocks():
        left_only.extend(left[left_pos:match.a])
        right_only.extend(right[right_pos:match.b])
        common.extend(left[match.a:match.a + match.size])
        left_pos = match.a + match.size
        right_pos = match.b + match.size
    return bytes(common), bytes(left_only), bytes(right_only)


def load_oracle(code: str) -> dict[int, dict]:
    paths = sorted(glob.glob(f"captures_live/_thsdk_auction_USHA{code}_*.json"))
    if not paths:
        return {}
    payload = json.loads(Path(paths[-1]).read_text(encoding="utf-8"))
    return {int(row[TIME_KEY]): row for row in payload["data"]}


def nearest_oracle(oracle: dict[int, dict], timestamp: int) -> tuple[int, dict] | None:
    if not oracle:
        return None
    key = min(oracle, key=lambda value: abs(value - timestamp))
    if abs(key - timestamp) > 2:
        return None
    return key, oracle[key]


def short(data: bytes, width: int = 44) -> str:
    text = data.hex(" ")
    return text if len(text) <= width else text[:width] + "..."


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("code")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    paths = [
        Path(path)
        for path in sorted(
            glob.glob(f"captures_live/auction_raw_{args.code}_*.bin")
        )
    ]
    captures = [load_capture(path) for path in paths]
    by_signature: dict[str, list[Capture]] = defaultdict(list)
    for capture in captures:
        by_signature[capture.signature].append(capture)

    print(f"{args.code}: captures={len(captures)} variants={len(by_signature)}")
    representatives: list[Capture] = []
    for index, (_, group) in enumerate(by_signature.items(), 1):
        item = group[0]
        representatives.append(item)
        widths = Counter(anchor.width for anchor in item.anchors)
        print(
            f"  V{index}: n={len(group)} size={len(item.body)} "
            f"records={len(item.anchors)} ts_widths={dict(widths)} "
            f"file={item.path.name}"
        )
        print(f"      signature={short(bytes.fromhex(item.signature), 80)}")

    if len(representatives) < 2:
        print("Need at least two distinct wire variants.")
        return 1

    left, right = representatives[:2]
    shared_ts = sorted(set(left.records) & set(right.records))
    oracle = load_oracle(args.code)
    print(
        f"\ncompare: shared_timestamps={len(shared_ts)} "
        f"oracle_rows={len(oracle)}"
    )
    print(
        "time      left  right common  left-control       right-control      "
        "oracle(time,price,volume)"
    )

    left_extra: Counter[int] = Counter()
    right_extra: Counter[int] = Counter()
    for timestamp in shared_ts[:args.limit]:
        lrec = left.records[timestamp]
        rrec = right.records[timestamp]
        common, lextra, rextra = lcs_parts(lrec, rrec)
        left_extra.update(lextra)
        right_extra.update(rextra)
        truth = nearest_oracle(oracle, timestamp)
        if truth:
            oracle_ts, row = truth
            truth_text = (
                f"{dt.datetime.fromtimestamp(oracle_ts):%H:%M:%S},"
                f"{row.get(PRICE_KEY)},{row.get(VOLUME_KEY)}"
            )
        else:
            truth_text = "-"
        print(
            f"{dt.datetime.fromtimestamp(timestamp):%H:%M:%S}  "
            f"{len(lrec):>4}  {len(rrec):>5} {len(common):>6}  "
            f"{short(lextra):<18} {short(rextra):<18} {truth_text}"
        )
        print(f"          common={short(common, 110)}")

    print("\nvariant-only byte frequencies:")
    print("  left :", " ".join(f"{key:02x}:{count}" for key, count in left_extra.most_common(16)))
    print("  right:", " ".join(f"{key:02x}:{count}" for key, count in right_extra.most_common(16)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
