#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""离线对照沪市集合竞价变长记录与 thsdk 真值。

本工具只用于协议逆向，不参与正式解析。它把同日 thsdk 的 ``当前量`` 当 oracle，
验证原始响应中的 dt49 载荷，并输出后续反推控制字节所需的逐 tick 信息。

2026-07-27 的两个 603118 样本揭示：dt49 不是每条都独立发送完整 LE24。
当值不变时字段整体省略；当最低若干 LE 字节与前值相同时，这段相同前缀也可省略，
只发送从首个变化字节到最高字节的后缀。控制字节仍可能插入该后缀中间。

用法::

    py tests/analyze_auction_varlen.py ^
      captures_live/auction_raw_603118_20260727_161716_r1.bin ^
      --oracle captures_live/_thsdk_auction_USHA603118_1785132093.json

    # 同时验证目录里的两份 2026-07-27 抓包
    py tests/analyze_auction_varlen.py ^
      captures_live/auction_raw_603118_20260727_*.bin ^
      --oracle captures_live/_thsdk_auction_USHA603118_1785132093.json ^
      --only-interesting
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import _auction_ts_in_range


TIME_KEY = "\u65f6\u95f4"
PRICE_KEY = "\u4ef7\u683c"
VOLUME_KEY = "\u5f53\u524d\u91cf"
TIME_MARKERS = (0x62, 0x66)


@dataclass(frozen=True)
class TimestampHit:
    timestamp: int
    offset: int


@dataclass(frozen=True)
class PayloadMatch:
    positions: tuple[int, ...]
    inserted: tuple[int, ...]

    @property
    def contiguous(self) -> bool:
        return not self.inserted


def parse_field_table_fmt(body: bytes) -> list[tuple[int, list[int]]]:
    """提取沪市变长帧字段表，兼容纯代码和带市场字节的个股壳。"""
    start = body.find(b"\x0a\x70\x04")
    if start < 0:
        return []

    shell_pos = -1
    for i in range(start + 2, min(len(body), start + 60)):
        if body[i] != 0x11:
            continue
        payload6 = body[i + 1:i + 7]
        payload7 = body[i + 1:i + 8]
        if re.fullmatch(rb"\d{6}", payload6) or re.fullmatch(
                rb"\d[A-Za-z]\d{5}", payload7):
            shell_pos = i
            break
    if shell_pos < 0:
        return []

    fields: list[tuple[int, list[int]]] = []
    current: list[int] = []
    for value in body[start:shell_pos]:
        if value == 0x04:
            if current:
                fields.append((current[0], current[1:]))
            current = []
        else:
            current.append(value)
    return fields


def scan_timestamps(body: bytes) -> list[TimestampHit]:
    """复现正式解析器的时间戳候选扫描及 3 秒节拍过滤。"""
    candidates: dict[int, int] = {}
    for offset in range(len(body) - 3):
        for marker in TIME_MARKERS:
            if marker not in body[offset + 2:offset + 4]:
                continue
            timestamp = (
                (0x6A << 24)
                | (marker << 16)
                | (body[offset + 1] << 8)
                | body[offset]
            )
            if _auction_ts_in_range(timestamp):
                candidates.setdefault(timestamp, offset)

    for offset in range(len(body) - 4):
        marker = body[offset + 3]
        if marker not in TIME_MARKERS:
            continue
        timestamp = (
            (0x6A << 24)
            | (marker << 16)
            | (body[offset + 2] << 8)
            | body[offset]
        )
        if _auction_ts_in_range(timestamp):
            candidates.setdefault(timestamp, offset)

    if not candidates:
        return []
    residues = Counter(timestamp % 3 for timestamp in candidates)
    cadence = residues.most_common(1)[0][0]
    return [
        TimestampHit(timestamp, candidates[timestamp])
        for timestamp in sorted(candidates)
        if timestamp % 3 == cadence
    ]


def unchanged_le_prefix(previous: bytes | None, current: bytes) -> int:
    """返回当前值与前值相同的低位（LE 前缀）字节数。"""
    if previous is None:
        return 0
    count = 0
    while count < len(current) and current[count] == previous[count]:
        count += 1
    return count


def locate_payload(record: bytes, payload: bytes, start: int = 3,
                   max_inserted: int = 2) -> PayloadMatch | None:
    """在记录内定位载荷，允许载荷字节间夹入少量控制字节。

    选择规则依次为：夹入字节最少、跨度最短、起点最靠前。这里刻意不把
    ``record.find`` 的偶然命中当唯一答案，方便查看控制字节穿过字段的样本。
    """
    if not payload:
        return PayloadMatch((), ())

    matches: list[PayloadMatch] = []

    def walk(payload_index: int, cursor: int, positions: list[int]) -> None:
        if payload_index == len(payload):
            first, last = positions[0], positions[-1]
            inserted = tuple(
                record[i]
                for i in range(first, last + 1)
                if i not in positions
            )
            if len(inserted) <= max_inserted:
                matches.append(PayloadMatch(tuple(positions), inserted))
            return

        remaining = len(payload) - payload_index
        max_pos = min(
            len(record) - remaining,
            (positions[0] + len(payload) + max_inserted - 1)
            if positions else len(record) - remaining,
        )
        for pos in range(cursor, max_pos + 1):
            if record[pos] == payload[payload_index]:
                walk(payload_index + 1, pos + 1, positions + [pos])

    walk(0, start, [])
    if not matches:
        return None
    return min(
        matches,
        key=lambda match: (
            len(match.inserted),
            match.positions[-1] - match.positions[0],
            match.positions[0],
        ),
    )


def load_oracle(path: Path) -> dict[int, dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("data", payload)
    return {int(row[TIME_KEY]): row for row in rows}


def record_windows(body: bytes, hits: list[TimestampHit]) -> dict[int, bytes]:
    """按物理 offset 切出记录；时间戳值排序不参与边界判断。"""
    by_offset = sorted((hit.offset, hit.timestamp) for hit in hits)
    result: dict[int, bytes] = {}
    for index, (offset, timestamp) in enumerate(by_offset):
        end = by_offset[index + 1][0] if index + 1 < len(by_offset) else len(body)
        result[timestamp] = body[offset:end]
    return result


def hex_bytes(data: bytes) -> str:
    return data.hex(" ") if data else "-"


def analyze(path: Path, oracle: dict[int, dict],
            only_interesting: bool = False) -> bool:
    body = path.read_bytes()
    hits = scan_timestamps(body)
    windows = record_windows(body, hits)
    fields = parse_field_table_fmt(body)
    matched_hits = [hit for hit in hits if hit.timestamp in oracle]

    print(f"\n=== {path} ({len(body)}B) ===")
    print(
        "fmt: "
        + ", ".join(
            f"dt{field}=[{','.join(f'0x{x:02x}' for x in fmt)}]"
            for field, fmt in fields
        )
    )
    print(
        f"timestamps: candidates={len(hits)} "
        f"oracle_matched={len(matched_hits)}"
    )
    print(
        "time      ts_off  vol       omit  payload   positions  inserted  "
        "dt10_candidate"
    )

    previous_volume: bytes | None = None
    omit_counts: Counter[int] = Counter()
    match_kinds: Counter[str] = Counter()
    failures: list[str] = []

    for hit in hits:
        row = oracle.get(hit.timestamp)
        if row is None:
            continue
        volume = int(row[VOLUME_KEY])
        volume_le = volume.to_bytes(4, "little")[:3]
        omitted = unchanged_le_prefix(previous_volume, volume_le)
        payload = volume_le[omitted:]
        record = windows[hit.timestamp]
        match = locate_payload(record, payload)
        omit_counts[omitted] += 1

        if not payload:
            kind = "field-omitted"
            positions_text = "-"
            inserted_text = "-"
            # 字段整体省略无法仅凭 oracle 证明记录中不存在同值的偶然字节，
            # 但前后两份不同 fmt 抓包均呈同样行为。
        elif match is None:
            kind = "not-found"
            positions_text = "!"
            inserted_text = "!"
            failures.append(
                f"{dt.datetime.fromtimestamp(hit.timestamp):%H:%M:%S} "
                f"payload={payload.hex()} record={record.hex()}"
            )
        else:
            kind = "contiguous" if match.contiguous else "control-inserted"
            positions_text = ",".join(str(pos) for pos in match.positions)
            inserted_text = hex_bytes(bytes(match.inserted))
        match_kinds[kind] += 1

        interesting = omitted > 0 or kind != "contiguous"
        if not only_interesting or interesting:
            first_payload_pos = (
                match.positions[0]
                if payload and match is not None and match.positions
                else len(record)
            )
            # dt10 位于时间戳与 dt49 载荷之间；此处只展示候选区，不猜解码。
            price_region = record[3:first_payload_pos]
            print(
                f"{dt.datetime.fromtimestamp(hit.timestamp):%H:%M:%S}  "
                f"{hit.offset:>6}  {volume:>8}  {omitted:>4}  "
                f"{hex_bytes(payload):<8}  {positions_text:<9}  "
                f"{inserted_text:<8}  {hex_bytes(price_region)}"
            )
        previous_volume = volume_le

    print(
        "summary: "
        f"omit_low_bytes={dict(sorted(omit_counts.items()))}; "
        f"matches={dict(match_kinds)}"
    )
    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  {failure}")
    return (
        len(matched_hits) == len(hits)
        and len(matched_hits) > 0
        and not failures
    )


def expand_inputs(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matches = [Path(value) for value in glob.glob(pattern)]
        paths.extend(matches or [Path(pattern)])
    return sorted(dict.fromkeys(paths))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="沪市竞价变长编码逐点 oracle 对照器"
    )
    parser.add_argument("captures", nargs="+", help=".bin 路径，可使用 glob")
    parser.add_argument("--oracle", required=True, type=Path,
                        help="同日 thsdk call_auction JSON")
    parser.add_argument(
        "--only-interesting",
        action="store_true",
        help="只打印字段省略或夹入控制字节的 tick",
    )
    args = parser.parse_args()

    oracle = load_oracle(args.oracle)
    paths = expand_inputs(args.captures)
    missing = [path for path in paths if not path.is_file()]
    if missing:
        for path in missing:
            print(f"missing capture: {path}", file=sys.stderr)
        return 2

    results = [
        analyze(path, oracle, only_interesting=args.only_interesting)
        for path in paths
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
