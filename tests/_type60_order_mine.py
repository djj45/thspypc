#!/usr/bin/env python
"""Offline inspection of 0x60 order/cancel push candidates."""

import struct
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from _type60_mine import _frames  # noqa: E402
from _type60_verify import server_frames  # noqa: E402
from thspypc.codecs.numeric import decode_ths_float  # noqa: E402
from thspypc.features.superorder_protocol import (  # noqa: E402
    parse_order_queue_response,
)


TARGET_SUBTYPES = {0x08, 0x0C, 0x14, 0x18}


def _le32(body: bytes, offset: int):
    if offset + 4 > len(body):
        return None
    return struct.unpack_from("<I", body, offset)[0]


def main() -> None:
    candidates = [
        item
        for item in server_frames()
        if len(item[2]) > 5
        and item[2][:5] == b"\x09\x7b\xd0\x01\x60"
        and item[2][5] in TARGET_SUBTYPES
    ]
    print(f"count={len(candidates)}")
    for captured_at, stream, body in candidates:
        print(
            f"\n[{captured_at:9.3f}] stream={stream} "
            f"sub=0x{body[5]:02x} len={len(body)}"
        )
        print("offset 28:", body[28:].hex(" "))
        for offset in range(35, len(body) - 3):
            value = _le32(body, offset)
            if value is None:
                continue
            annotations = []
            if 1_700_000_000 <= value <= 1_900_000_000:
                annotations.append(datetime.fromtimestamp(value).isoformat())
            try:
                decoded = decode_ths_float(value)
            except (OverflowError, ValueError):
                decoded = None
            if decoded is not None and 1 <= decoded <= 1000:
                annotations.append(f"float={decoded:g}")
            if annotations:
                print(f"  le32@{offset:02d}={value:10d} {' '.join(annotations)}")

    print("\norder/cancel truth requests captured from the client:")
    for captured_at, stream, body in _frames("tcp.dstport==8901"):
        periods = [
            period
            for period in range(7170, 7176)
            if str(period).encode("ascii") in body
        ]
        if not periods:
            continue
        text = " ".join(body.decode("gbk", errors="replace").split())
        print(
            f"[{captured_at:9.3f}] stream={stream} periods={periods} "
            f"{text[:500]}"
        )

    print("\norder queue truth responses captured from the server:")
    for captured_at, stream, body in server_frames():
        parsed = parse_order_queue_response(body, side="buy")
        if parsed is None:
            continue
        print(
            f"[{captured_at:9.3f}] stream={stream} code={parsed['code']} "
            f"ts={parsed['ts']} price={parsed['price']} "
            f"meta={parsed['meta_value']} total={parsed['total_order_count']} "
            f"entries={[row['shares'] for row in parsed['entries']]}"
        )


if __name__ == "__main__":
    main()
