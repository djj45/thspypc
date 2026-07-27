#!/usr/bin/env python
"""Recover the common byte skeleton of Shanghai auction wire variants.

Responses for the same completed auction use several stateful variable-length
encodings.  Their byte-level LCS exposes stable literals (header, field table,
stock code, and many values), but variant-only bytes are *not* necessarily
junk: some carry omission bitmaps or delta state.  Consequently this tool is
an evidence/diagnostic aid, not a decoder.

The primary alignment is byte based.  An experimental bit alignment is
retained only for checking whether a sample requires non-byte-aligned edits.
The tool writes no files.
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


def bits(data: bytes) -> str:
    return "".join(f"{value:08b}" for value in data)


def packed(bit_string: str) -> bytes:
    if len(bit_string) % 8:
        raise ValueError("bit string is not byte aligned")
    return bytes(
        int(bit_string[offset:offset + 8], 2)
        for offset in range(0, len(bit_string), 8)
    )


@dataclass(frozen=True)
class Removal:
    side: str
    bit_offset: int
    phase: int
    value: int


def align_bytes(
    left: bytes, right: bytes, band_bytes: int = 128
) -> tuple[bytes, list[Removal]]:
    """Find the minimum-deletion common stream on physical byte boundaries."""
    width = band_bytes * 2 + 1
    bias = band_bytes
    infinity = 0xFFFF
    costs: list[array] = []
    paths: list[bytearray] = []

    for i in range(len(left) + 1):
        row = array("H", [infinity]) * width
        path = bytearray(width)
        for index in range(width):
            k = index - bias
            j = i + k
            if j < 0 or j > len(right):
                continue
            best = infinity
            move = 0
            if i == 0 and j == 0:
                best = 0
            if (
                i > 0
                and j > 0
                and left[i - 1] == right[j - 1]
                and costs[i - 1][index] < best
            ):
                best = costs[i - 1][index]
                move = 1
            if i > 0 and index + 1 < width:
                candidate = costs[i - 1][index + 1]
                if candidate != infinity and candidate + 1 < best:
                    best = candidate + 1
                    move = 2
            if j > 0 and index > 0:
                candidate = row[index - 1]
                if candidate != infinity and candidate + 1 < best:
                    best = candidate + 1
                    move = 3
            row[index] = best
            path[index] = move
        costs.append(row)
        paths.append(path)

    end_index = len(right) - len(left) + bias
    if not 0 <= end_index < width or costs[-1][end_index] == infinity:
        raise ValueError(
            f"no byte insertion alignment inside ±{band_bytes} bytes"
        )

    logical_reverse = bytearray()
    removals_reverse: list[Removal] = []
    i = len(left)
    index = end_index
    while i or i + index - bias:
        k = index - bias
        j = i + k
        move = paths[i][index]
        if move == 1:
            logical_reverse.append(left[i - 1])
            i -= 1
        elif move == 2:
            removals_reverse.append(Removal("left", (i - 1) * 8, 0, left[i - 1]))
            i -= 1
            index += 1
        elif move == 3:
            removals_reverse.append(Removal("right", (j - 1) * 8, 0, right[j - 1]))
            index -= 1
        else:
            raise ValueError(f"broken byte DP path at left byte {i}, right byte {j}")

    logical_reverse.reverse()
    return bytes(logical_reverse), list(reversed(removals_reverse))


def variant_name(payload: bytes) -> str:
    """Name the five wire families observed on 2026-07-27."""
    if payload.startswith(b"hd1.0") and payload[6:9] == b"\xb4\x3a\x91":
        return "A"
    if payload.startswith(b"hd1.M0"):
        return "B"
    if payload.startswith(b"hd1.0") and len(payload) > 5 and payload[5] == 0x9B:
        return "C"
    if payload.startswith(b"hd1.0") and len(payload) > 5 and payload[5] == 0x99:
        return "D"
    if payload.startswith(b"hd1.L0"):
        return "E"
    return "unknown"


def align(left: str, right: str, band_bytes: int = 128) -> tuple[str, list[Removal]]:
    """Find the minimum-insertion alignment with exact 8-bit removals.

    ``i`` and ``j`` always have the same bit phase, so the DP only stores
    ``k = (j - i) / 8`` inside a narrow band instead of the full bit grid.
    """
    width = band_bytes * 2 + 1
    bias = band_bytes
    infinity = 0xFFFF
    costs: list[array] = []
    paths: list[bytearray] = []

    for i in range(len(left) + 1):
        row = array("H", [infinity]) * width
        path = bytearray(width)
        for index in range(width):
            k = index - bias
            j = i + 8 * k
            if j < 0 or j > len(right):
                continue

            best = infinity
            move = 0
            if i == 0 and j == 0:
                best = 0
            if (
                i > 0
                and j > 0
                and left[i - 1] == right[j - 1]
                and costs[i - 1][index] < best
            ):
                best = costs[i - 1][index]
                move = 1  # matching bit
            if i >= 8 and index + 1 < width:
                candidate = costs[i - 8][index + 1]
                if candidate != infinity and candidate + 1 < best:
                    best = candidate + 1
                    move = 2  # remove eight bits from left
            if j >= 8 and index > 0:
                candidate = row[index - 1]
                if candidate != infinity and candidate + 1 < best:
                    best = candidate + 1
                    move = 3  # remove eight bits from right
            row[index] = best
            path[index] = move
        costs.append(row)
        paths.append(path)

    delta = len(right) - len(left)
    if delta % 8:
        raise ValueError(f"stream lengths differ by {delta} bits, not whole bytes")
    end_index = delta // 8 + bias
    if not 0 <= end_index < width or costs[-1][end_index] == infinity:
        raise ValueError(
            f"no 8-bit insertion alignment inside ±{band_bytes} bytes"
        )

    logical_reverse: list[str] = []
    removals_reverse: list[Removal] = []
    i = len(left)
    index = end_index
    while i or i + 8 * (index - bias):
        k = index - bias
        j = i + 8 * k
        move = paths[i][index]
        if move == 1:
            logical_reverse.append(left[i - 1])
            i -= 1
        elif move == 2:
            offset = i - 8
            removed = left[offset:i]
            removals_reverse.append(
                Removal("left", offset, offset % 8, int(removed, 2))
            )
            i -= 8
            index += 1
        elif move == 3:
            offset = j - 8
            removed = right[offset:j]
            removals_reverse.append(
                Removal("right", offset, offset % 8, int(removed, 2))
            )
            index -= 1
        else:
            raise ValueError(f"broken DP path at left bit {i}, right bit {j}")

    return "".join(reversed(logical_reverse)), list(reversed(removals_reverse))


def hd_payload(path: Path) -> bytes:
    data = path.read_bytes()
    offset = data.find(b"hd1.")
    if offset < 0:
        raise ValueError(f"{path}: hd1. marker not found")
    return data[offset:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--band-bytes", type=int, default=1024)
    parser.add_argument(
        "--bit-aligned",
        action="store_true",
        help="experimental: permit removals at non-byte bit phases",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if len(args.captures) < 2:
        parser.error("at least two captures are required")

    payloads = [hd_payload(path) for path in args.captures]
    for path, payload in zip(args.captures, payloads):
        print(
            f"{path.name}: variant={variant_name(payload)} "
            f"payload={len(payload)}B head={payload[:20].hex(' ')}"
        )

    common = payloads[0]
    all_removals: list[Removal] = []
    compared_size = len(common)
    for payload in payloads[1:]:
        left = common
        right = payload
        compared_size = len(left)
        if args.bit_aligned:
            common_bits, removals = align(bits(left), bits(right), args.band_bytes)
            common = packed(common_bits)
        else:
            common, removals = align_bytes(left, right, args.band_bytes)
        all_removals.extend(removals)

    print(
        f"inputs={len(payloads)} last_left={compared_size}B "
        f"last_right={len(payloads[-1])}B "
        f"common_skeleton={len(common)}B edits={len(all_removals)}"
    )
    for side in ("left", "right"):
        group = [item for item in all_removals if item.side == side]
        phases = Counter(item.phase for item in group)
        values = Counter(item.value for item in group)
        print(
            f"{side}: removed={len(group)} phases={dict(sorted(phases.items()))} "
            f"top_values="
            + " ".join(f"{value:02x}:{count}" for value, count in values.most_common(12))
        )
    if args.verbose:
        for item in all_removals:
            print(
                f"{item.side:5} bit={item.bit_offset:5} "
                f"byte={item.bit_offset // 8:4} phase={item.phase} "
                f"value=0x{item.value:02x}"
            )
    print(f"common skeleton head: {common[:96].hex(' ')}")
    print(
        "warning: edits are variant-specific encoded state; "
        "do not delete them in the production parser"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
