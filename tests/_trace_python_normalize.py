#!/usr/bin/env python
"""Trace the Python normalize_8901_response port operation-by-operation."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def normalize_traced(body: bytes):
    if not body.startswith(b"\x0a"):
        return body, []

    payload = body[1:]
    expected_size = struct.unpack_from(">I", payload)[0]
    source = payload[4:] + b"\0" * 32
    output = bytearray(expected_size + 8)
    output[:4] = source[:4]
    output_pos = 4
    source_pos = 5
    control = source[4]
    bits_left = 8
    dictionary = [0] * 0x10000
    log: list[tuple] = []

    def read_bit():
        nonlocal control, bits_left, source_pos
        bit = bool(control & 0x80)
        control = (control << 1) & 0xFF
        bits_left -= 1
        if bits_left == 0:
            control = source[source_pos] if source_pos < len(source) else 0
            source_pos += 1
            bits_left = 8
        return bit

    def read_source_byte():
        nonlocal source_pos
        if source_pos >= len(source):
            return 0
        value = source[source_pos]
        source_pos += 1
        return value

    def history_key():
        value = (output[output_pos - 3] << 4) ^ output[output_pos - 2]
        return ((value << 7) ^ output[output_pos - 1]) & 0xFFFF

    def append_byte(value):
        nonlocal output_pos
        log.append(("literal", output_pos, value, source_pos - 1))
        output[output_pos] = value
        output_pos += 1

    def append_reference(reference_pos):
        nonlocal output_pos
        log.append(("reference", output_pos, output[reference_pos], reference_pos))
        output[output_pos] = output[reference_pos]
        output_pos += 1

    while output_pos < expected_size:
        if not read_bit():
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())
            continue

        if not read_bit():
            dictionary[history_key()] = output_pos
            append_byte(read_source_byte())

        key = history_key()
        reference = dictionary[key]
        dictionary[key] = output_pos
        append_reference(reference)

        if not read_bit():
            continue
        append_reference(reference + 1)

        fourth_bit = read_bit()
        fifth_bit = read_bit()
        if not fourth_bit:
            if fifth_bit:
                append_reference(reference + 2)
            continue

        append_reference(reference + 2)
        append_reference(reference + 3)
        if not fifth_bit:
            continue

        append_reference(reference + 4)
        sixth_bit = read_bit()
        if not sixth_bit:
            seventh_bit = read_bit()
            eighth_bit = read_bit()
            if seventh_bit:
                append_reference(reference + 5)
                append_reference(reference + 6)
                if eighth_bit:
                    append_reference(reference + 7)
            elif eighth_bit:
                append_reference(reference + 5)
            continue

        for offset in range(5, 9):
            append_reference(reference + offset)
        seventh_bit = read_bit()
        eighth_bit = read_bit()
        if not seventh_bit:
            if eighth_bit:
                append_reference(reference + 9)
            continue

        append_reference(reference + 9)
        append_reference(reference + 10)
        if not eighth_bit:
            continue
        append_reference(reference + 11)

        reference_pos = reference + 12
        while True:
            count = read_source_byte()
            for _ in range(max(0, count - 1)):
                if output_pos >= expected_size:
                    break
                append_reference(reference_pos)
                reference_pos += 1
            if count != 0xFF or source_pos >= len(source):
                break

    return bytes(output[:expected_size]), log


def main() -> int:
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    result, log = normalize_traced(raw)
    print(f"size={len(result)} log_entries={len(log)}")
    # show ops around output position 355-375
    for op, pos, value, src in log:
        if 350 <= pos <= 375:
            print(f"  {op} pos={pos} value=0x{value:02x} src={src}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
