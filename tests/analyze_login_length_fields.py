#!/usr/bin/env python
"""Verify that the alleged login ``account_type/K`` pair is length metadata.

This is an offline oracle: it reads captured 8901/9601 login frames and prints
only lengths and structural bytes.  Passport/signature/session values are never
printed.

Usage::

    py tests/analyze_login_length_fields.py captures_live/login_compare.pcap
    py tests/analyze_login_length_fields.py captures_live/*.pcapng
"""
from __future__ import annotations

import argparse
import base64
import os
import struct
import subprocess
from pathlib import Path


WIRESHARK_ROOT = (
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark"
)
TSHARK = os.path.join(WIRESHARK_ROOT, "tshark.exe")
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"
PASSPORT_MARKER = b"Passport64="


def _tcp_payloads(path: Path) -> list[bytes]:
    command = [
        TSHARK,
        "-r",
        str(path),
        "-Y",
        "(tcp.dstport==8901 or tcp.dstport==9601) and tcp.payload",
        "-T",
        "fields",
        "-e",
        "tcp.payload",
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        check=True,
        timeout=180,
    )
    payloads = []
    for line in result.stdout.decode("ascii", errors="ignore").splitlines():
        try:
            payloads.append(bytes.fromhex(line.strip().replace(":", "")))
        except ValueError:
            continue
    return payloads


def _frames(payload: bytes) -> list[bytes]:
    frames = []
    cursor = 0
    while True:
        start = payload.find(FRAME_MAGIC, cursor)
        if start < 0 or start + 12 > len(payload):
            return frames
        try:
            size = int(payload[start + 4:start + 12], 16)
        except ValueError:
            cursor = start + 4
            continue
        body_start = start + 12
        body_end = body_start + size
        if body_end <= len(payload):
            frames.append(payload[body_start:body_end])
        cursor = max(body_end, start + 4)


def analyze_body(body: bytes) -> dict[str, object] | None:
    ask = body.find(b"Ask=login")
    marker = body.find(PASSPORT_MARKER, ask)
    if ask < 0 or marker < 0 or ask < 15:
        return None
    value_start = marker + len(PASSPORT_MARKER)
    passport64 = body[value_start:].rstrip(b"\r\n")
    try:
        raw = base64.b64decode(passport64, validate=True)
    except ValueError:
        return None
    if len(raw) < 5:
        return None

    fixed_len = value_start - ask
    suffix = body[ask - 2:ask]
    suffix_value = struct.unpack("<H", suffix)[0]
    raw_declared = struct.unpack("<H", raw[:2])[0]
    raw_head_len = struct.unpack("<H", raw[3:5])[0]
    expected_suffix = fixed_len + len(passport64) + 1
    return {
        "identity": "STANDARD" if b"UserName=" in body[ask:value_start] else "shell",
        "fixed_len": fixed_len,
        "passport64_len": len(passport64),
        "raw_len": len(raw),
        "raw_declared_len": raw_declared,
        "raw_kind": raw[2],
        "raw_head_len": raw_head_len,
        "suffix": suffix.hex(" "),
        "suffix_value": suffix_value,
        "expected_suffix": expected_suffix,
        "raw_length_ok": raw_declared == len(raw),
        "suffix_length_ok": suffix_value == expected_suffix,
        "legacy_k": (suffix[0] - fixed_len) & 0xFF,
        "passport64_plus_one_low": (len(passport64) + 1) & 0xFF,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcaps", nargs="+", type=Path)
    args = parser.parse_args()
    failed = False
    for path in args.pcaps:
        rows = []
        seen = set()
        for payload in _tcp_payloads(path):
            for body in _frames(payload):
                row = analyze_body(body)
                if row is None:
                    continue
                key = tuple(row.items())
                if key not in seen:
                    seen.add(key)
                    rows.append(row)
        print(f"{path}: {len(rows)} unique login shapes")
        for row in rows:
            print("  " + " ".join(f"{key}={value}" for key, value in row.items()))
            failed |= not bool(row["raw_length_ok"] and row["suffix_length_ok"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
