#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""离线核对 0x60/0x04 批量逐笔解码与 7169 活网真值。

只读取 ``kanpan_push_20260820_131534.pcap`` 和
``_type60_truth_603334.json``，不登录、不发送网络请求。
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.features.snapshot_protocol import (  # noqa: E402
    parse_trade_tick_batch_push,
)


TSHARK = (
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark\tshark.exe"
)
MAGIC = b"\xfd\xfd\xfd\xfd"
PCAP = str(ROOT / "captures_live" / "kanpan_push_20260820_131534.pcap")
TRUTH = ROOT / "captures_live" / "_type60_truth_603334.json"


def server_frames():
    result = subprocess.run(
        [
            TSHARK,
            "-r",
            PCAP,
            "-Y",
            "tcp.srcport==8901",
            "-T",
            "fields",
            "-e",
            "frame.time_relative",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.payload",
        ],
        capture_output=True,
        timeout=300,
        check=True,
    )
    frames = []
    for line in result.stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].strip():
            continue
        try:
            timestamp = float(parts[0])
            payload = bytes.fromhex(parts[2].replace(":", ""))
        except ValueError:
            continue
        offset = 0
        while True:
            start = payload.find(MAGIC, offset)
            if start < 0:
                break
            rest = payload[start + 4 :]
            if len(rest) < 8:
                break
            try:
                declared = int(rest[:8], 16)
            except ValueError:
                offset = start + 4
                continue
            body = rest[8 : 8 + declared]
            if len(body) == declared:
                frames.append((timestamp, parts[1], body))
            offset = start + 12 + declared
    return frames


def _matches_truth(record, truth, previous_truth) -> list[str]:
    checks = {
        "timestamp": truth["dt1"],
        "price": truth["price"],
        "volume": truth["dt10"],
        "direction": truth["dt13"],
        "delegate_a": truth["dt12"],
        "delegate_b": truth["dt74"],
        "seq": truth["seq"],
        "previous_trade_no": previous_truth["dt18"],
    }
    return [
        f"{name}: decoded={record.get(name)!r} truth={expected!r}"
        for name, expected in checks.items()
        if record.get(name) != expected
    ]


def main() -> int:
    if not TRUTH.is_file():
        print(f"缺少真值文件: {TRUTH}")
        return 2
    truth_rows = json.loads(TRUTH.read_text(encoding="utf-8"))
    truth = {row["seq"]: row for row in truth_rows}
    prefix = b"\x09\x7b\xd0\x01\x60\x04"
    batch_count = 0
    record_count = 0
    mismatches = []

    for captured_at, _stream, body in server_frames():
        if not body.startswith(prefix):
            continue
        if len(body) == 71:
            continue
        parsed = parse_trade_tick_batch_push(body)
        if parsed is None:
            continue
        records = parsed.get("records", [parsed])
        if parsed.get("event") == "trade_batch":
            batch_count += 1
        for record in records:
            seq = record["seq"]
            if seq not in truth or seq - 1 not in truth:
                continue
            record_count += 1
            problems = _matches_truth(record, truth[seq], truth[seq - 1])
            if problems:
                mismatches.append((captured_at, seq, problems))

    print(
        f"批量帧 {batch_count}/8，批量记录真值对照 {record_count}/33，"
        f"不一致 {len(mismatches)}"
    )
    for captured_at, seq, problems in mismatches:
        print(f"[{captured_at:.3f}s] seq={seq}")
        for problem in problems:
            print(f"  {problem}")
    if batch_count != 8 or record_count != 33 or mismatches:
        return 1
    print("OK: 8 个批量帧的全部 33 条记录与 7169 真值逐字段一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
