#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""bse_920083_20260815（盘中 10:15）stream 时间线：02 00 <cmd> 命令族分类。

目标：识别 AddCode/DelCode 订阅族、无请求主动下发的推送帧（S->C 无对应
C->S 命令）、以及各 cmd 的方向/大小分布。探针：不入库。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPDIR = os.path.join(ROOT, "captures_live")
PCAP = os.path.join(CAPDIR, "bse_920083_20260815_101552.pcapng")
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _stream_payload(filt: str) -> bytes:
    hexp = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y", filt, "-T", "fields", "-e", "tcp.payload"],
        capture_output=True, timeout=600,
    ).stdout.decode("ascii", errors="replace").split()
    return bytes.fromhex("".join(hexp)) if hexp else b""


def _walk(data: bytes):
    pos = 0
    n = len(data)
    while pos + 12 <= n:
        idx = data.find(MAGIC, pos)
        if idx < 0 or idx + 12 > n:
            return
        try:
            length = int(data[idx + 4: idx + 12], 16)
        except ValueError:
            pos = idx + 1
            continue
        if not 0 < length <= 4_000_000 or idx + 12 + length > n:
            pos = idx + 1
            continue
        yield data[idx + 12: idx + 12 + length]
        pos = idx + 12 + length


def _snippet(body: bytes) -> str:
    txt = re.sub(rb"[^\x20-\x7e]", b".", body[:80]).decode("ascii")
    return txt


def main():
    streams_raw = subprocess.run(
        [TSHARK, "-r", PCAP, "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=600,
    ).stdout.decode()
    stream_ids = sorted({int(s) for s in streams_raw.split() if s.isdigit()})
    print(f"tcp 流: {stream_ids}")

    cmd_stats = defaultdict(Counter)   # (cmd) -> {方向: 帧数}
    cmd_sizes = defaultdict(list)
    lines = []
    for sid in stream_ids:
        for direction, filt in (
            ("C->S", f"tcp.stream=={sid} and tcp.dstport==8901"),
            ("S->C", f"tcp.stream=={sid} and tcp.srcport==8901"),
        ):
            data = _stream_payload(filt)
            n = 0
            for body in _walk(data):
                n += 1
                if len(body) >= 16 and body[9:11] == b"\x02\x00":
                    cmd = body[11]
                    cmd_stats[cmd][direction] += 1
                    cmd_sizes[cmd].append(len(body))
                    if len(lines) < 500:
                        lines.append(
                            f"s{sid} {direction} cmd=0x{cmd:02x} "
                            f"len={len(body)} :: {_snippet(body)}"
                        )
                elif len(body) >= 12 and body[8:10] in (b"\x00\x01", b"\x03\x00", b"\x01\x00"):
                    if len(lines) < 500:
                        b8 = body[8:10].hex()
                        lines.append(
                            f"s{sid} {direction} [{b8}] len={len(body)} :: {_snippet(body)}"
                        )
            print(f"stream {sid} {direction}: {n} 帧")

    print("\n== 02 00 <cmd> 命令分布 ==")
    for cmd in sorted(cmd_stats):
        c = cmd_stats[cmd]
        sizes = cmd_sizes[cmd]
        print(
            f"cmd=0x{cmd:02x} {'(V)' if cmd == 0x56 else '(T)' if cmd == 0x54 else ''}"
            f"  C->S={c['C->S']:4d}  S->C={c['S->C']:4d}"
            f"  长度 {min(sizes)}~{max(sizes)}"
        )

    print("\n== 时间线（前 400 行） ==")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
