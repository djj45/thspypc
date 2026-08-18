#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""在现有抓包里找封单额(dt44)的来路：
1. 客户端请求：DataType 含 265260 / 44 或未编目的字段集
2. 响应帧：字段表含 dt44(0x2C) 条目的 hd 表
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / "captures_live" / "stocklist_page_20260818_185944.pcapng"
TSHARK = Path(
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark\tshark.exe"
)
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args, timeout=240):
    r = subprocess.run(args, capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(r.stderr.decode("utf-8", "replace")[:300])
    return r


def split_frames(blob: bytes):
    frames, off = [], blob.find(MAGIC)
    while off != -1:
        try:
            n = int(blob[off + 4 : off + 12], 16)
        except ValueError:
            off = blob.find(MAGIC, off + 1)
            continue
        if not 0 < n < 8 * 1024 * 1024:
            off = blob.find(MAGIC, off + 1)
            continue
        s, e = off + 12, off + 12 + n
        if e > len(blob):
            off = blob.find(MAGIC, off + 1)
            continue
        frames.append(blob[s:e])
        off = blob.find(MAGIC, e)
    return frames


def main() -> None:
    # 1) 全部客户端请求帧：收集 DataType 集合
    req = _run([
        str(TSHARK), "-r", str(PCAP), "-Y",
        "tcp.port==8901 and tcp.dstport==8901 and tcp.payload",
        "-T", "fields", "-e", "tcp.payload",
    ])
    dt_sets: Counter[tuple[int, ...]] = Counter()
    for line in req.stdout.decode("ascii", "replace").splitlines():
        try:
            payload = bytes.fromhex(line.replace(":", ""))
        except ValueError:
            continue
        for f in split_frames(payload):
            m = re.search(rb"DataType=([\d,\[\]]+?)\r?\n", f)
            if not m:
                continue
            ids = tuple(
                int(x)
                for x in re.sub(r"[\[\]]", "", m.group(1).decode()).split(",")
                if x
            )
            dt_sets[ids] += 1
    print(f"[请求 DataType 集合共 {len(dt_sets)} 种]")
    for ids, n in dt_sets.most_common():
        marks = []
        if 265260 in ids:
            marks.append("★265260封单")
        if 44 in ids:
            marks.append("★44")
        known = {
            5, 6, 7, 10, 17, 19, 48, 66, 49, 13, 461256, 70, 27, 127, 12, 69,
            33, 1968584, 2942, 592890, 25, 24, 31, 9, 3541450, 592888, 2947,
            30, 8, 45, 1111, 199112, 68758, 68762, 265260,
        }
        unknown = [i for i in ids if i not in known]
        if unknown:
            marks.append(f"未知:{unknown}")
        print(f"  x{n:<4} {len(ids)}列 {' '.join(marks)}")
        print(f"        {','.join(map(str, ids))}")

    # 2) 响应帧：字段表含 dt44 的 hd 表
    streams = _run([
        str(TSHARK), "-r", str(PCAP), "-T", "fields", "-e", "tcp.stream",
    ])
    stream_ids = sorted({s for s in streams.stdout.decode("ascii").split() if s})
    found = 0
    for st in stream_ids:
        try:
            fol = _run([
                str(TSHARK), "-r", str(PCAP), "-q", "-z", f"follow,tcp,raw,{st}",
            ], timeout=120)
        except RuntimeError:
            continue
        text = fol.stdout.decode("ascii", "replace")
        blob = bytes.fromhex("".join(re.findall(r"^\t?[0-9a-fA-F]+\r?$", text, re.M)))
        if len(blob) < 200:
            continue
        for idx, frame in enumerate(split_frames(blob)):
            for marker in (b"hd3.1\x00", b"hd1.0"):
                pos = frame.find(marker)
                if pos < 0:
                    continue
                base = pos + 6
                if len(frame) < base + 10:
                    continue
                fc = struct.unpack("<H", frame[base + 8 : base + 10])[0]
                ft = frame[base + 10 : base + 10 + fc * 4]
                dts = [ft[i * 4] for i in range(fc)] if len(ft) >= fc * 4 else []
                if 44 in dts and found < 6:
                    found += 1
                    print(
                        f"\n[响应含 dt44] stream={st} frame#{idx} marker={marker} "
                        f"fc={fc} dts={dts}"
                    )
                break
    if not found:
        print("\n[响应] 未发现字段表含 dt44 的 hd 表")


if __name__ == "__main__":
    main()
