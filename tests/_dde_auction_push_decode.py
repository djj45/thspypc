#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""集合竞价阶段指数推送帧（097bd00f）字节级逆向工具。

从今天的竞价抓包中重组完整 THS 帧，提取所有 097bd00f 推送帧，按
(stream, 帧长) 聚类，并对 1A0001 / 399001 序列做字节差分，定位
撮合价 / 未匹配量 / 时间戳等字段位置。

用法::

    uv run python tests/_dde_auction_push_decode.py
"""
from __future__ import annotations

import collections
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from thspypc import decode_ths_float  # noqa: E402
from capture_index_push import (  # noqa: E402
    _packet_rows,
    reconstruct_frames,
    _find_tool,
)

PCAP = ROOT / "captures_live" / "index_push_20260811_091425.pcapng"
INDEX_MAGIC = b"\x09\x7b\xd0\x0f"


def collect_index_push_events(tshark, pcap):
    rows = _packet_rows(tshark, pcap)
    events = reconstruct_frames(rows)
    pushes = [e for e in events if e.direction == "S2C" and e.body[:4] == INDEX_MAGIC]
    return pushes


def main() -> int:
    tshark = _find_tool("tshark")
    pushes = collect_index_push_events(tshark, PCAP)
    print(f"=== {PCAP.name}: {len(pushes)} 个 097bd00f 推送帧 ===\n")

    # 1. 按 (stream, 帧长) 聚类
    by_len = collections.Counter()
    samples = {}
    for e in pushes:
        key = (e.stream, len(e.body))
        by_len[key] += 1
        if key not in samples:
            samples[key] = e
    print("[1] 帧长分布 (stream, len, count)")
    for (st, length), count in sorted(by_len.items(), key=lambda x: (x[0][0], -x[1])):
        print(f"  stream={st} len={length:>4} ×{count}")

    # 2. 对最大的两类（上证 stream0 / 深证 stream1 的主长度）取时间序列做差分
    #    先找各 stream 的主导帧长
    dominant = {}
    for (st, length), count in by_len.items():
        if count >= 5 and (st not in dominant or count > dominant[st][1]):
            dominant[st] = (length, count)
    print(f"\n[2] 各 stream 主导帧长: {dominant}")

    for st, (length, _) in dominant.items():
        seq = sorted([e for e in pushes if e.stream == st and len(e.body) == length],
                     key=lambda e: e.time)
        if len(seq) < 2:
            continue
        print(f"\n=== stream {st} len={length} 序列差分（前 6 帧）===")
        base = seq[0].body
        for e in seq[:6]:
            diff_bytes = [off for off in range(len(base)) if base[off] != e.body[off]]
            # 折叠成连续区间
            ranges = []
            for b in diff_bytes:
                if ranges and b == ranges[-1][1] + 1:
                    ranges[-1][1] = b
                else:
                    ranges.append([b, b])
            rstr = ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges)
            print(f"  t={e.time:7.1f}s 变化字节@[{rstr}]")

        # 3. 对前 80 字节做逐 4 字节 LE32 解码尝试（thd float），打印可能的数值字段
        print(f"\n  --- stream {st} 首帧逐 4B ths-float 解码（前 80B）---")
        b0 = seq[0].body
        for off in range(0, min(80, len(b0) - 3), 4):
            val = struct.unpack_from("<I", b0, off)[0]
            f = decode_ths_float(val)
            print(f"    off={off:>3} hex={b0[off:off+4].hex()} le32={val:#010x} thsfloat={f:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
