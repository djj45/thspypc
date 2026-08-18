#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""从既有同花顺客户端抓包中挖掘 type-02 订阅帧（按列刷新/订阅推送候选）。

特征（2026-08-18 会话内发现）：帧 body 偏移 [9:11] = 02 00，随后 'V'(0x56)
+ LE32 长度。当时只识别了形态未逆向。本探针统计全部帧签名，定位 02 00 V
族帧并导出完整样本供离线分析。

探针：不入库（tests/_*.py 约定）。pcap 含登录/账户流量，仅本地分析。
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPDIR = os.path.join(ROOT, "captures_live")
OUT = os.path.join(CAPDIR, "_type02_frames_dump.txt")
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

# 同花顺客户端（非 thspypc）的看盘/切股抓包
CANDIDATES = [
    "fast_switch_20260813_013906.pcapng",
    "index_push_20260805_140642.pcapng",
    "bse_920083_20260815_101552.pcapng",
]
CANDIDATES += sorted(
    f for f in os.listdir(CAPDIR)
    if re.fullmatch(r"kanpan_2026080[4-7].*\.pcap", f)
)


def _payloads(pcap: str, port: int):
    """按 tcp 流、按方向取拼接 payload（捕获顺序）。"""
    streams_raw = subprocess.run(
        [TSHARK, "-r", pcap, "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=600,
    ).stdout.decode("ascii", errors="replace")
    stream_ids = sorted({int(s) for s in streams_raw.split() if s.isdigit()})
    for sid in stream_ids:
        for direction, filt in (
            ("C->S", f"tcp.stream=={sid} and tcp.dstport=={port}"),
            ("S->C", f"tcp.stream=={sid} and tcp.srcport=={port}"),
        ):
            hexp = subprocess.run(
                [TSHARK, "-r", pcap, "-Y", filt, "-T", "fields", "-e", "tcp.payload"],
                capture_output=True, timeout=600,
            ).stdout.decode("ascii", errors="replace").split()
            data = bytes.fromhex("".join(hexp)) if hexp else b""
            if data:
                yield sid, direction, data


def _walk_frames(data: bytes):
    """按 fd*4 + 8hex长度 切帧；坏长度就重新扫描 magic。"""
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


def is_type02(body: bytes) -> bool:
    return (
        len(body) >= 16
        and body[9] == 0x02
        and body[10] == 0x00
        and body[11] == 0x56  # 'V'
    )


def main():
    lines = []
    sig_hits = Counter()          # 签名 → 帧数
    sig_origin = defaultdict(list)  # 签名 → (来源, 样本帧)
    all_sigs = Counter()          # 全部帧签名（找邻居族用）

    for name in CANDIDATES:
        pcap = os.path.join(CAPDIR, name)
        if not os.path.exists(pcap):
            continue
        print(f"scan {name} ...", flush=True)
        for port in (8901, 9601):
            for sid, direction, data in _payloads(pcap, port):
                for body in _walk_frames(data):
                    sig = body[:16]
                    all_sigs[sig] += 1
                    if is_type02(body):
                        key = sig
                        sig_hits[key] += 1
                        if len(sig_origin[key]) < 3:
                            sig_origin[key].append(
                                (name, sid, direction, len(body), body)
                            )

    lines.append("== type-02 命中签名（body[:16]） ==")
    for sig, count in sig_hits.most_common():
        origins = sig_origin[sig]
        sizes = {o[3] for o in origins}
        lines.append(f"{sig.hex()}  帧数={count}  样本长度={sorted(sizes)}")
        for name, sid, direction, size, body in origins:
            lines.append(f"  [{name} stream={sid} {direction} len={size}]")
            lines.append(f"  head: {body[:64].hex()}")
            # 'V' 之后的 LE32 长度
            if len(body) >= 16:
                vlen = struct.unpack_from("<I", body, 12)[0]
                lines.append(f"  V后LE32={vlen}  body长={size}")
            lines.append(f"  hex: {body.hex()[:1200]}")
        lines.append("")

    lines.append("== 全帧签名 top40（含非命中，供族谱对照） ==")
    for sig, count in all_sigs.most_common(40):
        lines.append(f"{sig.hex()}  x{count}")

    text = "\n".join(lines)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text[:4000])
    print(f"\n完整结果已写入 {OUT}")


if __name__ == "__main__":
    sys.exit(main())
