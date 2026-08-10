#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""用 tshark follow-stream（流重组）提取板块通道客户端字节，验证帧顺序。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def frames_from_payload(payload: bytes):
    frames = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            try:
                blen = int(sub[:8], 16)
            except ValueError:
                blen = 0
            frames.append(sub[8:8 + blen])
    return frames


def main():
    pcap = ROOT / "captures_live" / "system_blocks_20260801_132302.pcap"
    # 方法1：逐包拼接（与之前分析一致）
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              "tcp.stream==2 and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    joined = bytes.fromhex(hexp) if hexp else b""
    # 方法2：tshark 流重组（follow stream，raw hex）
    out = _run([
        TSHARK, "-r", str(pcap), "-q", "-z", "follow,tcp,raw,2",
    ])
    reasm = b""
    for line in out.splitlines():
        if re.fullmatch(r"[0-9A-Fa-f]{32,}", line.strip()):
            reasm += bytes.fromhex(line.strip())
    # follow,tcp,raw 同时含双向字节，需要拆客户端方向：找 login 之后的下一个
    # 服务器帧。简化：只比较两种方法各自的帧序列开头。
    f_join = frames_from_payload(joined)
    f_reasm = frames_from_payload(reasm)
    print(f"joined: {len(f_join)} frames, reassembled: {len(f_reasm)} frames")

    def brief(frames, n=22):
        out_lines = []
        for i, fb in enumerate(frames[:n]):
            txt = fb.decode("gbk", errors="replace")
            label = "login" if "Ask=login" in txt else (
                "subreal" if "subreal" in txt else (
                    "pageid" if "pageid=" in txt else (
                        "mkt-init" if "MarketCode" in txt else (
                            "qureal" if "qureal" in txt or "qustocklink" in txt else (
                                "query" if "CodeList=" in txt else "other")))))
            out_lines.append(f"  [{i:2d}] {len(fb):5d}B {label}")
        return "\n".join(out_lines)

    print("--- joined (逐包拼接) ---")
    print(brief(f_join))
    print("--- reassembled (follow stream) 前 2000 字节 ---")
    print(reasm[:2000].hex(" ") if reasm else "(空)")
    if len(reasm) > 2000:
        print("...")
        print(reasm[2000:4000].hex(" "))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
