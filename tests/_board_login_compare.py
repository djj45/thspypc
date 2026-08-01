#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""对比 MAIN/板块通道的 login 帧前 32 字节 + 字段顺序，确认 identity 差异。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def first_login(pcap_name, sid):
    pcap = os.path.join(ROOT, "captures_live", pcap_name)
    hexp = "".join(
        _run([TSHARK, "-r", pcap, "-Y",
              f"tcp.stream=={sid} and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    data = bytes.fromhex(hexp) if hexp else b""
    for sub in data.split(MAGIC):
        if len(sub) < 8:
            continue
        try:
            blen = int(sub[:8], 16)
        except ValueError:
            continue
        fb = sub[8:8 + blen]
        if b"Ask=login" in fb:
            return fb
    return None


def summarize(tag, fb):
    print(f"--- {tag} ({len(fb)}B) ---")
    print(f"  head: {fb[:32].hex(' ')}")
    txt = fb.decode("gbk", errors="replace")
    m = re.search(r"Passport64=(\S*)", txt)
    p64 = m.group(1) if m else ""
    fields = txt.replace("Passport64=" + p64, "").replace("\r\n\n", "|\\r\\n\\n|").replace("\r\n", "|\\r\\n|").replace("\n", "|\\n|")
    print(f"  fields: {fields[:260]}")
    print(f"  passport64 len: {len(p64)}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    summarize("L2 MAIN s0", first_login("system_blocks_20260801_132302.pcap", 0))
    summarize("L2 BOARD s2", first_login("system_blocks_20260801_132302.pcap", 2))
    summarize("NORM MAIN s0", first_login("system_blocks_20260801_132439.pcap", 0))
    summarize("NORM BOARD s2", first_login("system_blocks_20260801_132439.pcap", 2))
