#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""检查抓包各 8901 流的 login 是否使用同一 Passport64。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def main():
    for pcap_name in (
        "system_blocks_20260801_132302.pcap",
        "system_blocks_20260801_132439.pcap",
    ):
        pcap = ROOT / "captures_live" / pcap_name
        out = _run([
            TSHARK, "-r", str(pcap), "-Y", "tcp.port==8901",
            "-T", "fields", "-e", "tcp.stream", "-e", "tcp.dstport",
            "-e", "tcp.payload",
        ])
        passports = {}
        identities = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            sid, dport, hexp = parts[:3]
            try:
                sid = int(sid)
            except ValueError:
                continue
            if dport != "8901":
                continue
            hexp = "".join(hexp.split())
            if not hexp:
                continue
            data = bytes.fromhex(hexp)
            for sub in data.split(MAGIC):
                if len(sub) < 8:
                    continue
                try:
                    blen = int(sub[:8], 16)
                except ValueError:
                    continue
                fb = sub[8:8 + blen]
                if b"Passport64=" not in fb:
                    continue
                p64 = fb.split(b"Passport64=", 1)[1].split(b"\n", 1)[0]
                passports.setdefault(sid, p64[:24])
                txt = fb.decode("gbk", errors="replace")
                identity = "no-user" if "UserName=" not in txt else (
                    "manual" if "__manual" in txt else "thsuser"
                )
                identities[sid] = identity
        print(f"===== {pcap_name} =====")
        uniq = set(passports.values())
        print(f"  不同 Passport64 前缀数: {len(uniq)} {sorted(uniq)[:3]}")
        for sid in sorted(passports):
            print(f"  stream {sid}: {passports[sid]}... [{identities.get(sid)}]")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
