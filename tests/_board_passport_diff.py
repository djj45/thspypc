#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""对比当前 HTTP 票据与抓包 login 帧里的旧票据字段。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.client import THSClient  # noqa: E402


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def load_env(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def captured_passport(pcap_name: str, sid: int) -> bytes:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
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
        if b"Passport64=" in fb:
            return fb.split(b"Passport64=", 1)[1].split(b"\n", 1)[0]
    return b""


def decode_fields(passport64: bytes) -> dict:
    try:
        raw = base64.b64decode(passport64)
    except Exception:
        return {}
    text = raw.decode("gbk", errors="replace")
    fields = {}
    for field in text.split("\r\n"):
        if "=" in field:
            k, _, v = field.partition("=")
            fields[k.strip()] = v.strip()
    return fields


def main():
    env = load_env(ROOT / ".env")
    client = THSClient(env["THS_USERNAME"], env["THS_PASSWORD"],
                       env.get("THS_IMEI") or None)
    client.authenticate()
    material = client._auth_service.require_current()
    cur = decode_fields(material.passport64.encode())
    old = decode_fields(captured_passport("system_blocks_20260801_132302.pcap", 2))
    print("字段对比（当前 vs 抓包旧票据）:")
    for key in sorted(set(cur) | set(old)):
        cv, ov = cur.get(key, "<无>"), old.get(key, "<无>")
        mark = "  " if cv == ov else "★"
        print(f"  {mark} {key:22s} cur={cv[:60]!r} old={ov[:60]!r}")
    client.disconnect()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
