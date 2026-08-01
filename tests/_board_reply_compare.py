#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""对比：我的 fu4 login 回复 vs 抓包 login 回复的完整字段。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.auth_protocol import LoginIdentity, build_login_body  # noqa: E402
from thspypc.protocol import MARKET_PORT  # noqa: E402


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


def captured_reply(pcap_name: str, sid: int) -> bytes:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              f"tcp.stream=={sid} and tcp.srcport==8901",
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
        if b"Reply=login" in fb:
            return fb
    return b""


def main():
    env = load_env(ROOT / ".env")
    client = THSClient(env["THS_USERNAME"], env["THS_PASSWORD"],
                       env.get("THS_IMEI") or None)
    client.authenticate()
    material = client._auth_service.require_current()
    body = build_login_body(
        material.passport64,
        client.mac64,
        identity=LoginIdentity.BOARD,
        profile=material.profile,
    )
    import socket as _socket
    pb = client._auth.get("passport_bytes", b"")
    if isinstance(pb, str):
        pb = pb.encode()
    ips = []
    for field in pb.split(b"|"):
        text = field.decode("gbk", errors="replace")
        if not text.startswith("M_hqdns="):
            continue
        for entry in text[len("M_hqdns="):].split(","):
            if not entry.startswith("fu4."):
                continue
            try:
                _, _, ips = _socket.gethostbyname_ex(entry.split(":", 1)[0])
            except OSError:
                continue
    host = ips[0]
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(body) + b"\n")
    mine = sock.recv(65536)
    sock.close()
    cap = captured_reply("system_blocks_20260801_132302.pcap", 2)
    print(f"host={host} mine={len(mine)}B captured={len(cap)}B")
    for tag, data in (("mine", mine), ("captured", cap)):
        txt = data.decode("gbk", errors="replace")
        print(f"--- {tag} ---")
        for line in txt.replace("\r\n", "\n").split("\n"):
            if line.strip():
                print("   ", line.strip()[:150])
    client.disconnect()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
