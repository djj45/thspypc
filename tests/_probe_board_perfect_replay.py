#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：完美重放——抓包旧票据 + 原样引导帧 + 抓包时序。

用法:
    py tests/_probe_board_perfect_replay.py                 # L2
    py tests/_probe_board_perfect_replay.py --env normal    # 普通
    py tests/_probe_board_perfect_replay.py --ip 47.101.213.41

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    parse_board_quote_response,
)
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


def extract(pcap_name: str, sid: int) -> list[bytes]:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              f"tcp.stream=={sid} and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    data = bytes.fromhex(hexp) if hexp else b""
    frames = []
    for sub in data.split(MAGIC):
        if len(sub) >= 8:
            try:
                blen = int(sub[:8], 16)
            except ValueError:
                blen = 0
            frames.append(sub[8:8 + blen])
    return frames


def summarize(fb: bytes) -> str:
    txt = fb.decode("gbk", errors="replace")
    if "hd3.1" in txt:
        return f"hd3.1 {len(fb)}B"
    if "rettype=ini" in txt:
        return f"init-reply {len(fb)}B"
    if "markettime=48" in txt:
        return f"hd1.0-board {len(fb)}B"
    if "errorcode" in txt:
        return f"error {len(fb)}B"
    if txt.strip():
        return f"text {len(fb)}B {txt[:50]!r}"
    return f"binary {len(fb)}B"


def read_all(sock: socket.socket, wait: float) -> list[bytes]:
    out = []
    deadline = time.time() + wait
    sock.settimeout(0.3)
    while time.time() < deadline:
        try:
            out.append(read_frame_quiet(sock))
        except (socket.timeout, OSError, ValueError):
            break
    return out


def read_frame_quiet(sock):
    from thspypc.protocol import read_frame
    return read_frame(sock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--ip", default="")
    args = parser.parse_args()
    if args.env == "l2":
        pcap, sid = "system_blocks_20260801_132302.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_5716.bin"
        captured_ip = "106.15.249.238"
    else:
        pcap, sid = "system_blocks_20260801_132439.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_392.bin"
        captured_ip = "122.9.78.232"
    frames = extract(pcap, sid)
    captured_login = frames[0]
    cap_passport = captured_login.split(b"Passport64=", 1)[1].split(b"\n", 1)[0]
    host = args.ip or captured_ip
    print(f"== {args.env} @ {host} 用抓包旧票据 + 原样帧 ==")
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(captured_login) + b"\n")
    reply = sock.recv(65536)
    vc = ""
    for line in reply.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1].strip()
    print(f"login: VerifyCode={vc} ({len(reply)}B)")
    if vc != "0":
        sock.close()
        return 1
    # 抓包时序：login 回复后 ~0.45s 发第一批，随后 0.26s/0.06s 分批
    groups = [
        ("B1 subreal×15+pageid", frames[1:17], 0.45),
        ("B2 MKT_INIT+qureal-init×10", frames[17:28], 0.26),
        ("B3 subreal+pageid+board-query", frames[28:47], 0.06),
        ("B4 qureal-poll+subreal+pageid", frames[47:56], 0.06),
        ("B5 [5],[55]+subreal+StockNameVer", frames[56:63], 0.1),
        ("B6 查询帧", [req_file.read_bytes()], 0.1),
    ]
    for tag, group, gap in groups:
        time.sleep(gap)
        payload = b"".join(group)
        print(f"--- {tag} ({len(payload)}B) ---")
        try:
            sock.sendall(payload)
        except OSError as e:
            print(f"  send 失败: {e}")
            break
        replies = read_all(sock, 0.6)
        for r in replies[:5]:
            print("  <-", summarize(r))
        if len(replies) > 5:
            print(f"  ... 共 {len(replies)} 帧")
        if not replies:
            print("  （无响应）")
    sock.close()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
