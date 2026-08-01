#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：一次新鲜登录 + 帧间无多余 \\n 的完整引导 + 板块查询。

用法:
    py tests/_probe_board_clean.py --ip 8.134.146.31          # .env（L2）
    py tests/_probe_board_clean.py --env normal --ip 122.9.78.232

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

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.auth_protocol import LoginIdentity, build_login_body  # noqa: E402
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


def extract_frames(pcap_name: str, sid: int) -> list[bytes]:
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


def build_board_login(passport64: str, mac64: str, profile) -> bytes:
    if profile.supports_manual_identity:
        fields = [
            "Ask=login",
            f"C-Version={profile.tcp_version}",
            "VerifyType=1",
            f"Mac64={mac64}",
            "C-SupportPushVer=1.0",
            "C-SupReqDataVer=hq6.0",
            "C-SupPushDataVer=hq6.0",
        ]
        fixed = ("\n".join(fields) + "\nPassport64=").encode("gbk")
        suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    else:
        fixed = (
            "Ask=login\n"
            f"C-Version={profile.tcp_version}\n"
            "UserName=__manual\r\n\n"
            "Password=__manual\r\n\n"
            "VerifyType=1\n"
            f"Mac64={mac64}\n"
            "C-SupportPushVer=1.0\n"
            "C-SupReqDataVer=hq6.0\n"
            "C-SupPushDataVer=hq6.0\n"
            "Passport64="
        ).encode("gbk")
        suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + suffix
    return prefix + fixed + passport64.encode("ascii")


def summarize(fb: bytes) -> str:
    txt = fb.decode("gbk", errors="replace")
    if "hd3.1" in txt:
        return f"hd3.1 {len(fb)}B"
    if "rettype=ini" in txt:
        return f"init-reply {len(fb)}B"
    if "markettime=48" in txt:
        return f"hd1.0-board {len(fb)}B"
    if "errorcode" in txt:
        return f"error {len(fb)}B {txt[:60]!r}"
    if txt.strip():
        return f"text {len(fb)}B {txt[:60]!r}"
    return f"binary {len(fb)}B"


def read_all(sock: socket.socket, wait: float) -> list[bytes]:
    out = []
    deadline = time.time() + wait
    sock.settimeout(0.3)
    while time.time() < deadline:
        try:
            out.append(read_frame_quiet(sock))
        except socket.timeout:
            break
        except (OSError, ValueError):
            break
    return out


def read_frame_quiet(sock):
    from thspypc.protocol import read_frame
    return read_frame(sock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--identity", choices=("board", "standard", "manual"),
                        default="board")
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        pcap, sid = "system_blocks_20260801_132302.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_5716.bin"
        idx = dict(subreal=(1, 6), pageid=(16, 17), mkt=(17, 18),
                   qureal=(18, 28), classify=(56, 57), stockname=(62, 63))
    else:
        env = load_env(ROOT / ".env.normal")
        pcap, sid = "system_blocks_20260801_132439.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_392.bin"
        idx = dict(subreal=(1, 6), pageid=(22, 23), mkt=(31, 32),
                   qureal=(32, 42), classify=(65, 66), stockname=(84, 85))

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    if args.identity == "board":
        login_body = build_board_login(
            material.passport64,
            client.mac64,
            material.profile,
        )
    else:
        identity = (
            LoginIdentity.STANDARD
            if args.identity == "standard"
            else LoginIdentity.MANUAL
        )
        login_body = build_login_body(
            material.passport64,
            client.mac64,
            identity=identity,
            profile=material.profile,
        )
    frames = extract_frames(pcap, sid)
    query = req_file.read_bytes()
    print(f"== {user} ({args.env}) @ {args.ip} 票据{len(material.passport64)}B ==")
    sock = socket.create_connection((args.ip, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(login_body) + b"\n")
    reply = sock.recv(65536)
    rtxt = reply.decode("gbk", errors="replace")
    vc = ""
    for line in rtxt.replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1].strip()
    print(f"login: VerifyCode={vc} ({len(reply)}B)")
    if vc != "0":
        sock.close()
        client.disconnect()
        return 1

    steps = [
        ("subreal×5", frames[idx["subreal"][0]:idx["subreal"][1]]),
        ("pageid", frames[idx["pageid"][0]:idx["pageid"][1]]),
        ("MKT_INIT", frames[idx["mkt"][0]:idx["mkt"][1]]),
        ("qureal-init×10", frames[idx["qureal"][0]:idx["qureal"][1]]),
        ("[5],[55]", frames[idx["classify"][0]:idx["classify"][1]]),
        ("StockNameVer", frames[idx["stockname"][0]:idx["stockname"][1]]),
    ]
    for tag, group in steps:
        payload = b"".join(group)
        print(f"--- {tag} ({len(payload)}B, 无额外\\n) ---")
        try:
            sock.sendall(payload)
        except OSError as e:
            print(f"  send 失败: {e}")
            break
        replies = read_all(sock, 1.0)
        for r in replies[:6]:
            print("  <-", summarize(r))
        if len(replies) > 6:
            print(f"  ... 共 {len(replies)} 帧")
        if not replies:
            print("  （无响应）")
    print("--- 板块行情查询 ---")
    try:
        sock.sendall(query)
    except OSError as e:
        print(f"  send 失败: {e}")
        sock.close()
        client.disconnect()
        return 1
    replies = read_all(sock, 3.0)
    found = False
    for r in replies:
        recs = parse_board_quote_response(r)
        if recs:
            found = True
            print(f"  ✓✓ 0x130 {len(recs)} 条！first={recs[0].get('code')} "
                  f"{recs[0].get('name')} dt10={recs[0].get('dt10')}")
        else:
            print("  <-", summarize(r))
    if not found:
        print(f"  ✗ 无 0x130 数据（共 {len(replies)} 帧）")
    sock.close()
    client.disconnect()
    return 0 if found else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
