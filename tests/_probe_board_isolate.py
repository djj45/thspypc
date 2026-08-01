#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：隔离测试——登录后单发各引导帧/组合，观察服务器是否响应。

用法:
    py tests/_probe_board_isolate.py                 # .env（L2）
    py tests/_probe_board_isolate.py --env normal    # .env.normal

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
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    parse_board_quote_response,
)
from thspypc.protocol import (  # noqa: E402
    MARKET_PORT,
    read_frame,
)


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
    if "Reply=login" in txt:
        return f"login-reply {len(fb)}B"
    if "markettime=48" in txt:
        return f"hd1.0/board {len(fb)}B"
    if "rettype=ini" in txt:
        return f"init-reply {len(fb)}B"
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
            out.append(read_frame(sock))
        except (socket.timeout, OSError, ValueError):
            break
    return out


def try_case(host: str, login_body: bytes, frames: list[bytes], tag: str,
             with_nl: bool) -> str:
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
        sock.settimeout(8.0)
        sock.sendall(encode_frame(login_body) + b"\n")
        resp = read_frame(sock)
        if "VerifyCode=0" not in resp.decode("gbk", "replace"):
            sock.close()
            return f"login fail ({len(resp)}B)"
    except (OSError, ValueError) as e:
        return f"login error: {e}"
    try:
        payload = b"".join(fb + (b"\n" if with_nl else b"") for fb in frames)
        sock.sendall(payload)
        replies = read_all(sock, 2.5)
        lines = " | ".join(summarize(r) for r in replies[:6])
        extra = f" +{len(replies)-6} more" if len(replies) > 6 else ""
        result = f"replies={len(replies)}: {lines}{extra}"
        for r in replies:
            recs = parse_board_quote_response(r)
            if recs:
                result += f" || 0x130={len(recs)} first={recs[0].get('code')}"
    except (OSError, ValueError) as e:
        result = f"send/recv error: {e}"
    try:
        sock.close()
    except OSError:
        pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--host", default="")
    parser.add_argument("--warm-main", action="store_true",
                        help="先建 MAIN 连接再测板块通道")
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        pcap, sid = "system_blocks_20260801_132302.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_5716.bin"
        captured_ip = "106.15.249.238"
    else:
        env = load_env(ROOT / ".env.normal")
        pcap, sid = "system_blocks_20260801_132439.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_392.bin"
        captured_ip = "122.9.78.232"

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    if args.warm_main:
        lr = client.connect_main()
        print(f"MAIN: success={lr.success} server={lr.server}")
    material = client._auth_service.require_current()
    login_body = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )
    frames = extract_frames(pcap, sid)
    query = req_file.read_bytes()
    if args.host:
        hosts = [args.host]
    else:
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
                domain = entry.split(":", 1)[0]
                try:
                    _, _, ips = _socket.gethostbyname_ex(domain)
                except OSError:
                    continue
        hosts = ips or [captured_ip]
    cases = [
        ("subreal×5+MKT_INIT+query", frames[1:6] + frames[17:18] + [query], True),
        ("full burst 1..63", frames[1:63], True),
    ]
    for host in hosts:
        print(f"\n== host={host} ==")
        for tag, group, with_nl in cases:
            print(f"  {tag:28s} -> {try_case(host, login_body, group, tag, with_nl)}")
            time.sleep(1.0)
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
