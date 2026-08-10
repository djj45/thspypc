#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：仿 hexin 客户端「会话捆绑」——同时建 main/shlv2/szlv2/fu4
连接并登录，再对 fu4 发板块引导帧，验证服务器是否开始响应。

用法:
    py tests/_probe_board_bundle.py                 # .env（L2）
    py tests/_probe_board_bundle.py --env normal    # .env.normal

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
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


def resolve_group(client: THSClient, prefix: str) -> list[str]:
    import socket as _socket
    pb = client._auth.get("passport_bytes", b"")
    if isinstance(pb, str):
        pb = pb.encode()
    for field in pb.split(b"|"):
        text = field.decode("gbk", errors="replace")
        if not text.startswith("M_hqdns="):
            continue
        for entry in text[len("M_hqdns="):].split(","):
            if not entry.startswith(prefix):
                continue
            domain = entry.split(":", 1)[0]
            try:
                _, _, ips = _socket.gethostbyname_ex(domain)
            except OSError:
                continue
            return ips
    return []


def open_login(host: str, body: bytes, tag: str, result: dict) -> None:
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
        sock.settimeout(8.0)
        sock.sendall(encode_frame(body) + b"\n")
        resp = read_frame(sock)
        ok = "VerifyCode=0" in resp.decode("gbk", "replace")
    except (OSError, ValueError) as e:
        ok = False
        resp = b""
        result[tag] = (None, f"err {e}")
        return
    result[tag] = (sock, "ok" if ok else "login-fail")
    if not ok:
        sock.close()


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


def read_avail(sock: socket.socket, wait: float) -> list[bytes]:
    out = []
    deadline = time.time() + wait
    sock.settimeout(0.3)
    while time.time() < deadline:
        try:
            out.append(read_frame(sock))
        except (socket.timeout, OSError, ValueError):
            break
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
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
    material = client._auth_service.require_current()
    login_body = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )
    frames = extract_frames(pcap, sid)
    query = req_file.read_bytes()
    print(f"== {user} ({args.env}) ==")

    if args.env == "l2":
        groups = {
            "fu4": resolve_group(client, "fu4."),
            "shlv2": resolve_group(client, "shlv2."),
            "szlv2": resolve_group(client, "szlv2."),
            "main": resolve_group(client, "main.") or resolve_group(client, "ifindhq."),
        }
    else:
        groups = {
            "fu4": resolve_group(client, "fu4."),
            "main": resolve_group(client, "main.") or resolve_group(client, "ifindhq."),
        }
    print("  IP 组:", {k: v[:3] for k, v in groups.items()})

    # 并发建连 + 登录（仿 hexin 会话捆绑）
    targets = {}
    for tag, ips in groups.items():
        host = ips[0] if ips else ""
        if not host:
            continue
        targets[tag] = (host, login_body)
    results = {}
    threads = [
        threading.Thread(
            target=open_login,
            args=(host, body, tag, results),
            daemon=True,
        )
        for tag, (host, body) in targets.items()
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    for tag, (sock, status) in results.items():
        print(f"  [{tag}] {targets[tag][0]} -> {status}")

    fu4_sock = results.get("fu4", (None, ""))[0]
    if fu4_sock is None:
        print("fu4 登录失败")
        for sock, _ in results.values():
            if sock:
                sock.close()
        client.disconnect()
        return 1

    try:
        payload = b"".join(fb + b"\n" for fb in frames[1:6])
        print(f"发送 subreal×5 ({len(payload)}B)...")
        fu4_sock.sendall(payload)
        replies = read_avail(fu4_sock, 2.0)
        print(f"  subreal 后回复 {len(replies)} 帧")
        for r in replies[:5]:
            print("   <-", summarize(r))
        if not replies:
            payload = frames[17:18][0] + b"\n"
            print("发送 MKT_INIT...")
            fu4_sock.sendall(payload)
            replies = read_avail(fu4_sock, 2.0)
            print(f"  MKT_INIT 后回复 {len(replies)} 帧")
            for r in replies[:5]:
                print("   <-", summarize(r))
        print("发送板块行情查询...")
        fu4_sock.sendall(query + b"\n")
        replies = read_avail(fu4_sock, 3.0)
        print(f"  查询后回复 {len(replies)} 帧")
        found = False
        for r in replies:
            recs = parse_board_quote_response(r)
            if recs:
                found = True
                print(f"  ✓✓ 0x130 {len(recs)} 条，first={recs[0].get('code')} {recs[0].get('name')}")
            else:
                print("   <-", summarize(r))
        if not found and not replies:
            print("  （无任何回复）")
    except OSError as e:
        print(f"  连接异常: {e}")
    finally:
        for sock, _ in results.values():
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
