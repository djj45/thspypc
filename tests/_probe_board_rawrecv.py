#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：登录 fu4 后发引导突发，直接 recv 原始字节看服务器是否回包。

用法:
    py tests/_probe_board_rawrecv.py                 # .env（L2）
    py tests/_probe_board_rawrecv.py --env normal    # .env.normal
    py tests/_probe_board_rawrecv.py --ip 106.15.249.238

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

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--ip", default="")
    parser.add_argument("--no-nl", action="store_true", help="帧间不加 \\n")
    parser.add_argument("--cap-passport", action="store_true",
                        help="用抓包里的旧 Passport64 登录")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="登录后到首组引导帧的延迟秒数")
    parser.add_argument("--groups", action="store_true",
                        help="按组发送，每组后 raw recv 定位断连帧")
    parser.add_argument("--per-frame", action="store_true",
                        help="逐帧发送（每帧单独 sendall + 小延时）")
    parser.add_argument("--only-login", action="store_true",
                        help="登录后不发任何引导帧，直接观察")
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
    host = args.ip or captured_ip
    captured_login = frames[0]
    cap_passport = captured_login.split(b"Passport64=", 1)[1].split(b"\n", 1)[0]
    if args.cap_passport:
        fixed, _, _ = login_body.partition(b"Passport64=")
        login_body = fixed + b"Passport64=" + cap_passport
        print("  ★ 使用抓包旧票据登录")
    print(f"== {user} @ {host} ==")
    print(f"  捕获票据长度 {len(cap_passport)}，本机票据长度 {len(material.passport64)}")
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(login_body) + b"\n")
    reply = sock.recv(65536)
    print(f"login reply {len(reply)}B:")
    rtxt = reply.decode("gbk", errors="replace")
    for line in rtxt.replace("\r\n", "\n").split("\n"):
        if line.strip():
            print(f"    {line.strip()[:160]}")
    if args.only_login:
        sock.settimeout(4.0)
        try:
            chunk = sock.recv(65536)
            print(f"  login 后收到 {len(chunk)}B: {chunk[:80]!r}" if chunk else "  login 后连接关闭")
        except socket.timeout:
            print("  login 后 4s 无数据（连接存活）")
        sock.close()
        client.disconnect()
        return 0
    burst = b"".join(fb + b"\n" for fb in frames[1:63]) + query + b"\n"
    if args.no_nl:
        burst = b"".join(frames[1:63]) + query
    if args.groups:
        if args.delay:
            print(f"等待 {args.delay}s 后发送...")
            time.sleep(args.delay)
        groups = [
            ("subreal×5", frames[1:6]),
            ("subreal×10", frames[6:16]),
            ("pageid", frames[16:17]),
            ("MKT_INIT", frames[17:18]),
            ("qureal-init×10", frames[18:28]),
            ("subreal+pageid", frames[28:46]),
            ("board-query", [query]),
            ("qureal-poll", frames[47:49]),
            ("[5],[55]+stockname", frames[56:57] + frames[62:63]),
        ]
        for tag, group in groups:
            if args.per_frame:
                payload = b"".join(
                    fb + (b"\n" if not args.no_nl else b"") for fb in group
                )
            else:
                payload = b"".join(
                    fb + (b"\n" if not args.no_nl else b"") for fb in group
                )
            print(f"--- 发送 {tag} ({len(payload)}B) ---")
            try:
                if args.per_frame:
                    for fb in group:
                        sock.sendall(fb + (b"\n" if not args.no_nl else b""))
                        time.sleep(0.15)
                else:
                    sock.sendall(payload)
            except OSError as e:
                print(f"  send 失败: {e}")
                break
            time.sleep(0.7 if not args.per_frame else 0.5)
            sock.settimeout(0.8)
            got = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        print("  ★ 服务器关闭连接")
                        sock.close()
                        client.disconnect()
                        return 0
                    got += chunk
                except socket.timeout:
                    break
                except OSError as e:
                    print(f"  recv 异常: {e}")
                    sock.close()
                    client.disconnect()
                    return 0
            if got:
                print(f"  收到 {len(got)}B magic={got.count(MAGIC)}")
            else:
                print("  （无响应）")
        sock.close()
        client.disconnect()
        return 0
    print(f"发送突发 {len(burst)}B")
    sock.sendall(burst)
    sock.settimeout(3.0)
    chunks = []
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                print("服务器关闭连接")
                break
            chunks.append(chunk)
            print(f"  recv {len(chunk)}B head={chunk[:16].hex(' ')}")
            if len(b"".join(chunks)) > 262144:
                break
    except socket.timeout:
        print("recv 超时（服务器无响应）")
    except OSError as e:
        print(f"recv 异常: {e}")
    total = b"".join(chunks)
    if total:
        print(f"共收到 {len(total)}B，magic 帧数: {total.count(MAGIC)}")
        print("  head:", total[:120].hex(" "))
    sock.close()
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
