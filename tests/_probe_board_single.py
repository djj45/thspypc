#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：单次新鲜登录 + 单个 subreal 帧，观察服务器行为。

每次运行只做一次 HTTP 鉴权和一次 login（避免票据复用），逐个 IP 独立运行。

用法:
    py tests/_probe_board_single.py --ip 106.15.249.238        # .env（L2）
    py tests/_probe_board_single.py --env normal --ip 122.9.78.232
    py tests/_probe_board_single.py --all

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


def subreal_frame(channel: str, pageid: int) -> bytes:
    cls = {"URS": "URSI", "UCT": "UCTF", "UNX": "UNXF",
           "UCX": "UCXF", "UME": "UMEF"}.get(channel, channel + "I")
    text = (
        f"instid=2147483647\nmethod=subreal\nmarket={channel}\nperiod=0\n"
        f"action=change\nclass={cls}\ncodelist= \npageid={pageid}\n"
    ).encode("gbk")
    return b"\x09" + text


def run_case(client: THSClient, host: str, pageid: int, channel: str,
             delay: float) -> None:
    material = client._auth_service.require_current()
    login_body = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.settimeout(8.0)
    sock.sendall(encode_frame(login_body) + b"\n")
    try:
        reply = sock.recv(65536)
    except socket.timeout:
        print(f"  {host}: login 超时")
        sock.close()
        return
    rtxt = reply.decode("gbk", errors="replace")
    vc = pt = "?"
    for line in rtxt.replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1].strip()
        elif line.startswith("PromptText="):
            pt = line.split("=", 1)[1].strip()
    if vc != "0":
        print(f"  {host}: VerifyCode={vc} PromptText={pt!r}")
        sock.close()
        return
    sname = ""
    for line in rtxt.replace("\r\n", "\n").split("\n"):
        if line.startswith("S-Name="):
            sname = line.split("=", 1)[1].strip()
    print(f"  {host}: login OK [{sname}]，{delay}s 后发 {channel} subreal...")
    time.sleep(delay)
    frame = encode_frame(subreal_frame(channel, pageid))
    sock.sendall(frame + b"\n")
    sock.settimeout(4.0)
    got = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                print(f"  {host}: 服务器 FIN（subreal 后收到 {len(got)}B）")
                break
            got += chunk
            if len(got) > 262144:
                break
    except socket.timeout:
        print(f"  {host}: 4s 无响应（连接存活，已收 {len(got)}B）")
    except OSError as e:
        print(f"  {host}: recv 异常 {e}")
    if got:
        print(f"  {host}: 收到 {len(got)}B magic={got.count(MAGIC)} "
              f"head={got[:60].hex(' ')}")
    sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    parser.add_argument("--ip", default="")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        captured_ip = "106.15.249.238"
        pageid = 5716
    else:
        env = load_env(ROOT / ".env.normal")
        captured_ip = "122.9.78.232"
        pageid = 392

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    print(f"== {user} ({args.env}) 票据 {len(client._auth_service.require_current().passport64)}B ==")

    if args.all:
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
    else:
        hosts = [args.ip or captured_ip]
    for idx, host in enumerate(hosts):
        channel = "URS" if idx % 2 == 0 else "UCT"
        if idx > 0:
            # 每个 IP 用全新票据（同票据多连接触发 -300 票据消费保护）
            client._auth_service.authenticate()
            print(f"  （重新鉴权，新票据 {len(client._auth_service.require_current().passport64)}B）")
        run_case(client, host, pageid, channel, args.delay)
        time.sleep(1.0)
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
