#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：逐组发送板块通道引导帧，观察服务器响应/断连，定位关键帧。

用法:
    py tests/_probe_board_stepwise.py                 # .env（L2）
    py tests/_probe_board_stepwise.py --env normal    # .env.normal

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
    if not path.exists():
        return result
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
        return "login-reply"
    if "method=init" in txt or "rettype=ini" in txt:
        return f"init-reply {len(fb)}B: {txt[:60]!r}"
    if "qureal" in txt:
        return f"qureal {len(fb)}B: {txt[:60]!r}"
    if "subreal" in txt:
        return f"subreal-reply {len(fb)}B"
    if "errorcode" in txt:
        return f"error {len(fb)}B: {txt[:70]!r}"
    if txt.strip():
        return f"text {len(fb)}B: {txt[:70]!r}"
    return f"binary {len(fb)}B"


def read_avail(sock: socket.socket, wait: float) -> list[bytes]:
    """在 wait 秒窗口内读取所有已到达的帧（短超时循环）。"""
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
    parser.add_argument("--host", default="")
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        pcap, sid = "system_blocks_20260801_132302.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_5716.bin"
        level2 = True
        captured_ip = "106.15.249.238"
    else:
        env = load_env(ROOT / ".env.normal")
        pcap, sid = "system_blocks_20260801_132439.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_392.bin"
        level2 = False
        captured_ip = "122.9.78.232"

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    if not user or not pwd:
        print("缺少账号凭据")
        return 1

    print(f"== {user} ({args.env}) ==")
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    login_body = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )

    candidates = _resolve_fu4_hosts(client)
    probed = client._probe_fastest_hosts(candidates, timeout=1.0, role="board")
    candidates = probed or candidates
    if args.host:
        candidates = [args.host]
    else:
        candidates = [captured_ip] + [
            ip for ip in candidates if ip != captured_ip
        ]
    sock = None
    for host in candidates:
        print(f"连接 {host} ...")
        try:
            sock = socket.create_connection((host, MARKET_PORT), timeout=15)
            sock.settimeout(8.0)
            sock.sendall(encode_frame(login_body) + b"\n")
            resp = read_frame(sock)
        except OSError as e:
            print(f"  连接/登录异常: {e}")
            sock.close()
            sock = None
            continue
        print("login:", summarize(resp))
        if "VerifyCode=0" in resp.decode("gbk", "replace"):
            break
        print("  login 失败，换 IP")
        sock.close()
        sock = None
    if sock is None:
        return 1

    frames = extract_frames(pcap, sid)
    for idx, fb in enumerate(frames[:20]):
        print(f"  frame[{idx}] len={len(fb)} head={fb[:12].hex(' ')}")
    print("  ...")
    groups = [
        ("subreal×5", frames[1:6]),
        ("subreal×10", frames[6:16]),
        ("pageid×3", frames[16:17]),
        ("MKT_INIT", frames[17:18]),
        ("qureal-init×10", frames[18:28]),
        ("subreal×5+pageid", frames[28:34]),
        ("subreal×5+pageid", frames[34:40]),
        ("subreal×5+pageid", frames[40:46]),
        ("board-list-query", frames[46:47]),
        ("qureal-poll", frames[47:49]),
        ("subreal+pageid", frames[49:56]),
        ("[5],[55]", frames[56:57]),
        ("subreal×5", frames[57:62]),
        ("StockNameVer", frames[62:63]),
        ("board-list-query-2", frames[63:64]),
    ]
    for label, group in groups:
        if not group:
            continue
        print(f"\n--- send {label} ({len(group)} frames) ---")
        try:
            for fb in group:
                sock.sendall(fb)
        except OSError as e:
            print(f"  ✗ send 失败: {e}（服务器已断连）")
            break
        replies = read_avail(sock, 1.0)
        if replies:
            for r in replies[:8]:
                print("  <-", summarize(r))
            if len(replies) > 8:
                print(f"  ... 共 {len(replies)} 帧")
        else:
            print("  （无响应）")
        if label in ("board-list-query", "board-list-query-2"):
            for r in replies:
                recs = parse_board_quote_response(r)
                if recs:
                    print(f"  ✓✓ 0x130 记录 {len(recs)} 条！"
                          f" first={recs[0].get('code')} {recs[0].get('name')}")

    sock.close()
    client.disconnect()
    return 0


def _resolve_fu4_hosts(client: THSClient) -> list[str]:
    """从 passport M_hqdns 提取 fu4（板块通道）域名并解析 IP。"""
    import socket as _socket
    pb = client._auth.get("passport_bytes", b"")
    if isinstance(pb, str):
        pb = pb.encode()
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
            print(f"  fu4 {domain} -> {ips}")
            return ips
    print("  ⚠ 无 fu4 域名，回退 ifindhq")
    return client._resolve_market_hosts(pb)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
