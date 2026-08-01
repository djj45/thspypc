#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：找到板块专用通道的最小必需引导序列。

方法：HTTP 鉴权 → 按账号身份打开独立 8901 连接 → 按阶段重放 pcap 引导帧
（subreal / pageid / MKT_INIT / qureal-init / [5],[55] / StockNameVer），
每阶段后重放抓包的板块行情请求帧，检查是否解析出 0x130 记录。

用法:
    py tests/_probe_board_bootstrap.py                 # .env（L2）
    py tests/_probe_board_bootstrap.py --env normal    # .env.normal

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import argparse
import os
import re
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
from thspypc.features.auth_protocol import build_passport64  # noqa: E402
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    parse_board_quote_response,
)
from thspypc.protocol import (  # noqa: E402
    MARKET_HOSTS,
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


def extract_frames(pcap_name: str, sid: int, lo: int, hi: int) -> list[bytes]:
    """用 tshark 从 pcap 提取 stream sid 的 [lo, hi) 客户端帧体。"""
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
    return [f for f in frames[lo:hi] if f]


def build_board_login(passport64: str, mac64: str, profile) -> bytes:
    """按账号 profile 构造板块通道 login（L2 无用户名；普通 __manual）。"""
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
        # 抓包普通板块通道 suffix=5e 07；先后退到计算式（与 L2 同风格）
        suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + suffix
    return prefix + fixed + passport64.encode("ascii")


def open_and_login(
    client: THSClient,
    login_body: bytes,
    *,
    offset: int = 0,
) -> tuple[socket.socket | None, int]:
    """开一条板块连接并 login；返回 (sock, 尝试数)。按 offset 轮换候选 IP。"""
    hosts = client._resolve_market_hosts(
        client._auth.get("passport_bytes", b"")
    )
    if not hosts:
        hosts = list(MARKET_HOSTS)
    probed = client._probe_fastest_hosts(hosts, timeout=1.0, role="board")
    candidates = probed or hosts
    if offset:
        candidates = candidates[offset:] + candidates[:offset]
    tried = 0
    for host in candidates:
        tried += 1
        try:
            sock = socket.create_connection((host, MARKET_PORT), timeout=15)
        except OSError:
            continue
        try:
            sock.sendall(encode_frame(login_body) + b"\n")
            sock.settimeout(8.0)
            resp = read_frame(sock)
        except (OSError, ValueError):
            sock.close()
            continue
        vc = ""
        for line in resp.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
            if line.startswith("VerifyCode="):
                vc = line.split("=", 1)[1]
        if vc == "0":
            print(f"  ✓ login OK @ {host}")
            return sock, tried
        print(f"  login {host} VerifyCode={vc}")
        sock.close()
    return None, tried


def drain(sock: socket.socket, seconds: float) -> int:
    """排空 sock 上已到达的帧（用短超时），返回帧数。"""
    sock.settimeout(0.2)
    n = 0
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            read_frame(sock)
            n += 1
        except (socket.timeout, OSError, ValueError):
            break
    return n


def try_board_query(sock: socket.socket, query: bytes, timeout: float = 3.0) -> list[dict]:
    """发板块行情查询，读若干帧，返回第一个解析出 0x130 记录的列表。"""
    sock.settimeout(1.0)
    sock.sendall(query + b"\n")
    sock.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError):
            break
        records = parse_board_quote_response(body)
        if records:
            return records
    return []


STAGES = {
    "l2": [
        ("A subreal+pageid+MKT_INIT", 1, 18),
        ("B +qureal-init×10", 1, 28),
        ("C +[5],[55]", 1, 57),
        ("D +StockNameVer", 1, 63),
    ],
    "normal": [
        ("A subreal+pageid+MKT_INIT", 1, 32),
        ("B +qureal-init×10", 1, 42),
        ("C +[5],[55]", 1, 66),
        ("D +StockNameVer", 1, 85),
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=("l2", "normal"), default="l2")
    args = parser.parse_args()

    if args.env == "l2":
        env = load_env(ROOT / ".env")
        pcap, sid = "system_blocks_20260801_132302.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_5716.bin"
    else:
        env = load_env(ROOT / ".env.normal")
        pcap, sid = "system_blocks_20260801_132439.pcap", 2
        req_file = ROOT / "captures_live" / "_board_req_list_392.bin"

    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    if not user or not pwd:
        print("缺少账号凭据")
        return 1

    print(f"== 账号 {user}（{args.env}）pcap={pcap} ==")
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    login_body = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )
    print(f"  login body {len(login_body)}B profile={material.profile.name}")

    query = req_file.read_bytes()
    print(f"  重放查询帧 {req_file.name} {len(query)}B")

    offset = 0
    for label, lo, hi in STAGES[args.env]:
        print(f"\n--- 阶段 {label} (frames {lo}-{hi}) ---")
        sock, tried = open_and_login(client, login_body, offset=offset)
        offset = (offset + tried) % max(1, len(client._probe_cache.get("board", (0, []))[1]) or 1)
        if sock is None:
            print("  ✗ login 失败，跳过")
            continue
        try:
            frames = extract_frames(pcap, sid, lo, hi)
            print(f"  重放 {len(frames)} 个引导帧")
            for fb in frames:
                sock.sendall(fb + b"\n")
            time.sleep(0.8)
            drained = drain(sock, 1.2)
            print(f"  排空 {drained} 帧")
            records = try_board_query(sock, query)
            if records:
                first = records[0]
                print(f"  ✓✓ 解析出 {len(records)} 条 0x130 记录！"
                      f" first={first.get('code')} {first.get('name')} dt10={first.get('dt10')}")
                sock.close()
                client.disconnect()
                print("\n最小引导集 =", label)
                return 0
            else:
                print("  ✗ 无 0x130 数据")
        finally:
            sock.close()

    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
