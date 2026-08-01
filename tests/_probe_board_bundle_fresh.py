#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网探针：每通道独立新票据的并发捆绑建连（复刻抓包 7 连接会话组）。

用法:
    py tests/_probe_board_bundle_fresh.py                 # L2
    py tests/_probe_board_bundle_fresh.py --env normal    # 普通

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

TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.client import THSClient  # noqa: E402
from thspypc.codecs.framing import encode_frame  # noqa: E402
from thspypc.features.auth_protocol import LoginIdentity, build_login_body  # noqa: E402
from thspypc.protocol import (  # noqa: E402
    MARKET_PORT,
    read_frame,
    resolve_fu4_hosts,
    resolve_l2_hosts_grouped,
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


def login(host: str, body: bytes, results: dict, tag: str) -> None:
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=10)
        sock.settimeout(8.0)
        sock.sendall(encode_frame(body) + b"\n")
        resp = read_frame(sock)
        vc = ""
        for line in resp.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
            if line.startswith("VerifyCode="):
                vc = line.split("=", 1)[1].strip()
        if vc == "0":
            results[tag] = sock
        else:
            results[tag] = None
            sock.close()
    except Exception:
        results[tag] = None


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
    client = THSClient(username=user, password=pwd, imei=imei)
    print(f"== {user} ({args.env}) ==")

    # 每个通道独立 HTTP 鉴权拿新票据
    bodies = {}
    materials = {}
    for tag in ("main", "shlv2", "szlv2", "fu4"):
        material = client._auth_service.authenticate()
        materials[tag] = material
        if tag == "fu4":
            identity = LoginIdentity.BOARD
        elif tag in ("shlv2", "szlv2"):
            identity = LoginIdentity.MANUAL
        else:
            identity = LoginIdentity.STANDARD
        bodies[tag] = build_login_body(
            material.passport64,
            client.mac64,
            identity=identity,
            profile=material.profile,
        )

    groups = {
        "main": client._resolve_market_hosts(materials["main"].passport_bytes)
        or ["139.159.135.214"],
        "shlv2": resolve_l2_hosts_grouped(
            materials["shlv2"].passport_bytes
        ).get("sh", []),
        "szlv2": resolve_l2_hosts_grouped(
            materials["szlv2"].passport_bytes
        ).get("sz", []),
        "fu4": resolve_fu4_hosts(materials["fu4"].passport_bytes),
    }
    print("  hosts:", {k: v[:2] for k, v in groups.items()})
    results = {}
    threads = [
        threading.Thread(
            target=login,
            args=(groups[tag][0], bodies[tag], results, tag),
            daemon=True,
        )
        for tag in ("main", "shlv2", "szlv2", "fu4")
        if groups[tag]
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    print("  登录结果:", {k: ("ok" if v else "fail") for k, v in results.items()})

    fu4 = results.get("fu4")
    if fu4 is None:
        print("fu4 登录失败")
        for v in results.values():
            if v:
                v.close()
        client.disconnect()
        return 1
    frames = extract_frames(pcap, sid)
    if args.env == "l2":
        boot = frames[1:6]
    else:
        boot = frames[1:6]
    payload = b"".join(boot)
    print(f"发送 fu4 引导 {len(payload)}B ...")
    try:
        fu4.sendall(payload)
        fu4.settimeout(0.5)
        got = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = fu4.recv(65536)
                if not chunk:
                    print("服务器 FIN")
                    break
                got += chunk
            except socket.timeout:
                break
            except OSError as e:
                print("recv err:", e)
                break
        print(f"收到 {len(got)}B magic={got.count(MAGIC)}")
        if got:
            print("  head:", got[:80].hex(" "))
        print("发板块查询...")
        query = req_file.read_bytes()
        fu4.sendall(query)
        fu4.settimeout(0.5)
        got2 = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = fu4.recv(65536)
                if not chunk:
                    print("查询后服务器 FIN")
                    break
                got2 += chunk
            except socket.timeout:
                break
            except OSError as e:
                print("查询 recv err:", e)
                break
        print(f"查询后收到 {len(got2)}B magic={got2.count(MAGIC)}")
        if got2:
            from thspypc.features.system_blocks_protocol import (
                parse_board_quote_response,
            )
            for sub in got2.split(MAGIC):
                if len(sub) < 8:
                    continue
                try:
                    blen = int(sub[:8], 16)
                except ValueError:
                    continue
                recs = parse_board_quote_response(sub[8:8 + blen])
                if recs:
                    print(f"  ✓✓ 0x130 {len(recs)} 条！first={recs[0].get('code')}")
    except OSError as e:
        print("引导发送异常:", e)
    for v in results.values():
        if v:
            v.close()
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
