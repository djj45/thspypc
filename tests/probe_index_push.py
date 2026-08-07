#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""指数快照订阅推送探针（盘中用）。

对 shlv2/szlv2 发 pageid=4214 指数订阅帧（399002/1A0002），观察：
  - 注册回执 CodeListSize 是否 >= 1
  - 之后服务器是否持续推送指数行情帧（像个股 71B 快照那样）

用法：
    uv run python tests/probe_index_push.py
"""
from __future__ import annotations

import os
import pathlib
import re
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.features.snapshot_protocol import (
    SNAPSHOT_DATATYPE,
    SNAPSHOT_PAGEID,
    SNAPSHOT_SUBTYPE,
)
from thspypc.protocol import (
    MARKET_PORT,
    build_init_query,
    build_manual_login_body,
    build_passport64,
    encode_frame,
    read_frame,
    resolve_l2_hosts_grouped,
)


def load_dotenv() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def build_index_subscribe(code: str, market: int, seq: int = 0) -> bytes:
    """复刻 build_snapshot_subscribe，但允许 1A0002 这类非纯数字代码。"""
    outer_text = f"CodeList={market}({code},);\r\npageid={SNAPSHOT_PAGEID}\r\n".encode(
        "gbk"
    )
    datatype_text = ",".join(str(v) for v in SNAPSHOT_DATATYPE) + ","
    inner_text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        "DateTime=0(0-0)\r\n"
        "LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={SNAPSHOT_PAGEID}\r\n"
    ).encode("gbk")
    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner_header, 4, 0x71 & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\x00\x01"
    struct.pack_into("<I", inner_header, 18, len(inner_text))
    inner_frame = bytes(inner_header) + inner_text
    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = SNAPSHOT_SUBTYPE
    header[11:13] = b"\x02\x00"
    struct.pack_into("<I", header, 19, len(outer_text))
    return encode_frame(bytes(header) + outer_text + inner_frame)


def open_manual(hosts: list[str], main_ip: str, passport64: bytes,
                mac64: str, init_market_code: str):
    preferred = sorted(
        hosts,
        key=lambda h: (
            0 if h.startswith(("8.134.", "122.9.")) else 1,
            h,
        ),
    )
    for host in preferred:
        if host == main_ip:
            continue
        print(f"  尝试 {host} ...", flush=True)
        try:
            sock = socket.create_connection((host, MARKET_PORT), timeout=6)
            sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
            sock.settimeout(8)
            resp = read_frame(sock)
            vc = [
                ln
                for ln in resp.decode("gbk", "replace").splitlines()
                if ln.startswith("VerifyCode=")
            ]
            if vc and vc[0].endswith("=0"):
                sock.sendall(build_init_query(market_code=init_market_code) + b"\n")
                end = time.time() + 8
                while time.time() < end:
                    sock.settimeout(2)
                    try:
                        read_frame(sock)
                    except Exception:
                        break
                print(f"  login ok @ {host}", flush=True)
                return sock
            print(f"  login 被拒 @ {host}: {vc}", flush=True)
            sock.close()
        except Exception as exc:  # noqa: BLE001
            print(f"  host fail {host}: {exc}", flush=True)
    return None


def read_some(sock, label: str, seconds: float) -> None:
    end = time.time() + seconds
    n = 0
    pushes: list[tuple[str, int, int]] = []
    saved: list[bytes] = []
    while time.time() < end:
        sock.settimeout(min(5.0, max(0.5, end - time.time())))
        try:
            b = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as exc:
            print(f"  [{label}] 读失败: {exc}", flush=True)
            break
        n += 1
        m = re.search(rb"CodeListSize=(\d+)", b)
        if m:
            print(f"  [{label}] 注册回执 CodeListSize={m.group(1).decode()} "
                  f"({len(b)}B)", flush=True)
            continue
        tag = "hd3.1" if b"hd3.1\x00" in b else ("hd1.0" if b"hd1.0\x00" in b else "")
        if tag:
            code = b[29:35].decode("ascii", "replace") if len(b) >= 36 else "?"
            mf = b[28] if len(b) >= 29 else -1
            pushes.append((code, mf, len(b)))
            if len(pushes) <= 12:
                head = b[:60].decode("gbk", "replace").replace("\n", "\\n")
                print(f"  [{label}] {len(b)}B {tag} flagbyte={mf:#04x} "
                      f"code={code} head={head[:40]!r}", flush=True)
        else:
            saved.append(b)
            if len(saved) <= 6:
                head = b[:70].decode("gbk", "replace").replace("\n", "\\n")
                print(f"  [{label}] {len(b)}B 其他帧: {head[:60]!r}", flush=True)
    if saved:
        out = pathlib.Path(__file__).resolve().parent.parent / "captures_live"
        out.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = out / f"index_push_{label.split(':')[0]}_{stamp}.bin"
        path.write_bytes(b"".join(saved))
        print(f"  已保存 {len(saved)} 帧 -> {path}", flush=True)
    print(f"  [{label}] 共 {n} 帧, push-like={len(pushes)} "
          f"{pushes[:12]}", flush=True)


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("登录拿 passport64 ...", flush=True)
    client = THSClient(username, password, imei)
    result = client.connect()
    if not result.success:
        print(f"!! 登录失败: {result.error} {result.detail}")
        return 1
    main_ip = client._connected_ip
    passport64 = build_passport64(client._auth)
    mac64 = client.mac64
    grouped = resolve_l2_hosts_grouped(client._auth.get("passport_bytes", b""))
    client.disconnect()
    print(f"  主连接 {main_ip}; 沪 {len(grouped['sh'])} IP, "
          f"深 {len(grouped['sz'])} IP", flush=True)

    cases = (
        ("sz", "32;", "399001", 32),
        ("sh", "16;144;", "1A0001", 16),
    )
    for key, init, code, market in cases:
        print(f"\n===== {key} 指数快照订阅 {code} market={market} =====", flush=True)
        sock = open_manual(grouped[key], main_ip, passport64, mac64, init)
        if sock is None:
            print("  !! 无可用主机", flush=True)
            continue
        sock.sendall(build_index_subscribe(code, market) + b"\n")
        read_some(sock, f"{key}:{code}", 15)
        sock.close()

    print("\n完成。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
