#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""历史指数分时对比探针：复现客户端 pageid=77 历史分时请求并解码。

对比 1A0001 / 1A0002 在指定历史日的分时点位，用于定位"领先"黄线数据源。
用法：
    uv run python tests/probe_hist_index_compare.py 2026-07-23
"""
from __future__ import annotations

import datetime
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.codecs.numeric import decode_ths_float
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


def date_to_bar(date: datetime.date) -> int:
    packed = ((date.year - 1900) << 9) | (date.month << 5) | date.day
    return packed * 2048 + 606


def build_hist_timeline(code: str, market: int, date: datetime.date) -> bytes:
    bar = date_to_bar(date)
    text = (
        f"CodeList={market}({code},);\r\n"
        "DataType=13,19,40,10,23,22,6,\r\n"
        f"DateTime=8192({bar}-{bar + 355})\r\n"
        "LackTime=0,3,0,0,0,0,0,0\r\n"
        "pageid=77\r\n"
    ).encode("gbk")
    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, 0x005B)
    header[7:11] = b"\x12\x00\t\x00"
    header[11:13] = b"\x00\x01"
    header[18] = 0x20
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def open_manual(hosts: list[str], main_ip: str, p64: bytes, m64: str):
    for host in sorted(hosts, key=lambda h: (0 if h.startswith(("8.134.", "122.9.")) else 1, h)):
        if host == main_ip:
            continue
        try:
            s = socket.create_connection((host, MARKET_PORT), timeout=6)
            s.sendall(encode_frame(build_manual_login_body(p64, m64)) + b"\n")
            s.settimeout(8)
            resp = read_frame(s)
            vc = [
                ln
                for ln in resp.decode("gbk", "replace").splitlines()
                if ln.startswith("VerifyCode=")
            ]
            if vc and vc[0].endswith("=0"):
                s.sendall(build_init_query(market_code="16;144;") + b"\n")
                end = time.time() + 8
                while time.time() < end:
                    s.settimeout(2)
                    try:
                        read_frame(s)
                    except Exception:
                        break
                return s, host
            s.close()
        except Exception:
            continue
    return None, None


def decode_hd1_timeline(norm: bytes) -> list[dict]:
    pos = norm.find(b"hd1.0\x00")
    if pos < 0:
        return []
    base = pos + len(b"hd1.0\x00")
    rc = struct.unpack_from("<H", norm, base)[0]
    rec = struct.unpack_from("<H", norm, base + 6)[0]
    fc = struct.unpack_from("<H", norm, base + 8)[0]
    fields = [
        (norm[base + 10 + i * 4], norm[base + 10 + i * 4 + 1], norm[base + 10 + i * 4 + 3])
        for i in range(fc)
    ]
    shell_pos = base + 10 + fc * 4
    data_pos = shell_pos + 22
    rows = []
    for i in range(rc):
        o = data_pos + i * rec
        if o + rec > len(norm):
            break
        vals: dict[int, object] = {}
        off = 0
        for d, f, w in fields:
            raw = struct.unpack_from("<I", norm, o + off)[0]
            vals[d] = decode_ths_float(raw) if f == 0x70 else raw
            off += w
        rows.append(vals)
    return rows


def main() -> int:
    load_dotenv()
    date_str = sys.argv[1] if len(sys.argv) > 1 else "2026-07-23"
    date = datetime.date.fromisoformat(date_str)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("登录拿 passport ...")
    client = THSClient(username, password, imei)
    result = client.connect()
    if not result.success:
        print(f"!! 登录失败: {result.error}")
        return 1
    main_ip = client._connected_ip
    p64 = build_passport64(client._auth)
    m64 = client.mac64
    grouped = resolve_l2_hosts_grouped(client._auth.get("passport_bytes", b""))
    client.disconnect()

    sock, host = open_manual(grouped["sh"], main_ip, p64, m64)
    if sock is None:
        print("!! 无可用沪 L2 主机")
        return 1
    print(f"  host: {host}")

    for code in ("1A0001", "1A0002"):
        print(f"\n=== {code} {date} 历史分时 ===")
        sock.sendall(build_hist_timeline(code, 16, date) + b"\n")
        body = None
        end = time.time() + 10
        while time.time() < end:
            sock.settimeout(min(4, max(0.5, end - time.time())))
            try:
                b = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError):
                break
            if b.startswith(b"\x0a"):
                body = b
                break
        if body is None:
            print("  无响应")
            continue
        from thspypc.codecs.compression import normalize_8901_response

        norm = normalize_8901_response(body)
        rows = decode_hd1_timeline(norm)
        print(f"  行数: {len(rows)}")
        if len(rows) >= 162:
            for i in (0, 1, 120, 121, 160, 161, 162, 240, 241):
                if i < len(rows):
                    r = rows[i]
                    print(f"  #{i}: dt10={r.get(10)} dt40={r.get(40)}")
        else:
            for i, r in enumerate(rows[:5]):
                print(f"  #{i}: dt10={r.get(10)} dt40={r.get(40)}")
    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
