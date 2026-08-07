#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""指数分时抓包探针（盘中用）。

对 shlv2/szlv2 直接发 pageid=4214 指数分时查询，观察：
  1. 指数作为主查询代码（16(1A0002) / 32(399002)）服务器回什么表
  2. 指数是否也能随 4214 请求注册并持续推送（像个股快照那样）
  3. 个股+伴随基准指数（000938 + 32(399002)）的响应/推送形态

用法：
    uv run python tests/probe_index_timeline.py
"""
from __future__ import annotations

import os
import pathlib
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.features.system_blocks_protocol import (
    _decode_bitrle_0x13746d0,
    _decode_row,
    _hd3_rows,
    _transpose_bitplane_0x1763410,
)
from thspypc.features.timeline_protocol import build_timeline_l2_query
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


def open_manual(host: str, passport64: bytes, mac64: str,
                init_market_code: str, timeout: float = 12.0):
    """__manual 登录 + init，返回 socket。"""
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
    sock.settimeout(8)
    resp = read_frame(sock)
    vc = ""
    for line in resp.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1]
    if vc != "0":
        sock.close()
        raise RuntimeError(f"__manual 登录失败 VC={vc} @ {host}")

    sock.sendall(build_init_query(market_code=init_market_code) + b"\n")
    n_bytes = 0
    n_frames = 0
    end = time.time() + timeout
    while time.time() < end:
        sock.settimeout(min(3.0, max(0.5, end - time.time())))
        try:
            b = read_frame(sock)
            n_bytes += len(b)
            n_frames += 1
        except (socket.timeout, OSError, ValueError):
            break
    print(f"  init({init_market_code}) @ {host}: {n_frames}帧/{n_bytes}B")
    if n_bytes < 5000:
        print("  !! init 响应过小，此 IP 可能不支持该市场")
    return sock


def dump_frame(label: str, body: bytes) -> None:
    text = body[:140].decode("gbk", "replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    hd = body.find(b"hd3.1\x00")
    if hd < 0:
        print(f"  [{label}] {len(body)}B 无 hd3.1: {text[:100]!r}")
        return
    base = hd + 6
    rc, flag, rec_size, fc = struct.unpack_from("<IHHH", body, base)
    print(f"  [{label}] {len(body)}B hd3.1 rc={rc} flag=0x{flag:04x} "
          f"rec={rec_size} fc={fc}")
    if flag == 0x009e:
        # 指数分时表：26B 壳，BitRLE 在 ft_end+26
        ft_end = base + 10 + fc * 4
        fields = []
        for i in range(fc):
            dtype = body[base + 10 + i * 4]
            fmt = body[base + 10 + i * 4 + 1]
            width = body[base + 10 + i * 4 + 3]
            fields.append((dtype, fmt, width))
        pos = ft_end + 26
        size = struct.unpack(">I", body[pos:pos + 4])[0]
        if 0 < size <= 2_000_000 and size % rec_size == 0:
            bitplane = _decode_bitrle_0x13746d0(body[pos:], size)
            rows = _transpose_bitplane_0x1763410(
                bitplane, rec_size, size // rec_size
            )
            n = size // rec_size
            first = _decode_row(rows[:rec_size], fields)
            last = _decode_row(rows[-rec_size:], fields)
            print(f"    指数表: rows={n} code={last.get('code')} "
                  f"最新点位 dt10={last.get('dt10')}")
            print(f"    首点: dt10={first.get('dt10')} 末点: dt10={last.get('dt10')}")
            out = pathlib.Path(__file__).resolve().parent.parent / "captures_live"
            out.mkdir(exist_ok=True)
            path = out / f"index_timeline_{label.split(':')[-1]}_{time.strftime('%Y%m%d_%H%M%S')}.bin"
            path.write_bytes(body)
            print(f"    已保存 -> {path}")
            return
        print(f"    0x009e BitRLE 长度异常: {size}")
        return
    parsed = _hd3_rows(body, 0x00B4, 0x007E, 0x0042, 0x0046)
    if parsed is None:
        print(f"    (通用 hd3.1 解析失败; 文本头: {text[:80]!r})")
        return
    _flag, _rsize, fields, code, rows = parsed
    n = len(rows) // _rsize
    print(f"    通用解析: code={code!r} rows={n} fields={[f[0] for f in fields][:12]}")
    if n == 0:
        return
    first = _decode_row(rows[:_rsize], fields)
    last = _decode_row(rows[-_rsize:], fields)
    print(f"    首行: {first}")
    print(f"    末行: {last}")


def read_loop(sock, label: str, seconds: float) -> int:
    end = time.time() + seconds
    count = 0
    while time.time() < end:
        sock.settimeout(min(5.0, max(0.5, end - time.time())))
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as exc:
            print(f"  [{label}] 读失败: {exc}")
            break
        count += 1
        dump_frame(label, body)
    return count


def main() -> int:
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    print("登录拿 passport64 ...")
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
    print(f"  主连接 {main_ip}; L2 沪 {len(grouped['sh'])} IP, "
          f"深 {len(grouped['sz'])} IP")

    for attempt in range(2):
        failed_hosts: list[str] = []
        for key, market_code, init in (("sh", "16", "16;144;"), ("sz", "32", "32;")):
            hosts = [h for h in grouped[key] if h != main_ip] or grouped[key]
            if not hosts:
                print(f"!! 无 {key} L2 IP")
                continue
            host = hosts[0]
            print(f"\n===== {key} L2 {host} =====")
            try:
                sock = open_manual(host, passport64, mac64, init)
            except RuntimeError as exc:
                print(f"  !! {exc}")
                failed_hosts.append(host)
                continue

            index_codes = (
                ("1A0001", "1A0002")
                if key == "sh"
                else ("399001", "399002")
            )
            for code in index_codes:
                print(f"\n--- 查询指数 {code} (market={market_code}) ---")
                sock.sendall(
                    build_timeline_l2_query(code, market=int(market_code)) + b"\n"
                )
                n = read_loop(sock, f"{key}:{code}", 10)
                print(f"  [{key}:{code}] 共 {n} 帧")

            if key == "sz":
                print("\n--- 对照：个股 000938 + 伴随基准 32(399002) ---")
                sock.sendall(
                    build_timeline_l2_query(
                        "000938", market=33, extra_codelist="32(399002,);"
                    )
                    + b"\n"
                )
                n = read_loop(sock, "sz:000938+399002", 12)
                print(f"  [sz:000938+399002] 共 {n} 帧")
            sock.close()

        if not failed_hosts:
            break
        print(f"\n重试：重新 HTTP 鉴权拿新鲜 passport64 ...")
        client = THSClient(username, password, imei)
        result = client.connect()
        if not result.success:
            print(f"!! 重新登录失败: {result.error}")
            return 1
        passport64 = build_passport64(client._auth)
        mac64 = client.mac64
        main_ip = client._connected_ip
        client.disconnect()

    print("\n完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
