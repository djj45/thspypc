#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""最干净的诊断：__manual 登录后，原始 recv 看 server 发什么（无心跳、无 read_frame）。

目的：搞清 __manual 连接登录后 server 主动推不推、推什么。
"""
from __future__ import annotations
import os, sys, time, datetime, socket
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
from thspypc import THSClient
from thspypc.protocol import encode_frame, build_passport64, MARKET_PORT
from _manual_login_test import build_manual_login_body


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip(); v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    try:
        r = client.connect()
        if not r.success:
            print(f"✗ {r.error}"); return 1
        passport64 = build_passport64(client._auth)
        mac64 = client.mac64; host = client._connected_ip
        print(f"✓ 普通登录 {r.server}")
        client.disconnect()
    finally:
        try: client.disconnect()
        except Exception: pass

    print("\n__manual 登录新连接，然后【什么都不发】，原始 recv 12s 看 server 主动推什么...")
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
    sock.settimeout(12.0)
    buf = b""
    t0 = time.time()
    print(f"  t={0:.1f}s 开始 recv（12s）...")
    while time.time() - t0 < 12:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            print(f"  t={time.time()-t0:.1f}s recv timeout（无数据）")
            break
        if not data:
            print(f"  t={time.time()-t0:.1f}s ★连接关闭（FIN）！")
            break
        buf += data
        print(f"  t={time.time()-t0:.1f}s +{len(data)}B (累计 {len(buf)}B)")
    sock.close()

    print(f"\n累计收到 {len(buf)}B。扫描 fdfdfdfd 帧：")
    import re
    # 简单按 fdfdfdfd 分段
    segs = buf.split(b"\xfd\xfd\xfd\xfd")
    print(f"  {len(segs)} 段")
    for i, seg in enumerate(segs[:8]):
        if len(seg) < 8:
            print(f"  seg{i}: 前缀 {len(seg)}B {seg.hex(' ')}"); continue
        # 前8字节是 ascii hex 长度
        try:
            bodylen = int(seg[:8], 16)
        except Exception:
            print(f"  seg{i}: 非 hex 长度 {seg[:8]!r}"); continue
        body = seg[8:8+bodylen]
        head = body[:24].hex(' ')
        try:
            asc = body[:50].decode('gbk','replace').replace('\n','|').replace('\r','')[:50]
        except Exception:
            asc = ''
        is_push = (len(body)==321 and body[0]==0x09) or (len(body)==71 and body[0]==0x09 and len(body)>14 and body[14]==0x80)
        mark = ' ★PUSH' if is_push else ''
        print(f"  seg{i}: len字段={bodylen} body={len(body)}B{mark}\n      head: {head}\n      asc: {asc!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
