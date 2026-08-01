#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★决定性实验 v7：普通 thspypc 连接（已 init）+ 用构造函数造 104540 风格触发帧。

v6 教训：重放抓包原字节会断连（含过期 instid/seq）。必须用 thspypc 构造函数造新帧。

104540 触发序列（stream1，收 174 推送）结构：
  1. subreal×5（pageid=4214）—— 文本帧 instid=2147483647
  2. reg 帧 byte11-12=02 04：'\r\npageid=4214\r' （sub 0x0002，订阅id=4）
  3. reg 帧 byte11-12=fc 03：'CodeList=17(<code>,);\r\npageid=4214\r' （sub 0x0002，订阅id=3）

byte11-12 第二字节是【订阅计数器】（02→pageid订阅, fc→code订阅），每次递增。
本脚本用 thspypc 构造函数造这些帧（新 instid/seq），在已 init 的普通连接上发。
"""
from __future__ import annotations
import os, sys, time, datetime, socket, struct, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    encode_frame, read_frame, build_subreal_query, SUBREAL_CHANNELS,
    build_heartbeat_8901, is_snapshot_push, parse_snapshot_push,
)


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


def build_pageid_subscribe(pageid: int, sub_id: int) -> bytes:
    """reg 帧 byte11-12=02 <sub_id>: '\r\npageid=<pid>\r' (sub 0x0002)。
    抓包：head=09 00 16 00 00 00 00 12 00 02 00 02 04 00 00 00 00 00 00 0f 00 00 00 + text。
    off19=0x0f=15（'\r\npageid=4214\r' 长度）。
    """
    text = f"\r\npageid={pageid}\r".encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09; hdr[1:5] = b"\x00\x16\x00\x00"
    hdr[7:11] = b"\x12\x00\x02\x00"
    hdr[11] = 0x02; hdr[12] = sub_id & 0xFF
    struct.pack_into("<I", hdr, 19, len(text))
    return encode_frame(bytes(hdr) + text)


def build_code_subscribe(code: str, market: int, pageid: int, sub_id: int) -> bytes:
    """reg 帧 byte11-12=fc <sub_id>: 'CodeList=<mk>(<code>,);\r\npageid=<pid>\r' (sub 0x0002)。
    抓包：head=09 00 16 00 00 00 00 12 00 02 00 fc 03 00 ... off19=0x24=36。
    """
    text = f"CodeList={market}({code},);\r\npageid={pageid}\r".encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09; hdr[1:5] = b"\x00\x16\x00\x00"
    hdr[7:11] = b"\x12\x00\x02\x00"
    hdr[11] = 0xFC; hdr[12] = sub_id & 0xFF
    struct.pack_into("<I", hdr, 19, len(text))
    return encode_frame(bytes(hdr) + text)


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    code = "603118"; market = 17
    for a in sys.argv[1:]:
        if a.isdigit() and len(a) == 6:
            code = a; market = 17 if code.startswith("6") else 33

    print("【1】普通 thspypc 登录（已含 init 激活）...")
    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    try:
        r = client.connect()
        if not r.success:
            print(f"✗ {r.error}"); return 1
        print(f"✓ {r.server}")
    except Exception as e:
        print(f"✗ {e}"); return 1

    outpath = os.path.join(os.path.dirname(__file__), "..", "captures_live", "_trigger_v7_out.txt")
    fout = open(outpath, "w", encoding="utf-8")
    def log(s):
        print(s); fout.write(s + "\n"); fout.flush()

    sock = client._sock
    print(f"\n【2】用构造函数造 104540 风格触发帧（code={code} mk={market} pageid=4214）...")
    with client._sock_lock:
        # subreal×5 pageid=4214
        for ch in SUBREAL_CHANNELS:
            sock.sendall(encode_frame(build_subreal_query(0x7FFFFFFF, channel=ch, action="change", pageid=4214)) + b"\n")
        log("  发 subreal×5（pageid=4214）")
        # reg: pageid 订阅 byte11-12=02 04
        sock.sendall(build_pageid_subscribe(4214, 0x04) + b"\n")
        log("  发 pageid 订阅（02 04）")
        # reg: code 订阅 byte11-12=fc 03 ×3
        for _ in range(3):
            sock.sendall(build_code_subscribe(code, market, 4214, 0x03) + b"\n")
        log(f"  发 code 订阅×3（fc 03）{code}")

    sock.settimeout(2.0)
    t0 = time.time(); n = 0; stock_n = 0; idx_n = 0
    while time.time() - t0 < 30:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as e:
            log(f"  [read err] {e}"); break
        n += 1
        if b"tsi0=" in body: continue
        if is_snapshot_push(body):
            stock_n += 1
            rec = parse_snapshot_push(body)
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★★STOCK71B #{stock_n} {rec}")
            continue
        if len(body) == 321 and body[0] == 0x09:
            idx_n += 1
            log(f"  #{n} ★INDEX321B #{idx_n}"); continue
        if n <= 12:
            asc = body[:36].decode('gbk','replace').replace('\n','|').replace('\r','')[:36]
            log(f"  #{n} {len(body)}B: {body[:14].hex(' ')}  {asc!r}")
    log(f"\n【汇总】30s 收 {n} 帧，321B指数 {idx_n}，71B个股 {stock_n}")
    if stock_n > 0: log("✓✓✓ 推送成功！")
    elif n == 0: log("✗ 零响应")
    else: log("⚠ 有响应无推送")
    fout.close()
    try: client.disconnect()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
