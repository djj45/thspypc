#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""验证 71B 触发：用「服务器主动 login」方式连接 122.9.205.228。

决定性发现（2026-08-07 抓包 flow1 分析）：
122.9.205.228 是「服务器主动 login」类型——TCP 连上后服务器立即主动推
``Reply=login VerifyCode=0``，客户端不发 login 帧，直接发 subreal 订阅。

thspypc 的 ``_open_manual_push_connection`` 走标准 ``thsuser`` login 流程
（客户端发 login → 服务器回），这与同花顺的握手方式不同，导致服务器端会话
类型不一样，71B 逐笔通道未开启（549B 十档仍能收）。

本脚本：raw socket 连 122.9.205.228 → 等「服务器主动 login」→ 发 subreal×8
+ 1334 分时 + 4214 订阅 → 收 30s 看 71B。

用法：
    py tests/_71b_server_login.py 002384
    py tests/_71b_server_login.py 002384 --ip 122.9.205.228
"""
import argparse
import os
import socket
import struct
import sys
import time
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.codecs.framing import read_frame, encode_frame  # noqa: E402
from thspypc.features.snapshot_protocol import (  # noqa: E402
    SNAPSHOT_PAGEID, build_snapshot_subscribe, parse_snapshot_push,
)
from thspypc.protocol import build_subreal_query  # noqa: E402


def build_single_subscribe(code, market, datatype, pageid=SNAPSHOT_PAGEID, seq=0):
    dt_text = ",".join(str(v) for v in datatype) + ","
    text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={dt_text}\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")
    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\x00\x01"
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def send_subreal_batch(sock, pageid):
    markets = ["URS", "UCT", "UNX", "UCX", "UME", "UGF", "UGF", "UNS"]
    classes = ["URSI", "UCTF", "UNXF", "UCXF", "UMEF", "UGFF", "UGFO", "UNSI"]
    for mkt, cls in zip(markets, classes):
        f = build_subreal_query(0x7FFFFFFF, channel=mkt, action="change",
                                class_prefix=cls, pageid=pageid)
        try:
            sock.sendall(encode_frame(f) + b"\n")
        except OSError:
            pass


def classify(body):
    if len(body) in (71, 72) and body[0] == 0x09 and body[1:4] == b"\x7b\xd0\x01":
        return "71B逐笔"
    if body[0] == 0x09 and body[1:4] == b"\x7b\xd0\x0f" and len(body) >= 300:
        return "549B十档"
    if b"tsi0=" in body[:30]:
        return "心跳"
    if b"Reply=login" in body or b"VerifyCode=" in body:
        return "login"
    if b"CodeListSize" in body:
        return "注册响应"
    if b"hd1.0" in body[:80] or b"hd3.1" in body[:80]:
        return "数据响应"
    return f"{len(body)}B?"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("code", nargs="?", default="002384")
    ap.add_argument("--ip", default="122.9.205.228")
    ap.add_argument("--port", type=int, default=8901)
    ap.add_argument("--seconds", type=int, default=30)
    args = ap.parse_args()
    code = args.code
    market = 17 if code.startswith("6") else 33

    print(f"=== 连接 {args.ip}:{args.port}（服务器主动 login 模式）===")
    sock = socket.create_connection((args.ip, args.port), timeout=10)
    sock.settimeout(3.0)
    print(f"✓ TCP 已连接 {args.ip}:{args.port}")

    # 等「服务器主动 login」
    print("等待服务器主动推送 Reply=login...")
    got_login = False
    t0 = time.time()
    while time.time() - t0 < 5:
        try:
            body = read_frame(sock)
        except socket.timeout:
            print(f"  [{time.time()-t0:.1f}s] 无服务器主动帧")
            continue
        except (OSError, ValueError) as e:
            print(f"  [读异常] {e}")
            break
        tag = classify(body)
        print(f"  ← {tag} {len(body)}B: {body[:80].decode('gbk','replace')!r}")
        if b"Reply=login" in body or b"VerifyCode=0" in body:
            got_login = True
            print("  ✓ 收到服务器主动 login（VerifyCode=0）")
            break
    if not got_login:
        print("✗ 5s 内未收到服务器主动 login。该 IP 可能不是「主动 login」类型。")
        print("  继续尝试发订阅...")

    # 发 subreal×8 (5716)
    print("\n发 subreal×8 (pageid=5716)...")
    send_subreal_batch(sock, 5716)
    time.sleep(0.3)
    # 发 subreal×8 (1334)
    print("发 subreal×8 (pageid=1334)...")
    send_subreal_batch(sock, 1334)
    time.sleep(0.3)

    # 发 4214 订阅
    f = build_snapshot_subscribe(code, market=market, seq=0)
    sock.sendall(f + b"\n")
    print(f"发 4214 订阅（DT=10,24,30,69,70,127）")

    # 收 seconds 秒
    sock.settimeout(1.0)
    print(f"\n=== 收 {args.seconds}s 推送 ===")
    counter = Counter()
    t0 = time.time()
    while time.time() - t0 < args.seconds:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as e:
            print(f"  [读异常] {e}")
            break
        tag = classify(body)
        counter[tag] += 1
        if tag == "71B逐笔":
            rec = parse_snapshot_push(body)
            if counter["71B逐笔"] <= 8:
                print(f"  [+{time.time()-t0:5.1f}s] ★71B 价={rec['price']:.2f} 量={rec['volume']} 向={rec['direction']} seq={rec['seq']}")
        elif counter.get(tag, 0) <= 2:
            print(f"  [+{time.time()-t0:5.1f}s] {tag} {len(body)}B head={body[:16].hex(' ')}")

    print(f"\n=== 汇总 ===")
    print(f"  {dict(counter)}")
    n71 = counter.get("71B逐笔", 0)
    print(f"\n{'★ 71B 触发成功！' if n71 > 0 else '✗ 仍无 71B'}")

    try:
        sock.close()
    except OSError:
        pass
    return 0 if n71 > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
