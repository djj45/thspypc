#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""活网重放不同 DataType 组合的 pageid=4214 订阅，定位哪个 DT 触发 71B 逐笔推送。

背景
----
2026-08-07 抓包（kanpan_push_20260807_130011.pcap）确认客户端打开分时图瞬间
发了**多个** 4214 订阅，thspypc 只复刻了其中 DT=10,24,30,69,70,127 的那个
（→ 只收 549B 十档）。客户端还发了 DT 大集合的单子帧
（7,8,9,10,13,14,19,69,70,74,75,85,90,92,130,6,45,66,380,402,407,663,665,
1606,2081,262763）——怀疑这个触发 71B。

方法
----
连接深市 szlv2 L2 服务器，依次发：
  ①  thspypc 现有 DT=[10,24,30,69,70,127]     → 应只收 549B
  ②  客户端 DT 大集合                          → 看是否触发 71B
  ③  单独加逐笔候选字段（74/75/85/90/92 等）   → 收窄触发字段

每个订阅后收 N 秒，统计 71B/549B 帧数 + 样本。

用法
----
    py tests/_replay_71b_subscribe.py 002384
    py tests/_replay_71b_subscribe.py 002384 --seconds 12
"""
import argparse
import datetime
import os
import socket
import struct
import sys
import time
import threading
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc import THSClient  # noqa: E402
from thspypc.codecs.framing import read_frame, encode_frame  # noqa: E402
from thspypc.features.snapshot_protocol import (  # noqa: E402
    SNAPSHOT_PAGEID,
    build_snapshot_subscribe,
    parse_snapshot_push,
)
from thspypc.protocol import build_subreal_query  # noqa: E402

# 客户端 9 个 subreal 频道（pageid=5716，class 前缀）
SUBREAL_CHANNELS_FULL = ["URS", "UCT", "UNX", "UCX", "UME", "UGF", "UGF", "UNS"]
_SUBREAL_CLASS = {
    "URS": "URSI", "UCT": "UCTF", "UNX": "UNXF", "UCX": "UCXF",
    "UME": "UMEF", "UGF": "UGFF", "UNS": "UNSI",
}
# UGF 有两个 class：UGFF 和 UGFO


# ── 客户端抓包里的真实 DT 组合 ──
DT_THSPYPC = [10, 24, 30, 69, 70, 127]                     # thspypc 现用（→549B）
DT_CLIENT_FULL = [                                          # +18.545 帧
    7, 8, 9, 10, 13, 14, 19, 69, 70, 74, 75, 85, 90, 92,
    130, 6, 45, 66, 380, 402, 407, 663, 665, 1606, 2081, 262763,
]
# 候选：只加 L2 逐笔相关字段
DT_PLUS_TICK = [10, 24, 30, 69, 70, 127, 74, 75, 85, 90, 92, 130]


def build_single_subscribe(code, market, datatype, pageid=SNAPSHOT_PAGEID, seq=0):
    """构造单子帧 4214 订阅（head[11:13]=00 01，非嵌套）。

    对应客户端 +18.545 的帧结构。
    """
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
    header[11:13] = b"\x00\x01"          # 单子帧标记
    struct.pack_into("<I", header, 19, len(text))
    return encode_frame(bytes(header) + text)


def load_dotenv():
    p = os.path.join(ROOT, ".env")
    if not os.path.exists(p):
        return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def classify(body):
    if len(body) in (71, 72) and body[0] == 0x09 and body[1:4] == b"\x7b\xd0\x01":
        return "71B逐笔"
    if body[0] == 0x09 and body[1:4] == b"\x7b\xd0\x0f" and len(body) >= 300:
        return "549B十档"
    if b"tsi0=" in body[:30]:
        return "心跳"
    if b"CodeListSize" in body:
        return "注册响应"
    if b"hd1.0" in body[:80] or b"hd3.1" in body[:80]:
        return "数据响应"
    return f"{len(body)}B?"


def collect(sock, seconds, label, dump=False):
    """收 seconds 秒，返回 counter。"""
    print(f"\n{'='*64}")
    print(f"【{label}】收 {seconds}s 推送...")
    print(f"{'='*64}")
    counter = Counter()
    t0 = time.time()
    last_report = t0
    while time.time() - t0 < seconds:
        try:
            body = read_frame(sock)
        except socket.timeout:
            now = time.time()
            if now - last_report > 5:
                print(f"  [+{now-t0:.0f}s] 已收 {sum(counter.values())} 帧 {dict(counter)}")
                last_report = now
            continue
        except (OSError, ValueError) as e:
            print(f"  [读异常] {e}")
            break
        tag = classify(body)
        counter[tag] += 1
        if tag == "71B逐笔":
            rec = parse_snapshot_push(body)
            if counter["71B逐笔"] <= 5:
                print(f"  [+{time.time()-t0:5.1f}s] ★71B 价={rec['price']:.2f} 量={rec['volume']} 向={rec['direction']} seq={rec['seq']}")
        if dump and sum(counter.values()) <= 12:
            print(f"    [{tag}] {len(body)}B head={body[:20].hex(' ')}")
    print(f"\n  汇总 {label}: {dict(counter)}")
    return counter


def _drain(sock):
    """非阻塞读掉缓冲区里的积压帧。"""
    old = sock.gettimeout()
    sock.settimeout(0.3)
    n = 0
    while True:
        try:
            read_frame(sock)
            n += 1
        except (socket.timeout, OSError, ValueError):
            break
    sock.settimeout(old)
    if n:
        print(f"  (清空积压 {n} 帧)")


def send_subreal(sock, pageid=5716):
    """发客户端 9 频道 subreal 注册（URS/UCT/UNX/UCX/UME/UGF×2/UNS）。"""
    classes = ["URSI", "UCTF", "UNXF", "UCXF", "UMEF", "UGFF", "UGFO", "UNSI"]
    markets = ["URS", "UCT", "UNX", "UCX", "UME", "UGF", "UGF", "UNS"]
    n = 0
    for mkt, cls in zip(markets, classes):
        # build_subreal_query 默认 class_prefix 从 channel 推导，这里显式传
        f = build_subreal_query(0x7FFFFFFF, channel=mkt, action="change",
                                class_prefix=cls, pageid=pageid)
        try:
            sock.sendall(encode_frame(f) + b"\n")
            n += 1
        except OSError:
            pass
    return n


def build_1334_timeline(code, market):
    """复刻 +16.743 的 1334 L2 分时订阅（双子帧）。"""
    import struct as _s
    from thspypc.codecs.framing import encode_frame as enc
    # 主子帧文本
    main_text = (
        f"CodeList=32(399002,);{market}({code},);\r\n"
        f"DataType=272,229,271,228,13,227,19,40,226,54,39,225,10,38,224,223,230,6,45,1110,1111,380,\r\n"
        f"DateTime=8192(0-0)\r\n"
        f"LackTime=0,3,0,0,0,0,0,0\r\n"
        f"pageid=1334\r\n"
    ).encode("gbk")
    # 次子帧：注册指数
    sub_text = b"CodeList=32(399002,);\r\npageid=1334\r\n"
    # 外层 head
    head = bytearray(23)
    head[0] = 0x09
    head[1:5] = b"\x00\x16\x00\x00"
    _s.pack_into("<H", head, 5, 0x11CD)
    head[7:11] = b"\x12\x00\x09\x00"
    head[11:13] = b"\x5a\x01"      # route 0x015a
    head[18] = 0x20
    _s.pack_into("<I", head, 19, len(main_text))
    body = bytes(head) + main_text
    # 次子帧 head (22B)
    sub_head = bytearray(22)
    sub_head[0:4] = b"\x00\x16\x00\x00"
    _s.pack_into("<H", sub_head, 4, 0x015A)  # 注意：次帧 seq 复用
    sub_head[6:10] = b"\x12\x00\x02\x00"
    sub_head[10:12] = b"\x5a\x02"
    _s.pack_into("<I", sub_head, 18, len(sub_text))
    body += bytes(sub_head) + sub_text
    return enc(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("code", nargs="?", default="002384")
    ap.add_argument("--seconds", type=int, default=12, help="每个场景收多少秒")
    ap.add_argument("--scene", default="all",
                    help="all/subreal/1334/4214/full（见代码）")
    ap.add_argument("--dump", action="store_true", help="打印每个收到的帧头部")
    ap.add_argument("--replay-raw", action="store_true",
                    help="原始字节重放抓包 flow1 的 12 个 TCP 包（最忠实复刻）")
    args = ap.parse_args()
    code = args.code
    market = 17 if code.startswith("6") else 33
    load_dotenv()

    client = THSClient(
        username=os.environ["THS_USERNAME"],
        password=os.environ["THS_PASSWORD"],
        imei=os.environ.get("THS_IMEI", "").strip() or None,
        enable_heartbeat=False,
    )

    # ★ 绕过 MAIN connect（避免 main init 失败 + 会话冲突）：
    # 只做 HTTP 鉴权拿 passport，然后直接建立 sz L2 推送连接。
    # sz L2 连接独立于 main，不需要 main init（见 _open_manual_pushshake 注释）。
    client.authenticate()
    print("✓ HTTP 鉴权完成（passport 已获取）")

    # ★ 强制 sz L2 连接到抓包里的 71B 来源 IP（122.9.205.228）
    force_ip = os.environ.get("THS_FORCE_SZ_IP", "122.9.205.228")
    client._probe_cache["sz"] = (time.time(), [force_ip])
    client._login_rr_offset["sz"] = 0
    print(f"✓ 强制 sz L2 IP = {force_ip}")

    # 直接建立 sz L2 连接（不走 snapshot_subscribe 的整套 service 流程）
    # THSClient 多继承 ConnectionPrimitives，方法直接可用
    sock = client._open_manual_push_connection(market, skip_init=False)
    if sock is None:
        print("✗ sz L2 连接建立失败")
        return 1
    try:
        peer = sock.getpeername()
        print(f"✓ sz L2 连接已建立 peer={peer[0]}:{peer[1]}")
    except OSError:
        print("✓ sz L2 连接已建立")
    sock.settimeout(1.0)

    # 发 4214 订阅注册帧（确认 CodeListSize≥1）
    reg = build_snapshot_subscribe(code, market=market, seq=0)
    sock.sendall(reg + b"\n")
    registered = False
    t0 = time.time()
    while time.time() - t0 < 4:
        try:
            resp = read_frame(sock)
        except (socket.timeout, OSError, ValueError):
            break
        if b"CodeListSize" in resp:
            import re as _re
            m = _re.search(rb"CodeListSize=(\d+)", resp)
            if m:
                print(f"✓ 4214 注册响应 CodeListSize={m.group(1).decode()}")
                registered = int(m.group(1)) >= 1
            break
    if not registered:
        print("⚠ 4214 注册未确认 CodeListSize≥1，继续测试")

    # 可选：原始字节重放模式（最忠实复刻抓包）
    if args.replay_raw:
        rawpath = os.path.join(ROOT, "captures_live", "_71b_trigger_payloads.bin")
        if not os.path.exists(rawpath):
            print(f"✗ 原始重放文件不存在: {rawpath}")
            return 1
        print(f"\n{'#'*64}")
        print(f"# 原始字节重放（抓包 flow1 +16~19s 的 12 个 TCP 包）")
        print(f"{'#'*64}")
        _drain(sock)
        raw = open(rawpath, "rb").read()
        off = 0
        n = 0
        while off + 8 <= len(raw):
            dt, plen = struct.unpack("<fI", raw[off:off+8])
            off += 8
            pl = raw[off:off+plen]
            off += plen
            try:
                sock.sendall(pl + b"\n")
                n += 1
                print(f"  重放 +{dt:.2f}s 包({len(pl)}B)")
            except OSError as e:
                print(f"  发送失败: {e}")
                break
        print(f"  已重放 {n} 个原始包")
        c = collect(sock, args.seconds, "原始字节重放", dump=True)
        n71 = c.get("71B逐笔", 0)
        print(f"\n★ 原始重放 71B={n71} {'触发成功！' if n71>0 else '仍无71B'}")
        try: sock.close()
        except OSError: pass
        return 0

    scenes = []
    if args.scene in ("all", "full"):
        scenes.append(("full", "完整序列：subreal5716+1334+4214"))
    if args.scene in ("all", "subreal"):
        scenes.append(("subreal", "subreal5716 + 4214"))
    if args.scene in ("all", "1334"):
        scenes.append(("1334", "1334分时 + 4214"))
    if args.scene in ("all", "4214"):
        scenes.append(("4214", "仅4214（baseline）"))

    results = {}
    for sid, (skey, label) in enumerate(scenes, 1):
        print(f"\n{'#'*64}")
        print(f"# 场景 {sid}: {label}")
        print(f"{'#'*64}")
        # 每个场景前先清空接收缓冲（读掉积压帧）
        _drain(sock)
        try:
            if skey in ("full", "subreal"):
                n = send_subreal(sock, pageid=5716)
                print(f"  发 subreal×{n} (pageid=5716)")
                time.sleep(0.3)
            if skey in ("full", "1334"):
                # 先发 subreal(1334) 注册（抓包 +5.65/+16.42 都发了）
                n2 = send_subreal(sock, pageid=1334)
                print(f"  发 subreal×{n2} (pageid=1334)")
                time.sleep(0.2)
                f = build_1334_timeline(code, market)
                sock.sendall(f + b"\n")
                print(f"  发 1334 L2分时订阅")
                time.sleep(0.3)
            # 4214 订阅（所有场景都发）
            f = build_snapshot_subscribe(code, market=market, seq=0)
            sock.sendall(f + b"\n")
            print(f"  发 4214 订阅")
        except OSError as e:
            print(f"  发送失败: {e}")
        c = collect(sock, args.seconds, label, dump=args.dump)
        results[label] = c

    # 总结
    print(f"\n{'='*64}")
    print("【总结】71B 触发对比")
    print(f"{'='*64}")
    for label, c in results.items():
        n71 = c.get("71B逐笔", 0)
        n549 = c.get("549B十档", 0)
        mark = "★ 触发71B" if n71 > 0 else "✗ 无71B"
        print(f"  {label:<28} 71B={n71:<4} 549B={n549:<4} {mark}")

    try:
        sock.close()
    except OSError:
        pass
    try:
        client.disconnect()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
