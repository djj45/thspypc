#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""诊断脚本：订阅后 dump socket 收到的每一个原始帧（不过滤）。

目标：搞清楚服务器到底推不推、推什么格式。绕过 _snapshot_loop/is_snapshot_push。
发完 subreal×5 + 分时请求后，直接 read_frame 循环，每帧打印 len + hex头 + ascii。
"""
from __future__ import annotations
import os, sys, time, datetime, threading, socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    build_subreal_query, build_snapshot_subscribe, encode_frame,
    read_frame, SNAPSHOT_PAGEID, SNAPSHOT_PAGEID_SUB, SUBREAL_CHANNELS,
    is_snapshot_push, parse_snapshot_push, build_list_quote_query,
    build_init_query,
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


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    code = sys.argv[1] if len(sys.argv) > 1 else "603118"
    secs = 30.0
    if "--secs" in sys.argv:
        i = sys.argv.index("--secs")
        if i + 1 < len(sys.argv):
            secs = float(sys.argv[i + 1])

    # 用 enable_heartbeat=False 避免心跳线程抢读 socket
    client = THSClient(username=username, password=password, imei=imei,
                       enable_heartbeat=False)
    try:
        print("→ 登录（关闭心跳，独占 socket 读取）...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error} / {result.detail}")
            return 1
        print(f"✓ 登录成功 {result.server}")
        sock = client._sock
        market = 17 if code.startswith("6") else 33

        print(f"\n→ 发送分时订阅请求（code={code} market={market}）...")
        # 模式：sub1/sub2/dual/nosub/full（full=完整复刻hexin序列）
        mode = "dual"
        for a in sys.argv[1:]:
            if a in ("sub1", "sub2", "dual", "nosub", "full"):
                mode = a
        print(f"  模式: {mode}")
        with client._sock_lock:
            if mode == "full":
                # ★完整复刻 hexin t=30.06s 序列：
                # 1) pageid=5716 多股订阅（注册股票到推送通道）
                frame5716 = build_list_quote_query(
                    [code], market=market,
                    datatype=[10, 6, 66, 1111],
                    pageid=SNAPSHOT_PAGEID_SUB, seq=0x006f)
                sock.sendall(frame5716 + b"\n")
                print("  [full] 已发 5716 多股注册")
            if mode != "nosub":
                for ch in SUBREAL_CHANNELS:
                    body = build_subreal_query(0x7FFFFFFF, channel=ch,
                                              action="change", pageid=SNAPSHOT_PAGEID)
                    sock.sendall(encode_frame(body) + b"\n")
            if mode == "sub1":
                # 单独测试子帧1：0x0002 轻量注册（单独一帧）
                import struct as _st
                text1 = f"CodeList={market}({code},);\r\npageid=4214\r\n".encode("gbk")
                sub1 = bytearray(23)
                sub1[0]=0x09; sub1[1:5]=b"\x00\x16\x00\x00"
                sub1[7:11]=b"\x12\x00\x02\x00"; sub1[11]=0x02; sub1[12]=0x00
                _st.pack_into("<I", sub1, 19, len(text1))
                sock.sendall(encode_frame(bytes(sub1)+text1) + b"\n")
                print("  (仅子帧1 单独一帧)")
            elif mode == "sub2":
                # 单独测试子帧2：0x0009（用 build_snapshot_subscribe 但只要子帧2部分）
                # 直接构造单子帧2
                from thspypc.protocol import SNAPSHOT_DATATYPE
                import struct as _st
                dt_str = ",".join(str(d) for d in SNAPSHOT_DATATYPE) + ","
                text2 = (f"CodeList={market}({code},);\r\nDataType={dt_str}\r\n"
                         f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\npageid=4214\r\n").encode("gbk")
                sub2 = bytearray(23)
                sub2[0]=0x09; sub2[1:5]=b"\x00\x16\x00\x00"
                _st.pack_into("<H", sub2, 5, 0x0071)
                sub2[7:11]=b"\x12\x00\x09\x00"; sub2[11]=0x00; sub2[12]=0x01
                _st.pack_into("<I", sub2, 19, len(text2))
                sock.sendall(encode_frame(bytes(sub2)+text2) + b"\n")
                print("  (仅子帧2 单独一帧)")
            elif mode in ("dual", "full"):
                # 双子帧（子帧1+子帧2 拼接，字节级复刻抓包）
                self_seq = 0x0071
                frame = build_snapshot_subscribe(code, market=market, seq=self_seq)
                sock.sendall(frame + b"\n")
                print("  (%s) 已发 4214 双子帧" % mode)
        print("✓ 请求已发送\n")

        print(f"→ dump socket 收到的帧（{secs}s，每帧打印 len/头/ascii）...")
        print("="*70)
        sock.settimeout(2.0)
        t0 = time.time()
        n = 0
        snap_n = 0
        size_dist = {}
        while time.time() - t0 < secs:
            try:
                body = read_frame(sock)
            except socket.timeout:
                continue
            except (OSError, ValueError) as e:
                print(f"  [read err] {e}")
                continue
            n += 1
            size_dist[len(body)] = size_dist.get(len(body), 0) + 1
            is_snap = is_snapshot_push(body)
            if is_snap:
                snap_n += 1
                rec = parse_snapshot_push(body)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] #{n} ★SNAP {len(body)}B: {rec}")
                continue
            # 非快照帧：前40字节 hex + ascii
            head = body[:40].hex(' ')
            # 前3帧打印完整 hex（诊断服务器响应内容）
            if n <= 3:
                print(f"  #{n} {len(body)}B 完整hex:")
                for i in range(0, len(body), 32):
                    print(f"    {body[i:i+32].hex(' ')}")
                try:
                    full_asc = body.decode('gbk','replace').replace('\n','|').replace('\r','')[:200]
                    print(f"        ascii: {full_asc!r}")
                except Exception:
                    pass
                continue
            try:
                asc = body[:60].decode('gbk', 'replace').replace('\n','|').replace('\r','')[:60]
            except Exception:
                asc = ""
            # 只打印前 30 个非快照帧 + 每隔一段
            if n <= 30 or n % 50 == 0:
                print(f"  #{n} {len(body)}B: {head}")
                if asc.strip():
                    print(f"        ascii: {asc!r}")

        print("="*70)
        print(f"\n【汇总】{secs:.0f}s 内收到 {n} 帧，其中快照帧 {snap_n} 个")
        print(f"帧大小分布: {sorted(size_dist.items())}")
        if n == 0:
            print("✗ 服务器零响应。请求格式问题或需要更多前置。")
        elif snap_n == 0:
            print("⚠ 收到帧但无 71B 快照。可能现价在别的帧格式里。")
            print("  看上面的帧内容，找含 ASCII 代码 + 价位数值的帧。")
        else:
            print("✓ 收到快照推送！")
        return 0
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
