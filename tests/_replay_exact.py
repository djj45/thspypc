#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""精确复刻 hexin 131453 包 stream1 的完整激活序列，看 CodeListSize。

逐字节复刻 hexin 在发 4214 订阅帧之前的完整序列：
  1. 5716 多股查询（CodeList=33(...002396,...) sub=0x0009 rt=0x0001 seq=0x106f）
  2. subreal×5（pageid=5716，不是 4214！）
  3. 5716 注册帧（sub=0x0002 rt=0x0401 pageid=5716）
  4. 4214 订阅帧（我们的 build_snapshot_subscribe）

关键假设：步骤 1-3 中的某一步激活了"允许 4214 注册"的会话状态。
"""
from __future__ import annotations
import datetime, os, sys, socket, struct, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    read_frame, encode_frame, build_snapshot_subscribe,
    build_subreal_query, SUBREAL_CHANNELS, build_passport64, MARKET_PORT,
)
sys.path.insert(0, os.path.dirname(__file__))
from _manual_login_test import build_manual_login_body


def build_query(code_text: str, datatype: list[int], pageid: int,
                seq: int, byte6_hi: int = 0x00, rt: int = 0x0001) -> bytes:
    """通用 0x0009 查询帧。byte6_hi 控制 seq 高字节（hexin 用 0x10）。"""
    dt_s = ",".join(str(d) for d in datatype) + ","
    text = (f"CodeList={code_text}\r\nDataType={dt_s}\r\n"
            f"DateTime=0(0-0)\r\nLackTime=0,0,0,0,0,0,0,0\r\npageid={pageid}\r\n").encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09; hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, (seq & 0xFF) | (byte6_hi << 8))
    hdr[7:11] = b"\x12\x00\x09\x00"
    struct.pack_into("<H", hdr, 11, rt)
    struct.pack_into("<I", hdr, 19, len(text))
    return encode_frame(bytes(hdr) + text)


def build_pageid_reg(pageid: int, rt_hi: int, rt_lo: int) -> bytes:
    """5716 注册帧（sub=0x0002 rt=自定义, 文本 pageid=XXXX）。"""
    text = f"\r\npageid={pageid}\r\n".encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09; hdr[1:5] = b"\x00\x16\x00\x00"
    hdr[7:11] = b"\x12\x00\x02\x00"
    hdr[11] = rt_lo; hdr[12] = rt_hi
    struct.pack_into("<I", hdr, 19, len(text))
    return encode_frame(bytes(hdr) + text)


def load_dotenv():
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(p): return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("=")
        if k and k not in os.environ: os.environ[k.strip()] = v.strip().strip('"').strip("'")


def read_responses(sock, label, duration=5.0):
    """读服务器响应，打印 CodeListSize 等。"""
    sock.settimeout(duration)
    t0 = time.time(); n = 0
    while time.time() - t0 < duration:
        try:
            body = read_frame(sock)
        except socket.timeout:
            break
        except (OSError, ValueError) as e:
            print(f"    [{label}] 读异常: {e}"); return False
        n += 1
        if b"CodeListSize" in body:
            import re
            m = re.search(rb"CodeListSize=(\d+)", body)
            val = m.group(1).decode() if m else "?"
            print(f"    [{label}] ★ CodeListSize={val} ({len(body)}B)")
        elif b"tsi0=" in body:
            continue  # 心跳
        elif n <= 3:
            prev = body[:50].decode("gbk","replace").replace("\n","|").replace("\r","")[:50]
            print(f"    [{label}] #{n} {len(body)}B {prev!r}")
    return True


def main():
    load_dotenv()
    code = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].isdigit() else "002396"
    market = 17 if code.startswith("6") else 33
    username = os.environ["THS_USERNAME"]; password = os.environ["THS_PASSWORD"]
    imei = os.environ.get("THS_IMEI","").strip() or None

    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}"); return 1
    print(f"✓ 普通登录 {r.server}")
    passport64 = build_passport64(client._auth)
    mac64 = client.mac64
    host = client._connected_ip
    client.disconnect()

    # ★ 用 __manual 登录开新连接（hexin 收推送的连接就是 __manual 登录的）
    use_manual = "--no-manual" not in sys.argv
    if use_manual:
        print(f"\n【0】用 UserName=__manual 开新连接...")
        login_body = build_manual_login_body(passport64, mac64)
        sock = socket.create_connection((host, MARKET_PORT), timeout=15)
        sock.sendall(encode_frame(login_body) + b"\n")
        sock.settimeout(8.0)
        resp = read_frame(sock)
        vc = ""
        for line in resp.decode("gbk","replace").replace("\r\n","\n").split("\n"):
            if line.startswith("VerifyCode="):
                vc = line.split("=",1)[1]
        if vc != "0":
            print(f"  ✗ __manual 登录失败 VerifyCode={vc}")
            # 回退到普通连接
            client2 = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
            client2.connect()
            sock = client2._sock
            client = client2
            print(f"  回退普通连接 {client._connected_ip}")
        else:
            print(f"  ✓ __manual 登录成功")
            # __manual 连接不发 init（HANDOFF §2 确认 __manual 连接发 init 会被拒断连）
    else:
        client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
        client.connect()
        sock = client._sock
        print(f"普通连接 {client._connected_ip}（无 __manual）")

    # 步骤1: 5716 多股查询（含目标 code，byte6_hi=0x10 复刻 hexin seq=0x106f）
    # hexin: CodeList=33(000063,000938,...,002396,...) DataType=10,6,66,1111 pageid=5716
    cl = f"{market}({code},)"
    sock.sendall(build_query(cl, [10, 6, 66, 1111], 5716, seq=0x6f, byte6_hi=0x10) + b"\n")
    print("【1】发 5716 多股查询（含 002396，seq高字节0x10）")
    if not read_responses(sock, "step1", 3.0): return 1

    # 步骤2: subreal×5（pageid=5716，复刻 hexin）
    for ch in SUBREAL_CHANNELS:
        sock.sendall(encode_frame(
            build_subreal_query(0x7FFFFFFF, channel=ch, action="change",
                                pageid=5716)) + b"\n")
    print("【2】发 subreal×5 (pageid=5716)")
    if not read_responses(sock, "step2", 3.0): return 1

    # 步骤3: 5716 注册帧（sub=0x0002 rt=0x0401）
    sock.sendall(build_pageid_reg(5716, 0x04, 0x01) + b"\n")
    print("【3】发 5716 注册帧（rt=0x0401）")
    if not read_responses(sock, "step3", 3.0): return 1

    # 步骤4: 4214 订阅帧（嵌套双子帧）
    sock.sendall(build_snapshot_subscribe(code, market=market, seq=0) + b"\n")
    print("【4】发 4214 订阅帧")
    if not read_responses(sock, "step4-订阅", 5.0): return 1

    # 步骤5: 等 71B 推送
    print("\n【5】等 71B 推送（30s）...")
    sock.settimeout(2.0)
    t0 = time.time(); push_n = 0; other_n = 0
    from thspypc.protocol import is_snapshot_push, parse_snapshot_push
    while time.time() - t0 < 30:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as e:
            print(f"  读异常: {e}"); break
        if is_snapshot_push(body):
            push_n += 1
            rec = parse_snapshot_push(body)
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            if push_n <= 5:
                print(f"  [{ts}] ★71B #{push_n} {rec['code']} 现价={rec['price']:.3f}")
        elif b"tsi0=" in body:
            continue
        else:
            other_n += 1
    print(f"\n汇总: 71B推送={push_n}, 其他帧={other_n}")
    if push_n > 0:
        print("✓✓✓ 推送成功！")
    else:
        print("✗ 仍无推送")
    try: client.disconnect()
    except: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
