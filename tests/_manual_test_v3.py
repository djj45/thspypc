#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★决定性实验 v3：__manual 登录 + 复刻最小预热（5716 指数注册）验证推送通道。

v2 结论：__manual 登录 + 双子帧注册 → CodeListSize=1，但 45s 无任何推送。
抓包新发现：__manual stream1 在 t=5.28s 就开始收 321B 指数推送（399001深证成指），
而我的 v2 测试一帧推送都没收到。说明【推送通道需要预热才激活】。

抓包 t=5.26s 之前 __manual stream1 发的预热：5716 注册帧（注册 399001,399006 指数）。
格式（双子帧）：
  子帧1: byte11-12=01 00, sub 0x0002, text='|pageid=5716|'  (15B, off19=0x0f)
  子帧2: byte11-12=fc 00, sub 0x0002, text='CodeList=32(399001,399006,);|pageid=5716|'

本脚本：
  1. __manual 登录
  2. 发 5716 指数注册（验证推送通道激活 → 应收 321B 指数推送）
  3. 若指数推送 OK，再发个股 4214 注册，等 71B 推送
  4. 全程心跳保活
"""
from __future__ import annotations
import os, sys, time, datetime, socket, struct, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
from thspypc import THSClient
from thspypc.protocol import (
    encode_frame, read_frame, build_subreal_query, SUBREAL_CHANNELS,
    SNAPSHOT_PAGEID, build_passport64, MARKET_PORT, build_heartbeat_8901,
)
from _manual_login_test import (
    build_manual_login_body, build_dual_subframe_trigger,
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


def build_5716_index_register(codes="399001,399006", market=32, byte11_12_2=b"\xfc\x00"):
    """5716 指数注册双子帧（复刻 t=0.59s）。
    子帧1: sub 0x0002, byte11-12=01 00, text='|pageid=5716|'
    子帧2: sub 0x0002, byte11-12=<byte11_12_2>, text='CodeList=<mk>(<codes>,);|pageid=5716|'
    """
    text1 = b"|pageid=5716|"
    sub1 = bytearray(23)
    sub1[0] = 0x09; sub1[1:5] = b"\x00\x16\x00\x00"
    sub1[7:11] = b"\x12\x00\x02\x00"; sub1[11] = 0x01; sub1[12] = 0x00
    struct.pack_into("<I", sub1, 19, len(text1))
    text2 = f"CodeList={market}({codes},);|pageid=5716|".encode("gbk")
    sub2 = bytearray(23)
    sub2[0] = 0x09; sub2[1:5] = b"\x00\x16\x00\x00"
    sub2[7:11] = b"\x12\x00\x02\x00"; sub2[11] = byte11_12_2[0]; sub2[12] = byte11_12_2[1]
    struct.pack_into("<I", sub2, 19, len(text2))
    return encode_frame(bytes(sub1) + text1 + bytes(sub2) + text2)


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None
    code = "002396"; market = 33
    for a in sys.argv[1:]:
        if a.isdigit() and len(a) == 6:
            code = a; market = 17 if code.startswith("6") else 33

    print("【1】普通登录拿 Passport64...")
    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    try:
        r = client.connect()
        if not r.success:
            print(f"✗ {r.error}"); return 1
        passport64 = build_passport64(client._auth)
        mac64 = client.mac64; host = client._connected_ip
        print(f"✓ {r.server}")
        client.disconnect()
    finally:
        try: client.disconnect()
        except Exception: pass

    print("\n【2】__manual 登录...")
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
    sock.settimeout(8.0)
    resp = read_frame(sock)
    vc = ""
    for line in resp.decode("gbk","replace").replace("\r\n","\n").split("\n"):
        if line.startswith("VerifyCode="): vc = line.split("=",1)[1]
    if vc != "0":
        print(f"✗ __manual 登录失败 vc={vc}"); sock.close(); return 1
    print("✓ __manual 登录成功")

    outpath = os.path.join(os.path.dirname(__file__), "..", "captures_live", "_manual_test_v3_out.txt")
    fout = open(outpath, "w", encoding="utf-8")
    def log(s):
        print(s); fout.write(s + "\n"); fout.flush()

    # 心跳线程
    hb_stop = threading.Event()
    def hb_loop():
        cnt = 0
        while not hb_stop.is_set():
            if hb_stop.wait(8.0): break
            try: sock.sendall(build_heartbeat_8901(cnt & 0xFFFF) + b"\n"); cnt += 1
            except Exception: break
    threading.Thread(target=hb_loop, daemon=True).start()

    print(f"\n【3】复刻最小预热：subreal×5 + 5716 指数注册，验证推送通道...")
    for ch in SUBREAL_CHANNELS:
        sock.sendall(encode_frame(build_subreal_query(0x7FFFFFFF, channel=ch, action="change", pageid=SNAPSHOT_PAGEID)) + b"\n")
    log("  发 subreal×5")
    sock.sendall(build_5716_index_register() + b"\n")
    log("  发 5716 指数注册（399001,399006）")

    # 读取循环：分类统计 321B 指数推送 / 71B 个股推送 / 其他
    sock.settimeout(2.0)
    t0 = time.time(); n = 0; idx_n = 0; stock_n = 0
    stock_registered = False
    while time.time() - t0 < 25:
        try:
            body = read_frame(sock)
        except socket.timeout:
            # 12s 后若指数推送都没来，仍尝试个股注册
            if not stock_registered and time.time() - t0 > 6:
                log("  ★ 6s 到，发个股 4214 注册（不等指数推送）")
                sock.sendall(build_dual_subframe_trigger(code, market=market) + b"\n")
                stock_registered = True
            continue
        except (OSError, ValueError) as e:
            log(f"  [read err] {e}"); break
        n += 1
        is_hb = b"tsi0=" in body
        if is_hb: continue
        if len(body) == 321 and body[0] == 0x09:
            idx_n += 1
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★INDEX321B 指数推送 #{idx_n}")
            if not stock_registered:
                log(f"  ★ 推送通道激活！发个股 4214 注册（{code}）")
                sock.sendall(build_dual_subframe_trigger(code, market=market) + b"\n")
                stock_registered = True
            continue
        if len(body) == 71 and body[0] == 0x09 and body[14] == 0x80:
            stock_n += 1
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★★STOCK71B 个股推送 #{stock_n} {body[29:35]!r}")
            continue
        if n <= 12:
            asc = body[:45].decode('gbk','replace').replace('\n','|').replace('\r','')[:45]
            log(f"  #{n} {len(body)}B: {body[:20].hex(' ')}  {asc!r}")
    hb_stop.set()
    log(f"\n【汇总】25s 收 {n} 帧，321B指数推送 {idx_n}，71B个股推送 {stock_n}")
    if idx_n > 0:
        log("✓ 推送通道激活（收到指数推送）")
    if stock_n > 0:
        log("✓✓✓ 个股推送成功！")
    fout.close(); sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
