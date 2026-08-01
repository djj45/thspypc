#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★决定性实验 v2：__manual 登录后复刻完整分时请求 burst，看推送。

v1 结论：__manual 登录成功 + 双子帧注册 → 服务器回 CodeListSize=1（注册确认），
但 30s 内无 71B 推送。

v2 改进：
  1. 注册后复刻抓包 t=30.16-30.22s 的完整 4214 burst（多个 byte11-12 变体）
  2. 加心跳（__manual 连接也靠心跳保活）
  3. dump 更长时间 + 打印所有非心跳帧

关键疑点：推送是否需要 burst 里的某个特定查询（如 byte11-12=02 01 + DataType=70,69,10）。
"""
from __future__ import annotations
import os, sys, time, datetime, socket, struct, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
from thspypc import THSClient
from thspypc.protocol import (
    encode_frame, read_frame, build_subreal_query, SUBREAL_CHANNELS,
    SNAPSHOT_PAGEID, is_snapshot_push, parse_snapshot_push,
    build_passport64, MARKET_PORT, build_heartbeat_8901,
)
from _manual_login_test import (
    build_manual_login_body, build_dual_subframe_trigger,
    build_manual_login_body_v2,
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


def build_query_frame(code, market, datatype, byte11_12, seq, dt_str="0(0-0)"):
    """通用单子帧 0x0009 查询构造。"""
    dt_s = ",".join(str(d) for d in datatype) + ","
    text = (f"CodeList={market}({code},);\r\nDataType={dt_s}\r\n"
            f"DateTime={dt_str}\r\nLackTime=0,0,0,0,0,0,0,0\r\npageid=4214\r\n").encode("gbk")
    hdr = bytearray(23)
    hdr[0] = 0x09
    hdr[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", hdr, 5, seq & 0xFFFF)
    hdr[7:11] = b"\x12\x00\x09\x00"
    hdr[11] = byte11_12[0]; hdr[12] = byte11_12[1]
    struct.pack_into("<I", hdr, 19, len(text))
    return encode_frame(bytes(hdr) + text)


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
            print(f"✗ 登录失败: {r.error}"); return 1
        passport64 = build_passport64(client._auth)
        mac64 = client.mac64; host = client._connected_ip
        print(f"✓ {r.server}")
        client.disconnect()
    finally:
        try: client.disconnect()
        except Exception: pass

    print("\n【2】__manual 登录开新连接...")
    login_body = build_manual_login_body(passport64, mac64)
    sock = socket.create_connection((host, MARKET_PORT), timeout=15)
    sock.sendall(encode_frame(login_body) + b"\n")
    sock.settimeout(8.0)
    resp = read_frame(sock)
    txt = resp.decode("gbk", "replace")
    vc = ""
    for line in txt.replace("\r\n", "\n").split("\n"):
        if line.startswith("VerifyCode="):
            vc = line.split("=", 1)[1]
    if vc != "0":
        print(f"✗ __manual 登录失败 VerifyCode={vc}"); sock.close(); return 1
    print(f"✓ __manual 登录成功")

    outpath = os.path.join(os.path.dirname(__file__), "..", "captures_live", "_manual_test_v2_out.txt")
    fout = open(outpath, "w", encoding="utf-8")
    def log(s):
        print(s); fout.write(s + "\n"); fout.flush()

    print(f"\n【3】复刻完整 burst + 心跳，dump 45s（code={code} mk={market}）...")
    # subreal×5
    for ch in SUBREAL_CHANNELS:
        sock.sendall(encode_frame(build_subreal_query(0x7FFFFFFF, channel=ch, action="change", pageid=SNAPSHOT_PAGEID)) + b"\n")
    log("  发 subreal×5")
    # 双子帧注册（抓包 t=30.155）
    sock.sendall(build_dual_subframe_trigger(code, market=market) + b"\n")
    log("  发双子帧注册")
    time.sleep(0.3)
    # 复刻 burst 里 byte11-12=02 01 的查询（DataType=70,69,10,9,8 抓包 t=30.20s seq=0x1086）
    sock.sendall(build_query_frame(code, market, [70,69,10,9,8], b"\x02\x01", 0x0086) + b"\n")
    log("  发 byte11-12=0201 DataType=70,69,10,9,8")
    time.sleep(0.05)
    # byte11-12=00 01 综合查询（DataType=7,8,9,10,...）
    sock.sendall(build_query_frame(code, market, [7,8,9,10,13,14,19,69,70,74,75,85,90,92,130,6], b"\x00\x01", 0x0097) + b"\n")
    log("  发 byte11-12=0001 DataType=7,8,9,10,...")

    # 启动心跳线程
    hb_stop = threading.Event()
    def hb_loop():
        cnt = 0
        while not hb_stop.is_set():
            if hb_stop.wait(8.0): break
            try:
                sock.sendall(build_heartbeat_8901(cnt & 0xFFFF) + b"\n")
                cnt += 1
            except Exception: break
    hb_t = threading.Thread(target=hb_loop, daemon=True); hb_t.start()
    log("  心跳线程已启动（8s 间隔）")

    sock.settimeout(2.0)
    t0 = time.time(); n = 0; snap_n = 0
    while time.time() - t0 < 45:
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as e:
            log(f"  [read err] {e}"); break
        n += 1
        if is_snapshot_push(body):
            snap_n += 1
            rec = parse_snapshot_push(body)
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★★SNAP {len(body)}B: {rec}")
            continue
        is_hb = b"\x12\x00\x03\x00" in body[:12] and b"tsi0=" in body
        if is_hb:
            continue
        if n <= 15 or n % 30 == 0:
            head = body[:24].hex(' ')
            asc = body[:50].decode('gbk','replace').replace('\n','|').replace('\r','')[:50]
            log(f"  #{n} {len(body)}B: {head}  {asc!r}")
    hb_stop.set()
    log(f"\n【汇总】45s 收 {n} 帧，71B 快照 {snap_n} 个")
    if snap_n > 0:
        log("✓✓✓ 推送成功！__manual + burst 触发！")
    elif n > 0:
        log("⚠ 有响应无推送。")
    else:
        log("✗ 零响应。")
    fout.close(); sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
