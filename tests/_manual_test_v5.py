#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★决定性实验 v5：__manual 登录 + INIT 握手 + 注册，验证推送。

v4 失败原因新发现：__manual stream1 在 t=1.04s 发了 INIT 请求（subtype 0x0001，
C-Modules=MEQT），这是激活行情/推送通道的关键步骤。我之前所有测试都没发 INIT。

本脚本：
  1. 普通登录拿 Passport64
  2. __manual 登录新连接
  3. ★发 INIT 请求（build_init_query），读 init 响应配置帧
  4. subreal×5（pageid=5716）+ PushField 注册帧（重放抓包）
  5. 等 321B 指数推送（验证推送通道激活）
  6. 股票 4214 注册 + 等 71B 推送
"""
from __future__ import annotations
import os, sys, time, datetime, socket, struct, subprocess, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
from thspypc import THSClient
from thspypc.protocol import (
    encode_frame, read_frame, build_subreal_query, build_passport64,
    MARKET_PORT, build_heartbeat_8901, FRAME_MAGIC, build_init_query,
)
from _manual_login_test import build_manual_login_body
import capture_timeline as c

TSHARK = c.TSHARK
PCAP = "captures_live/realtime_push_20260724_131453.pcap"


def extract_frame_by_time(t_lo, t_hi, match_bytes, stream=1):
    r = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y",
         f"tcp.stream=={stream} and tcp.dstport==8901 and tcp.len>0 and "
         f"frame.time_relative>{t_lo} and frame.time_relative<{t_hi}",
         "-T", "fields", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    for ln in r.stdout.decode().splitlines():
        hexp = "".join(ln.split())
        if not hexp:
            continue
        raw = bytes.fromhex(hexp)
        idx = 0
        while True:
            pos = raw.find(FRAME_MAGIC, idx)
            if pos < 0:
                break
            next_pos = raw.find(FRAME_MAGIC, pos + 4)
            seg = raw[pos:next_pos] if next_pos > 0 else raw[pos:]
            if len(seg) >= 12:
                try:
                    bodylen = int(seg[4:12], 16)
                except Exception:
                    idx = pos + 4; continue
                body = seg[12:12 + bodylen]
                if match_bytes in body and len(body) == bodylen:
                    return seg[:12 + bodylen]
            idx = pos + 4
    return None


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

    pushfield_frame = extract_frame_by_time(0.58, 0.61, b"PushField")
    stock_frame = extract_frame_by_time(30.15, 30.165, b"pageid=4214")
    print(f"PushField帧 {len(pushfield_frame) if pushfield_frame else 0}B, 股票帧 {len(stock_frame) if stock_frame else 0}B")
    if not pushfield_frame or not stock_frame:
        print("✗ 帧提取失败"); return 1

    print("\n【1】普通登录拿 Passport64...")
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

    outpath = os.path.join(os.path.dirname(__file__), "..", "captures_live", "_manual_test_v5_out.txt")
    fout = open(outpath, "w", encoding="utf-8")
    def log(s):
        print(s); fout.write(s + "\n"); fout.flush()

    hb_stop = threading.Event()
    def hb_loop():
        cnt = 0
        while not hb_stop.is_set():
            if hb_stop.wait(8.0): break
            try: sock.sendall(build_heartbeat_8901(cnt & 0xFFFF) + b"\n"); cnt += 1
            except Exception: break
    threading.Thread(target=hb_loop, daemon=True).start()

    # ★ 关键新增：发 INIT 请求，读 init 响应配置帧
    print("\n【3】★ 发 INIT 请求（激活行情/推送通道），读配置帧...")
    init_req = build_init_query()
    log(f"  发 INIT 请求（{len(init_req)}B）")
    sock.sendall(init_req + b"\n")
    # 读 init 响应（可能多帧，配置帧 ~大）
    sock.settimeout(5.0)
    init_frames = 0
    try:
        while init_frames < 5:
            try:
                ib = read_frame(sock)
                init_frames += 1
                if b"S-OS=" in ib or b"SName" in ib or b"MarketTime" in ib:
                    log(f"  ✓ init 配置帧 #{init_frames} {len(ib)}B")
                else:
                    log(f"  init 响应帧 #{init_frames} {len(ib)}B head:{ib[:16].hex(' ')}")
            except socket.timeout:
                log(f"  init 响应读完（共 {init_frames} 帧）")
                break
    except Exception as e:
        log(f"  init 读异常: {e}")

    print("\n【4】subreal×5 + PushField 注册，等指数推送...")
    sock.settimeout(2.0)
    for ch in ["URS", "UCT", "UNX", "UCX", "UME"]:
        sock.sendall(encode_frame(build_subreal_query(0x7FFFFFFF, channel=ch, action="change", pageid=5716)) + b"\n")
    log("  发 subreal×5（pageid=5716）")
    sock.sendall(pushfield_frame + b"\n")
    log("  发 PushField 注册帧")

    t0 = time.time(); n = 0; idx_n = 0; stock_n = 0; stock_sent = False
    while time.time() - t0 < 40:
        if not stock_sent and (idx_n > 0 or time.time() - t0 > 12):
            log(f"  ★ 发股票 4214 注册帧")
            sock.sendall(stock_frame + b"\n")
            stock_sent = True
        try:
            body = read_frame(sock)
        except socket.timeout:
            continue
        except (OSError, ValueError) as e:
            log(f"  [read err] {e}"); break
        n += 1
        if b"tsi0=" in body: continue
        if len(body) == 321 and body[0] == 0x09:
            idx_n += 1
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★INDEX321B 指数推送 #{idx_n}")
            continue
        if len(body) == 71 and body[0] == 0x09 and body[14] == 0x80:
            stock_n += 1
            try: cd = body[29:35].decode('ascii')
            except Exception: cd = "?"
            log(f"  [{datetime.datetime.now().strftime('%H:%M:%S')}] #{n} ★★STOCK71B 个股推送 #{stock_n} code={cd}")
            continue
        if n <= 12:
            asc = body[:38].decode('gbk','replace').replace('\n','|').replace('\r','')[:38]
            log(f"  #{n} {len(body)}B: {body[:16].hex(' ')}  {asc!r}")
    hb_stop.set()
    log(f"\n【汇总】40s 收 {n} 帧，321B指数推送 {idx_n}，71B个股推送 {stock_n}")
    if idx_n > 0: log("✓ 推送通道激活（指数推送）")
    if stock_n > 0: log("✓✓✓ 个股推送成功！")
    fout.close(); sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
