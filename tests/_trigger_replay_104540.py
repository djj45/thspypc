#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""★决定性实验 v6：普通 thspypc 连接（已 init 激活）+ 重放 104540 精确触发序列。

新认知：
  - 104540 包 stream1 收 174 推送，首请求是 subreal×5(pageid=4214) + 37B/58B注册，
    【没有 INIT】（连接是预存的，早激活过了）。
  - 我之前用 pageid=5716 的 subreal（131453包风格），可能错了。
  - 我的普通 thspypc 连接【已经发过 init 激活行情通道】（_send_init_handshake），
    最接近"预存连接"状态。

本脚本：用普通 thspypc 连接（已 init），重放 104540 stream1 的精确触发帧字节，看推送。
关键：subreal 用 pageid=4214（不是5716）。
"""
from __future__ import annotations
import os, sys, time, datetime, socket, subprocess, threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
from thspypc import THSClient
from thspypc.protocol import (
    read_frame, build_heartbeat_8901, FRAME_MAGIC, is_snapshot_push, parse_snapshot_push,
)
import capture_timeline as c

TSHARK = c.TSHARK
PCAP = "captures_live/realtime_push_20260724_104540.pcap"


def extract_all_client_frames(t_lo, t_hi, stream=1):
    """提取 stream<stream> t∈[t_lo,t_hi) 所有客户端 fdfdfdfd 帧（含magic+hexlen），按顺序。"""
    r = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y",
         f"tcp.stream=={stream} and tcp.dstport==8901 and tcp.len>0 and "
         f"frame.time_relative>={t_lo} and frame.time_relative<{t_hi}",
         "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    frames = []
    for ln in r.stdout.decode().splitlines():
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        hexp = "".join(parts[1].split())
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
                if len(seg[12:12 + bodylen]) == bodylen:
                    frames.append(seg[:12 + bodylen])
            idx = pos + 4
    return frames


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

    print("【提取 104540 stream1 触发帧】t=68.6-68.7s...")
    frames = extract_all_client_frames(68.6, 68.7, stream=1)
    # 过滤掉心跳
    real_frames = []
    for f in frames:
        body = f[12:]
        if b"tsi0=" in body:
            continue
        real_frames.append(f)
    print(f"  共 {len(real_frames)} 个非心跳触发帧:")
    for i, f in enumerate(real_frames[:8]):
        body = f[12:]
        print(f"    帧{i}: {len(body)}B head:{body[:14].hex(' ')}")
    if len(real_frames) < 3:
        print("✗ 触发帧提取不足"); return 1

    print("\n【1】普通 thspypc 登录（已含 init 激活）...")
    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    try:
        r = client.connect()
        if not r.success:
            print(f"✗ {r.error}"); return 1
        print(f"✓ {r.server}（init 已激活）")
    except Exception as e:
        print(f"✗ 异常 {e}"); return 1

    outpath = os.path.join(os.path.dirname(__file__), "..", "captures_live", "_trigger_v6_out.txt")
    fout = open(outpath, "w", encoding="utf-8")
    def log(s):
        print(s); fout.write(s + "\n"); fout.flush()

    sock = client._sock
    print(f"\n【2】重放 104540 触发序列（前 {min(10, len(real_frames))} 帧），dump 30s 看推送...")
    with client._sock_lock:
        for i, f in enumerate(real_frames[:10]):
            sock.sendall(f + b"\n")
            body = f[12:]
            log(f"  发帧{i} ({len(body)}B head:{body[:12].hex(' ')})")
            time.sleep(0.02)

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
            log(f"  #{n} ★INDEX321B #{idx_n}")
            continue
        if n <= 12:
            asc = body[:36].decode('gbk','replace').replace('\n','|').replace('\r','')[:36]
            log(f"  #{n} {len(body)}B: {body[:14].hex(' ')}  {asc!r}")
    log(f"\n【汇总】30s 收 {n} 帧，321B指数 {idx_n}，71B个股 {stock_n}")
    if stock_n > 0: log("✓✓✓ 推送成功！")
    fout.close()
    try: client.disconnect()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
