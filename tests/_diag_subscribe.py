#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""诊断：发分时订阅帧后，服务器到底回了什么？（打印所有原始响应帧）

不走 client 的 callback 模式（那会吞掉非 71B 帧），直接 read_frame 看全部。
"""
from __future__ import annotations
import datetime, os, sys, socket, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    read_frame, encode_frame, build_snapshot_subscribe,
    build_subreal_query, SUBREAL_CHANNELS, SNAPSHOT_PAGEID,
)


def load_dotenv():
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(p): return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("=")
        k = k.strip(); v = v.strip().strip('"').strip("'")
        if k and k not in os.environ: os.environ[k] = v

def main():
    load_dotenv()
    code = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].isdigit() else "000938"
    market = 17 if code.startswith("6") else 33
    username = os.environ["THS_USERNAME"]; password = os.environ["THS_PASSWORD"]
    imei = os.environ.get("THS_IMEI","").strip() or None

    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}"); return 1
    print(f"✓ 登录 {r.server}")
    sock = client._sock

    # ★ 先发 subreal×5（pageid=4214）—— _manual_test_v2 用这个拿到了 CodeListSize=1
    use_subreal = "--no-subreal" not in sys.argv
    with client._sock_lock:
        if use_subreal:
            for ch in SUBREAL_CHANNELS:
                sock.sendall(encode_frame(
                    build_subreal_query(0x7FFFFFFF, channel=ch, action="change",
                                        pageid=SNAPSHOT_PAGEID)) + b"\n")
            print(f"已发 subreal×5 (pageid=4214)")
        # 发订阅帧（嵌套双子帧）
        frame = build_snapshot_subscribe(code, market=market, seq=0)
        print(f"发订阅帧 body[{len(frame)-12}]: {frame[12:40].hex(' ')}...")
        sock.sendall(frame + b"\n")
    print("已发送。读服务器响应（20s）...\n")

    sock.settimeout(2.0)
    t0 = time.time(); n = 0
    while time.time() - t0 < 20:
        try:
            body = read_frame(sock)
        except socket.timeout:
            el = time.time() - t0
            if n == 0 and el > 5:
                print(f"  [{el:.0f}s] 仍无任何响应...")
            continue
        except (OSError, ValueError) as e:
            print(f"  [读异常] {e}"); break
        n += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        # 分类
        tag = ""
        if b"tsi0=" in body: tag = "[心跳]"
        elif b"errorcode" in body[:120]: tag = "[错误]"
        elif b"CodeListSize" in body: tag = "[注册响应]"
        elif b"hd1.0" in body: tag = "[hd1.0数据]"
        elif b"hd3.1" in body: tag = "[hd3.1数据]"
        elif len(body) in (71,72) and body[0]==0x09: tag = "[★71B推送?]"
        elif len(body)==321 and body[0]==0x09: tag = "[321B指数]"
        preview = body[:60].decode("gbk","replace").replace("\n","|").replace("\r","")[:60]
        print(f"  [{ts}] #{n} {len(body)}B {tag}")
        print(f"    hex: {body[:30].hex(' ')}")
        print(f"    txt: {preview!r}")
    print(f"\n汇总: 20s 收 {n} 帧")
    try: client.disconnect()
    except: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
