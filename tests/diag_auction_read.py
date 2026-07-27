#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""诊断：为什么 read_frame 读不到竞价响应。

monkey-patch protocol.read_frame，每次读取后打印帧摘要，
然后调 client.auction()，看循环卡在哪一帧。
"""
from __future__ import annotations
import datetime, logging, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
logging.basicConfig(level=logging.INFO, format="  ·%(levelname)s %(name)s: %(message)s", stream=sys.stdout)

from thspypc import THSClient
import thspypc.protocol as proto

_orig_read_frame = proto.read_frame
_call_count = [0]

def spy_read_frame(sock):
    _call_count[0] += 1
    n = _call_count[0]
    try:
        body = _orig_read_frame(sock)
    except Exception as e:
        print(f"  [read_frame#{n}] 异常: {type(e).__name__}: {e}")
        raise
    # 帧摘要
    size = len(body)
    has_hd = b"hd1.0" in body or b"Ihd1.0" in body
    has_codelist = b"CodeListSize" in body
    has_login = b"login" in body
    has_market = b"MarketCode" in body or b"MarketTime" in body
    has_603118 = b"603118" in body
    tags = []
    if has_login: tags.append("login")
    if has_market: tags.append("init/markettime")
    if has_codelist: tags.append("CodeListSize")
    if has_hd: tags.append("★hd1.0")
    if has_603118: tags.append("603118")
    # 前 60 字节 ascii
    ascii_preview = body[:80].decode("latin1", "replace").replace("\x00", ".").replace("\r", ".").replace("\n", ".")
    print(f"  [read_frame#{n}] {size}B [{','.join(tags) or '?'}] {ascii_preview[:70]}")
    # ★ 对含 hd1.0 的帧，立即测试 parse_auction_response 并存盘
    if b"hd1.0" in body and not has_codelist and not has_login:
        import os
        outp = os.path.join(os.path.dirname(__file__), "..", "captures_live", f"_diag_frame_{n}.bin")
        with open(outp, "wb") as f:
            f.write(body)
        try:
            recs = proto.parse_auction_response(body)
            print(f"           → parse_auction_response 返回 {len(recs)} 条")
            if recs:
                print(f"           首条: {recs[0]}")
            else:
                # 解析失败，dump 帧头结构帮助定位
                p = body.find(b"hd1.0")
                print(f"           ✗ 解析返回空！hd1.0@{p}，帧头 hex: {body[p:p+20].hex()}")
                print(f"           Ihd1.0? {b'Ihd1.0' in body}  flag 字节: {body[p+6:p+12].hex()}")
        except Exception as e:
            print(f"           → parse 异常: {type(e).__name__}: {e}")
    return body

proto.read_frame = spy_read_frame
# client.py 里 read_frame 是 from .protocol import 进来的，patch protocol 模块属性即可
# （client 用的是 import 时绑定的名字，需要也 patch client 模块的引用）
import thspypc.client as client_mod
client_mod.read_frame = spy_read_frame


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path): return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")


def main():
    load_dotenv()
    client = THSClient(username=os.environ["THS_USERNAME"],
                       password=os.environ["THS_PASSWORD"],
                       imei=os.environ.get("THS_IMEI"))
    try:
        r = client.connect()
        if not r.success:
            print("登录失败:", r.error); return 1
        print("✓ 登录成功\n→ 查 603118 竞价（带 read_frame 诊断）...")
        trade_date = datetime.date(2026, 7, 27)
        try:
            recs = client.auction("603118", trade_date=trade_date, timeout=30.0)
            print(f"\n结果: {len(recs)} 条")
        except Exception as e:
            print(f"\n✗ 异常: {type(e).__name__}: {e}")
            print(f"  read_frame 共调用 {_call_count[0]} 次")
        return 0
    finally:
        client.disconnect()

if __name__ == "__main__":
    sys.exit(main())
