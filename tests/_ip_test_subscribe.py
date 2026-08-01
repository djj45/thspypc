#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""快速测试：哪些 IP 能让 __manual + 4214 订阅拿到 CodeListSize=1。"""
from __future__ import annotations
import os, sys, socket, struct, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import (
    read_frame, encode_frame, build_snapshot_subscribe,
    build_passport64, MARKET_PORT, MARKET_HOSTS,
)
sys.path.insert(0, os.path.dirname(__file__))
from _manual_login_test import build_manual_login_body


def load_dotenv():
    p = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(p): return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("=")
        if k and k not in os.environ: os.environ[k.strip()] = v.strip().strip('"').strip("'")


def test_ip(host, passport64, mac64, code="000938", market=33):
    """连指定 IP, __manual 登录, 发 4214 订阅, 返回 CodeListSize。"""
    try:
        sock = socket.create_connection((host, MARKET_PORT), timeout=8)
    except OSError as e:
        return f"连接失败 {e}"
    try:
        sock.sendall(encode_frame(build_manual_login_body(passport64, mac64)) + b"\n")
        sock.settimeout(6)
        resp = read_frame(sock)
        vc = ""
        for line in resp.decode("gbk","replace").replace("\r\n","\n").split("\n"):
            if line.startswith("VerifyCode="): vc = line.split("=",1)[1]
        if vc != "0":
            sock.close(); return f"登录失败 VC={vc}"
        # 发 4214 订阅
        sock.sendall(build_snapshot_subscribe(code, market=market, seq=0) + b"\n")
        sock.settimeout(5)
        import re
        for _ in range(5):
            try:
                body = read_frame(sock)
            except (socket.timeout, OSError, ValueError):
                break
            m = re.search(rb"CodeListSize=(\d+)", body)
            if m:
                sock.close(); return f"CodeListSize={m.group(1).decode()}"
        sock.close(); return "无CodeListSize响应"
    except Exception as e:
        try: sock.close()
        except: pass
        return f"异常 {e}"


def main():
    load_dotenv()
    username = os.environ["THS_USERNAME"]; password = os.environ["THS_PASSWORD"]
    imei = os.environ.get("THS_IMEI","").strip() or None
    code = sys.argv[1] if len(sys.argv)>1 and sys.argv[1].isdigit() else "000938"
    market = 17 if code.startswith("6") else 33

    # 普通登录拿 Passport64
    client = THSClient(username=username, password=password, imei=imei, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}"); return 1
    passport64 = build_passport64(client._auth)
    mac64 = client.mac64
    client.disconnect()
    print(f"已获取 Passport64，测试 IP × __manual + 4214 订阅（code={code}）\n")

    # 测一批 IP
    import socket as _s
    # 动态解析域名拿 IP
    ips = set()
    for h in MARKET_HOSTS[:8]:
        ips.add(h)
    # 加几个动态解析的
    for domain in ("shlv2.123ths.com", "szlv2.123ths.com"):
        try:
            _, _, addrs = _s.gethostbyname_ex(domain)
            ips.update(addrs[:3])
        except OSError: pass

    ok_ips = []
    for ip in sorted(ips):
        result = test_ip(ip, passport64, mac64, code, market)
        tag = "✓" if "CodeListSize=1" in result else "✗"
        print(f"  {tag} {ip:20s} {result}")
        if "CodeListSize=1" in result:
            ok_ips.append(ip)
        time.sleep(0.5)  # 避免太快

    print(f"\n=== 结果：{len(ok_ips)}/{len(ips)} 个 IP 注册成功（CodeListSize=1）===")
    if ok_ips:
        print(f"成功 IP: {ok_ips}")
    else:
        print("全部失败")


if __name__ == "__main__":
    sys.exit(main())
