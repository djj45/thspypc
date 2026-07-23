#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
解码 hexin login 帧里的 Passport64（1130 字符），对比 thspypc 生成的（2304），
找出 thspypc 多保留、被服务器拒（VerifyCode=-1）的字段。

用法：
    py tests/analyze_passport64_diff.py                    # 从默认 pcap 提取 + HTTP 鉴权对比
    py tests/analyze_passport64_diff.py --pcap xxx.pcap    # 指定 pcap
    py tests/analyze_passport64_diff.py --no-http          # 不做 HTTP 鉴权，只解 hexin 的

背景：抓包发现 hexin 实际发送的 Passport64 = 1130 字符，而 thspypc build_passport64
生成 2304 字符。hexin 缓存文件里是 2304，但发送时又过滤掉一半字段只剩 1130。
thspypc 一直用缓存值（2304），含服务器不接受的字段 → VerifyCode=-1。
"""
import argparse
import base64
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
TSHARK = os.path.join(WS, "tshark.exe")
PCAP = os.path.join(os.path.dirname(__file__), "..", "captures_live", "login_compare.pcap")
MAGIC = b"\xfd\xfd\xfd\xfd"


def _tshark(y_filter, fields, pcap=None):
    pcap = pcap or PCAP
    cmd = [TSHARK, "-r", pcap, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _split_frames(payload):
    frames = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            frames.append(sub[8:])
    return frames


def extract_hexin_passport64():
    """从 pcap 提取 hexin login 帧里的 Passport64 值。"""
    out = _tshark("tcp.dstport==8901 and tcp.payload", ["tcp.payload"])
    passports = []
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"Ask=login" not in body:
                continue
            text = body.decode("gbk", errors="replace")
            m = re.search(r"Passport64=(\S+)", text)
            if m:
                p64 = m.group(1).strip()
                passports.append(p64)
    return passports


def decode_passport64_fields(p64: str) -> tuple[set[str], list[str]]:
    """解码 Passport64，返回 (字段名集合, 字段顺序列表)。

    Passport64 = base64( head128(128B) + prefix_5b(5B) + fields_body )
    fields_body 分隔符可能是 |（服务端原始 / hexin 发送）或 \\r\\n（thspypc 生成）。
    本函数同时处理两种分隔符。

    注意：字段值可能含特殊字符（如 M_zx 的值含 IP:端口:...），所以不能简单
    split——用正则提取每段的 key 部分（= 前的标识符）。
    """
    raw = base64.b64decode(p64)
    # 跳过 128B head128 + 5B prefix
    fields_body = raw[133:]
    text = fields_body.decode("gbk", errors="replace")
    # 同时按 | 和 \r\n 分隔
    parts = re.split(r"[|\r\n]+", text)
    fields = []
    for p in parts:
        p = p.strip()
        if "=" in p:
            k = p.split("=", 1)[0].strip()
            # 字段名是字母数字下划线（排除字段值里的噪声）
            if k and re.match(r"^[A-Za-z_]\w*$", k):
                # 去重但保留首次出现顺序（同一字段可能出现多次，取第一次）
                if k not in fields:
                    fields.append(k)
    return set(fields), fields


def main():
    global PCAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--no-http", action="store_true",
                    help="不做 HTTP 鉴权（只解 hexin 的）")
    args = ap.parse_args()
    if args.pcap:
        PCAP = args.pcap

    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return 1

    # ---- 提取 hexin 的 Passport64 ----
    print("="*60)
    print("【1】提取 hexin login 帧的 Passport64")
    print("="*60)
    passports = extract_hexin_passport64()
    if not passports:
        print("✗ 未提取到 Passport64")
        return 1
    # 用最短的那个（最可能是过滤后的纯净版）
    hexin_p64 = min(passports, key=len)
    print(f"  共 {len(passports)} 个 Passport64，长度分布:")
    from collections import Counter
    len_dist = Counter(len(p) for p in passports)
    for ln, n in sorted(len_dist.items()):
        print(f"    {ln} 字符: {n} 个")
    print(f"  采用最短的（{len(hexin_p64)} 字符）做解码")

    hexin_fields_set, hexin_fields_list = decode_passport64_fields(hexin_p64)
    print(f"\n  hexin Passport64 解码后字段（{len(hexin_fields_set)} 个，按顺序）:")
    for i, k in enumerate(hexin_fields_list, 1):
        print(f"    {i:2d}. {k}")

    if args.no_http:
        print("\n（--no-http，跳过 thspypc 对比）")
        return 0

    # ---- HTTP 鉴权拿真实 passport_bytes，生成 thspypc 的 Passport64 ----
    print(f"\n{'='*60}")
    print("【2】HTTP 鉴权 + 生成 thspypc Passport64 对比")
    print("="*60)
    # 读 .env
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    user = pwd = ""
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if line.startswith("THS_USERNAME="):
                user = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("THS_PASSWORD="):
                pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not user or not pwd:
        print("✗ 缺 .env 账号，无法做 HTTP 鉴权对比")
        return 1

    from thspypc.protocol import full_http_auth, build_passport64, parse_passport_fields

    print(f"  HTTP 三步鉴权 (account={user[:4]}***)...")
    try:
        auth = full_http_auth(user, pwd)
    except Exception as e:
        print(f"✗ HTTP 鉴权失败: {e}")
        return 1
    pb = auth["passport_bytes"]
    print(f"  服务端 passport_bytes: {len(pb)} 字节，含字段:")
    server_fields = parse_passport_fields(pb)
    for k in server_fields:
        print(f"    {k}")

    # build_passport64 的过滤逻辑（_PASSPORT_DROP_FIELDS）
    from thspypc.protocol import _PASSPORT_DROP_FIELDS
    print(f"\n  _PASSPORT_DROP_FIELDS（thspypc 会丢弃的）: {sorted(_PASSPORT_DROP_FIELDS)}")

    thspypc_p64 = build_passport64(auth)
    print(f"\n  thspypc Passport64 长度: {len(thspypc_p64)} 字符")
    thspypc_fields_set, thspypc_fields_list = decode_passport64_fields(thspypc_p64)
    print(f"  thspypc Passport64 保留字段（{len(thspypc_fields_set)} 个）:")
    for i, k in enumerate(thspypc_fields_list, 1):
        print(f"    {i:2d}. {k}")

    # ---- 字段差异对比 ----
    print(f"\n{'='*60}")
    print("【3】字段差异（★ 定位 -1 根因）")
    print("="*60)
    only_thspypc = thspypc_fields_set - hexin_fields_set
    only_hexin = hexin_fields_set - thspypc_fields_set

    if only_thspypc:
        print(f"\n  ⚠ thspypc 有、hexin 没有的字段（{len(only_thspypc)} 个）★疑似导致 -1:")
        for k in sorted(only_thspypc):
            v = server_fields.get(k, "?")
            if len(v) > 50:
                v = v[:50] + "..."
            print(f"      + {k} = {v}")
    else:
        print("\n  ✓ thspypc 没有多余字段")

    if only_hexin:
        print(f"\n  hexin 有、thspypc 没有的字段（{len(only_hexin)} 个）:")
        for k in sorted(only_hexin):
            print(f"      - {k}")

    print(f"\n  共有字段: {len(thspypc_fields_set & hexin_fields_set)} 个")

    # 给出修复建议
    if only_thspypc:
        print(f"\n{'='*60}")
        print("【修复建议】")
        print("="*60)
        print(f"  把以下 {len(only_thspypc)} 个字段加入 _PASSPORT_DROP_FIELDS：")
        print(f"  {sorted(only_thspypc)}")
        print(f"  即在 protocol.py 的 _PASSPORT_DROP_FIELDS frozenset 里追加这些字段名")

    return 0


if __name__ == "__main__":
    sys.exit(main())
