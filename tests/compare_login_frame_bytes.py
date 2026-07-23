#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
逐字节对比 thspypc login 帧与 hexin 抓包 login 帧（聚焦 head128 + 帧封装结构）。

用途：当 login 后服务器返回 0 字节直接 FIN（连错误码都不给）时，说明帧的二进制
      结构根本不对，服务器没把它当 login 帧。本脚本对比帧的每个字节段。

用法：
    py tests/compare_login_frame_bytes.py                # 从默认 pcap 提取 hexin 帧
    py tests/compare_login_frame_bytes.py --pcap xxx.pcap
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


def extract_hexin_login_bodies():
    """从 pcap 提取 hexin login 帧的完整 body（含 head128）。"""
    out = _tshark("tcp.dstport==8901 and tcp.payload", ["tcp.payload"])
    bodies = []
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"Ask=login" in body:
                bodies.append(body)
    return bodies


def hex_dump(data, prefix="  ", max_bytes=256):
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{prefix}{i:04x}  {hex_part:<48s}  {ascii_part}")
    if len(data) > max_bytes:
        print(f"{prefix}... (省略 {len(data)-max_bytes} 字节)")


def main():
    global PCAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=None)
    args = ap.parse_args()
    if args.pcap:
        PCAP = args.pcap

    # ---- 提取 hexin login 帧 ----
    hexin_bodies = extract_hexin_login_bodies()
    if not hexin_bodies:
        print("✗ 未提取到 hexin login 帧")
        return 1
    # 取第一个（所有 login 帧结构应该一致）
    hexin_body = hexin_bodies[0]
    print(f"hexin login 帧：{len(hexin_bodies)} 个，分析第 1 个（{len(hexin_body)} 字节）\n")

    # ---- 生成 thspypc login body ----
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
    from thspypc.protocol import (full_http_auth, build_passport64,
                                   build_login_body_pc, generate_mac64)
    auth = full_http_auth(user, pwd)
    passport64 = build_passport64(auth)
    mac64 = generate_mac64()
    thspypc_body = build_login_body_pc(passport64, mac64)
    print(f"thspypc login body：{len(thspypc_body)} 字节\n")

    # ---- 【1】前缀字节对比（head128 之前的帧头）----
    print("="*60)
    print("【1】帧头前缀对比（Ask=login 之前的二进制头）")
    print("="*60)
    # 找 Ask=login 的位置
    h_idx = hexin_body.find(b"Ask=login")
    t_idx = thspypc_body.find(b"Ask=login")
    print(f"  hexin:   Ask=login @ offset {h_idx}")
    print(f"  thspypc: Ask=login @ offset {t_idx}")
    if h_idx != t_idx:
        print(f"  ⚠ 偏移不同！head 长度不一致（hexin={h_idx} vs thspypc={t_idx}）")

    print(f"\n  hexin 前缀（{h_idx} 字节）:")
    hex_dump(hexin_body[:h_idx], "    ")
    print(f"\n  thspypc 前缀（{t_idx} 字节）:")
    hex_dump(thspypc_body[:t_idx], "    ")

    # ---- 【2】逐字节对比前缀（取较短的对齐）----
    print(f"\n{'='*60}")
    print("【2】前缀逐字节对比")
    print("="*60)
    min_len = min(h_idx, t_idx)
    diffs = []
    for i in range(min_len):
        if hexin_body[i] != thspypc_body[i]:
            diffs.append((i, hexin_body[i], thspypc_body[i]))
    if not diffs:
        print(f"  ✓ 前 {min_len} 字节完全一致")
    else:
        print(f"  ⚠ {len(diffs)} 处不同（前 {min_len} 字节）:")
        for off, hb, tb in diffs[:20]:
            print(f"    offset {off}: hexin=0x{hb:02x} thspypc=0x{tb:02x}")

    # ---- 【3】login 文本字段顺序 ----
    print(f"\n{'='*60}")
    print("【3】login 文本字段（Ask=login 之后）")
    print("="*60)
    h_text = hexin_body[h_idx:].decode("gbk", errors="replace")
    t_text = thspypc_body[t_idx:].decode("gbk", errors="replace")
    # 取第一个 Passport64 之前的内容（字段顺序部分）
    h_fields = re.findall(r"(\w+(?:-\w+)*)=", h_text.split("Passport64")[0])
    t_fields = re.findall(r"(\w+(?:-\w+)*)=", t_text.split("Passport64")[0])
    print(f"  hexin 字段顺序:   {h_fields}")
    print(f"  thspypc 字段顺序: {t_fields}")
    if h_fields == t_fields:
        print("  ✓ 字段顺序一致")
    else:
        print("  ⚠ 字段顺序不同！")

    # ---- 【4】帧封装对比（magic + 长度 + body）----
    print(f"\n{'='*60}")
    print("【4】完整帧封装（fdfdfdfd + 8hex长度 + body）")
    print("="*60)
    from thspypc.protocol import encode_frame
    # hexin 抓包的是原始 tcp payload（含 magic + len）
    # 重新提取一个含 magic 的完整帧
    out = _tshark("tcp.dstport==8901 and tcp.payload", ["tcp.payload"])
    hexin_raw_frame = None
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        # payload 本身可能就是完整帧（magic + len + body）
        if MAGIC in payload and b"Ask=login" in payload:
            hexin_raw_frame = payload
            break
    thspypc_raw_frame = encode_frame(thspypc_body)

    if hexin_raw_frame:
        print(f"  hexin 原始帧前 32 字节:")
        hex_dump(hexin_raw_frame[:32], "    ", max_bytes=32)
    print(f"\n  thspypc 原始帧前 32 字节:")
    hex_dump(thspypc_raw_frame[:32], "    ", max_bytes=32)

    # 检查 thspypc 是否正确加了 trailing \n
    print(f"\n  thspypc 帧 + \\n 末尾: {thspypc_raw_frame[-3:].hex(' ')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
