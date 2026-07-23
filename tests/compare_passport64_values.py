#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
逐字段值对比 thspypc Passport64 与 hexin 抓包的（字段集已对齐，查值差异）。

用途：字段集都是 20 个，但 thspypc 生成的 Passport64=1228 字符，hexin=1124/1130，
      差 ~100 字符。本脚本逐字段比值，找出值不同的字段。

用法：
    py tests/compare_passport64_values.py
"""
import base64
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))


def decode_passport64_kv(p64: str) -> dict:
    """解码 Passport64，返回 {字段名: 值} 字典。"""
    raw = base64.b64decode(p64)
    fields_body = raw[133:]  # 跳过 head128(128) + prefix_5b(5)
    text = fields_body.decode("gbk", errors="replace")
    parts = re.split(r"[|\r\n]+", text)
    kv = {}
    for p in parts:
        p = p.strip()
        if "=" in p:
            k, _, v = p.partition("=")
            k = k.strip()
            if k and re.match(r"^[A-Za-z_]\w*$", k):
                kv[k] = v.strip()
    return kv


def main():
    # ---- 提取 hexin 的 Passport64 ----
    from compare_login_frame_bytes import extract_hexin_login_bodies
    bodies = extract_hexin_login_bodies()
    if not bodies:
        print("✗ 未提取到 hexin login 帧")
        return 1
    # 取一个含 Passport64 的
    hexin_p64 = None
    for b in bodies:
        m = re.search(rb"Passport64=(\S+)", b)
        if m:
            p64 = m.group(1).decode("ascii")
            if hexin_p64 is None or len(p64) < len(hexin_p64):
                hexin_p64 = p64
    print(f"hexin Passport64: {len(hexin_p64)} 字符")
    hexin_kv = decode_passport64_kv(hexin_p64)
    print(f"hexin 字段数: {len(hexin_kv)}")

    # ---- 生成 thspypc 的 Passport64 ----
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    user = pwd = ""
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("THS_USERNAME="):
            user = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("THS_PASSWORD="):
            pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
    from thspypc.protocol import full_http_auth, build_passport64
    auth = full_http_auth(user, pwd)
    thspypc_p64 = build_passport64(auth)
    print(f"thspypc Passport64: {len(thspypc_p64)} 字符")
    thspypc_kv = decode_passport64_kv(thspypc_p64)
    print(f"thspypc 字段数: {len(thspypc_kv)}")

    # ---- 逐字段值对比 ----
    print(f"\n{'='*70}")
    print("逐字段值对比（★ 定位剩余差异）")
    print(f"{'='*70}")
    all_keys = sorted(set(hexin_kv) | set(thspypc_kv))
    diff_count = 0
    for k in all_keys:
        hv = hexin_kv.get(k, "(无)")
        tv = thspypc_kv.get(k, "(无)")
        if hv == tv:
            mark = "✓"
            disp_v = hv if len(hv) <= 50 else hv[:50] + f"...({len(hv)})"
            print(f"  {mark} {k:20s} = {disp_v}")
        else:
            mark = "⚠"
            diff_count += 1
            hv_disp = hv if len(hv) <= 45 else hv[:45] + f"...({len(hv)})"
            tv_disp = tv if len(tv) <= 45 else tv[:45] + f"...({len(tv)})"
            print(f"  {mark} {k:20s}")
            print(f"        hexin:   {hv_disp}")
            print(f"        thspypc: {tv_disp}")

    print(f"\n{'='*70}")
    print(f"差异字段数: {diff_count}")
    print(f"{'='*70}")

    # 统计各字段值长度差异（解释总长度差）
    if diff_count:
        print("\n值长度差异明细（解释 Passport64 总长度差）:")
        hexin_total = sum(len(v) for v in hexin_kv.values())
        thspypc_total = sum(len(v) for v in thspypc_kv.values())
        print(f"  hexin 值总长: {hexin_total}, thspypc 值总长: {thspypc_total}, 差: {thspypc_total - hexin_total}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
