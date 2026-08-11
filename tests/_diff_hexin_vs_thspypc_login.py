"""逐字节对比 hexin 真实 login 帧 vs thspypc 生成的 login 帧。

从 captures_live/hexin_login_now.pcapng 提取 hexin 的 STANDARD login 帧，
用同一 Passport64 + Mac64 让 thspypc 生成对照帧，逐字节 diff，定位所有差异。

⚠ 诊断脚本（playbook §13），用于定位 check 之外的帧差异。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from probe_check_k import reassemble_stream, split_frames  # noqa: E402
from scapy.all import rdpcap, TCP, IP  # noqa: E402

from thspypc.features.auth_protocol import (  # noqa: E402
    LoginIdentity,
    PC_LEVEL2_LOGIN_PROFILE,
    build_login_body,
)


def main() -> int:
    pcap = Path(sys.argv[1] if len(sys.argv) > 1 else "captures_live/hexin_login_now.pcapng")
    pkts = rdpcap(str(pcap))
    streams: dict = {}
    for p in pkts:
        if TCP in p and IP in p and (p[TCP].dport == 8901 or p[TCP].sport == 8901):
            key = tuple(sorted([(p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport)]))
            streams.setdefault(key, []).append(p)

    # 取第一个 STANDARD login 帧（带 UserName=thsuser）
    hexin_body = None
    for key, pkts_in_stream in streams.items():
        ckey = ((pkts_in_stream[0][IP].src, pkts_in_stream[0][TCP].sport),
                (pkts_in_stream[0][IP].dst, pkts_in_stream[0][TCP].dport))
        c2s = reassemble_stream(pkts_in_stream, ckey[0])
        for fl, body in split_frames(c2s):
            if b"Ask=login" in body and b"UserName=thsuser" in body:
                hexin_body = body
                break
        if hexin_body:
            break

    if not hexin_body:
        print("✗ 未找到 STANDARD login 帧")
        return 1

    print(f"hexin STANDARD login body: {len(hexin_body)} bytes")

    # 提取 hexin 的 Passport64 和 Mac64
    text = hexin_body[hexin_body.find(b"Ask=login"):].decode("gbk", errors="replace")
    fields: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.split("\x00")[0].strip()

    passport64 = fields.get("Passport64", "")
    mac64 = fields.get("Mac64", "")
    print(f"  Passport64 len={len(passport64)}, Mac64={mac64!r}")

    # 用同样的 passport64 + mac64 生成 thspypc 帧
    thspypc_body = build_login_body(
        passport64, mac64, identity=LoginIdentity.STANDARD, profile=PC_LEVEL2_LOGIN_PROFILE
    )
    print(f"thspypc body: {len(thspypc_body)} bytes")
    print()

    # 逐字节 diff
    min_len = min(len(hexin_body), len(thspypc_body))
    diffs = []
    for i in range(min_len):
        if hexin_body[i] != thspypc_body[i]:
            diffs.append(i)
    # 长度差异
    len_diff = len(hexin_body) - len(thspypc_body)

    print(f"=== 逐字节 diff（共 {min_len} 字节对比）===")
    print(f"差异字节数: {len(diffs)}")
    print(f"长度差: hexin 比 thspypc {'长' if len_diff>0 else '短'} {abs(len_diff)} bytes")
    print()

    if not diffs and len_diff == 0:
        print("★ 完全一致！")
        return 0

    # 分组显示差异（连续字节归一组）
    print("差异位置（连续归组）:")
    groups = []
    for d in diffs:
        if groups and d == groups[-1][-1] + 1:
            groups[-1].append(d)
        else:
            groups.append([d])
    for g in groups:
        start = g[0]
        end = g[-1]
        hexin_seg = hexin_body[start:end+1]
        thspypc_seg = thspypc_body[start:end+1]
        # 找这个位置在哪个字段
        context = ""
        if start < 13:
            context = "[prefix]"
        else:
            # 找在 fixed 文本里还是 passport 里
            fixed_start = hexin_body.find(b"Ask=login")
            passport_start = hexin_body.find(b"Passport64=")
            if start < passport_start:
                seg = hexin_body[fixed_start:start]
                last_line = seg.split(b"\n")[-1]
                context = f"[fixed near {last_line!r}]"
            else:
                context = "[passport 区域]"
        print(f"  [{start:#06x}..{end:#06x}] ({len(g)} bytes) {context}")
        print(f"    hexin:   {hexin_seg.hex(' ')}")
        print(f"    thspypc: {thspypc_seg.hex(' ')}")
        try:
            print(f"    hexin ascii:   {hexin_seg.decode('ascii')!r}")
            print(f"    thspypc ascii: {thspypc_seg.decode('ascii')!r}")
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
