#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""离线挖掘 kanpan_push_20260820_131534.pcap 中 0x60/0x04 逐笔推送帧。

交接文档(2026-08-19 HANDOFF 第六节)结论:
  - 72B ``09 7b d0 01 60 04`` 单笔实时成交已解析(is_trade_tick_push);
  - 同子类型还有变长帧未展开;单笔序号 7468→7482 的缺口是批量帧对照锚点。

本脚本只读 pcap,不做任何登录:
  1. 提取全部服务端 8901 帧;
  2. 列出所有 0x60/0x04 前缀帧(72B 之外的即变长批量候选);
  3. 收集 72B 单笔帧的 seq 时间线,定位缺口;
  4. 收集客户端 DateTime=7169 逐笔回放请求及其响应,作为字段真值。
"""
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

PCAP = str(ROOT / "captures_live" / "kanpan_push_20260820_131534.pcap")


def _frames(direction_filter):
    r = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y", direction_filter, "-T", "fields",
         "-e", "frame.time_relative", "-e", "tcp.stream", "-e", "tcp.payload"],
        capture_output=True, timeout=300)
    out = []
    for line in r.stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].strip():
            continue
        try:
            t = float(parts[0])
        except ValueError:
            continue
        payload = bytes.fromhex(parts[2].replace(":", ""))
        # 帧可能粘连;按 MAGIC 切分,去掉 8 字节 ASCII 长度头
        offset = 0
        while True:
            idx = payload.find(MAGIC, offset)
            if idx < 0:
                break
            rest = payload[idx + 4:]
            if len(rest) < 8:
                break
            try:
                declared = int(bytes(rest[:8]), 16)
            except ValueError:
                offset = idx + 4
                continue
            body = rest[8:8 + declared]
            if len(body) < declared:
                # 跨 TCP 段,跳过(整流重组由 capture_kanpan_push 处理)
                offset = idx + 4
                continue
            out.append((t, parts[1], body))
            offset = idx + 4 + 8 + declared
    return out


def main():
    print("== 服务端 8901 帧 ==")
    server = _frames("tcp.srcport==8901")
    print(f"共 {len(server)} 帧")

    prefix = b"\x09\x7b\xd0\x01\x60\x04"
    type60 = [(t, s, b) for t, s, b in server if b.startswith(prefix)]
    other60 = [
        (t, s, b) for t, s, b in server
        if b[:5] == b"\x09\x7b\xd0\x01\x60" and not b.startswith(prefix)
    ]
    print(f"0x60/0x04 前缀帧: {len(type60)} 个")
    lengths = {}
    for t, s, b in type60:
        lengths.setdefault(len(b), []).append((t, s, b))
    for length in sorted(lengths):
        print(f"  len={length}: {len(lengths[length])} 帧")

    print("\n== 72B 单笔帧 seq 时间线 ==")
    singles = sorted(lengths.get(72, []), key=lambda x: x[0])
    for t, s, b in singles:
        seq = struct.unpack_from("<I", b, 67)[0]
        trade_no = struct.unpack_from("<I", b, 39)[0]
        ts = struct.unpack_from("<I", b, 43)[0]
        price_raw = struct.unpack_from("<I", b, 47)[0]
        volume = struct.unpack_from("<I", b, 51)[0]
        direction = struct.unpack_from("<I", b, 55)[0]
        code = b[29:35].decode("ascii")
        print(f"  [{t:9.3f}s] stream={s} {code} seq={seq} trade_no={trade_no} "
              f"ts={ts} price_raw={price_raw:#x} vol={volume} dir={direction}")
    if singles:
        seqs = [struct.unpack_from("<I", b, 67)[0] for _, _, b in singles]
        gaps = [(a, b2) for a, b2 in zip(seqs, seqs[1:]) if b2 != a + 1]
        print(f"  seq 缺口: {gaps}")

    print(f"\n== 非 72B 的 0x60/0x04 变长帧(全部 dump) ==")
    for length in sorted(lengths):
        if length == 72:
            continue
        print(f"\n-- len={length}, {len(lengths[length])} 帧 --")
        for t, s, b in sorted(lengths[length], key=lambda x: x[0])[:8]:
            print(f"  [{t:9.3f}s] stream={s}")
            for i in range(0, len(b), 16):
                chunk = b[i:i + 16]
                hexs = " ".join(f"{v:02x}" for v in chunk)
                asc = "".join(chr(v) if 0x20 <= v < 0x7f else "." for v in chunk)
                print(f"    {i:4d}: {hexs:<48s} {asc}")

    print(f"\n== 其他 0x60 子类型(撤单 08/0c 之外) ==")
    sub = {}
    for t, s, b in other60:
        sub.setdefault((b[5], len(b)), []).append(t)
    for (subtype, length), times in sorted(sub.items()):
        print(f"  subtype={subtype:#04x} len={length}: {len(times)} 帧, "
              f"t={times[0]:.3f}~{times[-1]:.3f}")

    print("\n== 客户端 7169 回放请求 ==")
    client = _frames("tcp.dstport==8901")
    for t, s, b in client:
        if b"7169" in b:
            text = b.decode("gbk", errors="replace")
            text = " ".join(text.split())
            print(f"  [{t:9.3f}s] stream={s} {text[:300]}")
    print(f"\n(客户端帧总数 {len(client)})")


if __name__ == "__main__":
    main()
