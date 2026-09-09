#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""分析 board94 抓包（v2）：严格过滤 + 按 stream 分类 + 关键请求全文。

tests/_*.py 约定：探针不入库。
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
PCAP = ROOT / "captures_live" / "board94_20260909_capture.pcap"
MAGIC = b"\xfd\xfd\xfd\xfd"

sys.path.insert(0, str(ROOT / "src"))


def run(args):
    r = subprocess.run(args, capture_output=True, timeout=300)
    return r.stdout


def stream_ids(pcap):
    out = run([TSHARK, "-r", str(pcap), "-T", "fields", "-e", "tcp.stream"])
    return sorted({int(x) for x in out.decode().split() if x.isdigit()})


def stream_payload(pcap, sid, direction):
    field = "tcp.payload"
    filt = f"tcp.stream=={sid}"
    filt += " and tcp.dstport==8901" if direction == "dst" else " and tcp.srcport==8901"
    out = run([TSHARK, "-r", str(pcap), "-Y", filt, "-T", "fields", "-e", field])
    return bytes.fromhex("".join(out.decode().split()))


def split_frames(data):
    frames = []
    pos = 0
    while True:
        idx = data.find(MAGIC, pos)
        if idx < 0:
            break
        body = data[idx + 4:]
        if len(body) < 8:
            break
        try:
            blen = int(body[:8], 16)
        except ValueError:
            pos = idx + 4
            continue
        frames.append(body[8:8 + blen])
        pos = idx + 4 + 8 + blen
    return frames


def extract_requests(frame):
    """从帧体提取 (route, seq, h17, fields_text) 列表——只认文本形态的查询子帧。

    真实查询子帧 = 0x09 + 4B len + 2B seq + ... + 23B 头 + gbk 文本
    （CodeList=...pageid=...）。在帧体里直接找文本锚点再回退 23B 取头，
    避开二进制表/推送的误切分。
    """
    out = []
    for m in re.finditer(rb"CodeList=", frame):
        start = m.start()
        if start < 23:
            continue
        head = frame[start - 23:start]
        if head[0] != 0x09:
            continue
        # 文本延伸到 pageid=NNNN 之后
        text_end = frame.find(b"pageid=", start)
        if text_end < 0:
            continue
        text_end += 32
        text = frame[start:text_end].decode("gbk", "replace")
        # 截到 pageid 数值结尾
        text = re.sub(r"(pageid=\d+).*", r"\1", text, flags=re.S)
        route = struct.unpack("<H", head[11:13])[0]
        seq = struct.unpack("<H", head[5:7])[0]
        h17 = head[17] if len(head) > 17 else None
        out.append((route, seq, h17, text))
    return out


def parse_fields(text):
    fields = {}
    for m in re.finditer(r"(\w+)=([^\r\n]*)", text):
        fields.setdefault(m.group(1), m.group(2))
    return fields


def main():
    streams = stream_ids(PCAP)
    all_requests = []  # (sid, route, seq, h17, fields)
    board_streams = []
    for sid in streams:
        payload = stream_payload(PCAP, sid, "dst")
        if not payload:
            continue
        frames = split_frames(payload)
        reqs = []
        is_board = False
        for fr in frames:
            probe = fr[:3000].decode("gbk", "replace")
            if "MarketCode=96" in probe or "MarketCode=88;128" in probe:
                is_board = True
            for route, seq, h17, text in extract_requests(fr):
                reqs.append((sid, route, seq, h17, parse_fields(text), text))
        if reqs:
            all_requests.extend(reqs)
            kind = "FU4-BOARD" if is_board else "OTHER"
            print(f"stream {sid}: {len(frames)} frames, {len(reqs)} text-requests, board_channel={is_board}")
            if is_board:
                board_streams.append(sid)

    print(f"\nboard(fu4) streams: {board_streams}")

    # 汇总：按 (pageid, route, period, DataType前缀) 计数
    counter = Counter()
    for sid, route, seq, h17, f, text in all_requests:
        pageid = f.get("pageid", "?")
        period = f.get("DateTime", "?").split("(")[0]
        dt = f.get("DataType", "?")[:20]
        counter[(sid in board_streams, pageid, f"0x{route:04X}", period, dt)] += 1
    print("\n===== 请求汇总（is_board, pageid, route, period, DataType）=====")
    for k, v in sorted(counter.items(), key=lambda x: (-x[1])):
        print(f"  {v:3d}x board={k[0]} pageid={k[1]} route={k[2]} period={k[3]} DT={k[4]}")

    # 关键请求全文：所有流上 pageid=12480 的每种形态取首个
    print("\n===== pageid=12480 关键请求全文（全部流）=====")
    seen = set()
    for sid, route, seq, h17, f, text in all_requests:
        if f.get("pageid") != "12480":
            continue
        period = f.get("DateTime", "?").split("(")[0]
        key = (sid in board_streams, f"0x{route:04X}", period, f.get("DataType", "")[:22])
        if key in seen:
            continue
        seen.add(key)
        cl = f.get("CodeList", "")
        markets = sorted({part.split("(")[0] for part in cl.split("),") if "(" in part})
        print(f"\n--- stream{sid}({'fu4' if sid in board_streams else 'L2'}) "
              f"route=0x{route:04X} seq=0x{seq:04X} h17=0x{h17:02X}")
        print(f"    CodeList[len={len(cl)}] markets={markets}: "
              f"{cl[:200]}{'…' if len(cl) > 200 else ''}")
        print(f"    DataType={f.get('DataType','')} DateTime={f.get('DateTime','')} "
              f"LackTime={f.get('LackTime','')}")
        if f.get("SortBy"):
            print(f"    Sort: By={f['SortBy']} Dir={f.get('SortDir')} "
                  f"Begin={f.get('SortBegin')} Count={f.get('SortCount')} Append={f.get('SortAppend')}")
        if f.get("ReqFuquan"):
            print(f"    ReqFuquan={f['ReqFuquan']}")


if __name__ == "__main__":
    main()
