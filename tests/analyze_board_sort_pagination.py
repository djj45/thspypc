#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
专项分析：板块列表「表头排序 + 翻页」抓包（2026-08-02 新增 pageid 1333/1334）。

用法
----
    py tests/analyze_board_sort_pagination.py <pcap>

输出
----
    1. 1333/1334 请求按出现顺序去重：pageid、market、代码数、DataType、DateTime、
       排序参数、完整文本（去二进制头）；代码列表只显示首尾各 3 个。
    2. 全部请求里含 Sort/Order 文本的帧（可能携带排序参数）。
    3. 每个 pageid 的去重文本清单（用于 diff 排序/翻页到底改了什么）。
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

WS_CANDIDATES = [
    r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = next((c for c in WS_CANDIDATES
           if os.path.exists(os.path.join(c, "tshark.exe"))), WS_CANDIDATES[0])
TSHARK = os.path.join(WS, "tshark.exe")
MAGIC = b"\xfd\xfd\xfd\xfd"
PORT = 8901
TARGET_PAGEIDS = {"1333", "1334", "392", "5716", "1341"}


def _streams(pcap_path):
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", f"tcp.port=={PORT}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    sids = [s for s in r.stdout.decode().split() if s]
    out = []
    for sid in sorted(set(sids), key=lambda x: int(x)):
        rc = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.dstport=={PORT}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        client_hex = "".join(rc.stdout.decode().split())
        if client_hex:
            out.append((sid, bytes.fromhex(client_hex)))
    return out


def _frames(stream_bytes):
    for sub in stream_bytes.split(MAGIC):
        if len(sub) >= 8:
            yield sub[8:]


def _clean_text(frame_body):
    """去掉 8901 二进制头，返回干净的 GBK 文本。"""
    text = frame_body.decode("gbk", errors="replace")
    # 二进制头/控制字符清理：保留可见 ASCII + GBK 中文
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t")
    return " ".join(cleaned.split())


def _parse(clean):
    if "pageid=" not in clean and "CodeList=" not in clean:
        return None
    info = {"text": clean}
    m = re.search(r"pageid=(\d+)", clean)
    if m:
        info["pageid"] = m.group(1)
    m = re.search(r"CodeList=(\d+)\(([^)]*)\)", clean)
    if m:
        info["market"] = m.group(1)
        codes = [c.strip() for c in m.group(2).split(",") if c.strip()]
        info["codes"] = codes
    m = re.search(r"DataType=([\d,\[\]]+)", clean)
    if m:
        info["datatype"] = m.group(1).rstrip(",")
    m = re.search(r"DateTime=(\d+)(?:\(([^)]*)\))?", clean)
    if m:
        info["period"] = m.group(1)
        info["args"] = m.group(2) or ""
    return info


def _short_codes(codes, n=3):
    if not codes:
        return "[]"
    if len(codes) <= n * 2:
        return repr(codes)
    return repr(codes[:n] + ["…"] + codes[-n:]) + f" (共{len(codes)}个)"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    args = ap.parse_args()

    order: list[str] = []
    seen: dict[str, int] = {}
    first: dict[str, dict] = {}
    sort_hits: list[str] = []

    for sid, client_bytes in _streams(args.pcap):
        for fb in _frames(client_bytes):
            clean = _clean_text(fb)
            if not clean:
                continue
            if re.search(r"Sort|Order", clean, re.IGNORECASE):
                sort_hits.append(clean)
            parsed = _parse(clean)
            if parsed is None:
                continue
            pid = parsed.get("pageid", "?")
            if pid not in TARGET_PAGEIDS:
                continue
            if clean not in seen:
                seen[clean] = 0
                order.append(clean)
                first[clean] = parsed
            seen[clean] += 1

    print(f"共 {len(order)} 种去重请求文本（pageid∈{sorted(TARGET_PAGEIDS)}）\n")
    for clean in order:
        info = first[clean]
        cnt = seen[clean]
        codes = info.get("codes", [])
        print(f"[{cnt}x] pageid={info.get('pageid','?')} "
              f"market={info.get('market','-')} "
              f"codes={_short_codes(codes)} "
              f"DataType={info.get('datatype','-')} "
              f"DateTime={info.get('period','-')}({info.get('args','')})")
        print(f"        {clean[:220]}{'…' if len(clean) > 220 else ''}")

    if sort_hits:
        print(f"\n★ 含 Sort/Order 文本的帧（{len(sort_hits)} 帧，去重如下）：")
        for hit in sorted(set(sort_hits)):
            print(f"  {hit[:240]}")
    else:
        print("\n★ 未发现含 Sort/Order 参数的请求文本（排序可能只改 CodeList/DataType）")


if __name__ == "__main__":
    main()
