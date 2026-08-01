#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
补抓历史分时 2026-06-30 与 2026-07-23 两日样本（四日期离线回归），
并顺带确认 dt54 哨兵字段（0xFFFFFFFF → 0.0）的原始值语义。

背景
----
现有离线回归已覆盖 2026-05-13/05-14（timeline_20260724_092405_resp_stream1.bin）
与 2026-07-28（history_companion_000001_000938_20260514_20260728_*.bin）。
路线图要求补 06-30、07-23 两日，形成四日期逐点回归；同时 dt54 字段
当前按 ``0xFFFFFFFF`` 哨兵映射 0.0（见 codecs/numeric.py），需要抓包
确认该哨兵在真实数据中的出现规律。

用法
----
    py tests/capture_history_timeline_dates.py                  # 默认 180s
    py tests/capture_history_timeline_dates.py --duration 240
    py tests/capture_history_timeline_dates.py --analyze-only xxx.pcap

操作步骤：
    1. 登录同花顺，打开【000938 紫光股份】的【分时图】（当天即可）
    2. 运行脚本选网卡
    3. 抓包期间，按 ← 方向键逐日回翻：
       2026-07-31 → 07-30 → … → 07-23（停 4 秒）
       继续翻到 2026-06-30（停 4 秒）
       （若客户端有日历选择器，直接选这两个日期更稳）
    4. 换一只沪市票（如 600519）重复一次（可选，验证沪市编码）

产物：
    captures_live/history_timeline_dates_<ts>.pcap
    captures_live/history_000938_20260630_<ts>.bin   （按 代码×日期 分帧 dump）
    captures_live/history_000938_20260723_<ts>.bin
"""
import argparse
import datetime
import os
import re
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

from thspypc.protocol import (  # noqa: E402
    date_to_normal_timeline_bar,
    date_to_timeline_bar,
    normalize_8901_response,
    normal_timeline_bar_to_date,
    parse_history_timeline_response,
    timeline_bar_to_date,
)

WS_CANDIDATES = [
    r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = next((c for c in WS_CANDIDATES
           if os.path.exists(os.path.join(c, "tshark.exe"))), WS_CANDIDATES[0])
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = str(ROOT / "captures_live")

MAGIC = b"\xfd\xfd\xfd\xfd"
PORT = 8901
TARGET_DATES = ("2026-06-30", "2026-07-23")
TARGET_CODES = ("000938", "600519")


def list_interfaces():
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    ifaces = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            ifaces[m.group(1)] = (m.group(2), m.group(3))
    return ifaces


def pick_interface():
    ifaces = list_interfaces()
    if not ifaces:
        print(f"✗ 未检测到网卡（检查 Wireshark/Npcap）: {TSHARK}")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    return choice if choice in ifaces else default


def capture(iface, duration, pcap_path):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（端口 {PORT}，网卡 {iface}）")
    print(f"{'='*64}")
    print(">>> 操作：000938 分时图 → 按 ← 翻到 2026-07-23（停 4s）")
    print("       继续 ← 到 2026-06-30（停 4s）→ 回到当天；可选换 600519 重复")
    print("-" * 64)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", f"tcp port {PORT}",
             "-w", pcap_path, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        pass
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"\n抓包完成：{pcap_path} ({size:,} bytes)")


def _tshark_streams(pcap_path, port=PORT):
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", f"tcp.port=={port}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    stream_ids = [s for s in r.stdout.decode().split() if s]
    results = []
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
        rc = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.dstport=={port}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        client_hex = "".join(rc.stdout.decode().split())
        rs = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.srcport=={port}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        server_hex = "".join(rs.stdout.decode().split())
        if client_hex or server_hex:
            results.append((sid,
                            bytes.fromhex(client_hex) if client_hex else b"",
                            bytes.fromhex(server_hex) if server_hex else b""))
    return results


def _split_frames(stream_bytes):
    frames = []
    for sub in stream_bytes.split(MAGIC):
        if len(sub) >= 8:
            frames.append(sub[8:])
    return frames


def _parse_request(frame_body):
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    info = {}
    m = re.search(r"DateTime=(\d+)\(([^)]*)\)", text)
    if not m:
        return None
    info["period"] = int(m.group(1))
    args = m.group(2)
    info["args"] = args
    parts = [p.strip() for p in args.split("-")]
    info["arg1"] = parts[0] if parts else ""
    m = re.search(r"CodeList=(\d+)\(([^)]*)\)", text)
    if m:
        info["market"] = m.group(1)
        codes = [c.strip() for c in m.group(2).split(",") if c.strip()]
        info["codes"] = codes
        info["code"] = codes[0] if codes else ""
    m = re.search(r"pageid=(\d+)", text)
    if m:
        info["pageid"] = m.group(1)
    return info


def _date_of_bar_start(bar_start: int, pageid: str | None) -> str:
    """按 pageid 选解码器还原日期。

    2026-08-01 抓包修正：4417（L2）与 9354/9355 全部使用 packed-date 游标
    （normal_timeline_bar_to_date）。旧 ordinal 解码会把 07-23 误标成
    07-26、06-30 误标成 07-01（两者在 05-13/14 等日期巧合一致）。
    """
    try:
        return normal_timeline_bar_to_date(bar_start).date().isoformat()
    except Exception:
        return f"bar#{bar_start}"


def _dt54_raw_scan(frame_body, records):
    """在归一化响应里按 bar_index 定位行首，读 dt54 原始 u32。

    前提：parse_history_timeline_response 已成功；行首 = dt1(bar_index) u32，
    字段表按 4 字节/项排列，dt54 的列序号 = 其在字段表中的位置。
    """
    if not records:
        return None
    if frame_body.startswith(b"\x0a"):
        try:
            frame_body = normalize_8901_response(frame_body)
        except ValueError:
            return None
    # L2 混合响应里 0x007E（基准，无 dt54）在前、0x0082（目标股，含 dt54）在后，
    # 必须逐表找含 dt54 的那张，并把 bar 搜索限定在该表区间内。
    col = None
    table_region = None
    pos = 0
    while True:
        idx = frame_body.find(b"hd1.0", pos)
        if idx < 0:
            return None
        pos = idx + 6
        if pos + 10 > len(frame_body):
            continue
        header = struct.unpack("<IHHH", frame_body[pos: pos + 10])
        field_count = header[3]
        if not 0 < field_count <= 50:
            continue
        table_start = pos + 10
        fields = [
            frame_body[table_start + i * 4]
            for i in range(field_count)
        ]
        if 54 not in fields:
            continue
        next_marker = frame_body.find(b"hd1.0", pos)
        col = fields.index(54)
        table_region = (idx, next_marker if next_marker >= 0 else len(frame_body))
        break
    if col is None or table_region is None:
        return None
    region_start, region_end = table_region
    samples = []
    for rec in records[:3] + records[-2:]:
        bar = rec.get("bar_index")
        if bar is None:
            continue
        pos = frame_body.find(
            struct.pack("<I", bar & 0xFFFFFFFF),
            region_start,
            region_end,
        )
        if pos < 0:
            continue
        raw = struct.unpack("<I", frame_body[pos + col * 4: pos + col * 4 + 4])[0]
        samples.append((bar, raw, rec.get("dt54")))
    return samples


def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return
    print(f"\n{'='*64}\n分析 {pcap_path}\n{'='*64}")
    streams = _tshark_streams(pcap_path, PORT)
    print(f"共 {len(streams)} 条 {PORT} TCP 流\n")

    found: dict[tuple[str, str], list[tuple[dict, bytes]]] = {}
    pageid_count: dict[str, int] = {}
    for sid, client_bytes, server_bytes in streams:
        sframes = _split_frames(server_bytes)
        for fb in _split_frames(client_bytes):
            parsed = _parse_request(fb)
            if parsed is None:
                continue
            pid = parsed.get("pageid", "?")
            pageid_count[pid] = pageid_count.get(pid, 0) + 1
            if parsed.get("period") != 8192:
                continue
            try:
                arg1 = int(parsed.get("arg1", "0"))
            except ValueError:
                continue
            if arg1 == 0:
                continue  # 当日分时 DateTime=8192(0-0)，不是历史
            date_str = _date_of_bar_start(arg1, parsed.get("pageid"))
            for code in parsed.get("codes", []):
                found.setdefault((code, date_str), []).append((parsed, sframes))

    # ── 报告 1：抓到哪些日期 ──
    print("【1】历史分时请求（DateTime=8192 且非 0 起点）按 代码×日期 分组")
    if not found:
        print("  ✗ 未抓到历史分时请求（确认：打开的是分时图并按 ← 翻过日期）")
    for (code, date_str), pairs in sorted(found.items()):
        target = "★目标" if date_str in TARGET_DATES else ""
        print(f"  {code} {date_str} {target}: {len(pairs)} 个请求")

    # ── 报告 2：目标日期逐点解码 + dt54 哨兵 ──
    print("\n【2】目标日期解码（241 点 + dt54 哨兵原始值）")
    dumped: dict[tuple[str, str], list[bytes]] = {}
    for (code, date_str), pairs in found.items():
        if date_str not in TARGET_DATES:
            continue
        expected_bar = date_to_normal_timeline_bar(date_str)
        for req, sframes in pairs[:1]:
            for sf in sframes:
                is_candidate = (
                    sf.startswith(b"\x0a")
                    or b"hd1.0\x00" in sf
                    or b"hd3.1\x00" in sf
                )
                if not is_candidate:
                    continue
                try:
                    recs = parse_history_timeline_response(sf, code=code)
                except Exception as exc:
                    print(f"  ✗ {code} {date_str}: 解析失败 {exc}")
                    continue
                # 内容寻址配对：只认首行 bar 等于该日期 packed 游标的响应，
                # 避免同流多日期响应互相串绑。
                if not recs or recs[0]["bar_index"] != expected_bar:
                    continue
                dumped.setdefault((code, date_str), []).append(sf)
                first, last = recs[0], recs[-1]
                print(f"  {code} {date_str}: {len(recs)} 点 "
                      f"dt10[{first['dt10']}→{last['dt10']}] "
                      f"dt13[{first['dt13']}→{last['dt13']}]")
                raw_samples = _dt54_raw_scan(sf, recs)
                if raw_samples is None:
                    print("      dt54: 未定位字段列（无 0x0082/0x0042 常规布局）")
                else:
                    for bar, raw, value in raw_samples:
                        sentinel = "← 0xFFFFFFFF 哨兵→0.0" if raw == 0xFFFFFFFF else ""
                        print(f"      bar={bar} raw_u32=0x{raw:08X} "
                              f"decoded={value} {sentinel}")
                break

    # ── dump：按 代码×日期 存响应帧 ──
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n【dump】→ {PCAP_DIR}")
    for (code, date_str), frames in sorted(dumped.items()):
        name = f"history_{code}_{date_str.replace('-', '')}_{ts}.bin"
        Path(os.path.join(PCAP_DIR, name)).write_bytes(b"".join(frames))
        print(f"  {name}  {len(frames)} 帧 {sum(len(f) for f in frames):,}B")
    if not dumped:
        print("  （无目标日期样本可 dump）")

    # ── 报告 3：pageid 概览 ──
    print("\n【3】pageid 分布")
    for pid, cnt in sorted(pageid_count.items(), key=lambda x: -x[1]):
        print(f"  pageid={pid}: {cnt} 次")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--analyze-only", metavar="PCAP")
    args = ap.parse_args()
    if args.analyze_only:
        analyze(args.analyze_only)
        return
    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"history_timeline_dates_{ts}.pcap")
    capture(iface, args.duration, pcap_path)
    analyze(pcap_path)


if __name__ == "__main__":
    main()
