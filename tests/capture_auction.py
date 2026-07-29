#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端打开【分时图】时的全部请求/响应，定位【集合竞价】数据。

背景
----
分时查询（pageid=4214，DateTime=8192(0-0)）只返回 9:30-15:00 的 241 根，
**不含 9:15-9:25 集合竞价**。但同花顺客户端盘后打开分时图能看到完整的竞价段
（9:15-9:25 的逐笔/开盘价），说明竞价数据来自另一个请求。本脚本抓 hexin
打开分时图时发的**所有** 8901 请求，并对每个响应帧**实际解码**（根数/首根
bar_index/首根现价），直接定位哪个响应含竞价数据。

★ 盘后/随时都能抓（不需要交易日盘中）：只要在同花顺里打开目标股票分时图，
  让客户端把所有请求重发一遍即可。

用法
----
    py tests/capture_auction.py                          # 抓 60s
    py tests/capture_auction.py --duration 90 --code 000938
    py tests/capture_auction.py --analyze-only xxx.pcap --code 000938

★ 操作步骤（盘后即可，随时抓）：
    1. 启动同花顺并登录
    2. 运行本脚本，选网卡（WLAN 一般是 4）
    3. 抓包期间，在 hexin 里做以下操作（每步停 3-5 秒让请求分开）：
       a. 打开【目标股票分时图】（如 000938）← 触发所有分时相关请求
       b. 在分时图上鼠标移到【最左端 9:15-9:25 区域】（看竞价段，可能触发额外请求）
       c. 切到另一只票再切回来（让请求重发，便于抓全）
    4. Ctrl+C 或等自动结束

产物：captures_live/auction_<时间戳>.pcap + 终端分析报告 + resp_streamN.bin
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys

# ── Wireshark 路径探测 ──
WS_CANDIDATES = [
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = next((c for c in WS_CANDIDATES
           if os.path.exists(os.path.join(c, "tshark.exe"))), WS_CANDIDATES[0])
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符

# 已知 pageid 含义
PAGEID_MEANING = {
    "9354": "分时图(普通)",
    "9355": "K线图",
    "4214": "★L2分时(推送)",
}


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
        print("✗ 未检测到网卡（检查 Wireshark/Npcap 是否安装）")
        print(f"  期望路径: {TSHARK}")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    if choice not in ifaces:
        print("无效编号，用默认")
        choice = default
    return choice


def capture(iface, duration, pcap_path, code):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（8901 端口，网卡 {iface}）")
    print(f"目标股票: {code}")
    print(f"{'='*64}")
    print(">>> 抓包期间操作（★关键：必须打开【集合竞价小窗】才抓得到竞价数据）：")
    print(f"    1. hexin 已登录")
    print(f"    2. 打开【{code} 分时图】（停 3-5s）")
    print(f"    ★3. 在分时图上找到【集合竞价】小窗/子图（通常在分时图下方或左侧，")
    print(f"        显示 9:15-9:25 的逐笔/委托），【点开/展开它】（停 5-10s）")
    print(f"       — 这一步是关键！竞价数据是打开小窗时单独请求的，分时主图不含")
    print(f"    4. 在竞价小窗里滚动/悬停（触发更多请求）")
    print(f"    5. 关掉竞价小窗再打开（让请求重发，便于抓全）")
    print("-" * 64)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp port 8901",
             "-w", pcap_path, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        pass
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"\n抓包完成：{pcap_path} ({size:,} bytes)")


# ── 分析逻辑 ──

def _tshark_streams(pcap_path, port=8901):
    """按 TCP 流重组，返回 [(stream_id, client_frames, server_bytes)]。

    client_frames: [(time_s, body)] 带相对时间戳的客户端请求帧
    """
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", f"tcp.port=={port}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    stream_ids = [s for s in r.stdout.decode().split() if s]
    results = []
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
        # 客户端请求帧 + 时间戳
        rc_time = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.dstport=={port}",
             "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        client_frames = []
        for ln in (rc_time.stdout.decode(errors="replace").splitlines()):
            parts = ln.split("\t")
            if len(parts) < 2 or not parts[1].strip():
                continue
            try:
                t = float(parts[0]) if parts[0].strip() else 0.0
            except ValueError:
                t = 0.0
            payload = bytes.fromhex(parts[1].replace(" ", "").replace("\n", ""))
            for sub in payload.split(MAGIC):
                if len(sub) >= 8:
                    client_frames.append((t, sub[8:]))
        # 服务端响应（合并）
        rs = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.srcport=={port}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        server_hex = "".join(rs.stdout.decode(errors="replace").split())
        server_bytes = bytes.fromhex(server_hex) if server_hex else b""
        if client_frames or server_bytes:
            results.append((sid, client_frames, server_bytes))
    return results


def _parse_request(frame_body):
    """解析客户端请求帧，提取所有文本字段。返回 dict 或 None。"""
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "pageid=" not in text and "DateTime=" not in text and "CodeList=" not in text:
        return None

    info = {}
    for key in ["pageid", "DateTime", "DataType", "CodeList",
                "LackTime", "ReqFuquan", "ReqCount"]:
        m = re.search(rf"{key}=([^\r\n]*)", text)
        if m:
            info[key.lower()] = m.group(1).rstrip(",").strip()

    if "datetime" in info:
        m = re.match(r"(\d+)\(([^)]*)\)", info["datetime"])
        if m:
            info["datetime_period"] = m.group(1)
            info["datetime_args"] = m.group(2)
    if "codelist" in info:
        codes = re.findall(r"\(([^)]*)\)", info["codelist"])
        info["codes"] = [c.rstrip(",").strip() for c in codes if c.strip()]
    return info


def _is_target(info, target_code):
    if not target_code:
        return False
    codes = info.get("codes", [])
    return any(target_code in c for c in codes)


def _decode_response_frames(server_bytes):
    """解码服务端响应里的每个 hd3.1/hd1.0 帧，返回摘要列表。

    每项: {tag, dc, flag, hs, fc, first_bar, first_dt10, n_recs, note}
    用 protocol.parse_timeline_l2_response / parse_kline_hd3_response 实解码。
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import (
        decode_ths_float,
        parse_closing_auction_response,
        parse_kline_hd3_response,
        parse_timeline_l2_response,
    )
    summaries = []
    # 按 MAGIC 拆响应帧
    for sub in server_bytes.split(MAGIC):
        if len(sub) < 8:
            continue
        body = sub[8:]  # 去长度头后的帧体（hd 标记在内部）
        # 试 hd3.1（分时/K线变体）
        closing = parse_closing_auction_response(body)
        if closing:
            summaries.append({
                "tag": "closing",
                "dc": len(closing),
                "flag": "0x0036",
                "hs": 16,
                "fc": 4,
                "first_bar": closing[0].get("time"),
                "first_dt10": closing[0].get("dt10"),
                "n_recs": len(closing),
                "note": (
                    f"closing auction "
                    f"{closing[0].get('time')}..{closing[-1].get('time')}"
                ),
            })
        if b"hd3.1\x00" in body:
            # 先看原始头（不做完整解析，提取 dc/flag/hs/fc）
            pos = body.find(b"hd3.1\x00")
            base = pos + 6
            if len(body) >= base + 10:
                dc = struct.unpack("<I", body[base:base+4])[0]
                flag = struct.unpack("<H", body[base+4:base+6])[0]
                hs = struct.unpack("<H", body[base+6:base+8])[0]
                fc = struct.unpack("<H", body[base+8:base+10])[0]
                tag = "hd3.1"
                note = ""
                first_bar = first_dt10 = None
                n_recs = 0
                # 试分时解析
                try:
                    recs = parse_timeline_l2_response(body)
                    if recs:
                        n_recs = len(recs)
                        first_bar = recs[0].get("bar_index")
                        first_dt10 = recs[0].get("dt10")
                        if n_recs > 240:
                            note = "★分时(241根=盘中)"
                        elif 0 < n_recs < 240:
                            note = f"★非241根({n_recs}根,疑似竞价!)"
                except Exception as e:
                    note = f"解析异常: {e}"
                # 试 K线解析（如果分时没解出）
                if n_recs == 0:
                    try:
                        recs = parse_kline_hd3_response(body)
                        if recs:
                            n_recs = len(recs)
                            first_bar = recs[0].get("bar_index") or recs[0].get("time")
                            note = f"K线({n_recs}根)"
                    except Exception:
                        pass
                summaries.append({
                    "tag": tag, "dc": dc, "flag": f"0x{flag:04x}",
                    "hs": hs, "fc": fc, "first_bar": first_bar,
                    "first_dt10": first_dt10, "n_recs": n_recs, "note": note,
                })
        elif b"hd1.0" in body:
            summaries.append({"tag": "hd1.0", "note": "(hd1.0 帧)"})
    return summaries


def analyze(pcap_path, target_code):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return

    print(f"\n{'='*64}")
    print(f"分析 {pcap_path}")
    print(f"目标股票: {target_code}")
    print(f"{'='*64}")

    streams = _tshark_streams(pcap_path, 8901)
    print(f"共 {len(streams)} 条 8901 TCP 流\n")

    # 收集目标股票的请求
    target_streams = []  # [(sid, client_frames, server_bytes, req_infos)]
    for sid, client_frames, server_bytes in streams:
        req_infos = []
        for t, body in client_frames:
            info = _parse_request(body)
            if info and _is_target(info, target_code):
                req_infos.append((t, info))
        if req_infos:
            target_streams.append((sid, client_frames, server_bytes, req_infos))

    print(f"含 {target_code} 的 TCP 流: {len(target_streams)} 条")

    # ── 核心报告：每条目标流的请求 + 响应解码 ──
    print(f"\n{'='*64}")
    print(f"【目标股票 {target_code} 的请求 + 响应解码】（★找含竞价数据的响应）")
    print(f"{'='*64}")

    if not target_streams:
        print(f"  ✗ 未抓到含 {target_code} 的请求")
        print(f"  确认 hexin 是否打开了 {target_code} 分时图，且抓包期间有操作")
        # 仍然展示所有 pageid 概览
        _show_pageid_overview(streams)
        return

    auction_candidates = []  # 疑似含竞价数据的 (sid, summary)
    for sid, _, server_bytes, req_infos in target_streams:
        print(f"\n── stream {sid}（{len(req_infos)} 个请求）──")
        # 请求摘要（去重展示）
        seen_keys = set()
        for t, info in req_infos:
            key = (info.get("pageid"), info.get("datetime"),
                   info.get("datatype", "")[:30], info.get("lacktime"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            pid = info.get("pageid", "?")
            pid_note = PAGEID_MEANING.get(pid, "")
            print(f"  请求[{t:5.1f}s] pageid={pid}{(' ('+pid_note+')') if pid_note else ''} "
                  f"DT={info.get('datetime','?')[:20]} "
                  f"DataType={info.get('datatype','?')[:25]} "
                  f"LackTime={info.get('lacktime','?')}")
        # 响应解码
        if len(server_bytes) < 50:
            print(f"  响应: 无数据")
            continue
        summaries = _decode_response_frames(server_bytes)
        if not summaries:
            print(f"  响应: {len(server_bytes)}B，无 hd3.1/hd1.0 帧")
            continue
        print(f"  响应({len(server_bytes)}B, {len(summaries)} 个 hd 帧):")
        for sm in summaries:
            if sm["tag"] == "hd1.0":
                print(f"    - hd1.0 帧")
                continue
            bar_s = str(sm["first_bar"]) if sm["first_bar"] is not None else "?"
            dt10_s = (f"{sm['first_dt10']:.2f}" if isinstance(sm["first_dt10"], (int, float))
                      else str(sm["first_dt10"]))
            print(f"    - {sm['tag']} dc={sm['dc']} flag={sm['flag']} "
                  f"hs={sm['hs']} fc={sm['fc']} → {sm['n_recs']}根, "
                  f"首根 bar={bar_s}, dt10={dt10_s}  {sm['note']}")
            # 收集疑似竞价候选（根数 < 241 或非标准）
            if sm["n_recs"] and sm["n_recs"] != 241 and sm["n_recs"] > 0:
                auction_candidates.append((sid, sm))

    # ── 竞价候选总结 ──
    print(f"\n{'='*64}")
    print("【竞价数据候选】（根数 ≠ 241 的响应，最可能含竞价）")
    print(f"{'='*64}")
    if not auction_candidates:
        print("  未发现非 241 根的响应。竞价数据可能：")
        print("    ① 藏在 241 根响应的某个字段里（dt16 哨兵？需查盘中）")
        print("    ② 走了非 hd3.1 帧（如 hd1.0 推送）")
        print("    ③ 用单独的 pageid 请求（未抓到，重抓时多操作几次分时图）")
    else:
        for sid, sm in auction_candidates:
            print(f"  stream {sid}: {sm['n_recs']}根 flag={sm['flag']} "
                  f"首bar={sm['first_bar']} 首dt10={sm['first_dt10']}  {sm['note']}")

    _show_pageid_overview(streams)
    _dump_responses(target_streams, pcap_path, target_code)


def _show_pageid_overview(streams):
    """所有请求的 pageid 分布。"""
    print(f"\n{'='*64}")
    print("【所有 pageid 分布】（看竞价走哪个 pageid）")
    print(f"{'='*64}")
    pid_count = {}
    for _, client_frames, _ in streams:
        for _, body in client_frames:
            info = _parse_request(body)
            if info and "pageid" in info:
                pid = info["pageid"]
                pid_count[pid] = pid_count.get(pid, 0) + 1
    if pid_count:
        for pid, cnt in sorted(pid_count.items(), key=lambda x: -x[1]):
            note = PAGEID_MEANING.get(pid, "")
            print(f"  pageid={pid}: {cnt} 次{(' ('+note+')') if note else ''}")
    else:
        print("  （未抓到任何 pageid 请求）")


def _dump_responses(target_streams, pcap_path, target_code):
    """导出目标流的服务端响应（供离线分析）。"""
    print(f"\n{'='*64}")
    print(f"【响应原始字节导出】（含 {target_code} 的 stream）")
    print(f"{'='*64}")
    exported = 0
    for sid, _, server_bytes, _ in target_streams:
        if len(server_bytes) < 50:
            continue
        stem, _suffix = os.path.splitext(pcap_path)
        out_path = f"{stem}_resp_stream{sid}.bin"
        with open(out_path, 'wb') as f:
            f.write(server_bytes)
        nframes = server_bytes.count(MAGIC)
        has_hd = b"hd1.0" in server_bytes or b"hd3.1" in server_bytes
        hd_mark = " [含 hd 帧 ★]" if has_hd else ""
        print(f"  stream {sid}: {len(server_bytes)}B, {nframes} 帧{hd_mark}"
              f" → {os.path.basename(out_path)}")
        exported += 1
    if exported == 0:
        print(f"  （无 {target_code} 响应数据）")


def main():
    ap = argparse.ArgumentParser(
        description="抓同花顺分时图请求/响应，定位集合竞价数据（盘后即可）")
    ap.add_argument("--duration", type=int, default=60,
                    help="抓包时长（秒，默认 60）")
    ap.add_argument("--code", default="000938",
                    help="目标股票代码（默认 000938）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap 文件")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only, args.code)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"auction_{ts}.pcap")

    capture(iface, args.duration, pcap_path, args.code)
    analyze(pcap_path, args.code)

    print(f"\n{'='*64}")
    print(f"pcap 已保存: {pcap_path}")
    print(f"重新分析: py tests/capture_auction.py --analyze-only \"{pcap_path}\"")


if __name__ == "__main__":
    main()
