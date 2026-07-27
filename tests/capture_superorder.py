#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端【超级盘口】打开时的全部 8901 请求/响应，定位集合竞价
9:15-9:25 完整逐 tick（每 3 秒一条，约 200 条）的来源协议。

背景
----
分时图 + 现有的 auction 查询（pageid=4214，周期码 7176）只拿到 ~160 条且带跳秒，
而 hexin 客户端【超级盘口】功能能显示 9:15-9:25 **每隔 3 秒、完整无缺** 的历史重现。
说明超级盘口走的是另一个请求（可能是不同 pageid / 不同周期码 / 不同 DataType），
返回的响应格式也可能不同。本脚本抓包定位：

  1. 超级盘口对应哪个请求（pageid / DateTime / DataType）
  2. 响应里 9:15-9:25 时间戳的数量 + 范围（验证是否完整 200 条）
  3. 响应帧结构（hd1.0 / hd3.1 / 别的标记 / 路由）

★ 盘后/随时都能抓：只要在同花顺里打开目标股票的【超级盘口】让请求重发即可。

用法
----
    py tests/capture_superorder.py                       # 抓 60s，目标 603118
    py tests/capture_superorder.py --duration 90 --code 603118
    py tests/capture_superorder.py --analyze-only xxx.pcap --code 603118

★ 操作步骤（关键：必须真正点开【超级盘口】面板）：
    1. 启动同花顺并登录
    2. 运行本脚本，选网卡（WLAN 一般是 4）
    3. 抓包期间：
       a. 打开【目标股票】（如 603118）的分时图
       b. ★ 点开【超级盘口】功能（通常在分时图工具栏、或右键菜单、或 F11）
          — 让它显示 9:15-9:25 的逐 3 秒历史重现
       c. 在超级盘口里悬停/滚动/点 9:15-9:25 区域（触发请求）
       d. 切到另一只票再切回来，重新打开超级盘口（让请求重发便于抓全）
    4. Ctrl+C 或等自动结束

产物：captures_live/superorder_<时间戳>.pcap + 终端分析报告 + resp_streamN.bin
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys

# ── Wireshark 路径探测（与 capture_auction.py 一致）──
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

# 已知 pageid 含义（超级盘口的 pageid 未知，抓出来填这里）
PAGEID_MEANING = {
    "9354": "分时图(普通)",
    "9355": "K线图",
    "4214": "L2分时(推送)/竞价(7176)",
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
    print(f"\n{'='*72}")
    print(f"开始抓包 {duration}s（8901 端口，网卡 {iface}）")
    print(f"目标股票: {code}")
    print(f"{'='*72}")
    print(">>> 抓包期间操作（★关键：必须真正点开【超级盘口】面板）：")
    print(f"    1. hexin 已登录")
    print(f"    2. 打开【{code} 分时图】")
    print(f"    ★3. 点开【超级盘口】（分时图工具栏 / 右键菜单 / 快捷键）")
    print(f"       — 让它显示 9:15-9:25 的逐 3 秒历史重现")
    print(f"    4. 在超级盘口里悬停/滚动到 9:15-9:25 区域（触发请求）")
    print(f"    5. 切到另一只票再切回来，重新打开超级盘口（让请求重发）")
    print("-" * 72)
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


# ── 流重组（复用 capture_auction.py 逻辑）──

def _tshark_streams(pcap_path, port=8901):
    """按 TCP 流重组，返回 [(stream_id, client_frames, server_bytes)]。"""
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", f"tcp.port=={port}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    stream_ids = [s for s in r.stdout.decode().split() if s]
    results = []
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
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
    """解析客户端请求帧，提取所有文本字段。"""
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "pageid=" not in text and "DateTime=" not in text and "CodeList=" not in text:
        return None
    info = {}
    for key in ["pageid", "DateTime", "DataType", "CodeList",
                "LackTime", "ReqFuquan", "ReqCount", "ServerCost"]:
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


# ── 核心：扫描响应里的 9:15-9:25 时间戳（不依赖 hd 标记）──

def _scan_auction_timestamps(server_bytes):
    """扫描响应里**竞价帧**（含 0xfc01 路由或 Ihd1.0 标记）的 9:15-9:25 时间戳。

    关键过滤（避免字段噪声误匹配）：
      1. 按 MAGIC 拆帧，只扫含 ``\\xfc\\x01`` 或 ``Ihd1.0`` 的竞价响应帧
         （跳过分时 0x0201、K线等其他响应）
      2. 4 字节 + 3 字节（沪市压缩格式）双向扫描取并集
      3. ``ts % 3 == base % 3`` 过滤：真实 tick 严格 3 秒整，秒数对齐到首条
         （9:15:00 ts%3=0）。字段噪声虽满足 3 字节模式，但秒数往往不在 3 秒网格上。

    返回 (count_4byte_raw, count_3byte_raw, count_aligned, first, last, sorted_ts_list, n_auction_frames)
      count_aligned 是过滤后的真实 tick 数（应接近 200）。
    """
    # 拆帧 + 识别竞价帧
    chunks = server_bytes.split(MAGIC)
    auction_bodies = []
    for chunk in chunks:
        body = chunk[8:] if len(chunk) > 8 else chunk   # 跳过 8B ASCII hex 长度
        if b"\xfc\x01" in body or b"Ihd1.0" in body:
            auction_bodies.append(body)
    if not auction_bodies:
        # 没有明确的竞价帧标记，退而扫描全部（供调试）
        auction_bodies = [chunk[8:] if len(chunk) > 8 else chunk for chunk in chunks]

    ts_set_4 = set()
    ts_set_3 = set()
    for body in auction_bodies:
        n = len(body)
        for i in range(n - 3):
            v = struct.unpack("<I", body[i:i+4])[0]
            if 1_700_000_000 < v < 1_800_000_000 and _ts_in_auction(v):
                ts_set_4.add(v)
        for i in range(n - 2):
            b1 = body[i + 1]
            if body[i + 2] != 0x62 or not (0xbc <= b1 <= 0xc0):
                continue
            ts = (body[i] | (b1 << 8) | (0x62 << 16) | (0x6a << 24)) & 0xFFFFFFFF
            if _ts_in_auction(ts):
                ts_set_3.add(ts)
    ts_all = ts_set_4 | ts_set_3

    # ts%3 对齐过滤：真实 tick 严格 3 秒网格，mod 应一致。
    # 用所有候选里 ts%3 的众数作 mod（噪声会分散在 0/1/2，真实 tick 聚集在一个值）。
    aligned = set()
    if ts_all:
        mod_count = {0: 0, 1: 0, 2: 0}
        for ts in ts_all:
            mod_count[ts % 3] += 1
        mod = max(mod_count, key=mod_count.get)
        aligned = {ts for ts in ts_all if ts % 3 == mod}

    first = last = None
    sorted_ts = sorted(aligned)
    if sorted_ts:
        first = _ts_to_hms(sorted_ts[0])
        last = _ts_to_hms(sorted_ts[-1])
    return (len(ts_set_4), len(ts_set_3), len(aligned),
            first, last, sorted_ts, len(auction_bodies))


def _ts_in_auction(ts):
    """unix 时间戳是否落在 CST 9:15:00-9:25:59（跨日通用，只看时:分:秒）。"""
    try:
        d = datetime.datetime.fromtimestamp(ts)
    except (OSError, ValueError, OverflowError):
        return False
    hms = d.hour * 3600 + d.minute * 60 + d.second
    return 9 * 3600 + 15 * 60 <= hms <= 9 * 3600 + 26 * 60


def _ts_to_hms(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except Exception:
        return "?"


def _detect_frame_tags(server_bytes):
    """检测响应里出现的帧标记（hd1.0 / hd3.1 / Ihd1.0 等）+ 路由字节。"""
    tags = []
    for tag in [b"hd1.0\x00", b"hd3.1\x00", b"hd1.0", b"hd3.1", b"Ihd1.0"]:
        if tag in server_bytes:
            tags.append(tag.decode("latin1").replace("\x00", "\\0"))
    # 路由 0xfc01（竞价）/ 0x0201（分时）
    routes = []
    if b"\xfc\x01" in server_bytes:
        routes.append("0xfc01(竞价)")
    if b"\x02\x01" in server_bytes:
        routes.append("0x0201(分时)")
    return tags, routes


def analyze(pcap_path, target_code):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return
    print(f"\n{'='*72}")
    print(f"分析 {pcap_path}")
    print(f"目标股票: {target_code}")
    print(f"{'='*72}")

    streams = _tshark_streams(pcap_path, 8901)
    print(f"共 {len(streams)} 条 8901 TCP 流\n")

    # 收集目标股票的请求
    target_streams = []
    for sid, client_frames, server_bytes in streams:
        req_infos = []
        for t, body in client_frames:
            info = _parse_request(body)
            if info and _is_target(info, target_code):
                req_infos.append((t, info))
        if req_infos:
            target_streams.append((sid, client_frames, server_bytes, req_infos))

    print(f"含 {target_code} 的 TCP 流: {len(target_streams)} 条")

    # ── 核心：每条流的请求 + 响应时间戳扫描 ──
    print(f"\n{'='*72}")
    print(f"【目标股票 {target_code} 的请求 + 响应 9:15-9:25 时间戳扫描】")
    print(f"{'='*72}")
    if not target_streams:
        print(f"  ✗ 未抓到含 {target_code} 的请求")
        print(f"  确认 hexin 是否打开了 {target_code} 超级盘口，抓包期间有操作")
        _show_all_pageids(streams)
        return

    best_candidates = []   # (sid, ts_count, first, last, req_summary)
    for sid, _, server_bytes, req_infos in target_streams:
        print(f"\n── stream {sid}（{len(req_infos)} 个请求，响应 {len(server_bytes)}B）──")
        # 请求摘要（去重）
        seen = set()
        for t, info in req_infos:
            key = (info.get("pageid"), info.get("datetime"),
                   info.get("datatype", "")[:40], info.get("lacktime"))
            if key in seen:
                continue
            seen.add(key)
            pid = info.get("pageid", "?")
            pid_note = PAGEID_MEANING.get(pid, "")
            dt = info.get("datetime", "?")[:25]
            dtype = info.get("datatype", "?")[:30]
            print(f"  请求[{t:5.1f}s] pageid={pid}{(' ('+pid_note+')') if pid_note else ''} "
                  f"DT={dt} DataType={dtype}")
        # 响应扫描
        if len(server_bytes) < 50:
            print(f"  响应: 无数据")
            continue
        c4, c3, call, first, last, ts_list, n_af = _scan_auction_timestamps(server_bytes)
        tags, routes = _detect_frame_tags(server_bytes)
        tag_str = "/".join(tags) if tags else "(无 hd 标记)"
        route_str = " ".join(routes) if routes else ""
        print(f"  响应扫描: 竞价帧 {n_af} 个, 9:15-9:25 时间戳 {call} 个 "
              f"(raw: 4字节{c4}+3字节{c3}, ts%3过滤后 {call})  范围 {first}-{last}")
        print(f"            帧标记: {tag_str}  路由: {route_str}")
        # 间隔分析（验证是否每 3 秒一条无缺）
        if call >= 10:
            gaps = {}
            for i in range(1, len(ts_list)):
                g = ts_list[i] - ts_list[i-1]
                gaps[g] = gaps.get(g, 0) + 1
            # 真实 tick 间隔 <= 30s；> 30s 的是混入的非竞价噪声
            real_gaps = {g: c for g, c in gaps.items() if g <= 30}
            noise_n = sum(c for g, c in gaps.items() if g > 30)
            gap_str = " ".join(f"{g}s×{c}" for g, c in sorted(real_gaps.items()))
            print(f"            间隔(<=30s): {gap_str}")
            if noise_n:
                print(f"            ⚠ 含 {noise_n} 个大间隔(>30s)，响应里混了非竞价噪声时间戳")
            # 用连续段（最长无大间隔段）算应有数
            seg_start = seg_end = ts_list[0]
            best_len = 0
            best_se = (ts_list[0], ts_list[0])
            cur_start = ts_list[0]
            for i in range(1, len(ts_list)):
                if ts_list[i] - ts_list[i-1] <= 30:
                    seg_end = ts_list[i]
                else:
                    if seg_end - cur_start > best_len:
                        best_len = seg_end - cur_start
                        best_se = (cur_start, seg_end)
                    cur_start = ts_list[i]
                    seg_end = ts_list[i]
            if seg_end - cur_start > best_len:
                best_se = (cur_start, seg_end)
            # 统计落在最长连续段内的 tick 数
            in_seg = [ts for ts in ts_list if best_se[0] <= ts <= best_se[1]]
            n_expected = (best_se[1] - best_se[0]) // 3 + 1
            missing = n_expected - len(in_seg)
            print(f"            最长连续段 {_ts_to_hms(best_se[0])}-{_ts_to_hms(best_se[1])}: "
                  f"应有 {n_expected} 条, 实际 {len(in_seg)}, 缺 {missing}")
            if missing == 0 and len(in_seg) >= 195:
                print(f"            ★★★ 完整无缺！这就是超级盘口的完整数据源")
            elif missing <= 5 and len(in_seg) >= 190:
                print(f"            ★ 接近完整（缺 {missing} 条），可能就是超级盘口")
        # 记录最佳候选
        req_sum = f"pageid={req_infos[0][1].get('pageid','?')} DT={req_infos[0][1].get('datetime','?')[:20]}"
        best_candidates.append((sid, call, first, last, req_sum, len(server_bytes)))

    # ── 总结：找出最像"完整 200 条"的流 ──
    print(f"\n{'='*72}")
    print("【超级盘口候选总结】（按时间戳数量排序，找完整 200 条的）")
    print(f"{'='*72}")
    best_candidates.sort(key=lambda x: -x[1])
    for sid, cnt, first, last, req, sz in best_candidates[:10]:
        mark = " ★最可能" if cnt >= 180 else ""
        print(f"  stream {sid}: {cnt} 条 ({first}-{last}) {req} [{sz}B]{mark}")

    _show_all_pageids(streams)
    _dump_responses(target_streams, pcap_path, target_code)


def _show_all_pageids(streams):
    """所有请求的 pageid + DateTime period 分布。"""
    print(f"\n{'='*72}")
    print("【所有 pageid / DateTime周期码 分布】（超级盘口可能用新 pageid 或新周期码）")
    print(f"{'='*72}")
    pid_count = {}
    period_count = {}
    for _, client_frames, _ in streams:
        for _, body in client_frames:
            info = _parse_request(body)
            if not info:
                continue
            if "pageid" in info:
                pid = info["pageid"]
                pid_count[pid] = pid_count.get(pid, 0) + 1
            if "datetime_period" in info:
                p = info["datetime_period"]
                period_count[p] = period_count.get(p, 0) + 1
    print("pageid 分布:")
    if pid_count:
        for pid, cnt in sorted(pid_count.items(), key=lambda x: -x[1]):
            note = PAGEID_MEANING.get(pid, "★未知(可能是超级盘口!)")
            print(f"  pageid={pid}: {cnt} 次 ({note})")
    else:
        print("  （未抓到任何 pageid 请求）")
    print("\nDateTime 周期码分布:")
    if period_count:
        known = {"8192": "分时", "16384": "日K", "7176": "集合竞价(已知)",
                 "7174": "?", "7173": "?", "7169": "?", "7424": "收盘集合竞价?"}
        for p, cnt in sorted(period_count.items(), key=lambda x: -x[1]):
            note = known.get(p, "★未知周期码")
            print(f"  周期码 {p}: {cnt} 次 ({note})")
    else:
        print("  （未抓到 DateTime 请求）")


def _dump_responses(target_streams, pcap_path, target_code):
    """导出目标流的服务端响应（供离线分析）。"""
    print(f"\n{'='*72}")
    print(f"【响应原始字节导出】（含 {target_code} 的 stream）")
    print(f"{'='*72}")
    exported = 0
    for sid, _, server_bytes, _ in target_streams:
        if len(server_bytes) < 50:
            continue
        out_path = pcap_path.replace('.pcap', f'_resp_stream{sid}.bin')
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
        description="抓同花顺【超级盘口】请求/响应，定位完整集合竞价数据源")
    ap.add_argument("--duration", type=int, default=60,
                    help="抓包时长（秒，默认 60）")
    ap.add_argument("--code", default="603118",
                    help="目标股票代码（默认 603118 沪市）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap 文件")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only, args.code)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"superorder_{ts}.pcap")

    capture(iface, args.duration, pcap_path, args.code)
    analyze(pcap_path, args.code)

    print(f"\n{'='*72}")
    print(f"pcap 已保存: {pcap_path}")
    print(f"重新分析: py tests/capture_superorder.py --analyze-only \"{pcap_path}\" --code {args.code}")


if __name__ == "__main__":
    main()
