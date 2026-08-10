#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""抓同花顺「个股实时分时推送」——服务端主动推送帧定位与解码。

背景（2026-07-24 离线扫 market_open.pcap 结论）
------------------------------------------------
thspypc 目前只能「请求-响应」拿当日分时（build_timeline_query, pageid=9354），
拿不到逐点实时推送。离线扫发现 8901 上全是异动通道 subreal（URS/UNX/UCX/UME/UCT）
+ qureal（异动查询），**没有**逐只股票现价推送。但那次抓的是冷启动，
没有「打开某只股分时图并保持界面」这一步。

本脚本目标：验证「分时实时推送」到底走哪个端口、什么订阅触发、现价怎么编码。

做法
----
1. 抓 8901 + 9601（可选 --all 全端口）
2. 分析阶段，核心是**找「客户端静默期（≥8s 无客户端→服务端数据）期间
   服务端仍在持续发数据的帧」**——这才是真·主动推送
3. 对推送帧尝试解码现价/均价逐点增长（dt10 现价、THS float 扫描）
4. 汇总所有订阅类请求（method=subreal/qureal/subrealorder/...），
   看「打开分时图」前后有没有新冒出来的订阅

用法
----
    py tests/capture_realtime_push.py                  # 抓 150s，8901+9601
    py tests/capture_realtime_push.py --duration 180   # 抓 180s
    py tests/capture_realtime_push.py --all            # 抓全端口（排除系统噪声）
    py tests/capture_realtime_push.py --analyze-only xxx.pcap   # 只分析

★操作步骤（关键，否则白抓）：
    1. 启动同花顺登录（可在抓之前先登好）
    2. 运行本脚本选网卡，抓包开始
    3. ★ 前 20 秒：什么操作都别做（采集「静默基线」，看心跳/推送节奏）
    4. ★ 打开一只活跃股票（如 600519 / 000938）的【分时图】（白线+黄线那条，
       不是 K线蜡烛图！），保持界面不动
    5. ★ 盯住分时图几分钟，看那条白线（现价）是否随盘逐点跳动
       （如果客户端自己都不跳，说明没行情源，抓不到东西）
    6. 可以再切到另一只票，再静默 30s
    7. 等抓包自动结束，脚本自动分析

产物：captures_live/realtime_push_<时间戳>.pcap + 终端分析报告
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
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = next((c for c in WS_CANDIDATES
           if os.path.exists(os.path.join(c, "tshark.exe"))), WS_CANDIDATES[0])
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符
PORTS_DEFAULT = [8901, 9601]
SILENCE_GAP = 8.0  # 客户端静默 ≥8s 视为「无请求」，此期间的服务端数据=推送


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


def capture(iface, duration, pcap_path, ports):
    os.makedirs(PCAP_DIR, exist_ok=True)
    if ports is None:
        bpf = None
        port_desc = "全部端口"
    else:
        # dumpcap BPF: tcp port 8901 or tcp port 9601 ...
        bpf = " or ".join(f"tcp port {p}" for p in ports)
        port_desc = "端口 " + "/".join(str(p) for p in ports)
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（{port_desc}，网卡 {iface}）")
    print(f"{'='*64}")
    print(">>> ★本次目标：定位「个股分时实时推送」的端口/订阅/现价字段")
    print("    关键操作（决定能不能抓到分时推送）：")
    print(f"    0. 运行脚本前：同花顺先登录好")
    print(f"    1. ★ 抓包开始后【前 20 秒什么操作都别做】（采集静默基线）")
    print(f"    2. 打开一只活跃股（如 600519/000938）的【分时图】（白线+黄线，非K线）")
    print(f"    3. 保持分时图界面不动，盯 2-3 分钟，确认白线（现价）随盘跳动")
    print(f"    4. 可换另一只票，再静默 30s")
    print("-" * 64)
    cmd = [DUMPCAP, "-i", iface, "-w", pcap_path, "-a", f"duration:{duration}"]
    if bpf:
        cmd[1:1] = ["-f", bpf]
    try:
        subprocess.run(cmd, timeout=duration + 15)
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        pass
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"\n抓包完成：{pcap_path} ({size:,} bytes)")


# ── 分析逻辑 ──

def _tshark_packets(pcap_path, ports):
    """提取每个 TCP 包的 (time, srcport, len, stream)，port 过滤。
    返回 list[(t, srcport, payload_len, stream)]，按时间排序。"""
    if ports is None:
        yfilter = "tcp.len>0"
    else:
        yfilter = "tcp.len>0 and (" + " or ".join(f"tcp.port=={p}" for p in ports) + ")"
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", yfilter,
         "-T", "fields", "-e", "frame.time_relative",
         "-e", "tcp.srcport", "-e", "tcp.len", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    pkts = []
    for ln in r.stdout.decode().splitlines():
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        t, src2, ln2, sid = parts
        try:
            t = float(t); ln2 = int(ln2); sid = int(sid)
        except ValueError:
            continue
        pkts.append((t, src2, ln2, sid))
    return pkts


def _tshark_streams(pcap_path, port):
    """按 TCP 流重组，返回 [(stream_id, client_bytes, server_bytes)]。"""
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
            frames.append(sub[8:])  # 去 8 字节 hex 长度头
    return frames


def _find_push_windows(pkts, ports):
    """找「客户端静默期（≥SILENCE_GAP 秒无客户端→服务端数据）期间，
    服务端仍在发数据」的时间窗口。返回 [(t_start, t_end, srv_bytes, srv_pkts)]。

    判定：以每个客户端包时间为参考，若下个客户端包距前一个 ≥ SILENCE_GAP，
    且这段时间内有服务端包，则记为推送窗口。
    """
    client_times = sorted(t for t, src, _, _ in pkts
                          if src not in [str(p) for p in (ports or [])])
    # 服务端包：srcport 在 ports 里（或 ports=None 时服务端方向用 stream 判断，
    # 这里简化：srcport==port 视为服务端）
    srv_set = {str(p) for p in (ports or [])}
    windows = []
    for i in range(1, len(client_times)):
        gap = client_times[i] - client_times[i - 1]
        if gap < SILENCE_GAP:
            continue
        t0, t1 = client_times[i - 1], client_times[i]
        # 统计 (t0, t1) 间的服务端包
        srv_pkts = [(t, ln) for t, src, ln, _ in pkts
                    if src in srv_set and t0 < t < t1]
        if srv_pkts:
            srv_bytes = sum(ln for _, ln in srv_pkts)
            windows.append((t0, t1, srv_bytes, len(srv_pkts)))
    return windows


def analyze(pcap_path, ports):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return

    print(f"\n{'='*64}")
    print(f"分析 {pcap_path}")
    print(f"{'='*64}")

    pkts = _tshark_packets(pcap_path, ports)
    if not pkts:
        print("✗ 未抓到任何 TCP 数据包。可能：选错网卡 / 同花顺没走这个网卡 /")
        print("  同花顺用的是别的端口（试 --all 全端口重抓）")
        return

    srv_set = {str(p) for p in (ports or [])}
    srv_bytes = sum(ln for t, src, ln, _ in pkts if src in srv_set)
    cli_bytes = sum(ln for t, src, ln, _ in pkts if src not in srv_set)
    tmin = min(t for t, *_ in pkts)
    tmax = max(t for t, *_ in pkts)
    print(f"抓包时长 {tmax-tmin:.1f}s，端口 {ports or '全部'}")
    print(f"服务端→客户端: {srv_bytes:,}B | 客户端→服务端: {cli_bytes:,}B "
          f"| 比 {srv_bytes/max(cli_bytes,1):.1f}x\n")

    # ── 报告 1：时间分布 ──
    print(f"{'='*64}")
    print("【1】流量时间分布（10s 桶，粗看推送节奏）")
    print(f"{'='*64}")
    buckets = {}
    for t, src, ln, _ in pkts:
        b = int(t // 10)
        buckets.setdefault(b, [0, 0])
        if src in srv_set:
            buckets[b][0] += ln
        else:
            buckets[b][1] += ln
    for b in sorted(buckets):
        sb, cb = buckets[b]
        bar = "#" * (sb // 3000)
        print(f"  {b*10:3d}-{b*10+10:3d}s: srv {sb:>8,}B cli {cb:>6,}B {bar}")

    # ── 报告 2：★核心——客户端静默期的服务端推送 ──
    print(f"\n{'='*64}")
    print(f"【2】★核心：客户端静默期（≥{SILENCE_GAP}s 无请求）的服务端推送")
    print(f"{'='*64}")
    windows = _find_push_windows(pkts, ports)
    if not windows:
        print("✗ 未发现「客户端静默期间服务端持续推送」的窗口。")
        print("  这意味着：服务端数据都是对客户端请求的响应，没有主动推送。")
        print("  可能：没在分时图界面 / 分时实时更新走别的端口（试 --all 重抓）")
    else:
        total_push = sum(w[2] for w in windows)
        print(f"发现 {len(windows)} 个静默期推送窗口，合计 {total_push:,}B 服务端数据\n")
        for t0, t1, sb, sp in windows:
            print(f"  [{t0:6.1f}s → {t1:6.1f}s] 静默 {t1-t0:5.1f}s, "
                  f"服务端推送 {sp:>4}包 {sb:>8,}B")

    # ── 报告 3：所有订阅类请求（method/pageid）──
    print(f"\n{'='*64}")
    print("【3】所有订阅类请求（找『打开分时图前后新冒出的订阅』）")
    print(f"{'='*64}")
    _report_subscribe_requests(pcap_path, ports, pkts)

    # ── 报告 4：推送帧内容探测 ──
    print(f"\n{'='*64}")
    print("【4】推送帧内容探测（尝试找现价/均价逐点）")
    print(f"{'='*64}")
    _probe_push_content(pcap_path, ports)

    print(f"\n{'='*64}")
    print(f"pcap: {pcap_path}")
    print(f"重分析: py tests/capture_realtime_push.py --analyze-only \"{pcap_path}\"")
    print(f"{'='*64}")


def _report_subscribe_requests(pcap_path, ports, pkts):
    """汇总所有订阅类请求，按出现时间列出，标注 method/pageid/market。"""
    if ports is None:
        # 全端口模式：扫所有可能的端口
        scan_ports = sorted({p for _, src, _, sid in pkts} |
                            {p for _, src, _, sid in pkts})
        # 取出现频次最高的端口
        from collections import Counter
        port_cnt = Counter()
        for _, src, _, _ in pkts:
            port_cnt[src] += 1
        scan_ports = [p for p, _ in port_cnt.most_common(6)]
    else:
        scan_ports = ports

    all_reqs = []  # [(t, port, method, pageid, market, snippet)]
    for port in scan_ports:
        try:
            streams = _tshark_streams(pcap_path, int(port))
        except (ValueError, subprocess.CalledProcessError):
            continue
        # 需要每帧的时间——改用 tshark 直接取 payload+time
        r = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.dstport=={port} and tcp.len>0",
             "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        for ln in r.stdout.decode().splitlines():
            parts = ln.split("\t")
            if len(parts) < 2:
                continue
            t_str, hex_payload = parts
            try:
                t = float(t_str)
            except ValueError:
                continue
            hex_payload = "".join(hex_payload.split())
            if not hex_payload:
                continue
            raw = bytes.fromhex(hex_payload)
            # 一个 TCP 包可能含多个 MAGIC 帧
            for fb in _split_frames(raw):
                try:
                    txt = fb.decode("gbk", "replace")
                except Exception:
                    continue
                method = re.search(r"method=(\w+)", txt)
                pageid = re.search(r"pageid=(\d+)", txt)
                market = re.search(r"market=(\w+)", txt)
                code = re.search(r"CodeList=\d+\(([^)]*)\)", txt) or \
                       re.search(r"codelist=([^\n]*)", txt)
                has_dt = "DateTime=" in txt or "datetime=" in txt
                if method or pageid or has_dt:
                    snippet = txt[:90].replace("\n", "\\n")
                    all_reqs.append((t, port,
                                     method.group(1) if method else "-",
                                     pageid.group(1) if pageid else "-",
                                     market.group(1) if market else "-",
                                     code.group(1)[:30] if code else "-",
                                     has_dt, snippet))

    if not all_reqs:
        print("  （未抓到任何订阅/查询请求）")
        return
    # 去重计数
    from collections import Counter
    key_cnt = Counter((p, m, pg, mk, cd, hdt)
                      for _, p, m, pg, mk, cd, hdt, _ in all_reqs)
    print(f"共 {len(all_reqs)} 个请求帧，{len(key_cnt)} 种不重复组合：\n")
    for (p, m, pg, mk, cd, hdt), cnt in key_cnt.most_common(30):
        dt_mark = " [有DateTime]" if hdt else ""
        print(f"  port={p} method={m:<12} pageid={pg:<6} market={mk:<5} "
              f"code={cd:<30} ×{cnt}{dt_mark}")
    # 首次出现时间线（看打开分时图前后冒出的新订阅）
    print(f"\n  ── 首次出现时间线（前 25 个不同请求）──")
    seen = set()
    shown = 0
    for t, p, m, pg, mk, cd, hdt, snip in sorted(all_reqs, key=lambda x: x[0]):
        key = (p, m, pg, mk, cd)
        if key in seen:
            continue
        seen.add(key)
        print(f"  {t:7.1f}s port={p} {m}/{pg} market={mk} code={cd}")
        shown += 1
        if shown >= 25:
            print(f"  ... （还有 {len(key_cnt)-shown} 种）")
            break


def _probe_push_content(pcap_path, ports):
    """对服务端帧尝试解码现价/均价。重点看 8901 的 hd 帧。"""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    try:
        from thspypc.protocol import decode_ths_float, parse_kline_hd3_response
    except ImportError as e:
        print(f"  （无法导入 protocol: {e}）")
        return

    scan_ports = ports or [8901, 9601]
    for port in scan_ports:
        try:
            streams = _tshark_streams(pcap_path, int(port))
        except Exception:
            continue
        for sid, cb, sb in streams:
            sframes = _split_frames(sb)
            # 找 hd 帧（分时响应格式）
            hd_frames = [f for f in sframes
                         if b"hd3.1\x00" in f or b"hd1.0" in f]
            if not hd_frames:
                continue
            print(f"\n  port={port} stream{sid}: {len(hd_frames)} 个 hd 帧 "
                  f"（分时格式）")
            for i, f in enumerate(hd_frames[:5]):
                tag = "hd3.1" if b"hd3.1\x00" in f else "hd1.0"
                try:
                    recs = parse_kline_hd3_response(f)
                except Exception as e:
                    print(f"    帧{i} [{tag}] {len(f)}B 解析失败: {e}")
                    continue
                if not recs:
                    print(f"    帧{i} [{tag}] {len(f)}B 解析为空")
                    continue
                # 看现价(dt10)是否随点递增（实时特征）
                prices = [r.get("dt10") for r in recs if r.get("dt10") is not None]
                t0 = recs[0].get("time")
                tN = recs[-1].get("time")
                ts0 = t0.strftime("%H:%M") if t0 else "?"
                tsN = tN.strftime("%H:%M") if tN else "?"
                price_note = ""
                if len(prices) >= 2:
                    price_note = f" 现价首={prices[0]} 末={prices[-1]}"
                print(f"    帧{i} [{tag}] {len(f)}B → {len(recs)} 点 "
                      f"[{ts0}→{tsN}]{price_note}")


def main():
    ap = argparse.ArgumentParser(
        description="抓同花顺「个股分时实时推送」——服务端主动推送定位")
    ap.add_argument("--duration", type=int, default=150, help="抓包时长（秒）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap")
    ap.add_argument("--all", action="store_true",
                    help="抓全端口（不限定 8901/9601，排查端口走偏）")
    ap.add_argument("--ports", default=None,
                    help="自定义端口，逗号分隔，如 8901,9601")
    args = ap.parse_args()

    if args.all:
        ports = None
    elif args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = PORTS_DEFAULT

    if args.analyze_only:
        analyze(args.analyze_only, ports)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"realtime_push_{ts}.pcap")

    capture(iface, args.duration, pcap_path, ports)
    analyze(pcap_path, ports)


if __name__ == "__main__":
    main()
