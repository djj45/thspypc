#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""抓同花顺「看盘界面实时推送」——服务端主动推送帧定位、解码与节奏统计。

背景
----
``capture_kanpan.py`` 是请求中心（分类客户端请求，找未实现协议），但**不解析服务端
推送帧**。本脚本补这个缺口，专门抓「看盘界面保持不动时，服务端持续推送的实时数据」：

  - **8901 pageid=4214 L2 十档盘口逐 tick 推送**（71 字节定长帧，含现价/成交量/
    tick 序号）—— 盘口面板的生命线，盘中持续推送
  - **9601 pushrealorder 短线精灵实时异动推送**（含异动类型/金额/涨跌幅）—— 短线
    精灵面板的生命线，盘中等秒级推送
  - **8901 subreal 订阅注册**（URS/UCT/UNX/UCX/UME + 1341/5716/392）—— 触发板块/
    盘口推送的前置订阅
  - **其他服务端推送**（板块行情 hd3.1 周期推送、指数推送等）

核心方法：**客户端静默期（≥6s 无客户端请求）期间，服务端仍在发的帧 = 真正的主动推送**。
对推送帧按类型解码：4214 用 ``is_snapshot_push`` + ``parse_snapshot_push``，
pushrealorder 用 ``parse_pushrealorder_response``，其余统计字节数和频率。

用法
----
    py tests/capture_kanpan_push.py                  # 抓 180s，8901+9601
    py tests/capture_kanpan_push.py --duration 300
    py tests/capture_kanpan_push.py --iface 4        # 非交互指定网卡
    py tests/capture_kanpan_push.py --analyze-only xxx.pcap

★操作步骤（严格按阶段，决定能否抓到推送）：
    1. 启动同花顺并登录（L2 账号更好，能抓 4214 十档推送），打开【看盘】界面
    2. 运行本脚本选网卡
    3. ★ 前 15 秒：什么操作都别做（采集静默基线，看心跳/推送节奏）
    4. ★ 在看盘界面**中间分时图**打开一只活跃股票（如 600519 / 000938），
       保持界面不动 60 秒（抓 4214 十档逐 tick 推送 + 分时实时点）
    5. ★ 右下角**短线精灵**保持打开（抓 pushrealorder 实时异动推送）
    6. ★ 可选：切到另一只票，再静默 30 秒
    7. 等抓包自动结束，脚本分析推送帧并 dump 样本

产物：captures_live/kanpan_push_<时间戳>.pcap +
      kanpan_push_<type>_<ts>.bin（按推送类型 dump 样本）
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.features.realorder_protocol import (  # noqa: E402
    ANOMALY_BYTE_MAP,
    ANOMALY_MAP_DXJL,
    parse_pushrealorder_response,
)
from thspypc.features.snapshot_protocol import (  # noqa: E402
    is_snapshot_push,
    parse_snapshot_push,
)
from thspypc.features.index_push_protocol import (  # noqa: E402
    is_index_push,
    parse_index_push,
)

# ── Wireshark 路径探测 ──
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

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901/9601 帧分隔符
PORTS = [8901, 9601]
SILENCE_GAP = 6.0  # 客户端静默 ≥6s 视为「无请求」，此期间服务端数据=推送


# ── 网卡选择 ──

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
        print(f"✗ 未检测到网卡（检查 Wireshark/Npcap 是否安装）: {TSHARK}")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    return choice if choice in ifaces else default


# ── 抓包 ──

def capture(iface, duration, pcap_path, stop_file=None):
    os.makedirs(PCAP_DIR, exist_ok=True)
    if stop_file and os.path.exists(stop_file):
        try:
            os.unlink(stop_file)
        except OSError:
            pass
    bpf = " or ".join(f"tcp port {p}" for p in PORTS)
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（端口 {PORTS}，网卡 {iface}）")
    print(f"{'='*64}")
    print(">>> 抓包期间按阶段操作（决定能否抓到推送）：")
    print("  ★ 0-15s：什么操作都别做（采集静默基线）")
    print("  ★ 15-75s：看盘界面分时图打开一只活跃股（如 600519），保持不动")
    print("           （抓 4214 十档逐 tick 推送 + 分时实时点）")
    print("  ★ 右下角短线精灵保持打开（抓 pushrealorder 实时异动）")
    print("  ★ 可选：切另一只票再静默 30s")
    if stop_file:
        print(f"  中途叫停：创建 {stop_file} 即可提前结束")
    print("-" * 64)
    proc = subprocess.Popen(
        [DUMPCAP, "-i", iface, "-f", bpf,
         "-w", pcap_path, "-a", f"duration:{duration}"],
    )
    stopped = False
    deadline = time.time() + duration + 15
    try:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(1)
            if stop_file and os.path.exists(stop_file):
                print("\n★ 收到停止信号，提前结束抓包（已保存已抓部分）")
                stopped = True
                break
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
        stopped = True
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if stop_file and os.path.exists(stop_file):
        try:
            os.unlink(stop_file)
        except OSError:
            pass
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"\n抓包{'提前' if stopped else ''}完成：{pcap_path} ({size:,} bytes)")


# ── 分析：TCP 流重组 + 帧切分 ──

def _tshark_streams(pcap_path):
    """按 TCP 流重组，返回 {stream_id: (client_bytes, server_bytes)}。"""
    r = subprocess.run(
        [TSHARK, "-r", pcap_path,
         "-Y", " or ".join(f"tcp.port=={p}" for p in PORTS),
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    stream_ids = [s for s in r.stdout.decode().split() if s]
    results = {}
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
        rc = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and (" +
             " or ".join(f"tcp.dstport=={p}" for p in PORTS) + ")",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        client_hex = "".join(rc.stdout.decode().split())
        rs = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and (" +
             " or ".join(f"tcp.srcport=={p}" for p in PORTS) + ")",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        server_hex = "".join(rs.stdout.decode().split())
        if client_hex or server_hex:
            results[sid] = (
                bytes.fromhex(client_hex) if client_hex else b"",
                bytes.fromhex(server_hex) if server_hex else b"",
            )
    return results


def _split_frames(stream_bytes):
    """按 MAGIC 切帧，去掉 8 字节 ASCII 长度头，返回 body 列表。"""
    frames = []
    for sub in stream_bytes.split(MAGIC):
        if len(sub) >= 8:
            frames.append(sub[8:])
    return frames


def _collect_client_frames(pcap_path):
    """收集所有客户端请求帧 + 时间戳，返回 [(t, body, stream)]。"""
    r = subprocess.run(
        [TSHARK, "-r", pcap_path,
         "-Y", " or ".join(f"tcp.dstport=={p}" for p in PORTS),
         "-T", "fields",
         "-e", "frame.time_relative", "-e", "tcp.stream", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    frames = []
    for line in r.stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].strip():
            continue
        try:
            t = float(parts[0])
        except ValueError:
            continue
        stream = parts[1]
        payload = bytes.fromhex(parts[2].replace(":", ""))
        for body in _split_frames(payload):
            frames.append((t, body, stream))
    return frames


def _collect_server_frames(pcap_path):
    """收集所有服务端帧 + 时间戳 + 源端口，返回 [(t, body, stream, srcport)]。"""
    r = subprocess.run(
        [TSHARK, "-r", pcap_path,
         "-Y", " or ".join(f"tcp.srcport=={p}" for p in PORTS),
         "-T", "fields",
         "-e", "frame.time_relative", "-e", "tcp.stream",
         "-e", "tcp.srcport", "-e", "tcp.payload"],
        capture_output=True, timeout=120)
    frames = []
    for line in r.stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3].strip():
            continue
        try:
            t = float(parts[0])
        except ValueError:
            continue
        stream = parts[1]
        srcport = parts[2]
        payload = bytes.fromhex(parts[3].replace(":", ""))
        for body in _split_frames(payload):
            frames.append((t, body, stream, srcport))
    return frames


# ── 推送帧分类 ──

def classify_server_frame(body, srcport):
    """分类一个服务端帧，返回 (kind, detail)。

    kind:
      - "index_push": 09 7b d0 0f 指数实时推送（五大指数点位）
      - "snapshot4214": 71 字节 L2 十档逐 tick 推送
      - "pushrealorder": 9601 短线精灵实时异动推送
      - "subreal_ack": subreal 订阅回执（8901）
      - "hd31_table": hd3.1 表响应（板块行情/成分股等周期推送）
      - "hd10_table": hd1.0 表响应
      - "heartbeat": 心跳
      - "other": 其他
    """
    # 心跳
    if len(body) <= 5 and (body[:1] == b"\x09" or body[-1:] == b"\x07"):
        return ("heartbeat", {})
    # 指数实时推送（09 7b d0 0f 帧）
    if is_index_push(body):
        parsed = parse_index_push(body)
        if parsed:
            return ("index_push", parsed)
        return ("index_push", {"len": len(body)})
    # 4214 十档逐 tick 推送（71 字节定长）
    if is_snapshot_push(body):
        parsed = parse_snapshot_push(body)
        return ("snapshot4214", parsed or {})
    # 9601 pushrealorder 短线精灵实时异动
    if b"pushrealorder" in body:
        records = parse_pushrealorder_response(body)
        if records:
            return ("pushrealorder", {"records": records, "count": len(records)})
        return ("pushrealorder", {"count": 0})
    # hd3.1 表（板块行情/成分股周期推送）
    if b"hd3.1" in body:
        return ("hd31_table", {"len": len(body)})
    # hd1.0 表
    if b"hd1.0" in body:
        return ("hd10_table", {"len": len(body)})
    # subreal 订阅回执（含 CodeListSize）
    if b"CodeListSize" in body:
        m = re.search(rb"CodeListSize=(\d+)", body)
        size = int(m.group(1)) if m else -1
        return ("subreal_ack", {"codelist_size": size, "len": len(body)})
    return ("other", {"len": len(body), "head_hex": body[:16].hex(" ")})


# ── 订阅类客户端请求识别 ──

def classify_subscribe_request(body):
    """识别客户端订阅类请求，返回 label 或 None。"""
    try:
        text = body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "method=subrealorder" in text:
        m = re.search(r"market=(\w+)", text)
        mk = m.group(1) if m else "?"
        return f"subrealorder(market={mk}, 9601短线精灵订阅)"
    if "method=subreal" in text:
        m = re.search(r"market=(\w+)", text)
        mk = m.group(1) if m else "?"
        m2 = re.search(r"pageid=(\d+)", text)
        pid = m2.group(1) if m2 else "?"
        return f"subreal(market={mk}, pageid={pid}, 8901订阅)"
    if "pageid=4214" in text:
        return "snapshot_subscribe(4214十档订阅)"
    if "method=qurealorder" in text:
        return "qurealorder(短线精灵历史查询)"
    if "method=statscalc" in text:
        return "statscalc(板块统计)"
    if "method=calcext" in text:
        return "calcext(板块扩展计算)"
    m = re.search(r"pageid=(\d+)", text)
    if m:
        return f"request(pageid={m.group(1)})"
    return None


# ── 分析主流程 ──

def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return
    print(f"\n{'='*64}")
    print(f"分析 {pcap_path}")
    print(f"{'='*64}")

    client_frames = _collect_client_frames(pcap_path)
    server_frames = _collect_server_frames(pcap_path)
    if not client_frames and not server_frames:
        print("✗ 未抓到任何 8901/9601 数据帧。可能：选错网卡 / 同花顺没走这个网卡")
        return

    tmin = min((f[0] for f in client_frames + server_frames), default=0)
    tmax = max((f[0] for f in client_frames + server_frames), default=0)
    print(f"抓包时长 {tmax-tmin:.1f}s")
    print(f"客户端请求帧: {len(client_frames)} | 服务端帧: {len(server_frames)}\n")

    # ── 报告 1：推送帧分类统计 ──
    print(f"{'='*64}")
    print("【1】服务端推送帧分类（盘中应看到 snapshot4214 / pushrealorder）")
    print(f"{'='*64}")
    kind_counter = Counter()
    kind_bytes = defaultdict(int)
    classified = []
    for t, body, stream, srcport in server_frames:
        kind, detail = classify_server_frame(body, srcport)
        kind_counter[kind] += 1
        kind_bytes[kind] += len(body)
        classified.append((t, kind, detail, body, srcport))

    kind_labels = {
        "index_push": "★ 指数实时推送（五大指数点位）",
        "snapshot4214": "★ 4214 十档逐 tick 推送（盘口）",
        "pushrealorder": "★ pushrealorder 短线精灵实时异动",
        "subreal_ack": "subreal 订阅回执",
        "hd31_table": "hd3.1 表（板块/成分股周期推送）",
        "hd10_table": "hd1.0 表",
        "heartbeat": "心跳",
        "other": "其他",
    }
    for kind, cnt in kind_counter.most_common():
        label = kind_labels.get(kind, kind)
        print(f"  {label}: {cnt} 帧, {kind_bytes[kind]:,}B")
    if not kind_counter.get("snapshot4214") and not kind_counter.get("pushrealorder"):
        print("  ⚠ 未抓到 4214/pushrealorder 推送——可能没在看盘界面/没开 L2/盘外")

    # ── 报告 2：推送节奏（逐秒桶）──
    print(f"\n{'='*64}")
    print("【2】推送节奏（5s 桶，看 snapshot4214/pushrealorder 是否持续推送）")
    print(f"{'='*64}")
    push_kinds = {"index_push", "snapshot4214", "pushrealorder"}
    buckets: dict[int, Counter] = defaultdict(Counter)
    for t, kind, detail, body, srcport in classified:
        b = int(t // 5)
        buckets[b][kind] += 1
    if not any(any(buckets[b][k] for k in push_kinds) for b in buckets):
        print("  ✗ 全程无指数/4214/pushrealorder 推送")
    else:
        print(f"  {'时间':>8s}  index  4214  pushreal  hd31  hd10  其他")
        for b in sorted(buckets):
            c = buckets[b]
            idx = c.get("index_push", 0)
            snap = c.get("snapshot4214", 0)
            dxjl = c.get("pushrealorder", 0)
            h31 = c.get("hd31_table", 0)
            h10 = c.get("hd10_table", 0)
            oth = sum(v for k, v in c.items()
                      if k not in push_kinds and k not in ("hd31_table", "hd10_table"))
            mark = " ←推送" if snap or dxjl or idx else ""
            print(f"  {b*5:3d}-{b*5+5:3d}s  {idx:5d}  {snap:4d}  {dxjl:8d}  {h31:4d}  {h10:4d}  {oth:4d}{mark}")

    # ── 报告 3：客户端静默期的服务端推送（真·主动推送）──
    print(f"\n{'='*64}")
    print(f"【3】★核心：客户端静默期（≥{SILENCE_GAP}s 无请求）的服务端推送")
    print(f"{'='*64}")
    client_times = sorted(t for t, body, stream in client_frames)
    windows = []
    for i in range(1, len(client_times)):
        gap = client_times[i] - client_times[i - 1]
        if gap < SILENCE_GAP:
            continue
        t0, t1 = client_times[i - 1], client_times[i]
        window_pushes = [(t, kind, detail) for t, kind, detail, body, srcport
                         in classified if t0 < t < t1]
        if window_pushes:
            wc = Counter(k for _, k, _ in window_pushes)
            windows.append((t0, t1, gap, len(window_pushes), wc))
    if not windows:
        print("  ✗ 未发现静默期推送窗口（客户端一直发请求，无法判定推送）")
    else:
        print(f"发现 {len(windows)} 个静默期推送窗口\n")
        for t0, t1, gap, npk, wc in windows:
            parts = ", ".join(f"{kind_labels.get(k,k).split(' ')[0]}×{c}"
                              for k, c in wc.most_common())
            print(f"  [{t0:6.1f}s → {t1:6.1f}s] 静默 {gap:5.1f}s, "
                  f"推送 {npk} 帧: {parts}")

    # ── 报告 4：客户端订阅类请求 ──
    print(f"\n{'='*64}")
    print("【4】客户端订阅类请求（看『打开看盘/切票前后』的订阅）")
    print(f"{'='*64}")
    seen = set()
    order = []
    for t, body, stream in client_frames:
        label = classify_subscribe_request(body)
        if label is None:
            continue
        if label not in seen:
            seen.add(label)
            order.append((t, label))
    if not order:
        print("  ✗ 未识别到订阅类请求")
    for t, label in order:
        print(f"  [{t:6.1f}s] {label}")

    # ── 报告 5：4214 推送解码示例 ──
    snapshots = [(t, detail) for t, kind, detail, body, srcport in classified
                 if kind == "snapshot4214" and detail]
    print(f"\n{'='*64}")
    print("【5】4214 十档逐 tick 推送解码示例（前 10 条）")
    print(f"{'='*64}")
    if not snapshots:
        print("  ✗ 未抓到 4214 推送（需要 L2 账号 + 在看盘界面打开活跃股）")
    else:
        codes_seen = Counter()
        for t, d in snapshots:
            codes_seen[d.get("code", "?")] += 1
        print(f"  共 {len(snapshots)} 帧，涉及代码: "
              f"{', '.join(f'{c}×{n}' for c, n in codes_seen.most_common(5))}")
        print(f"  示例（前 10 条）：")
        for t, d in snapshots[:10]:
            print(f"    [{t:6.1f}s] {d.get('market','?')} {d.get('code','?')} "
                  f"价 {d.get('price',0):.3f} 量 {d.get('volume',0)} "
                  f"tick {d.get('tick_seq','?')}")

    # ── 报告 6：pushrealorder 推送解码示例 ──
    dxjl = [(t, detail) for t, kind, detail, body, srcport in classified
            if kind == "pushrealorder"]
    print(f"\n{'='*64}")
    print("【6】pushrealorder 短线精灵实时异动推送示例（前 10 条）")
    print(f"{'='*64}")
    if not dxjl:
        print("  ✗ 未抓到 pushrealorder 推送（需要短线精灵面板打开 + 盘中时段）")
    else:
        total_records = sum(d.get("count", 0) for _, d in dxjl)
        rate = total_records / max(tmax - tmin, 1) * 60
        print(f"  共 {len(dxjl)} 帧 / {total_records} 条异动记录，"
              f"约 {rate:.0f} 条/分钟")
        shown = 0
        for t, d in dxjl:
            for rec in d.get("records", []):
                if shown >= 10:
                    break
                print(f"    [{t:6.1f}s] {rec.get('市场','?')} {rec.get('代码','?')} "
                      f"{rec.get('异动类型','?')} 金额 {rec.get('金额',0)} "
                      f"涨幅 {rec.get('涨幅',0)}%")
                shown += 1
            if shown >= 10:
                break

    # ── dump 样本 ──
    _dump_samples(classified, pcap_path)

    print(f"\n{'='*64}")
    print(f"pcap: {pcap_path}")
    print(f"重分析: py tests/capture_kanpan_push.py --analyze-only \"{pcap_path}\"")
    print(f"{'='*64}")


def _dump_samples(classified, pcap_path):
    """按推送类型 dump 前 N 帧原始字节，供离线回归。"""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    samples: dict[str, list[bytes]] = defaultdict(list)
    for t, kind, detail, body, srcport in classified:
        if kind in ("snapshot4214", "pushrealorder", "subreal_ack") and body:
            if len(samples[kind]) < 50:
                samples[kind].append(body)
    if not samples:
        return
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n【dump】推送样本 → {PCAP_DIR}")
    for kind, frames in samples.items():
        path = os.path.join(PCAP_DIR, f"kanpan_push_{kind}_{ts}.bin")
        Path(path).write_bytes(b"\n--\n".join(frames))
        print(f"  kanpan_push_{kind}_{ts}.bin  {len(frames)} 帧 "
              f"{sum(len(f) for f in frames):,}B")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--iface", help="网卡编号（如 4=WLAN），不传则交互选择")
    ap.add_argument("--stop-file", metavar="PATH",
                    help="存在该文件时提前结束抓包（中途叫停用）")
    ap.add_argument("--analyze-only", metavar="PCAP")
    args = ap.parse_args()
    if args.analyze_only:
        analyze(args.analyze_only)
        return
    iface = args.iface or pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"kanpan_push_{ts}.pcap")
    capture(iface, args.duration, pcap_path, stop_file=args.stop_file)
    analyze(pcap_path)


if __name__ == "__main__":
    main()
