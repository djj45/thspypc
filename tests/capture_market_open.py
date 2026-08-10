#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端开盘瞬间的批量请求 + 盘中实时推送（8901 + 9601 全流量）。

两个目标：
  A. 开盘批量请求 7000 股 —— 客户端启动时如何一次性拉全市场代码表 +
     行情快照（subreal×8 订阅 + 特殊 CodeList + init 启动序列）
  B. 盘中实时推送 —— 9601 pushrealorder 异动推送的频率、负载、代码分布

抓的是**被动监听 hexin.exe 的真实流量**，不需要账号/THSClient。

⚠ 必须盘中运行（周一~周五 9:25-15:00），否则没有异动推送。
   推荐 9:24 左右启动脚本 + 同花顺，覆盖 9:25 集合竞价启动序列 +
   9:30 开盘后的实时推送（默认 duration=180s）。

用法：
    uv run python tests/capture_market_open.py                 # 默认 180s
    uv run python tests/capture_market_open.py --duration 300  # 抓 5 分钟
    uv run python tests/capture_market_open.py --iface 4       # 指定网卡
    uv run python tests/capture_market_open.py --analyze-only  # 只分析现有 pcap（不抓包）

操作步骤（严格按顺序）：
    1. 先彻底退出同花顺（任务管理器确认 hexin.exe 没了）
    2. 9:24 左右运行本脚本，选网卡后开始抓包
    3. 看到「开始抓包」后，立即启动同花顺并登录
       （代码表/快照在启动后 ~10s 内一次性拉取，错过就要重来）
    4. 登录后切到「短线精灵」页面，滚动几下（触发推送接收）
    5. 保持同花顺在前台、短线精灵页面可见（不要最小化，否则可能停推）
    6. 等待自动结束，脚本出两段分析报告（A 批量请求 + B 实时推送）

产物：captures_live/market_open.pcap + 终端两段分析报告
"""
import argparse
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

# 用户指定的 Wireshark 便携版路径（4.4.7，含 Npcap 1.50）
WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "market_open.pcap")

# 帧分隔符（8901/9601 通用，见 protocol.py:29 FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"）
MAGIC = b"\xfd\xfd\xfd\xfd"

# 服务器清单（抓包时标注哪些是已知行情/短线精灵 IP）
MARKET_HOSTS = {
    "122.9.202.190", "122.9.125.190", "116.63.108.136",
    "8.134.98.163", "121.37.31.87", "8.138.46.177", "8.145.212.55",
}
REALORDER_HOSTS = {"106.14.65.90"}  # 9601 短线精灵（抓包确认）


# =============================================================================
# 标准件（与 capture_hexin_start.py / capture_stock_list.py 逐字一致）
# =============================================================================

def list_interfaces():
    """列网卡，返回 {编号: (设备, 描述)}。"""
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    ifaces = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            ifaces[m.group(1)] = (m.group(2), m.group(3))
    return ifaces


def pick_interface():
    """交互选网卡，默认 WLAN（带 ← 推荐 标记）。"""
    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未检测到网卡")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), None)
    if not default:
        default = next((n for n, (_, d) in ifaces.items()
                        if "WLAN" in d or "以太网" in d), list(ifaces.keys())[0])
    while True:
        choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
        if choice in ifaces:
            return choice, ifaces[choice][1]


def capture(iface, duration):
    """抓 8901+9601 全流量 duration 秒。"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*70}")
    print(f"开始抓包 {duration}s（8901 + 9601，网卡 {iface}）")
    print(f"{'='*70}")
    print(">>> 现在立即：")
    print("    1. 启动同花顺并登录（启动序列在登录后 ~10s 内拉代码表/快照）")
    print("    2. 登录后切到「短线精灵」页面，滚动几下")
    print("    3. 保持短线精灵页面可见（别最小化！）")
    print("-" * 70)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp port 8901 or tcp port 9601",
             "-w", PCAP, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"\n抓包完成：{PCAP} ({size:,} bytes)")


def _tshark(y_filter, fields):
    """跑 tshark 提取字段，返回解码后的 stdout 文本。"""
    cmd = [TSHARK, "-r", PCAP, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _split_frames(payload: bytes):
    """把一个 TCP payload 切成 [body 列表]（每帧去掉 8B ASCII 长度头）。"""
    out = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            out.append(sub[8:])
    return out


# =============================================================================
# 分析逻辑
# =============================================================================

def _is_8901_heartbeat(body: bytes) -> bool:
    """判断 8901 心跳帧：subtype hdr[7:11]==12 00 03 00，或文本含 tsi0=/tc=。"""
    if len(body) < 11:
        return False
    if body[7:11] == b"\x12\x00\x03\x00":
        return True
    text = body.decode("gbk", errors="replace")
    return ("tsi0=" in text) or ("tc=" in text and "10," in text)


def _is_9601_heartbeat(body: bytes) -> bool:
    """判断 9601 心跳帧：5 字节 body，[0]=0x09，[4]=0x07。"""
    return len(body) == 5 and body[0] == 0x09 and body[4] == 0x07


def _classify_request(body: bytes):
    """把一个客户端发出的帧分类。返回类别字符串（或 None=未识别/心跳）。"""
    if _is_8901_heartbeat(body) or _is_9601_heartbeat(body):
        return "heartbeat"
    text = body.decode("gbk", errors="replace")
    if "method=pushrealorder" in text:
        return "pushrealorder-ack"  # 客户端极少主动发，一般忽略
    if "method=subrealorder" in text:
        return "subrealorder(9601订阅)"
    if "method=subreal" in text:
        return "subreal(8901订阅)"
    if "method=qurealorder" in text:
        return "qurealorder(历史查询)"
    if "StockLinkVer=" in text and "C-Version=" in text:
        return "init(启动初始化)"
    if "DataType=199112" in text or "SortBy=199112" in text:
        return "stock_list(代码表翻页)"
    if "CodeList=" in text:
        # 细分 CodeList 请求
        if "1B0987" in text:
            return "CodeList-1B0987(触发码)"
        if "PushField=" in text:
            return "CodeList-PushField(快照)"
        if "DataType=" in text:
            return "CodeList(行情查询)"
        return "CodeList(其他)"
    if "StockNameVer=" in text or "upstockname" in text.lower():
        return "upstockname(名称同步)"
    if body[:1] == b"\x09":
        return "8901-其他(0x09头)"
    return "其他/未识别"


def _section_overview():
    """【0】连接概览。"""
    print(f"\n{'='*70}")
    print("【0】连接概览（8901 + 9601）")
    print(f"{'='*70}")
    # 端口/IP 分布
    out = _tshark("tcp.payload", ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"])
    port_ips = defaultdict(set)
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) < 4:
            continue
        src_ip, src_port, dst_ip, dst_port = p
        if dst_port and dst_port != "0":
            port_ips[dst_port].add(dst_ip)
        if src_port and src_port != "0":
            port_ips[src_port].add(src_ip)
    if not port_ips:
        print("  ✗ 未抓到任何 TCP 流量 — 可能没启动同花顺，或选错网卡")
        return
    notes = {"8901": "← 行情/鉴权/代码表/快照", "9601": "← 短线精灵"}
    for port in sorted(port_ips.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
        ips = sorted(port_ips[port])
        known = []
        for ip in ips:
            tag = ""
            if ip in MARKET_HOSTS:
                tag = "(已知行情)"
            elif ip in REALORDER_HOSTS:
                tag = "(已知短线精灵)"
            known.append(f"{ip}{tag}")
        print(f"  端口 {port}: {len(ips)} 个IP {known[:5]} {notes.get(port, '')}")

    # SYN 时间线
    out = _tshark("tcp.flags.syn==1 and tcp.flags.ack==0",
                  ["frame.number", "frame.time_relative", "ip.dst", "tcp.dstport", "tcp.stream"])
    conns = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 5:
            conns.append((p[0], float(p[1] or 0), p[2], p[3], p[4]))
    conns.sort(key=lambda x: x[1])
    by_port = defaultdict(int)
    for _, _, _, dport, _ in conns:
        by_port[dport] += 1
    if conns:
        print(f"\n  共 {len(conns)} 个 SYN：8901={by_port.get('8901',0)} "
              f"9601={by_port.get('9601',0)}（看启动时是否并发连多条）")
        ip_n = Counter(c[2] for c in conns)
        for ip, n in ip_n.most_common():
            tag = " 已知行情" if ip in MARKET_HOSTS else \
                  (" 已知短线精灵" if ip in REALORDER_HOSTS else "")
            print(f"    {ip}{tag}: {n} 次连接")
        print(f"\n  SYN 时间线（前 20）:")
        for fr, t, dip, dport, stream in conns[:20]:
            print(f"    帧{fr} t={t:.3f}s {dip}:{dport} stream={stream}")
    else:
        print("  ✗ 未抓到 SYN（可能走了已建立的长连接）")


def _collect_client_frames():
    """收集所有客户端发出的帧（dstport 8901/9601）。
    返回 [(frame, t, dst, dport, stream, body), ...]。"""
    out = _tshark("(tcp.dstport==8901 or tcp.dstport==9601) and tcp.payload",
                  ["frame.number", "frame.time_relative", "ip.dst",
                   "tcp.dstport", "tcp.stream", "tcp.payload"])
    frames = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) < 6:
            continue
        fr, t, dip, dport, stream, hx = p
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        for body in _split_frames(payload):
            frames.append((fr, float(t or 0), dip, dport, stream, body))
    return frames


def _collect_server_frames():
    """收集所有服务器返回的帧（srcport 8901/9601）。"""
    out = _tshark("(tcp.srcport==8901 or tcp.srcport==9601) and tcp.payload",
                  ["frame.number", "frame.time_relative", "ip.src",
                   "tcp.srcport", "tcp.stream", "tcp.payload"])
    frames = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) < 6:
            continue
        fr, t, sip, sport, stream, hx = p
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        for body in _split_frames(payload):
            frames.append((fr, float(t or 0), sip, sport, stream, body))
    return frames


def _section_batch_requests(client_frames):
    """A 段：开盘批量请求（7000 股）。"""
    print(f"\n{'='*70}")
    print("A 段：开盘批量请求（7000 股启动序列 + 代码表 + 快照）")
    print(f"{'='*70}")

    # 【A1】启动序列帧统计（过滤心跳）
    print(f"\n  【A1】启动序列帧统计（已过滤心跳）")
    real = [f for f in client_frames if _classify_request(f[5]) != "heartbeat"]
    n_hb = len(client_frames) - len(real)
    cats = Counter(_classify_request(f[5]) for f in real)
    if not real:
        print("    ✗ 未抓到客户端请求")
        print("      可能原因：① 没重启同花顺（启动序列只在登录后 ~10s 拉）")
        print("                ② 选错网卡；③ 抓包太短；④ 同花顺没连 8901/9601")
        return
    print(f"    客户端发出 {len(client_frames)} 帧（心跳 {n_hb}，实质 {len(real)}）:")
    for cat, n in cats.most_common():
        print(f"      {n:>4} × {cat}")

    # 【A2】批量请求结构（挑代表性请求打印字段）
    print(f"\n  【A2】批量请求结构（代表性请求的字段真值）")
    # 优先展示：触发码 / 代码表翻页 / 快照 / init 各一个
    shown_cats = set()
    samples = []
    for fr, t, dip, dport, stream, body in real:
        cat = _classify_request(body)
        if cat in ("heartbeat",) or cat in shown_cats:
            continue
        samples.append((cat, fr, t, dip, stream, body))
        shown_cats.add(cat)
        if len(samples) >= 6:
            break
    for cat, fr, t, dip, stream, body in samples:
        text = body.decode("gbk", errors="replace")
        print(f"\n    帧{fr} t={t:.3f}s dst={dip} stream={stream} [{cat}]")
        # 打印关键字段（截断超长的 CodeList）
        for key in ["CodeList", "DataType", "SortBy", "SortBegin", "SortCount",
                    "FuncPeriod", "PushField", "pageid", "market", "method",
                    "action", "C-Version", "C-Modules", "MarketCode"]:
            m = re.search(rf"(?:^|[^A-Za-z0-9_-]){key}=([^\r\n]*)", text)
            if m:
                val = m.group(1).strip()
                if len(val) > 80:
                    val = val[:80] + f"…({len(val)} chars)"
                print(f"      {key} = {val!r}")
    print("\n    ★ 看点：CodeList 是否为空市场码（如 16();17();=请求全市场）、"
          "DataType 真值、是否翻页（SortBegin>0 / 多次请求 SortCount 递增）")

    # 【A3】连接模型（按 dst,stream 分组）
    print(f"\n  【A3】连接模型（批量请求走几条连接 / 是否复用）")
    by_conn = defaultdict(list)
    for fr, t, dip, dport, stream, body in real:
        cat = _classify_request(body)
        if cat != "heartbeat":
            by_conn[(dip, stream)].append((t, cat))
    for (dip, stream), items in sorted(by_conn.items(), key=lambda x: x[1][0][0]):
        t0, t1 = items[0][0], items[-1][0]
        cat_set = Counter(c for _, c in items)
        print(f"    {dip} stream={stream}: {len(items)} 帧，"
              f"{t0:.2f}s~{t1:.2f}s（跨度 {t1-t0:.2f}s）")
        for c, n in cat_set.most_common():
            print(f"        {n} × {c}")


def _section_batch_responses(server_frames):
    """【A4】响应规模：hd3.1/hd1.0 响应，dc 记录数。"""
    print(f"\n  【A4】响应规模（全市场代码表是否一次性返回 dc≈7400）")
    big_dc = []  # dc>=500 的大响应
    resp_n = Counter()
    for fr, t, sip, sport, stream, body in server_frames:
        if b"hd3.1\x00" in body:
            resp_n["hd3.1"] += 1
            pos = body.find(b"hd3.1\x00") + 6
            dc = _try_parse_dc(body, pos)
            if dc and dc >= 500:
                big_dc.append((fr, t, sip, sport, stream, dc))
        elif b"hd1.0" in body:
            resp_n["hd1.0"] += 1
    # 收集所有 dc 值（不只大响应），看分布
    all_dc = Counter()
    for fr, t, sip, sport, stream, body in server_frames:
        if b"hd3.1\x00" in body:
            pos = body.find(b"hd3.1\x00") + 6
            dc = _try_parse_dc(body, pos)
            if dc:
                all_dc[dc] += 1
    print(f"    服务器响应帧：hd3.1={resp_n['hd3.1']} hd1.0={resp_n['hd1.0']}")
    if all_dc:
        dist = ", ".join(f"dc={d}×{n}" for d, n in all_dc.most_common(6))
        print(f"    hd3.1 dc 分布：{dist}")
    if big_dc:
        big_dc.sort(key=lambda x: -x[5])
        print(f"    ★ 大响应（dc≥500，可能是全市场代码表/快照）共 {len(big_dc)} 个:")
        for fr, t, sip, sport, stream, dc in big_dc[:10]:
            print(f"      帧{fr} t={t:.3f}s {sip}:{sport} stream={stream} dc={dc}")
        if big_dc[0][5] >= 5000:
            print(f"    ✓ 发现 dc≈{big_dc[0][5]} 的大帧 → 全市场代码表一次性返回")
        else:
            print(f"    ⚠ 最大 dc={big_dc[0][5]}，未见单次全市场帧（可能分批/翻页）")
    else:
        # 看是否有小 dc（如 40）= 翻页模式，而非解析失败
        if all_dc:
            print(f"    （无 dc≥500 大帧；均为小 dc → 走分页/翻页拉取，非一次性大帧）")
        else:
            print("    ✗ 未发现 dc≥500 的大响应（可能响应在抓包窗口外，或解析失败）")


def _try_parse_dc(body: bytes, pos: int):
    """从 hd3.1 头解析 dc（记录数），返回单个可信值或 None。

    hd3.1 头有两种变体，按可信度优先判断：
      1. LE16 dc + LE16 flag：flag==0x0100 是 stock_list 分页响应的可靠标志
         （见 protocol.py _parse_stock_list_hd31_variant，dc 合理范围 <6000）
      2. LE32 dc：批量行情（unk=0x18）变体，dc 可达 ~7400

    不能裸读 LE32 —— 当真实结构是「LE16+flag=0x0100」时，flag 字节会
    被并进 dc 的高位，产生 dc=16xxxxxx 的天文数字（实测误读 16777257）。
    所以先按 flag=0x0100 校验，通过才采信 LE16；否则才退回 LE32。
    """
    if len(body) < pos + 4:
        return None
    dc16 = struct.unpack("<H", body[pos:pos + 2])[0]
    flag = struct.unpack("<H", body[pos + 2:pos + 4])[0]
    if flag == 0x0100 and 0 < dc16 < 6000:
        return dc16
    dc32 = struct.unpack("<I", body[pos:pos + 4])[0]
    # 全市场代码表 / 批量行情 dc 合理范围 < 10000
    if 0 < dc32 < 10000:
        return dc32
    return None


def _section_pushes(server_frames):
    """B 段：盘中实时推送。"""
    print(f"\n{'='*70}")
    print("B 段：盘中实时推送（9601 pushrealorder）")
    print(f"{'='*70}")

    pushes = []
    for fr, t, sip, sport, stream, body in server_frames:
        if sport == "9601" and b"pushrealorder" in body:
            pushes.append((fr, t, body))

    # 【B1】推送帧统计
    print(f"\n  【B1】pushrealorder 帧统计")
    if not pushes:
        print("    ✗ 未抓到 pushrealorder 推送帧")
        print("      可能原因：① 非交易日/非盘中（必须 9:30-15:00）")
        print("                ② 同花顺没切到短线精灵页面")
        print("                ③ 同花顺被最小化（停推）")
        print("                ④ 选错网卡；⑤ 未订阅（subrealorder）")
        return
    sizes = [len(b) for _, _, b in pushes]
    times = [t for _, t, _ in pushes]
    total_bytes = sum(sizes)
    t0, t1 = min(times), max(times)
    span = t1 - t0
    print(f"    ★ 抓到 {len(pushes)} 个推送帧（{total_bytes:,} 字节）")
    print(f"    帧大小：min={min(sizes)} avg={sum(sizes)//len(sizes)} max={max(sizes)}")
    print(f"    时间跨度：{t0:.1f}s ~ {t1:.1f}s（{span:.1f}s）")
    if span > 0:
        print(f"    推送频率：≈ {len(pushes) / span * 60:.0f} 帧/分钟")

    # 【B2】异动代码分布
    print(f"\n  【B2】异动代码分布（推送帧里提取的股票代码）")
    codes = Counter()
    for _, _, body in pushes:
        # Format A: 0x21 + 6B ASCII（0/3/6 开头）
        for m in re.finditer(rb"\x21([036]\d{5})", body):
            codes[m.group(1).decode("ascii", errors="replace")] += 1
        # Format B: 0x2d + 1-2 字节 + 6B ASCII
        for m in re.finditer(rb"\x2d.{1,2}([036]\d{5})", body):
            codes[m.group(1).decode("ascii", errors="replace")] += 1
    if codes:
        print(f"    共 {sum(codes.values())} 次代码出现，唯一 {len(codes)} 只：")
        print(f"    出现最多的 15 个代码：")
        for code, n in codes.most_common(15):
            print(f"      {code}: {n} 次")
    else:
        print("    （未提取到代码 — 推送帧可能用了新格式，看 pcap 原文）")


def _section_subscribe_confirm(client_frames):
    """【B3】9601 订阅确认。"""
    print(f"\n  【B3】9601 订阅确认（subrealorder 订阅了哪些 market）")
    sub_markets = Counter()
    sub_actions = Counter()
    for fr, t, dip, dport, stream, body in client_frames:
        text = body.decode("gbk", errors="replace")
        if "method=subrealorder" not in text:
            continue
        for m in re.finditer(rb"action=(\w+)", body):
            sub_actions[m.group(1).decode("ascii", errors="replace")] += 1
        for m in re.finditer(rb"market=(\w+)", body):
            sub_markets[m.group(1).decode("ascii", errors="replace")] += 1
    if sub_markets:
        print(f"    subrealorder 订阅：")
        for mk, n in sub_markets.most_common():
            note = {"16": "沪", "32": "深", "151": "北交所", "48": "板块"}.get(mk, "")
            print(f"      market={mk} ({note}): {n} 次")
        print(f"    action 分布：{dict(sub_actions)}")
    else:
        print("    ✗ 未抓到 subrealorder 订阅（可能已订阅过/走了缓存）")


def _conclusions(client_frames, server_frames):
    print(f"\n{'='*70}")
    print("【结论】")
    print(f"{'='*70}")
    real = [f for f in client_frames if _classify_request(f[5]) != "heartbeat"]
    cats = Counter(_classify_request(f[5]) for f in real)
    has_trigger = any("1B0987" in c for c in cats)
    has_init = any("init" in c for c in cats)
    n_codetable = cats.get("stock_list(代码表翻页)", 0)
    print(f"  · 启动序列：subreal订阅={cats.get('subreal(8901订阅)',0)} "
          f"subrealorder={cats.get('subrealorder(9601订阅)',0)} "
          f"init={cats.get('init(启动初始化)',0)} "
          f"触发码={cats.get('CodeList-1B0987(触发码)',0)} "
          f"代码表翻页={n_codetable}")

    # 代码表拉取策略：两种模式择一判断（不写死）
    #   模式A「init 一次性大帧」：抓包窗口含 init + 触发码 + 服务器 dc≥5000 大响应
    #   模式B「DataType=199112 翻页」：客户端发 stock_list 分页请求，每页 dc=SortCount
    big_dc = []
    for fr, t, sip, sport, stream, body in server_frames:
        if b"hd3.1\x00" in body:
            pos = body.find(b"hd3.1\x00") + 6
            dc = _try_parse_dc(body, pos)
            if dc and dc >= 5000:
                big_dc.append(dc)
    if big_dc:
        print(f"  · 全市场代码【一次性返回】：服务器 dc≥5000 大帧（max dc={max(big_dc)}，"
              f"{len(big_dc)} 帧）")
        if has_trigger and has_init:
            print(f"    → 触发链：init + 触发码 1B0987 → 服务器一次性推回全市场代码表")
        else:
            print(f"    → 服务器主动推送全市场代码表")
    elif n_codetable > 0:
        # 翻页模式：从 stock_list 请求里提取真实 SortBegin/SortCount 序列
        sbs, scs = [], []
        for fr, t, dip, dport, stream, body in client_frames:
            text = body.decode("gbk", errors="replace")
            if "DataType=199112" not in text or "SortCount" not in text:
                continue
            msb = re.search(r"SortBegin=([^\r\n]*)", text)
            msc = re.search(r"SortCount=([^\r\n]*)", text)
            if msb:
                sbs.append(msb.group(1))
            if msc:
                scs.append(msc.group(1))
        print(f"  · 全市场代码【分页拉取】：DataType=199112，{n_codetable} 次请求")
        if scs:
            print(f"    → 每页 SortCount={scs[0]}（{'固定' if len(set(scs))==1 else '变化'}: {scs}）")
        if sbs:
            # 判断翻页方向（递增/递减/恒0）
            nums = []
            for s in sbs:
                try:
                    nums.append(int(s))
                except ValueError:
                    pass
            if len(nums) >= 2:
                if all(x == 0 for x in nums):
                    direction = "恒 0（重拉全量，非真翻页）"
                else:
                    # 看非零部分判断方向（首次请求 SortBegin 常为 0，忽略它）
                    nonzero = [x for x in nums if x != 0]
                    if len(nonzero) >= 2 and nonzero[-1] >= nonzero[0]:
                        direction = "递增（正序翻页）"
                    elif len(nonzero) >= 2:
                        direction = "递减（倒序翻页，从后往前）"
                    else:
                        direction = "仅 1 个非零值，方向不明"
                print(f"    → SortBegin 序列: {sbs} → {direction}")
    else:
        print(f"  · 全市场代码：（未见 init 大帧也未见 199112 翻页，"
              f"可能代码表在抓包窗口外已拉完）")

    # 推送
    pushes = [f for f in server_frames if f[3] == "9601" and b"pushrealorder" in f[5]]
    print(f"  · 实时推送：{len(pushes)} 帧 pushrealorder")
    if pushes:
        times = [t for _, t, _, _, _, _ in pushes]
        span = max(times) - min(times)
        if span > 0:
            print(f"    → 频率 ≈ {len(pushes) / span * 60:.0f} 帧/分钟")


def analyze():
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return
    _section_overview()
    client_frames = _collect_client_frames()
    server_frames = _collect_server_frames()
    _section_batch_requests(client_frames)
    _section_batch_responses(server_frames)
    _section_pushes(server_frames)
    _section_subscribe_confirm(client_frames)
    _conclusions(client_frames, server_frames)
    print(f"\npcap 已保存：{PCAP}")
    print(f"用 Wireshark 打开可 Follow TCP Stream 看具体内容")


def main():
    ap = argparse.ArgumentParser(
        description="抓开盘批量请求 + 盘中实时推送（8901 + 9601）")
    ap.add_argument("--duration", type=int, default=180,
                    help="抓包时长（秒），默认 180（覆盖 9:25-9:30）")
    ap.add_argument("--iface", default=None,
                    help="网卡编号（默认交互选择 WLAN）")
    ap.add_argument("--analyze-only", action="store_true",
                    help="只分析现有 pcap 不抓包（盘前调试用）")
    args = ap.parse_args()
    print("=" * 70)
    print("抓同花顺开盘批量请求（7000 股）+ 盘中实时推送")
    print("=" * 70)
    if args.analyze_only:
        analyze()
        return
    iface = args.iface
    desc = ""
    if iface is None:
        iface, desc = pick_interface()
        print(f"\n选用网卡 {iface}: {desc}")
    capture(iface, args.duration)
    analyze()


if __name__ == "__main__":
    raise SystemExit(main())
