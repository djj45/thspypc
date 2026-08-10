#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端拉取全市场股票列表的请求/响应（8901 端口）。

目的：搞清 hexin 拉全量代码表的——
  - 请求模型：是真"翻页"(SortBegin 递增) 还是"递增 SortCount 重拉"(SortBegin=0 固定)？
  - 请求参数真值：CodeList 的市场码(17/22/33/151?)、DataType(199112 是否带 55?)
  - 连接模型：同一 TCP 连接翻页，还是每页换连接？连哪些 IP？
  - 响应结构：hd3.1 头格式（dc LE16/LE32? preamble 几字节?）

用法：
    1. 先彻底退出同花顺（任务管理器确认 hexin.exe 没了）
    2. 运行本脚本，选网卡
    3. 看到"开始抓包"后，立即启动同花顺并登录
       （代码表在启动后 ~10 秒内一次性拉取，错过就要重来）
    4. 等 60 秒自动结束，或 Ctrl+C 提前停
    5. 脚本自动分析所有 stock_list 请求/响应并给出结论

产物：captures_live/stock_list.pcap + 终端分析报告
"""
import os
import re
import struct
import subprocess
import sys
from collections import OrderedDict, defaultdict

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "stock_list.pcap")
DURATION = 60  # 重启同花顺 + 登录 + 拉代码表，30s 不够

MAGIC = b"\xfd\xfd\xfd\xfd"  # 见 protocol.py FRAME_MAGIC


def list_interfaces():
    """列网卡，返回 {编号: 描述}。"""
    r = subprocess.run(
        [TSHARK, "-D"], capture_output=True,
        encoding="gbk", errors="replace", timeout=15,
    )
    ifaces = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            ifaces[m.group(1)] = (m.group(2), m.group(3))
    return ifaces


def pick_interface():
    """交互选网卡，默认 WLAN。"""
    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未检测到网卡。")
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


def capture(iface_num):
    """抓全端口 DURATION 秒（同花顺所有 TCP 流量）。"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n开始抓包 {DURATION}s（全端口 TCP）...")
    print(">>> 现在立即启动同花顺并登录（代码表在启动后 ~10s 内一次性拉取）")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface_num, "-w", PCAP, "-a", f"duration:{DURATION}"],
            timeout=DURATION + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"抓包完成：{PCAP} ({size:,} bytes)")


# ── 分析逻辑 ──

def _tshark(y_filter, fields):
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


def _extract_kv(text: str) -> dict:
    """从文本里提取 stock_list 相关 key=value。

    响应文本里夹带二进制头（OrderList= 后跟乱码），简单按 '=' partition 会错位。
    这里对关心的字段做精确正则提取（行首匹配，值到 \\r/\\n 止）。
    """
    kv = {}
    keys = ["CodeList", "DataType", "SortType", "SortBy", "SortDir", "SortAppend",
            "SortBegin", "SortCount", "FuncPeriod", "DateTime", "LackTime",
            "pageid",
            "SortTotal", "SortTop", "SortDataCount", "SortDataFirst",
            "SortCalcProgress", "OrderError", "OrderList", "CodeListSize"]
    for k in keys:
        # 行首匹配 key=（前面是非字母数字字符或开头），值到 \r \n 止
        m = re.search(rf"(?:^|[^A-Za-z0-9_-]){k}=([^\r\n]*)", text)
        if m:
            kv[k] = m.group(1).strip()
    return kv


def _port_overview():
    """端口分布概览（确认 stock_list 走 8901，不是 9605/HTTP）。"""
    print(f"\n{'='*70}")
    print("【1】端口分布（同花顺连接的所有服务器端口）")
    print(f"{'='*70}")
    out = _tshark("tcp.payload",
                  ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"])
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
        print("  （未抓到任何 TCP 流量 — 可能没启动同花顺，或选错网卡）")
        return
    notes = {"8901": "← 行情/鉴权/代码表",
             "9601": "← 短线精灵", "9605": "← 板块服务",
             "443": "← HTTPS", "80": "← HTTP"}
    for port in sorted(port_ips.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
        ips = list(port_ips[port])[:3]
        print(f"  端口 {port}: {len(port_ips[port])} 个IP {ips} {notes.get(port,'')}")


def _collect_stocklist_traffic():
    """收集所有 stock_list 请求(DataType=199112) 和响应(SortTotal)。
    返回 (requests, responses)，元素都是 dict。"""
    # 请求：含 DataType=199112 的客户端发出帧
    req_out = _tshark('tcp.payload contains "DataType=199112"',
                      ["frame.number", "frame.time_relative", "ip.dst",
                       "tcp.dstport", "tcp.stream", "tcp.payload"])
    requests = []
    for ln in req_out.splitlines():
        p = ln.split("\t")
        if len(p) < 6:
            continue
        fr, t, dip, dport, stream, hx = p
        if not hx:
            continue
        payload = bytes.fromhex(hx.replace(":", ""))
        for body in _split_frames(payload):
            text = body.decode("gbk", errors="replace")
            if "DataType=199112" not in text or "SortCount" not in text:
                continue
            requests.append({
                "frame": fr, "t": float(t or 0), "dst": dip, "stream": stream,
                "kv": _extract_kv(text),
            })

    # 响应：含 SortTotal 的服务器返回帧
    resp_out = _tshark('tcp.payload contains "SortTotal"',
                       ["frame.number", "frame.time_relative", "ip.src",
                        "tcp.srcport", "tcp.stream", "tcp.payload"])
    responses = []
    for ln in resp_out.splitlines():
        p = ln.split("\t")
        if len(p) < 6:
            continue
        fr, t, sip, sport, stream, hx = p
        if not hx:
            continue
        payload = bytes.fromhex(hx.replace(":", ""))
        for body in _split_frames(payload):
            text = body.decode("gbk", errors="replace")
            if "SortTotal" not in text:
                continue
            responses.append({
                "frame": fr, "t": float(t or 0), "src": sip, "stream": stream,
                "kv": _extract_kv(text), "body": body,
            })

    requests.sort(key=lambda r: r["t"])
    responses.sort(key=lambda r: r["t"])
    return requests, responses


def _parse_hd31_stocklist_header(body: bytes):
    """解析 stock_list 响应里的 hd3.1 头（16-bit dc 变体）。
    一个 body 可能含多个 hd3.1（夹杂其他子帧），返回第一个 dc 合理且 bitrle 对齐的。
    返回 dict 或 None。"""
    search_from = 0
    while True:
        pos = body.find(b"hd3.1\x00", search_from)
        if pos < 0:
            return None
        base = pos + 6
        if len(body) < base + 10:
            return None
        dc = struct.unpack("<H", body[base:base+2])[0]
        flag = struct.unpack("<H", body[base+2:base+4])[0]
        extra = struct.unpack("<H", body[base+4:base+6])[0]
        hs = struct.unpack("<H", body[base+6:base+8])[0]
        fc = struct.unpack("<H", body[base+8:base+10])[0]
        info = {"dc": dc, "flag": flag, "extra": extra, "hs": hs, "fc": fc,
                "hd_pos": pos}
        # 字段表后 preamble 8B，再 BitRLE 头(BE32=dc*hs)
        bitrle_off = base + 10 + fc * 4 + 8
        if len(body) >= bitrle_off + 4:
            info["bitrle_head"] = struct.unpack(">I", body[bitrle_off:bitrle_off+4])[0]
            info["expect_dc_hs"] = dc * hs
            info["bitrle_match"] = info["bitrle_head"] == info["expect_dc_hs"]
        # stock_list 响应特征：flag=0x0100 且 dc 合理（<6000）且 bitrle 对齐
        if flag == 0x0100 and 0 < dc < 6000 and info.get("bitrle_match"):
            return info
        search_from = pos + 6  # 找下一个 hd3.1


def _report_requests(requests):
    """报告 stock_list 请求：按连接分组，展示参数真值。"""
    print(f"\n{'='*70}")
    print("【2】stock_list 请求（DataType=199112）— 参数真值 + 连接模型")
    print(f"{'='*70}")
    if not requests:
        print("  ✗ 未抓到任何 stock_list 请求")
        print("    可能原因：① 没重启同花顺（代码表只在启动时拉）；② 选错网卡；③ 抓包太短")
        return {}

    by_conn = OrderedDict()
    for r in requests:
        by_conn.setdefault((r["dst"], r["stream"]), []).append(r)

    print(f"\n  共 {len(requests)} 个请求，{len(by_conn)} 个连接（dst_ip, tcp_stream）:")
    for (dip, stream), reqs in by_conn.items():
        t0, t1 = reqs[0]["t"], reqs[-1]["t"]
        same_conn = "★ 同连接多次请求" if len(reqs) > 1 else "(单次)"
        print(f"\n  ▶ dst={dip} stream={stream}：{len(reqs)} 个请求，"
              f"时间 {t0:.2f}s~{t1:.2f}s（跨度 {t1-t0:.2f}s）{same_conn}")
        for r in reqs:
            kv = r["kv"]
            print(f"    帧{r['frame']} t={r['t']:.3f}s")
            print(f"      CodeList   = {kv.get('CodeList','?')!r}")
            print(f"      DataType   = {kv.get('DataType','?')!r}")
            print(f"      SortBy/Dir = {kv.get('SortBy','?')} / {kv.get('SortDir','?')} "
                  f"(Append={kv.get('SortAppend','?')})")
            print(f"      ★ SortBegin = {kv.get('SortBegin','?')!r}   "
                  f"★ SortCount = {kv.get('SortCount','?')!r}")
    return by_conn


def _report_responses(responses, by_conn):
    """报告响应：SortTotal/SortDataCount + hd3.1 头。"""
    print(f"\n{'='*70}")
    print("【3】stock_list 响应（SortTotal）— 分页元数据 + hd3.1 头")
    print(f"{'='*70}")
    if not responses:
        print("  ✗ 未抓到含 SortTotal 的响应")
        return

    # 按连接分组，和请求配对
    resp_by_conn = defaultdict(list)
    for r in responses:
        resp_by_conn[(r["src"], r["stream"])].append(r)

    for (sip, stream), resps in resp_by_conn.items():
        print(f"\n  ▶ src={sip} stream={stream}：{len(resps)} 个响应")
        for r in resps:
            kv = r["kv"]
            hd = _parse_hd31_stocklist_header(r["body"])
            print(f"    帧{r['frame']} t={r['t']:.3f}s")
            print(f"      ★ SortTotal={kv.get('SortTotal','?')}  "
                  f"SortBegin={kv.get('SortBegin','?')}  "
                  f"SortCount={kv.get('SortCount','?')}  "
                  f"SortDataCount={kv.get('SortDataCount','?')}")
            oe = kv.get("OrderError", "")
            if oe:
                print(f"      ⚠ OrderError={oe!r}")
            if hd:
                match_mark = "✓" if hd.get("bitrle_match") else "✗"
                print(f"      hd3.1 头: dc={hd['dc']} flag={hd['flag']:#06x} "
                      f"hs={hd['hs']} fc={hd['fc']} "
                      f"| bitrle头={hd.get('bitrle_head','?')} "
                      f"vs dc*hs={hd.get('expect_dc_hs','?')} {match_mark}")
            else:
                print(f"      hd3.1 头: （无 hd3.1 标记，可能 hd1.0 或文本错误）")


def _report_connections():
    """8901 SYN 总览：hexin 连了哪些 IP、什么时候。"""
    print(f"\n{'='*70}")
    print("【4】8901 TCP 连接（SYN）总览")
    print(f"{'='*70}")
    out = _tshark("tcp.port==8901 and tcp.flags.syn==1 and tcp.flags.ack==0",
                  ["frame.number", "frame.time_relative", "ip.dst", "tcp.stream"])
    conns = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 4:
            conns.append((p[0], float(p[1] or 0), p[2], p[3]))
    conns.sort(key=lambda x: x[1])
    ip_count = defaultdict(int)
    for _, _, dip, _ in conns:
        ip_count[dip] += 1
    if not conns:
        print("  ✗ 未抓到 8901 SYN（同花顺可能没连 8901，或走的是已建立的长连接）")
        return
    print(f"\n  共 {len(conns)} 个 SYN，{len(ip_count)} 个目标 IP：")
    for ip, n in sorted(ip_count.items(), key=lambda x: -x[1]):
        print(f"    {ip}: {n} 次连接")
    print(f"\n  SYN 时间线（前 20）:")
    for fr, t, dip, stream in conns[:20]:
        print(f"    帧{fr} t={t:.3f}s dst={dip} stream={stream}")


def _conclusions(requests, by_conn):
    """关键结论汇总。"""
    print(f"\n{'='*70}")
    print("【结论】")
    print(f"{'='*70}")
    if not requests:
        print("  （无请求数据，无法下结论 — 请按提示重启同花顺重抓）")
        return

    # 1. 连接模型
    multi_conn = [k for k, v in by_conn.items() if len(v) > 1]
    print(f"  · 连接模型：{len(by_conn)} 个连接发了 stock_list 请求")
    if multi_conn:
        print(f"    → 同连接多次请求: {multi_conn}  ← hexin 在同一条连接上拉取")

    # 1.5 市场拆分：每个连接处理哪些市场（看初始请求的 CodeList）
    print(f"\n  · 市场拆分（每个连接的初始 CodeList）:")
    for (dip, stream), reqs in by_conn.items():
        # 第一个请求的 CodeList（通常是空的市场列表）
        first_cl = reqs[0]["kv"].get("CodeList", "?")
        # 提取市场码
        markets = re.findall(r"^(\d+)\(\)", first_cl)
        if not markets:
            markets = re.findall(r"(\d+)\(", first_cl)
        print(f"    {dip} stream={stream}: 初始 CodeList={first_cl[:50]!r} → 市场 {markets}")

    # 2. 翻页模型：SortBegin 是否恒 0，SortCount 是否递增（按连接分别看）
    print(f"\n  · 翻页模型（按连接）:")
    for (dip, stream), reqs in by_conn.items():
        sbs = [r["kv"].get("SortBegin", "") for r in reqs]
        scs = [r["kv"].get("SortCount", "") for r in reqs]
        dts = [r["kv"].get("DataType", "")[:15] for r in reqs]
        print(f"    {dip} stream={stream}:")
        print(f"      SortBegin: {sbs}")
        print(f"      SortCount: {scs}")
        print(f"      DataType : {dts}")
        if set(sbs) == {"0"} and len(set(scs)) > 1:
            print(f"      ★ SortBegin 恒 0 + SortCount 递增 = 「重拉全量」模型（非真翻页）")

    # 3. 全局参数真值
    # 只看 DataType=199112 的请求（排除后期切换到 7,49,... 行情查询的）
    dt112 = [r for r in requests if "199112" in r["kv"].get("DataType", "")]
    cls_set = set(r["kv"].get("CodeList", "") for r in dt112)
    # 从空 CodeList（17();22();...）里提取市场码
    empty_cls = [c for c in cls_set if re.match(r"^(\d+\(\);)+$", c)]
    print(f"\n  · 请求参数真值（仅 DataType=199112 的请求）:")
    print(f"    空 CodeList 样本: {empty_cls}")
    # 合并所有空 CodeList 里的市场码
    all_markets = set()
    for c in empty_cls:
        all_markets.update(re.findall(r"(\d+)\(\)", c))
    print(f"    出现的市场码: {sorted(all_markets)}")
    print(f"    （当前 protocol.py 默认市场: 17,33,151）")
    if 22 in all_markets and 33 not in all_markets:
        print(f"    ⚠ 真实用 22 表示深市，代码里写的 33 是错的！")
    elif 22 in all_markets and 33 in all_markets:
        print(f"    ★ 22 和 33 都出现 — 可能 22=深A主板, 33=深市另一类（待确认）")
    dt_set = set(r["kv"].get("DataType", "") for r in dt112)
    has_55 = any(",55" in d for d in dt_set)
    print(f"    DataType 取值: {dt_set}")
    if not has_55:
        print(f"    ★ 真实 DataType 不带 ,55（代码多带了）")


def analyze():
    """分析 pcap，聚焦 stock_list 请求/响应。"""
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return

    _port_overview()
    requests, responses = _collect_stocklist_traffic()
    by_conn = _report_requests(requests)
    _report_responses(responses, by_conn)
    _report_connections()
    _conclusions(requests, by_conn)

    print(f"\npcap 已保存: {PCAP}")
    print(f"如需深入分析，用 Wireshark 打开，Follow TCP Stream 看具体内容")
    print(f"或运行离线分析: py tests/analyze_pcap_pagination.py")


def main():
    print("=" * 70)
    print("抓同花顺 PC 股票列表请求（聚焦 stock_list 分页/参数真值）")
    print("=" * 70)
    iface_num, desc = pick_interface()
    print(f"\n选用网卡 {iface_num}: {desc}")
    capture(iface_num)
    analyze()


if __name__ == "__main__":
    raise SystemExit(main())
