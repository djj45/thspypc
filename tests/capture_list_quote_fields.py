#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 list_quotes（个股列表行情）请求/响应，逆向 DataType 字段编号。

用 Wireshark dumpcap 抓 8901 端口，提取每个含 ``DataType=`` 的请求帧，
打印它的字段列表 + 对应的 hd 响应帧原始字节（供离线解析对照）。

目的：你想把「成交额」加进表头，但不知道 dt 编号——运行本脚本后，
在同花顺里查看含成交额的列表，脚本会打出 hexin 实际发的 DataType 列表，
里面的编号就是答案。

用法：
    py tests/capture_list_quote_fields.py                # 默认 120s
    py tests/capture_list_quote_fields.py --duration 60

操作步骤：
    1. 先启动同花顺并登录，打开「沪深A股」列表，确认能正常显示行情
    2. 运行本脚本（选网卡后开始抓包）
    3. 抓包期间做以下操作触发 list_quote 请求（关键！否则抓不到）：
       a. 切到非列表页（自选股/分时图），再点回「沪深A股」列表
       b. 反复进出列表页几次
       c. 按 F5 / 右键「刷新」强制刷新行情
       d. 表头右键勾选「成交额」列，再刷新一次
       （滚动列表通常不触发新请求，它用缓存——要进出/刷新才行）
    4. 抓够后 Ctrl+C 提前结束，或等自动结束，脚本自动分析

产物：captures_live/list_quote_fields_<时间戳>.pcap + 字段分析报告
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
from collections import OrderedDict

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

# 自动探测：WS 路径不存在时，搜常见位置（D:/C: 盘的 Wireshark 便携版/安装版）
if not os.path.exists(TSHARK):
    for _cand in [
        r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
        r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
        r"C:\Program Files\Wireshark",
        r"D:\Program Files\Wireshark",
    ]:
        if os.path.exists(os.path.join(_cand, "tshark.exe")):
            WS = _cand
            DUMPCAP = os.path.join(WS, "dumpcap.exe")
            TSHARK = os.path.join(WS, "tshark.exe")
            break

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符

# README 已知字段（用于解析时标注含义）
# 2026-07-23 盘口/基本资料逆向确认（002353/688799/002432/002487/001317 多样本对照）：
#   dt24=买一价 dt25=买一量(股) → 涨停封单额 = dt24 × dt25
#   dt30=卖一价 dt31=卖一量(股) → 跌停封单额 = dt30 × dt31
#   dt69=涨停价(昨收×1.1) dt70=跌停价(昨收×0.9)
#   dt14=外盘 dt74=盘后量 dt75=盘后笔数
#   w8字段: dt146=总股本 dt151=流通股本 dt124=实际流通股 dt151(fmt62)=季报净利
#           dt107=年报净利 dt33=注册制上市日
KNOWN_FIELDS = {
    5: "代码", 6: "昨收", 7: "开盘价", 8: "最高", 9: "最低", 10: "现价/最新",
    12: "?", 13: "成交量(股,÷100手)", 14: "外盘(股)", 17: "竞价量",
    18: "?(非涨幅)", 19: "成交额/总金额",
    20: "?", 21: "?",
    24: "买一价", 25: "买一量(股)★封单量", 26: "买二价", 27: "买二量(股)",
    28: "买三价", 29: "买三量(股)",
    30: "卖一价", 31: "卖一量(股)", 32: "卖二价", 33: "卖二量(股)",
    34: "卖三价", 35: "卖三量(股)",
    38: "?", 39: "?",
    45: "?待查", 48: "4分涨/涨速", 49: "竞价笔", 66: "涨幅%",
    69: "涨停价(昨收×1.1)", 70: "跌停价(昨收×0.9)", 74: "盘后量(股)",
    75: "盘后笔数", 85: "?(原始字节,疑名称)", 90: "?待查", 92: "?待查",
    107: "上年年报净利润(fmt62,静态PE分母)", 122: "?", 123: "?",
    124: "实际流通股(fmt61,实换手分母)", 125: "?",
    130: "?待查",
    146: "总股本(fmt61)",
    150: "买四价", 151: "流通股本(fmt61)/TTM净利润(fmt62,动态PE分母)",
    152: "卖四价", 153: "卖四量(股)",
    154: "买五价", 155: "买五量(股)", 156: "卖五价", 157: "卖五量(股)",
    # 223-262 段是资金流（大/中/小单净额），不是买卖盘（2026-07-23 确认）
    223: "资金流-?", 224: "资金流-?", 237: "资金流-?", 238: "资金流-?",
    1111: "日期", 127: "?", 271: "?", 275: "?",
    2942: "?", 2947: "?", 3250: "?", 3251: "?", 3252: "?",
    461256: "?", 68285: "?", 3541450: "?",
    592888: "主力净量", 592890: "主力净流入",
    1968584: "换手率", 1771976: "量比", 199112: "涨幅(排序)",
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


def capture(iface, duration, pcap_path):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"开始抓包 {duration}s（8901 端口，网卡 {iface}）")
    print(f"{'='*60}")
    print(">>> 抓包期间操作（★本次目标：抓涨停股的五档盘口，逆向封单额）：")
    print("    封单额走 [19,223-262] 五档盘口请求，在「个股详情页/分时图」触发。")
    print("    1. 先记下目标涨停股的：买一价、买一量(手)、界面显示的封单额(元)")
    print("       （文档已知封单额的票：杰瑞002353=11.37亿 / 盛达000603=2.4亿 /")
    print("        中国西电601179=4.28亿 / 美利云000815=2.22亿 / 汉缆002498=1.63亿）")
    print("    2. 抓包开始后，在同花顺打开该涨停股的「个股详情页/分时图」")
    print("    3. 多进出几次该股详情页，确保抓到 [19,223-262] 盘口请求")
    print("    4. 如有刷新(F5)，多按几次")
    print("    脚本分析时会自动配对该股的盘口请求与响应，解出全部字段值。")
    print("-" * 60)
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


def _tshark_streams(pcap_path):
    """用 tshark 按 TCP 流重组，提取每个流的双向 payload。

    返回 list of (stream_id, client_payload_bytes, server_payload_bytes)。
    client = 发往 8901 的（dstport 8901），server = 从 8901 来的（srcport 8901）。
    """
    # 取所有 8901 流的 stream id
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", "tcp.port==8901",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120)
    stream_ids = [s for s in r.stdout.decode().split() if s]
    if not stream_ids:
        return []

    results = []
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
        # 客户端→服务器（请求）：dstport==8901
        rc = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y", f"tcp.stream=={sid} and tcp.dstport==8901",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        client_hex = "".join(rc.stdout.decode().split())
        # 服务器→客户端（响应）：srcport==8901
        rs = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y", f"tcp.stream=={sid} and tcp.srcport==8901",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60)
        server_hex = "".join(rs.stdout.decode().split())
        if client_hex or server_hex:
            results.append((sid,
                            bytes.fromhex(client_hex) if client_hex else b"",
                            bytes.fromhex(server_hex) if server_hex else b""))
    return results


def _split_frames(stream_bytes):
    """从重组的字节流里按 fdfdfdfd magic 切出帧体（去掉 8 字节 hex 长度）。"""
    frames = []
    for sub in stream_bytes.split(MAGIC):
        if len(sub) >= 8:
            # 8 字节 hex 长度（ASCII），之后是帧体
            frames.append(sub[8:])
    return frames


def _extract_request_fields(frame_body):
    """从请求帧体提取 DataType / CodeList / SortBy 等文本字段。

    返回 dict 或 None（不是 list_quote 请求时）。
    """
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "DataType=" not in text:
        return None
    info = {}
    m = re.search(r"DataType=([\d,]+)", text, re.IGNORECASE)
    if m:
        info["datatype"] = [int(x) for x in m.group(1).split(",") if x]
    m = re.search(r"CodeList=([\d();]+)", text)
    if m:
        info["codelist"] = m.group(1)
    m = re.search(r"SortBy=(\d+)", text)
    if m:
        info["sort_by"] = int(m.group(1))
    m = re.search(r"SortCount=(\d+)", text)
    if m:
        info["sort_count"] = int(m.group(1))
    return info if info else None


def _decode_depth_frame(frame_body):
    """解码五档盘口帧（含 dt24/dt25 买一价/量的 hd1.0 响应）。

    2026-07-23 用 002353 杰瑞股份（涨停，封单额 11.37 亿）对照破解确认：
      - 盘口请求 DataType 含 dt24(买一价)/dt25(买一量)，**不是** [19,223-262]
        （后者是资金流数据：大/中/小单净额，dt227≈dt19 成交额）
      - 买盘字段对（价/量）：dt24/25 dt26/27 dt28/29 dt150/151 dt154/155
      - 封单额 = dt24 × dt25（买一价 × 买一量，单位：股）

    帧结构：hd1.0\\0 + dc(LE32) + reserved(2B) + hs(LE16) + fc(LE16)
            + 字段表(fc×4B) + 记录区(dc×hs 字节，行主序明文)
    字段表每条 (dt 1B, fmt 1B, flags 1B, width 1B)；值用 decode_ths_float。

    Returns:
        list[dict]，每条 {code, dt<N>: float}。字段表不含 dt24 时返回空（非盘口帧）。
    """
    import struct
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import decode_ths_float  # noqa: E402

    pos = frame_body.find(b"hd1.0")
    if pos < 0:
        return []
    base = pos + 6
    if base + 10 > len(frame_body):
        return []
    dc = struct.unpack("<I", frame_body[base:base+4])[0]
    hs = struct.unpack("<H", frame_body[base+6:base+8])[0]
    fc = struct.unpack("<H", frame_body[base+8:base+10])[0]
    if not (0 < dc < 100 and 0 < hs < 500 and 0 < fc < 50):
        return []
    ftoff = base + 10
    ft = frame_body[ftoff:ftoff + fc*4]
    if len(ft) < fc*4:
        return []
    fields = [(ft[i*4], ft[i*4+1], ft[i*4+3]) for i in range(fc)]  # (dt,fmt,width)
    # 必须含 dt24（买一价）才认定为盘口帧
    if not any(d == 24 for d, _, _ in fields):
        return []
    recoff = ftoff + fc*4
    recs = []
    for r in range(dc):
        row = frame_body[recoff + r*hs: recoff + (r+1)*hs]
        if len(row) < hs:
            break
        rec = {}
        o = 0
        for dt, fmt, width in fields:
            chunk = row[o:o+width]
            o += width
            if dt == 5 and fmt == 0x20:
                rec["code"] = chunk[1:1+6].split(b"\x00")[0].decode("ascii", errors="replace")
            elif width == 4:
                rec[f"dt{dt}"] = decode_ths_float(struct.unpack("<I", chunk)[0])
        recs.append(rec)
    return recs


def _decode_any_hd_frame(frame_body):
    """通用 hd1.0/hd3.1 解码（不限字段表），返回记录列表。

    用于看任意个股明细帧（盘口/资金流等）的全部字段值。
    比 _decode_depth_frame 宽松：只要 dc/hs/fc 合理就解。
    """
    import struct
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import (decode_ths_float, parse_hd1_response,
                                  parse_hd3_response)  # noqa: E402

    if b"hd1.0" in frame_body:
        return parse_hd1_response(frame_body)
    if b"hd3.1" in frame_body:
        return parse_hd3_response(frame_body)
    return []


def _decode_all_hd_with_fields(hd_frames: list, request_dt: list[int]) -> list[dict]:
    """解码所有 hd 帧，返回字段表与本请求 DataType 匹配的记录。

    用于逆向盘口/资料字段：一个请求的 DataType 决定了它想要的字段，
    响应帧的字段表应包含这些字段（可能多带几个附加字段）。本函数解码每个
    hd 帧，保留字段表与 request_dt 有交集的记录，方便对照界面数值。

    Args:
        hd_frames: 同 stream 的所有 hd 响应帧体列表。
        request_dt: 本请求的 DataType 字段编号列表。

    Returns:
        list[dict]，每条是 {code, dt<N>: value, ...}。
    """
    import struct
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import (parse_hd1_response, parse_hd3_response,
                                  _parse_hd_field_table, _decode_bitrle_0x13746d0,
                                  _transpose_bitplane_0x1763410,
                                  decode_ths_float)  # noqa: E402

    request_set = set(request_dt)
    results = []
    for hf in hd_frames:
        # 先看字段表是否与请求有交集
        tag_off = hf.find(b"hd1.0")
        is_hd10 = tag_off >= 0
        if not is_hd10:
            tag_off = hf.find(b"hd3.1\x00")
        if tag_off < 0:
            continue
        base = tag_off + 6
        if base + 10 > len(hf):
            continue
        dc = struct.unpack("<I", hf[base:base+4])[0]
        hs = struct.unpack("<H", hf[base+6:base+8])[0]
        fc = struct.unpack("<H", hf[base+8:base+10])[0]
        if not (0 < dc < 100000 and 0 < hs < 2000 and 0 < fc < 100):
            continue
        ft = hf[base+10:base+10+fc*4]
        if len(ft) < fc*4:
            continue
        frame_dts = {ft[i*4] for i in range(fc)}
        # 精确匹配：字段表与请求交集应覆盖请求的大部分字段（≥50%），
        # 避免把同 stream 其他请求（仅个别字段重叠，如 dt10）的响应误关联。
        overlap = frame_dts & request_set
        if len(overlap) < max(1, len(request_set) // 2):
            continue
        # 用通用解码
        try:
            if is_hd10:
                recs = parse_hd1_response(hf)
            else:
                recs = parse_hd3_response(hf)
        except Exception:
            recs = []
        for r in recs:
            if r:
                results.append(r)
    return results


# 买盘字段对（价/量），用于盘口展示（2026-07-23 抓包确认字段编号）
_BUY_LEVEL_FIELDS = [
    ("买一", 24, 25), ("买二", 26, 27), ("买三", 28, 29),
    ("买四", 150, 151), ("买五", 154, 155),
]


def _analyze_depth_requests(streams, pcap_path):
    """配对五档盘口请求（DataType 含 dt24/dt25）与其响应，打印盘口 + 封单额。

    2026-07-23 三个样本对照确认封单额逻辑（见 protocol.parse_depth_quote_response）：
      - 涨停：卖一量(dt31)=0，封单额 = dt24(买一价) × dt25(买一量)
              （002353 杰瑞股份 → 11.37 亿）
      - 跌停：买一量(dt25)=0，封单额 = dt30(卖一价) × dt31(卖一量)
              （002432 九安医疗 → 3.93 亿）
      - 正常：买卖一档都有量，无封单（688799）

    配对策略：盘口请求 CodeList 是 ``<市场>(<代码>)`` 单股，响应是该股 hd1.0
    单股帧（dc=1，字段表含 dt24）。按解出的 code 与请求代码匹配。
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import parse_depth_quote_response  # noqa: E402

    print(f"\n{'='*60}")
    print("【五档盘口分析】—— 封单额（涨停=买一价×量，跌停=卖一价×量）")
    print(f"{'='*60}")

    # 收集所有盘口请求（DataType 含 24 且含 25）+ 所在 stream 的响应帧
    depth_reqs = []
    for sid, client_bytes, server_bytes in streams:
        cframes = _split_frames(client_bytes)
        sframes = _split_frames(server_bytes)
        for ci, fb in enumerate(cframes):
            info = _extract_request_fields(fb)
            if not info:
                continue
            dt = info.get("datatype", [])
            if 24 in dt and 25 in dt:  # 含买一价/量 = 盘口请求
                cl = info.get("codelist", "")
                m = re.search(r"\((\d+)", cl)
                code = m.group(1) if m else "?"
                depth_reqs.append((sid, code, dt, sframes))

    if not depth_reqs:
        print("✗ 未抓到五档盘口请求（DataType 含 dt24/dt25）")
        print("  需要：在同花顺打开个股的「个股详情页/分时图」触发盘口请求")
        return

    # 按 (stream, code) 去重
    seen = set()
    unique_reqs = []
    for sid, code, dt, sframes in depth_reqs:
        key = (sid, code)
        if key in seen:
            continue
        seen.add(key)
        unique_reqs.append((sid, code, dt, sframes))

    print(f"抓到 {len(depth_reqs)} 个盘口请求（去重后 {len(unique_reqs)} 只票）\n")
    for sid, code, dt, sframes in unique_reqs:
        print(f"{'─'*60}")
        print(f"【{code}】stream={sid}  DataType({len(dt)}字段): {dt}")
        # 在响应帧里用协议层函数解析，按 code 匹配
        matched = []
        for sf in sframes:
            result = parse_depth_quote_response(sf)
            if result and (result.get("code") == code or not matched):
                matched.append(result)
        if not matched:
            print(f"  ✗ 未找到 {code} 的盘口响应帧（可能响应未抓全）")
            continue
        for r in matched:
            print(f"  代码: {r.get('code','?')}")
            # 五档买盘
            for b in r.get("buy", []):
                if b["price"] > 0 or b["qty"] > 0:
                    qh = b["qty"] / 100
                    print(f"    {b['level']}: 价={b['price']:>9.2f}  "
                          f"量={b['qty']:>12,.0f}股({qh:>9,.0f}手)  "
                          f"金额={b['amount']:>16,.0f}")
            # 五档卖盘
            for s in r.get("sell", []):
                if s["price"] > 0 or s["qty"] > 0:
                    qh = s["qty"] / 100
                    print(f"    {s['level']}: 价={s['price']:>9.2f}  "
                          f"量={s['qty']:>12,.0f}股({qh:>9,.0f}手)  "
                          f"金额={s['amount']:>16,.0f}")
            # 封单额（智能判断涨跌停）
            seal = r.get("seal_amount", 0)
            stype = r.get("seal_type")
            if stype:
                print(f"    ★ {stype}封单额 = {seal:,.0f} 元 = "
                      f"{seal/1e8:.4f} 亿")
            else:
                print(f"    （正常股，买卖一档均有量，无封单）")
        print()


def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return

    print(f"\n{'='*60}")
    print(f"分析 {pcap_path}")
    print(f"{'='*60}")

    streams = _tshark_streams(pcap_path)
    print(f"共 {len(streams)} 条 8901 TCP 流\n")

    # 收集所有 list_quote / stock_list 请求（去重 by datatype+codelist）
    requests = OrderedDict()  # key -> {info, frame_body, server_frames}
    for sid, client_bytes, server_bytes in streams:
        req_frames = _split_frames(client_bytes)
        resp_frames = _split_frames(server_bytes)
        for fb in req_frames:
            info = _extract_request_fields(fb)
            if info is None:
                continue
            key = (tuple(info.get("datatype", [])),
                   info.get("codelist", ""), info.get("sort_by"))
            if key not in requests:
                requests[key] = {"info": info, "frame_body": fb,
                                 "server_frames": resp_frames, "stream": sid}

    if not requests:
        print("✗ 未抓到任何 DataType= 请求")
        print("  可能原因：同花顺没打开列表页 / 网卡选错 / 抓包时段无操作")
        return

    print(f"抓到 {len(requests)} 种不同的 DataType 请求\n")

    # 逐个打印
    for i, (key, data) in enumerate(requests.items(), 1):
        info = data["info"]
        dt = info.get("datatype", [])
        cl = info.get("codelist", "?")
        sb = info.get("sort_by")
        print(f"{'─'*60}")
        print(f"【请求 {i}】stream={data['stream']}  CodeList={cl}")
        if sb:
            print(f"  SortBy={sb}（排序查询）SortCount={info.get('sort_count','?')}")
        print(f"  DataType ({len(dt)} 字段): {dt}")
        # 标注每个已知字段
        annotated = []
        for d in dt:
            name = KNOWN_FIELDS.get(d, "★未知")
            annotated.append(f"{d}={name}")
        print(f"  含义: {annotated}")

        # 找对应的 hd 响应帧
        resp_frames = data["server_frames"]
        hd_frames = [f for f in resp_frames if b"hd1.0" in f or b"hd3.1" in f]
        if hd_frames:
            print(f"  响应: {len(hd_frames)} 个 hd 数据帧")
            # 解码所有 hd 响应帧，按"字段表含本请求 DataType 的"匹配，打印字段值
            decoded = _decode_all_hd_with_fields(hd_frames, dt)
            if decoded:
                print(f"  ── 字段值解码（用于对照界面数值逆向字段）──")
                for rec in decoded:
                    if rec.get("code"):
                        print(f"    代码: {rec['code']}")
                    for k in sorted(rec.keys(),
                                    key=lambda x: int(x[2:]) if x.startswith("dt") and x[2:].isdigit() else -1):
                        v = rec[k]
                        name = ""
                        if k.startswith("dt") and k[2:].isdigit():
                            name = KNOWN_FIELDS.get(int(k[2:]), "★未知")
                        if isinstance(v, float):
                            print(f"      {k:8s} = {v:>18.2f}  ({name})")
                        elif k != "code":
                            print(f"      {k:8s} = {v!r}  ({name})")
            else:
                for hf in hd_frames[:1]:
                    tag = "hd3.1" if b"hd3.1" in hf else "hd1.0"
                    print(f"    [{tag}] {len(hf)} 字节（未解出字段，头32B: {hf[:32].hex(' ')})")
        else:
            mt = [f for f in resp_frames if b"MarketTime" in f or b"SortTotal" in f]
            if mt:
                txt = mt[0].decode("gbk", errors="replace")[:100]
                print(f"  响应: 文本帧 {txt}")
            else:
                print(f"  响应: 无 hd 数据帧（{len(resp_frames)} 个其他帧）")
        print()

    # 汇总：所有出现过的字段编号
    print(f"{'='*60}")
    print("【汇总】所有请求里出现过的 DataType 字段编号：")
    print(f"{'='*60}")
    all_fields = set()
    for data in requests.values():
        all_fields.update(data["info"].get("datatype", []))
    for d in sorted(all_fields):
        name = KNOWN_FIELDS.get(d, "★未知-待逆向")
        print(f"  {d:>8}  {name}")

    # ── 五档盘口请求分析（封单额逆向关键）──
    # 重新取一次 streams（上面 requests 循环可能改了迭代状态）
    _analyze_depth_requests(streams, pcap_path)

    # 导出每个 stream 的完整响应原始字节（供离线搜数字定位字段）
    print(f"\n{'='*60}")
    print("【响应原始字节导出】（供离线搜封单额等字段用）")
    print(f"{'='*60}")
    streams_raw = _tshark_streams(pcap_path)
    for sid, client_bytes, server_bytes in streams_raw:
        if len(server_bytes) < 50:
            continue
        # 找响应里的股票代码（ASCII 6位数字）
        import re as _re
        codes = set(_re.findall(rb'(\d{6})', server_bytes))
        # 过滤掉 MarketTime 里的数字
        real_codes = [c.decode() for c in codes if not server_bytes.count(c) > 10][:10]
        out_path = pcap_path.replace('.pcap', f'_resp_stream{sid}.bin')
        with open(out_path, 'wb') as f:
            f.write(server_bytes)
        print(f"  stream {sid}: {len(server_bytes)}B → {out_path}")
        print(f"    含股票代码(抽样): {real_codes}")
    print(f"\n  ★ 封单额已确认走五档盘口请求 [19,223-262]（见上方分析）。")
    print(f"    涨停股的封单 = 买一档巨量挂单，对照界面封单额即可锁定字段。")


def main():
    ap = argparse.ArgumentParser(description="抓 list_quotes 请求逆向 DataType 字段")
    ap.add_argument("--duration", type=int, default=120, help="抓包时长（秒）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap 文件")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"list_quote_fields_{ts}.pcap")

    capture(iface, args.duration, pcap_path)
    analyze(pcap_path)

    print(f"\n{'='*60}")
    print(f"pcap 已保存: {pcap_path}")
    print(f"重新分析: py tests/capture_list_quote_fields.py --analyze-only \"{pcap_path}\"")


if __name__ == "__main__":
    main()
