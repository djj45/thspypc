#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端的分时图请求/响应（当日分时 + 历史回忆），逆向数据格式。

背景
----
当日分时的请求格式已实现（``protocol.build_timeline_query``，``DateTime=8192(0-0)``，
``pageid=9354``，子帧 0x0002 / 路由 0x000a）。但**历史某一天的"分时回忆"**
（在分时图上按 ←/→ 切到过往交易日）的请求格式未知——历史日期怎么传、是不是
还用 8192、pageid 是否变化、子帧/路由是否不同，都只能靠抓包确认。

关键假设（待抓包验证）：当日分时用 ``DateTime=8192(0-0)``，历史回忆很可能把
第二参数或第一参数换成日期/偏移。本脚本把所有含 ``pageid=9354`` 的请求**按
``DateTime`` 完整取值分组展示**，切到历史那天发的请求会立刻和当天的区分开。

本脚本会：
  1. 抓 8901 端口流量
  2. 提取所有疑似**分时**请求：含 ``pageid=9354`` 或 ``DateTime=8192`` 或
     ``DateTime=0x2000``（8192=0x2000 分时周期码）的帧
  3. 完整打印 ``DateTime=`` 后面括号里的取值（★这是历史回忆的破绽），并按
     取值分组汇总——同一种 DateTime 取值合并，列出代码/市场
  4. 配对响应，用 ``parse_kline_hd3_response`` 解码分时逐点数据（现价/量/额）
  5. 顺便抓 K线请求（``pageid=9355``）作对照，方便看分时与 K线协议差异

用法
----
    py tests/capture_timeline.py                  # 抓 120s
    py tests/capture_timeline.py --duration 180   # 抓 180s
    py tests/capture_timeline.py --analyze-only xxx.pcap   # 只分析已有 pcap

操作步骤（★关键，否则抓不到历史分时请求）：
    1. 启动同花顺并登录，打开某只股票（如 600519 贵州茅台），切到**分时图**
       （不是 K 线图！分时图是那条当天的白线 + 黄色均线）
    2. 运行本脚本，选网卡
    3. 抓包期间，依次操作（每步停 2-3 秒让请求分开）：
       a. 停在**当天**分时图（触发当日分时请求 DateTime=8192(0-0)）
       b. 按 **← 方向键**，切到**昨天/前几个交易日**的分时（★这是历史回忆，
          目标就是抓这个请求，看 DateTime 怎么变）
       c. 继续按 ← 往前翻几天
       d. 按 **→ 方向键**翻回来
       e. 换一只股票，重复 a~d
    4. 抓够后 Ctrl+C 或等自动结束，脚本自动分析

产物：captures_live/timeline_<时间戳>.pcap + 终端分析报告 + resp_streamN.bin
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
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符

# 分时图 pageid（K线图是 9355）
TIMELINE_PAGEID = "9354"
KLINE_PAGEID = "9355"
# 分时周期码 8192=0x2000（K线日=0x4000、周=0x5001...）
TIMELINE_PERIOD = 8192

# 分时 DataType 字段（与 protocol.TIMELINE_DATATYPE 一致，供标注用）
TIMELINE_FIELDS = {
    5: "代码", 6: "昨收", 10: "现价", 13: "成交量", 14: "外盘?",
    15: "?", 19: "成交额", 22: "买盘?", 23: "卖盘?", 45: "?", 54: "?",
}
KLINE_FIELDS = {
    1: "时间", 5: "代码", 6: "昨收", 7: "开", 8: "高", 9: "低",
    10: "现价", 11: "收", 13: "量", 19: "额",
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
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（8901 端口，网卡 {iface}）")
    print(f"{'='*64}")
    print(">>> 抓包期间操作（★本次目标：抓「历史分时回忆」请求 + 干净响应）：")
    print("    分时图 = 当天那条白线+黄均线（不是 K线蜡烛图！）。")
    print("    ★建议只看【一只票】（如紫光 000938），翻【明确日期】，方便后续校准解码。")
    print("    1. 打开某只股票（如 000938），切到【分时图】界面")
    print("    2. 停在当天分时（触发当日请求 DateTime=8192(0-0)）")
    print("    3. ★ 按 ← 方向键切到昨天/前几天分时（历史回忆，重点抓这个！）")
    print("       每翻一天【记住具体日期】，每步停 3-4 秒让请求分开")
    print("    4. 继续按 ← 往前翻 2-3 个明确日期")
    print("    5. 抓完后，记下：翻了哪几天 + 那几天的现价大约多少（校准用）")
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


def _parse_request(frame_body):
    """解析一个客户端请求帧，返回 (kind, info) 或 None。

    kind: "timeline" / "kline" / "other"
    info: dict 含 pageid、DateTime 完整取值、code、market、datatype 等
    """
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "pageid=" not in text and "DateTime=" not in text:
        return None

    info = {}

    # pageid
    m = re.search(r"pageid=(\d+)", text)
    if m:
        info["pageid"] = m.group(1)

    # ★ DateTime 完整取值（含括号）——历史回忆的破绽就在这里
    #   当日分时: DateTime=8192(0-0)
    #   历史回忆: DateTime=8192(<日期/偏移>-0) 或 DateTime=<其他>(...)
    m = re.search(r"DateTime=(\d+)\(([^)]*)\)", text)
    if m:
        info["datetime_period"] = int(m.group(1))
        info["datetime_args"] = m.group(2)  # 括号里的完整内容，原样保留
        # 尝试拆成两段 a-b
        parts = m.group(2).split("-")
        if len(parts) >= 1:
            info["datetime_arg1"] = parts[0].strip()
        if len(parts) >= 2:
            info["datetime_arg2"] = parts[1].strip()
    else:
        # 无括号变体：DateTime=8192 / DateTime=0
        m = re.search(r"DateTime=(\d+)", text)
        if m:
            info["datetime_period"] = int(m.group(1))

    # CodeList：33(000089,); 或 17(600519,);
    m = re.search(r"CodeList=(\d+)\(([^)]*)\)", text)
    if m:
        info["market"] = m.group(1)
        # 去掉末尾逗号，取代码
        codes_raw = m.group(2).rstrip(",").strip()
        info["codelist"] = codes_raw
        info["code"] = codes_raw.split(",")[0].strip() if codes_raw else ""

    # DataType
    m = re.search(r"DataType=([\d,\[\]]+)", text)
    if m:
        info["datatype"] = m.group(1).rstrip(",")

    # ReqFuquan（K线特有，分时无）
    m = re.search(r"ReqFuquan=(\w*)", text)
    if m:
        info["reqfuquan"] = m.group(1) or "(空)"

    # 判定类型
    pageid = info.get("pageid")
    dtp = info.get("datetime_period")
    if pageid == TIMELINE_PAGEID or dtp == TIMELINE_PERIOD:
        kind = "timeline"
    elif pageid == KLINE_PAGEID or info.get("reqfuquan") is not None:
        kind = "kline"
    elif dtp is not None and dtp != TIMELINE_PERIOD:
        # 其它周期码（日/周/月K），当 K线
        kind = "kline"
    else:
        kind = "other"
    return (kind, info)


def _decode_response(frame_body, kind):
    """解码分时/K线响应（hd3.1 变体），返回 dict 或 None。

    分时/K线响应都用 hd3.1 flag=0x0042/0x0046 变体，
    protocol.parse_kline_hd3_response 统一解码。
    """
    if b"hd3.1\x00" not in frame_body and b"hd1.0" not in frame_body:
        return None
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import parse_kline_hd3_response

    tag = "hd3.1" if b"hd3.1\x00" in frame_body else "hd1.0"
    try:
        recs = parse_kline_hd3_response(frame_body)
    except Exception as e:
        return {"tag": tag, "records": [], "error": str(e)}
    if not recs:
        return {"tag": tag, "records": [], "error": "解析为空"}
    return {"tag": tag, "records": recs, "error": ""}


def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return

    print(f"\n{'='*64}")
    print(f"分析 {pcap_path}")
    print(f"{'='*64}")

    streams = _tshark_streams(pcap_path, 8901)
    print(f"共 {len(streams)} 条 8901 TCP 流\n")

    timeline_reqs = []   # [(sid, info, sframes)]
    kline_reqs = []
    for sid, client_bytes, server_bytes in streams:
        cframes = _split_frames(client_bytes)
        sframes = _split_frames(server_bytes)
        for fb in cframes:
            parsed = _parse_request(fb)
            if parsed is None:
                continue
            kind, info = parsed
            if kind == "timeline":
                timeline_reqs.append((sid, info, sframes))
            elif kind == "kline":
                kline_reqs.append((sid, info, sframes))

    # ── 报告 1：分时请求，按 DateTime 完整取值分组（★核心）──
    print(f"{'='*64}")
    print("【1】分时请求（pageid=9354）—— 按 DateTime 取值分组（★历史回忆的破绽）")
    print(f"{'='*64}")
    if not timeline_reqs:
        print("✗ 未抓到分时请求（pageid=9354 / DateTime=8192）")
        print("  可能原因：")
        print("    ① 没在同花顺里打开【分时图】（不是 K线图！）")
        print("    ② 分时不走 8901（可能走别的端口，需改抓包端口重抓）")
        print("    ③ 选错网卡")
        print("  建议：重抓时务必打开股票的【分时图】，并按 ←/→ 切历史日期")
    else:
        # 按 datetime_args（括号内容）分组
        groups: dict[str, list[tuple]] = {}
        for sid, info, sframes in timeline_reqs:
            key = info.get("datetime_args",
                           f"(无括号, period={info.get('datetime_period')})")
            groups.setdefault(key, []).append((sid, info, sframes))

        print(f"\n抓到 {len(timeline_reqs)} 个分时请求，"
              f"按 DateTime 括号内容分成 {len(groups)} 组：\n")
        # ★ 重点：和「当日」DateTime=8192(0-0) 不同的就是历史回忆
        for gi, (dt_key, reqs) in enumerate(sorted(groups.items()), 1):
            is_today = dt_key == "0-0"
            mark = "  [当日]" if is_today else "★ [历史回忆/其他！与当日不同，重点看]"
            print(f"  ── 第 {gi} 组：DateTime={TIMELINE_PERIOD}({dt_key}){mark} ──")
            # 取该组第一个请求展示完整字段
            sid0, info0, sframes0 = reqs[0]
            _print_request_detail(info0)
            print(f"  本组共 {len(reqs)} 个请求，代码: "
                  f"{sorted({r[1].get('code','?') for r in reqs})}")
            # 解码响应
            resp = None
            for sf in sframes0:
                r = _decode_response(sf, "timeline")
                if r and r["records"]:
                    resp = r
                    break
            _print_response(resp, "timeline")
            print()

    # ── 报告 2：所有 pageid 概览（看分时 vs K线 pageid 是否如预期）──
    print(f"{'='*64}")
    print("【2】所有 pageid 分布（9354=分时 9355=K线，看有没有新 pageid）")
    print(f"{'='*64}")
    pageid_count = {}
    for sid, client_bytes, _ in streams:
        for fb in _split_frames(client_bytes):
            try:
                text = fb.decode("gbk", errors="replace")
            except Exception:
                continue
            m = re.search(r"pageid=(\d+)", text)
            if m:
                pid = m.group(1)
                pageid_count[pid] = pageid_count.get(pid, 0) + 1
    if pageid_count:
        for pid, cnt in sorted(pageid_count.items(), key=lambda x: -x[1]):
            note = ""
            if pid == TIMELINE_PAGEID:
                note = "  ← 分时图"
            elif pid == KLINE_PAGEID:
                note = "  ← K线图"
            print(f"  pageid={pid}: {cnt} 次{note}")
    else:
        print("  （未抓到任何 pageid 请求）")

    # ── 报告 3：K线请求对照（看分时和K线协议差异）──
    print(f"\n{'='*64}")
    print("【3】K线请求对照（pageid=9355，看分时 vs K线 协议区别）")
    print(f"{'='*64}")
    if not kline_reqs:
        print("  （本次未抓到 K线请求，可忽略）")
    else:
        seen = set()
        for sid, info, sframes in kline_reqs:
            key = (info.get("datetime_period"), info.get("datetime_args"),
                   info.get("code"), info.get("reqfuquan"))
            if key in seen:
                continue
            seen.add(key)
            print(f"  K线 stream={sid}: code={info.get('code','?')} "
                  f"DateTime={info.get('datetime_period')}({info.get('datetime_args','?')}) "
                  f"ReqFuquan={info.get('reqfuquan','无')}")

    # ── 报告 4：DateTime 周期码汇总 ──
    print(f"\n{'='*64}")
    print("【4】DateTime 周期码汇总（8192=分时，其它=K线周期）")
    print(f"{'='*64}")
    all_periods = {}
    for _, info, _ in timeline_reqs + kline_reqs:
        p = info.get("datetime_period")
        if p is not None:
            all_periods.setdefault(p, []).append(info.get("code", "?"))
    if all_periods:
        for p in sorted(all_periods):
            codes = sorted(set(all_periods[p]))[:5]
            name = "分时" if p == TIMELINE_PERIOD else f"周期0x{p:x}"
            print(f"  DateTime={p} ({name}): 涉及 {len(all_periods[p])} 请求, "
                  f"代码如 {codes}")
    else:
        print("  （无 DateTime 数据）")

    _dump_responses(streams, pcap_path, timeline_reqs)


def _print_request_detail(info):
    """打印单个请求的关键字段（分时专用标注）。"""
    if "datetime_period" in info:
        dtp = info["datetime_period"]
        name = "★分时" if dtp == TIMELINE_PERIOD else f"周期0x{dtp:x}"
        print(f"    DateTime = {dtp}({info.get('datetime_args','?')}) → {name}")
        if "datetime_arg1" in info:
            a1 = info["datetime_arg1"]
            hint = "（0=当天）" if a1 == "0" else f"（★非0，疑似日期/偏移：{a1}）"
            print(f"      括号第1参数 = {a1} {hint}")
        if "datetime_arg2" in info:
            print(f"      括号第2参数 = {info['datetime_arg2']}")
    if "pageid" in info:
        note = " (分时图)" if info["pageid"] == TIMELINE_PAGEID else ""
        print(f"    pageid = {info['pageid']}{note}")
    if "code" in info:
        print(f"    code = {info['code']} (market={info.get('market','?')})")
    if "datatype" in info:
        dts = [d for d in info["datatype"].split(",") if d.strip()]
        annotated = []
        for d in dts:
            if d.isdigit():
                annotated.append(f"{d}={TIMELINE_FIELDS.get(int(d), KLINE_FIELDS.get(int(d),'?'))}")
            else:
                annotated.append(d)
        print(f"    DataType = {info['datatype']}")
        print(f"             含义: {annotated}")


def _print_response(resp, kind):
    """打印响应解码结果（分时逐点 / K线 OHLC）。"""
    if resp is None:
        print(f"    响应: 未解出数据帧")
        return
    if resp.get("error"):
        print(f"    响应: [{resp['tag']}] 解析 {resp['error']}")
        return
    recs = resp["records"]
    print(f"    响应: [{resp['tag']}] {len(recs)} 个点")
    # 分时打印时间+现价+量；K线打印时间+OHLC
    for r in recs[:3]:
        t = r.get("time")
        ts = t.strftime("%Y-%m-%d %H:%M") if t else f"bar#{r.get('bar_index')}"
        if kind == "timeline":
            print(f"      {ts} 现价(dt10)={r.get('dt10','?')} "
                  f"量(dt13)={r.get('dt13','?')} 额(dt19)={r.get('dt19','?')}")
        else:
            print(f"      {ts} O={r.get('open','?')} H={r.get('high','?')} "
                  f"L={r.get('low','?')} C={r.get('close','?')}")
    if recs:
        r = recs[-1]
        t = r.get("time")
        ts = t.strftime("%Y-%m-%d %H:%M") if t else f"bar#{r.get('bar_index')}"
        if kind == "timeline":
            print(f"      末点 {ts} 现价={r.get('dt10','?')}")
        else:
            print(f"      末根 {ts} C={r.get('close','?')}")


def _dump_responses(streams, pcap_path, timeline_reqs):
    """导出含分时请求的 stream 的服务器响应（供离线分析）。"""
    print(f"\n{'='*64}")
    print("【响应原始字节导出】（含分时请求的 stream，供离线分析）")
    print(f"{'='*64}")
    timeline_sids = {sid for sid, _, _ in timeline_reqs}
    exported = 0
    for sid, client_bytes, server_bytes in streams:
        if sid not in timeline_sids:
            continue
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
        print("  （无分时响应数据，确认是否打开了分时图）")


def main():
    ap = argparse.ArgumentParser(
        description="抓同花顺分时图请求/响应（当日+历史回忆），逆向数据格式")
    ap.add_argument("--duration", type=int, default=120, help="抓包时长（秒）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap 文件")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"timeline_{ts}.pcap")

    capture(iface, args.duration, pcap_path)
    analyze(pcap_path)

    print(f"\n{'='*64}")
    print(f"pcap 已保存: {pcap_path}")
    print(f"重新分析: py tests/capture_timeline.py --analyze-only \"{pcap_path}\"")


if __name__ == "__main__":
    main()
