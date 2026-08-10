#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端的 K 线请求/响应（日K/周K/月K/5分K 等），逆向数据格式。

背景
----
Mac 版（thspy）已完整逆向 K 线协议：走 9602 端口、``id=210`` 文本格式、
``period`` 参数区分周期（0x3001=1分、0x3005=5分、0x4000=日、0x5001=周、
0x6001=月，见 PERIOD_MAP）、``datatype=1,7,8,9,11,13,19`` = 时间/开/高/低/
收/量/额、响应是 hd 压缩帧。

但 PC 版（thspypc）一直走 8901 端口，用的是 ``method=qureal``（多行 key=value）
而非 ``id=210`` 格式——已有 pcap 里看到的 qureal 都是 ``period=0``（实时快照，
datatype=5,55 代码+名称），从没抓到过真正的 K 线请求。**PC 版 K 线的请求格式
和响应结构需要本脚本抓包确认**。

本脚本会：
  1. 抓 8901 端口流量（K 线请求可能在 8901；若抓不到会提示也抓 8902/9602）
  2. 提取所有疑似 K 线请求：含 ``method=qureal``/``id=210``/``period``/
     ``qukline``/``kline``/``fuquan``（复权，K线特有）的帧
  3. 打印每个请求的完整参数（period 周期、datatype 字段、code、fuquan、start/count）
  4. 配对响应，解码 hd 压缩帧里的 OHLC 字段（开/高/低/收/量/额）
  5. 导出每个 stream 的原始响应字节（供离线搜数字定位）

用法
----
    py tests/capture_kline.py                  # 抓 120s
    py tests/capture_kline.py --duration 180   # 抓 180s
    py tests/capture_kline.py --analyze-only xxx.pcap   # 只分析已有 pcap

操作步骤（★关键，否则抓不到 K 线请求）：
    1. 先启动同花顺并登录，打开某只股票（如 600519 贵州茅台）
    2. 运行本脚本，选网卡
    3. 抓包期间，依次操作（每步停 2-3 秒让请求分开）：
       a. 切到「日K」线图，左右滑动/缩放几次（触发历史 K 线请求）
       b. ★ 2147 回溯专项：在日K图上按住 ← 方向键 / 拖到最左，连续翻页
          10-20 次（触发"加载更早历史"，观察 DateTime 窗口是否从
          (-2146-0) 变成更早的 (-N-M)）
       c. 切到「周K」
       d. 切到「月K」
       e. 切到「季K」（周期下拉菜单里的「季线」）
       f. 切到「年K」（「年线」）
       g. 依次切「5分K → 15分K → 30分K → 60分K」
       h. 切回复权前/前复权/后复权（触发 fuquan 参数变化）
       i. 换一只股票再看日K（触发不同 code 的请求）
    4. 抓够后 Ctrl+C 或等自动结束，脚本自动分析

产物：captures_live/kline_<时间戳>.pcap + 终端分析报告 + resp_streamN.bin
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

# 自动探测 Wireshark 路径
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

# Mac 版已逆向的 period 周期映射（thspy/protocol.py PERIOD_MAP）。
# PC 版 period 编码可能不同，这里仅作参考标注。
PERIOD_REF = {
    0x3001: "1分K", 0x3005: "5分K", 0x300F: "15分K", 0x301E: "30分K",
    0x303C: "60分K", 0x3078: "120分K",
    0x4000: "日K", 0x5001: "周K", 0x6001: "月K", 0x6003: "季K", 0x7001: "年K",
}

# K 线字段编号（Mac 版 DATATYPE_NAMES 确认）。K 线 datatype=1,7,8,9,11,13,19
KLINE_FIELDS = {
    1: "时间", 5: "代码", 6: "昨收", 7: "开盘价", 8: "最高价",
    9: "最低价", 10: "现价/最新", 11: "收盘价", 13: "成交量", 19: "成交额",
}

# 疑似 K 线请求的关键词（任一命中即提取）
KLINE_KEYWORDS = ["qureal", "id=210", "period=", "fuquan=", "qukline",
                  "kline", "qukline2", "history"]


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
    print(">>> 抓包期间操作（★本次目标：抓 K 线请求，逆向数据格式）：")
    print("    K 线请求在「个股 K 线图」打开/切换周期/缩放时触发。")
    print("    1. 打开某只股票（如 600519），确保能看到 K 线图")
    print("    2. ★ 2147 回溯专项：日K图上按住 ← / 拖到最左，连续翻页 10-20 次")
    print("       （观察 DateTime 窗口是否从 (-2146-0) 变成更早的 (-N-M)）")
    print("    3. 依次切换周期（每步停 2-3 秒，确保触发请求）：")
    print("       日K → 周K → 月K → 季K → 年K")
    print("       5分K → 15分K → 30分K → 60分K")
    print("       （季K/年K 在周期下拉菜单里找「季线/年线」）")
    print("    4. 日K图上左右滑动/滚轮缩放几次（触发历史 K 线加载）")
    print("    5. 切换复权：前复权 ↔ 后复权 ↔ 不复权")
    print("    6. 换另一只股票再看日K")
    print("    （关键：必须实际打开 K 线图并切换周期，否则抓不到请求）")
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


def _extract_kline_request(frame_body):
    """判断帧是否疑似 K 线请求，返回参数 dict 或 None。

    识别两种 PC/Mac 格式：
      - PC method= 格式: method=qureal\\nperiod=N\\ndatatype=...\\ncodelist=...
      - Mac id= 格式:    id=210&period=N&datatype=...&code=...
    含 fuquan=（复权）或 period≠0 是 K 线的强信号。
    """
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    low = text.lower()
    # 必须命中至少一个 K 线关键词
    if not any(kw in low for kw in KLINE_KEYWORDS):
        return None
    # 排除明显的非 K 线请求：
    #   - subreal（实时订阅推送，period 恒 0，不是 K 线）
    #   - 含 period=0 且无 fuquan（period=0 是实时快照，K 线 period≠0）
    if re.search(r"method=subreal", text):
        return None
    info = {}
    # method= 格式（PC）
    m = re.search(r"method=(\w+)", text)
    if m:
        info["method"] = m.group(1)
    # id= 格式（Mac）—— 注意 pageid= 不算（避免误匹配 pageid=9355 → id=9355）
    m = re.search(r"(?<![a-z])id=(\d+)", text)
    if m:
        info["id"] = m.group(1)
    # period（周期，K 线核心参数）
    m = re.search(r"period=(\w+)", text)
    if m:
        val = m.group(1)
        info["period_raw"] = val
        try:
            pv = int(val, 0)  # 支持 0x 十六进制
            info["period"] = pv
            info["period_name"] = PERIOD_REF.get(pv, f"?未知(0x{pv:x})")
        except ValueError:
            info["period"] = val
    # datatype
    m = re.search(r"datatype=([\d,\w]+)", text)
    if m:
        info["datatype"] = m.group(1)
    # code / codelist
    m = re.search(r"codelist=(\S+?)(?:[\r\n]|$)", text)
    if m:
        info["codelist"] = m.group(1).strip()
    m = re.search(r"[^l]code=(\w+)", text)  # 避免 codelist 的 code
    if m:
        info["code"] = m.group(1)
    # market
    m = re.search(r"market=(\w+)", text)
    if m:
        info["market"] = m.group(1)
    # fuquan（复权，K 线特有）—— 两种格式：Mac fuquan= / PC ReqFuquan=
    m = re.search(r"fuquan=(\w*)", text)
    if m:
        info["fuquan"] = m.group(1) or "(空)"
    m = re.search(r"ReqFuquan=(\w*)", text)
    if m:
        info["reqfuquan"] = m.group(1) or "(空)"
    # PC 版 pageid（9355=K线图页面，实测确认）
    m = re.search(r"pageid=(\d+)", text)
    if m:
        info["pageid"] = m.group(1)
    # PC 版 DateTime=周期码(历史偏移-0)，周期码=Mac PERIOD_MAP（0x3005=5分,0x4000=日...）
    m = re.search(r"DateTime=(\d+)\((-?\d+)-(-?\d+)\)", text)
    if m:
        dtp = int(m.group(1))
        info["datetime_period"] = dtp
        info["datetime_period_name"] = PERIOD_REF.get(dtp, f"?未知(0x{dtp:x})")
        info["datetime_offset"] = m.group(2)   # 历史偏移（-335/-2146 等）
        info["datetime_end"] = m.group(3)      # 窗口终点（0=最新；翻页后为更早的负偏移）
    # start/end/count（K 线历史范围）
    m = re.search(r"start=(-?\w+)", text)
    if m:
        info["start"] = m.group(1)
    m = re.search(r"count=(\w+)", text)
    if m:
        info["count"] = m.group(1)

    # ★ 过滤非 K 线：period=0 且无 fuquan 且非 id=210 → 是实时快照不是 K 线
    is_kline_strong = (
        info.get("fuquan") is not None          # 复权是 K 线特有
        or info.get("reqfuquan") is not None    # PC 版 ReqFuquan（K 线特有）
        or info.get("id") == "210"              # Mac 版 K 线 cmd
        or info.get("pageid") in ("9355",)      # PC 版 K 线图 pageid（实测确认）
        or info.get("method", "").startswith("qukline") or "kline" in info.get("method", "").lower()
        or (isinstance(info.get("period"), int) and info["period"] not in (0,))  # period≠0
        or (isinstance(info.get("datetime_period"), int)
            and info["datetime_period"] not in (0,))  # PC 版 DateTime 周期码≠0
        or info.get("start") is not None        # 历史范围参数
    )
    if not is_kline_strong:
        return None
    return info if info else None


def _decode_kline_response(frame_body, request_dt):
    """尝试解码 K 线响应（hd1.0/hd3.1），返回字段表 + 记录。

    K 线响应是 hd 压缩帧，字段含 时间/开/高/低/收/量/额。
    本函数复用 protocol 的 hd 解码，按 request_dt 匹配字段。
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from thspypc.protocol import (decode_ths_float, parse_hd1_response,
                                  parse_hd3_response)

    if b"hd1.0" in frame_body:
        tag = "hd1.0"
        try:
            recs = parse_hd1_response(frame_body)
        except Exception:
            recs = []
    elif b"hd3.1" in frame_body:
        tag = "hd3.1"
        try:
            recs = parse_hd3_response(frame_body)
        except Exception:
            recs = []
    else:
        return None

    # 只保留含 OHLC 字段的记录（K 线记录有 dt7/dt8/dt9/dt11 等）
    kline_recs = []
    dt_set = set()
    for r in recs:
        if not r:
            continue
        keys = set(int(k[2:]) for k in r if k.startswith("dt") and k[2:].isdigit())
        dt_set |= keys
        # K 线记录至少含 开/收 之一
        if 7 in keys or 11 in keys or 8 in keys:
            kline_recs.append(r)
    return {"tag": tag, "records": kline_recs, "all_dts": sorted(dt_set)}


def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return

    print(f"\n{'='*60}")
    print(f"分析 {pcap_path}")
    print(f"{'='*60}")

    streams = _tshark_streams(pcap_path, 8901)
    print(f"共 {len(streams)} 条 8901 TCP 流\n")

    # 收集所有疑似 K 线请求
    kline_reqs = []  # [(stream, t_approx, info, server_frames)]
    all_methods = set()
    for sid, client_bytes, server_bytes in streams:
        cframes = _split_frames(client_bytes)
        sframes = _split_frames(server_bytes)
        for fb in cframes:
            info = _extract_kline_request(fb)
            if info is None:
                # 顺便统计所有 method/id（帮助发现未知的 K 线 method）
                try:
                    txt = fb.decode("gbk", "replace")
                    mm = re.search(r"method=(\w+)", txt)
                    if mm:
                        all_methods.add(("method", mm.group(1)))
                    mm = re.search(r"id=(\d+)", txt)
                    if mm and mm.group(1) != "0":
                        all_methods.add(("id", mm.group(1)))
                except Exception:
                    pass
                continue
            kline_reqs.append((sid, info, sframes))

    # ── 报告 1：所有 method/id 概览 ──
    print(f"{'='*60}")
    print("【1】本 pcap 出现的所有 method= / id= （找 K 线用哪个）")
    print(f"{'='*60}")
    if all_methods:
        for kind, name in sorted(all_methods):
            print(f"  {kind}={name}")
    else:
        print("  （未抓到任何 method=/id= 请求）")

    # ── 报告 2：K 线请求详情 ──
    print(f"\n{'='*60}")
    print("【2】K 线请求详情（period 周期 / datatype 字段 / fuquan 复权）")
    print(f"{'='*60}")
    if not kline_reqs:
        print("✗ 未抓到疑似 K 线请求")
        print("  可能原因：")
        print("    ① 没在同花顺里打开 K 线图 / 切换周期")
        print("    ② K 线不走 8901（可能走 8902/9602，需改抓包端口重抓）")
        print("    ③ 选错网卡")
        print("  建议：重抓时务必打开股票 K 线图，切换 日K/周K/月K/5分K")
        # 仍导出响应字节供离线分析
        _dump_responses(streams, pcap_path)
        return

    # 按 (method/id, period/DateTime周期, code, fuquan) 去重展示
    seen = set()
    unique_reqs = []
    for sid, info, sframes in kline_reqs:
        key = (info.get("method") or info.get("id"),
               info.get("period") or info.get("datetime_period"),
               info.get("code") or info.get("codelist"),
               info.get("fuquan") or info.get("reqfuquan"),
               info.get("datetime_offset"),
               info.get("datetime_end"))
        if key in seen:
            continue
        seen.add(key)
        unique_reqs.append((sid, info, sframes))

    print(f"\n抓到 {len(kline_reqs)} 个 K 线请求（去重后 {len(unique_reqs)} 种）\n")
    for i, (sid, info, sframes) in enumerate(unique_reqs, 1):
        print(f"{'─'*60}")
        print(f"【请求 {i}】stream={sid}")
        m = info.get("method") or f"id={info.get('id')}"
        print(f"  类型: {m}")
        if "period" in info:
            pn = info.get("period_name", "?")
            print(f"  ★ period = {info['period_raw']} → {pn}")
        if "datetime_period" in info:
            pn = info.get("datetime_period_name", "?")
            print(f"  ★ DateTime = {info['datetime_period']}(0x{info['datetime_period']:x}) → {pn}"
                  f"  窗口=({info.get('datetime_offset','?')}-{info.get('datetime_end','?')})")
            if info.get("datetime_end") not in (None, "0"):
                print(f"      ← 窗口终点非 0：这是翻页加载更早历史的请求！")
        if "pageid" in info:
            print(f"  pageid = {info['pageid']}"
                  + ("（K线图页面）" if info["pageid"] == "9355" else ""))
        if "datatype" in info:
            dts = info["datatype"].split(",")
            annotated = [f"{d}={KLINE_FIELDS.get(int(d), '?')}" if d.isdigit()
                         else d for d in dts]
            print(f"  datatype = {info['datatype']}")
            print(f"           含义: {annotated}")
        if "code" in info:
            print(f"  code = {info['code']}")
        if "codelist" in info:
            print(f"  codelist = {info['codelist']}")
        if "market" in info:
            print(f"  market = {info['market']}")
        if "fuquan" in info:
            fuq = info["fuquan"]
            fuq_desc = {"Q": "前复权", "H": "后复权", "(空)": "不复权"}.get(fuq, "?")
            print(f"  ★ fuquan = {fuq!r} → {fuq_desc}")
        if "reqfuquan" in info:
            fuq = info["reqfuquan"]
            fuq_desc = {"Q": "前复权", "H": "后复权", "(空)": "不复权"}.get(fuq, "?")
            print(f"  ★ ReqFuquan = {fuq!r} → {fuq_desc}（PC 版复权字段）")
        if "start" in info:
            print(f"  start = {info['start']}（负数=从最近往回取 count 根）")
        if "count" in info:
            print(f"  count = {info['count']}")

        # ── 配对响应，解码 K 线数据 ──
        kline_resp = None
        for sf in sframes:
            # 尝试解码含 OHLC 字段的 hd 帧
            result = _decode_kline_response(sf, info.get("datatype", ""))
            if result and result["records"]:
                kline_resp = result
                break
        if kline_resp:
            print(f"\n  ── 响应解码 [{kline_resp['tag']}] ──")
            print(f"  字段表 dt 编号: {kline_resp['all_dts']}")
            print(f"  K 线记录数: {len(kline_resp['records'])}")
            # 打印前 5 根 K 线
            print(f"  前 5 根 K 线:")
            for rec in kline_resp["records"][:5]:
                parts = []
                for k in sorted(rec.keys(),
                                key=lambda x: int(x[2:]) if x.startswith("dt") and x[2:].isdigit() else -1):
                    v = rec[k]
                    name = KLINE_FIELDS.get(int(k[2:]), "") if k.startswith("dt") else ""
                    if isinstance(v, float):
                        parts.append(f"{name or k}={v:.2f}")
                    else:
                        parts.append(f"{name or k}={v}")
                print(f"    {'  '.join(parts)}")
        else:
            # 没解出 K 线记录，看响应帧类型
            hd_frames = [f for f in sframes if b"hd1.0" in f or b"hd3.1" in f]
            if hd_frames:
                print(f"\n  响应: {len(hd_frames)} 个 hd 帧（未解出 OHLC，"
                      f"可能字段表不含 dt7/8/9/11，或解码链不适用）")
                hf = hd_frames[0]
                tag = "hd3.1" if b"hd3.1" in hf else "hd1.0"
                # 打印字段表
                _print_field_table(hf, tag)
            else:
                mt = [f for f in sframes if b"MarketTime" in f]
                if mt:
                    print(f"\n  响应: 仅 MarketTime 文本帧（K 线数据可能未返回）")
                else:
                    print(f"\n  响应: 无 hd 数据帧（{len(sframes)} 个其他帧）")
        print()

    # ── 报告 3：汇总 ──
    print(f"\n{'='*60}")
    print("【3】K 线协议汇总")
    print(f"{'='*60}")
    # 周期：合并 period(Mac) 和 datetime_period(PC)
    periods = sorted(set(r[1].get("period") for r in unique_reqs
                         if isinstance(r[1].get("period"), int))
                     | set(r[1].get("datetime_period") for r in unique_reqs
                           if isinstance(r[1].get("datetime_period"), int)))
    print(f"  出现的周期码: {[hex(p) if isinstance(p, int) else p for p in periods]}")
    names = (set(r[1].get("period_name") for r in unique_reqs if "period_name" in r[1])
             | set(r[1].get("datetime_period_name") for r in unique_reqs
                   if "datetime_period_name" in r[1]))
    print(f"  对应周期: {sorted(names)}")
    fuquans = sorted((set(r[1].get("fuquan") for r in unique_reqs if "fuquan" in r[1])
                      | set(r[1].get("reqfuquan") for r in unique_reqs if "reqfuquan" in r[1])))
    print(f"  出现的复权值: {fuquans}")
    methods = sorted(set(r[1].get("method") or f"id={r[1].get('id')}" or "CodeList(PC)"
                         for r in unique_reqs))
    print(f"  请求格式: {methods}")

    _dump_responses(streams, pcap_path)


def _print_field_table(hf, tag):
    """打印 hd 帧的字段表（dt/fmt/width）。"""
    pos = hf.find(tag.encode() + b"\x00")
    if pos < 0:
        pos = hf.find(tag.encode())
    if pos < 0:
        return
    base = pos + len(tag) + 1
    if base + 10 > len(hf):
        return
    try:
        dc = struct.unpack("<I", hf[base:base+4])[0]
        hs = struct.unpack("<H", hf[base+6:base+8])[0]
        fc = struct.unpack("<H", hf[base+8:base+10])[0]
    except Exception:
        return
    if not (0 < fc < 100):
        return
    ft = hf[base+10:base+10+fc*4]
    if len(ft) < fc*4:
        return
    print(f"    字段表 (dc={dc} hs={hs} fc={fc}):")
    for i in range(fc):
        dt, fmt, fl, w = ft[i*4], ft[i*4+1], ft[i*4+2], ft[i*4+3]
        name = KLINE_FIELDS.get(dt, f"dt{dt}")
        print(f"      dt={dt:>4} fmt=0x{fmt:02x} width={w}  ({name})")


def _dump_responses(streams, pcap_path):
    """导出每个 stream 的服务器响应原始字节（供离线搜数字）。"""
    print(f"\n{'='*60}")
    print("【响应原始字节导出】（供离线搜 OHLC 数字定位字段用）")
    print(f"{'='*60}")
    exported = 0
    for sid, client_bytes, server_bytes in streams:
        if len(server_bytes) < 50:
            continue
        out_path = pcap_path.replace('.pcap', f'_resp_stream{sid}.bin')
        with open(out_path, 'wb') as f:
            f.write(server_bytes)
        # 统计含 hd 帧的
        nframes = server_bytes.count(MAGIC)
        has_hd = b"hd1.0" in server_bytes or b"hd3.1" in server_bytes
        hd_mark = " [含 hd 帧 ★]" if has_hd else ""
        print(f"  stream {sid}: {len(server_bytes)}B, {nframes} 帧{hd_mark} → {os.path.basename(out_path)}")
        exported += 1
    if exported == 0:
        print("  （无响应数据）")


def main():
    ap = argparse.ArgumentParser(description="抓同花顺 K 线请求/响应，逆向数据格式")
    ap.add_argument("--duration", type=int, default=120, help="抓包时长（秒）")
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包，直接分析指定 pcap 文件")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only)
        return

    iface = pick_interface()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"kline_{ts}.pcap")

    capture(iface, args.duration, pcap_path)
    analyze(pcap_path)

    print(f"\n{'='*60}")
    print(f"pcap 已保存: {pcap_path}")
    print(f"重新分析: py tests/capture_kline.py --analyze-only \"{pcap_path}\"")


if __name__ == "__main__":
    main()
