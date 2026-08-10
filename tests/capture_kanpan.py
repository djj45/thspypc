#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端「看盘主界面」全流量（8901 + 9601），自动分析「看盘界面
还有哪些协议没实现」。

看盘主界面布局（用户描述）::

    ┌─────────────┬───────────────────────┐
    │ 左·板块列表 │ 中上·分时 / 中下·K线 │
    │ 左·全市场股 ├───────────┬───────────┤
    │ 左·自选板块 │ 右上·盘口 │ 右下·短线 │
    │ 左·动态板块 │           │     精灵  │
    └─────────────┴───────────┴───────────┘

核心价值：内置「已知协议识别器」，对每个客户端请求帧用
(pageid + route + DateTime-period + DataType 头) 四元组判断，报告里逐帧标注
「✅ 已实现 / ❌ 未实现(缺口) / ❓ 未知协议」，帮你定位看盘界面还有哪些
协议没实现。

抓的是**被动监听 hexin.exe 的真实流量**，不需要账号/THSClient。

⚠ 看盘界面各区域的最佳抓包时段：
  · 分时/K线/盘口/板块：随时可抓（查的是当前行情/历史）
  · 短线精灵实时推送（9601 pushrealorder）：**必须盘中**（9:30-15:00）
  · 逐笔成交回放（pageid=4260）：盘中或盘后都可（查的是全天逐笔）

用法
----
    py tests/capture_kanpan.py                      # 默认 240s，交互选网卡
    py tests/capture_kanpan.py --duration 300
    py tests/capture_kanpan.py --duration 210 --iface 4
    py tests/capture_kanpan.py --stop-file captures_live/STOP   # 中途叫停
    py tests/capture_kanpan.py --analyze-only captures_live/xxx.pcap
    py tests/capture_kanpan.py --account level2     # 报告里的账号提示

操作步骤（严格按阶段做，阶段之间停 2-3 秒）：
    0. 启动同花顺并登录（Level2 账号最佳）
    1. 运行本脚本，选网卡
    2. 抓包期间按【看盘界面 7 区域】逐个操作：
       A【左·板块列表】  左侧导航切【板块】→ 行业/概念列表上下滚动各一次
       B【左·全市场个股】切【沪深A股】全市场列表 → 点表头 涨幅/换手/量比 排序
       C【中上·分时】    点一只个股看当日分时 → 按 ← 翻 1-2 个历史日期
       D【中下·K线】     切到 K 线 → 按 F8 切 1分/5分/15分/日/周/月 等周期
       E【右上·盘口】★重点★ 打开盘口面板，逐个点子标签：
                         五档→逐笔成交明细→委托队列→大盘买卖力→大单统计
                         （每个停 3 秒）← 逐笔成交/委托队列是路线图缺口！
       F【右下·短线精灵】切到短线精灵 → 滚动几下 → 改一次异动阈值
       G【收尾】         回到个股不动 30 秒（抓实时推送）
    3. 抓够后等待自动结束，脚本输出分析报告 + dump 未知帧样本

产物：captures_live/kanpan_<时间戳>.pcap +
      kanpan_unknown_<pageid>_<route>_<ts>.bin（未知帧样本，供离线逆向）
"""
import argparse
import datetime
import os
import re
import socket
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

from thspypc.protocol import (  # noqa: E402
    parse_history_timeline_response,
    parse_kline_hd3_response,
    parse_stock_list_response,
)

# ── Wireshark 路径探测（与 capture_system_blocks.py 一致）──
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
PCAP_DIR = str(ROOT / "captures_live")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901/9601 通用帧分隔符（protocol.py:29 FRAME_MAGIC）

# 已知行情/短线精灵服务器（抓包 IP 标注用；非穷尽，IP 会轮换）
MARKET_HOSTS = {
    "122.9.202.190", "122.9.125.190", "116.63.108.136",
    "8.134.98.163", "121.37.31.87", "8.138.46.177", "8.145.212.55",
}
REALORDER_HOSTS = {"106.14.65.90"}  # 9601 短线精灵

# 板块指数代码前缀（行业 881xxx；概念 885xxx/30xxxx）
BOARD_CODE_PREFIXES = ("881", "885", "301", "302", "303", "304", "305",
                       "306", "307", "308", "309")


# =============================================================================
# 协议识别器字典（来自代码探索：protocol.py / features/*_protocol.py /
# services/system_blocks.py / docs/ 各 HANDOFF）
# =============================================================================
# pageid → (中文标签, 实现状态)  状态: "ok"/"gap"/"unknown"
# pageid 在子帧头无固定偏移，但作为 GBK 文本行 pageid=NNNN 出现，可直接 re 提取。
KNOWN_PAGEIDS: dict[str, tuple[str, str]] = {
    # ── 个股行情（MAIN 主通道）──
    "1333": ("个股五档盘口(depth_quote)", "ok"),
    "1334": ("排行榜/涨跌幅榜(stock_list_hot)", "ok"),
    "1335": ("个股列表行情(list_quotes)", "ok"),
    "9354": ("当日分时/集合竞价(普通)", "ok"),
    "9355": ("历史分时/K线/历史竞价(普通)", "ok"),
    # ── L2 通道（pageid 复用，靠 period+route+DataType 区分）──
    "4214": ("L2通道:分时/十档盘口/竞价/逐tick推送", "ok"),
    "4417": ("L2历史分时/历史竞价", "ok"),
    # ── 指数 ──
    "77":   ("指数历史分时/指数分笔tick(4096)/指数日K", "ok"),
    "6240": ("指数当日分时/指数竞价(T_URL)", "ok"),
    # ── 系统板块（fu4 通道，普通/L2 各一套）──
    "5716": ("板块列表/全代码表/subreal(L2)", "ok"),
    "6000": ("板块成分股/分时/竞价(L2)", "ok"),
    "6002": ("板块历史分时/K线/竞价(L2)", "ok"),
    "392":  ("板块列表/全量行情(普通)", "ok"),
    "4180": ("板块成分股/分时(普通)", "ok"),
    "4181": ("板块历史分时/K线/竞价(普通)", "ok"),
    "1341": ("subreal实时订阅(板块)", "ok"),
    # 2026-08-07 双账号抓包：94 热点板块页面（Level2 0x0053/0x0153 路由族，
    # 普通 0x003A/0x013A；响应为 hd3.1 紧凑表，board_hot 已实现离线部分）
    "12480": ("热点板块(94, pageid=12480, hot_boards)", "ok"),
}
# 已知缺口 pageid（路线图/ HANDOFF 标注未实现，但协议已部分破解）
GAP_PAGEIDS: dict[str, str] = {
    "4260": "逐笔成交回放/超级盘口(period=7169, HANDOFF_SUPERORDER_20260726)",
}

# 已知 route（子帧头 LE16，单子帧偏移 11，双子帧查询子帧偏移 10）。
# route = 页面组件实例号，0x0100|base 是查询子帧常见派生。
KNOWN_ROUTES: set[int] = {
    0x0001,  # list_quotes / K线(日线以下) / 十档盘口(L2单子帧)
    0x001c,  # 五档盘口(嵌套外层)
    0x0021,  # 板块历史(普通)
    0x0039,  # 板块列表(旧路由, 08-01)
    0x0041,  # 板块分时(普通)
    0x0044,  # 成分股(普通) route_base
    0x0052,  # 板块列表/全量行情(L2)
    0x0058,  # L2历史分时(深市前缀)
    0x005c,  # 成分股(L2) route_base
    0x0067,  # 指数竞价(深)
    0x006c,  # 板块列表/全量行情(普通) / 历史分时(普通)前缀
    0x007a,  # 稀疏历史分时(0x7A)
    0x007c,  # L2历史分时(沪市前缀)
    0x0100,  # 全代码表 / 集合竞价(普通) / 板块各类查询子帧基址
    0x010a,  # 分时9354主请求
    0x0139,  # 板块列表查询(旧路由派生)
    0x014e,  # K线(周线及以上)
    0x0152,  # 板块列表/全量行情(L2查询子帧)
    0x0156,  # 排行榜 stock_list
    0x015a,  # 板块历史分时
    0x016c,  # 板块列表/历史分时(普通查询子帧)
    0x017d,  # 板块历史分时
    0x01fc,  # L2集合竞价(4214)
    0x0201,  # L2分时(4214)
}

# 看盘界面 7 区域（用于「区域 ↔ 协议映射」报告）
PANEL_AREAS = {
    "A": "左·板块列表",
    "B": "左·全市场个股",
    "C": "中上·分时",
    "D": "中下·K线",
    "E": "右上·盘口(★缺口重点)",
    "F": "右下·短线精灵",
    "G": "收尾·实时推送",
}


# =============================================================================
# 标准件（网卡交互 / 抓包 / tshark 提字段 / 帧切分）
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
    """交互选网卡，默认 WLAN。"""
    ifaces = list_interfaces()
    if not ifaces:
        print(f"✗ 未检测到网卡（检查 Wireshark/Npcap 是否安装）: {TSHARK}")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"),
                   next((n for n, (_, d) in ifaces.items()
                         if "WLAN" in d or "以太网" in d), list(ifaces.keys())[0]))
    while True:
        choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
        if choice in ifaces:
            return choice, ifaces[choice][1]


def capture(iface, duration, pcap_path, stop_file=None):
    """抓 8901+9601 全流量 duration 秒。"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    if stop_file and os.path.exists(stop_file):
        try:
            os.unlink(stop_file)
        except OSError:
            pass
    print(f"\n{'='*70}")
    print(f"开始抓包 {duration}s（8901 + 9601，网卡 {iface}）")
    print(f"{'='*70}")
    print(">>> 抓包期间按【看盘界面 7 区域】逐个操作（阶段间停 2-3 秒）：")
    print("  A【左·板块列表】  导航切【板块】→ 行业/概念列表上下滚动各一次")
    print("  B【左·全市场个股】切【沪深A股】→ 点表头 涨幅/换手/量比 排序")
    print("  C【中上·分时】    点个股看当日分时 → 按 ← 翻 1-2 个历史日期")
    print("  D【中下·K线】     切 K 线 → 按 F8 切 1分/5分/15分/日/周/月 周期")
    print("  E【右上·盘口】★重点★ 打开盘口面板逐个点子标签：")
    print("                     五档→逐笔成交明细→委托队列→大盘买卖力→大单统计")
    print("                     （每个停 3 秒）← 逐笔成交/委托队列是缺口！")
    print("  F【右下·短线精灵】切短线精灵 → 滚动几下 → 改一次异动阈值")
    print("  G【收尾】         回到个股不动 30 秒（抓实时推送）")
    if stop_file:
        print(f"  中途叫停：创建 {stop_file} 即可提前结束（脚本每 1 秒检查一次）")
    print("-" * 70)
    proc = subprocess.Popen(
        [DUMPCAP, "-i", iface, "-f", "tcp port 8901 or tcp port 9601",
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


def _tshark(pcap_path, y_filter, fields):
    """跑 tshark 提取字段，返回解码后的 stdout 文本。"""
    cmd = [TSHARK, "-r", pcap_path, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _split_frames(stream_bytes: bytes):
    """把 TCP payload 按 fdfdfdfd 切成 [body 列表]（去掉 8B ASCII 长度头）。"""
    out = []
    for sub in stream_bytes.split(MAGIC):
        if len(sub) >= 8:
            out.append(sub[8:])
    return out


def _collect_client_frames(pcap_path):
    """收集客户端发出的帧（dstport 8901/9601）。
    返回 [(frame, t, dst, dport, stream, body), ...]。"""
    out = _tshark(
        pcap_path,
        "(tcp.dstport==8901 or tcp.dstport==9601) and tcp.payload",
        ["frame.number", "frame.time_relative", "ip.dst",
         "tcp.dstport", "tcp.stream", "tcp.payload"],
    )
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


def _collect_server_frames(pcap_path):
    """收集服务器返回的帧（srcport 8901/9601）。"""
    out = _tshark(
        pcap_path,
        "(tcp.srcport==8901 or tcp.srcport==9601) and tcp.payload",
        ["frame.number", "frame.time_relative", "ip.src",
         "tcp.srcport", "tcp.stream", "tcp.payload"],
    )
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


def _try_parse_dc(body: bytes, pos: int):
    """从 hd3.1 头解析 dc（记录数），返回单个可信值或 None。
    逻辑同 capture_market_open.py：先按 flag==0x0100 校验 LE16，否则退回 LE32。"""
    if len(body) < pos + 4:
        return None
    dc16 = struct.unpack("<H", body[pos:pos + 2])[0]
    flag = struct.unpack("<H", body[pos + 2:pos + 4])[0]
    if flag == 0x0100 and 0 < dc16 < 6000:
        return dc16
    dc32 = struct.unpack("<I", body[pos:pos + 4])[0]
    if 0 < dc32 < 10000:
        return dc32
    return None


# =============================================================================
# 协议识别器
# =============================================================================

def _extract_pageid(text: str) -> str:
    """从帧文本提取 pageid（最稳，业务请求都带 pageid=N 文本行）。"""
    m = re.search(r"pageid=(\d+)", text)
    return m.group(1) if m else ""


def _extract_route(body: bytes):
    """提取 route（子帧头 LE16）。单子帧(0x09头)偏移 11，双子帧偏移 10。
    返回 "0xXXXX" 或 ""。两种偏移都试，取已知 route 优先，否则都返回供报告判断。"""
    candidates = []
    # 单子帧：body[0]=0x09，route 在 body[11:13]
    if len(body) >= 13 and body[0:1] == b"\x09":
        r11 = int.from_bytes(body[11:13], "little")
        candidates.append(r11)
    # 双子帧：body[0:4]=00 16 00 00，route 在 body[10:12]
    if len(body) >= 12 and body[0:4] == b"\x00\x16\x00\x00":
        r10 = int.from_bytes(body[10:12], "little")
        candidates.append(r10)
    # 优先返回已知 route；否则返回第一个非零
    for r in candidates:
        if r in KNOWN_ROUTES:
            return r
    for r in candidates:
        if r:
            return r
    return 0


def _extract_period(text: str) -> str:
    """提取 DateTime=NNNN 的 period（如 8192=当日分时, 7169=逐笔回放）。"""
    m = re.search(r"DateTime=(\d+)", text)
    return m.group(1) if m else ""


def _extract_datatype(text: str) -> str:
    """提取 DataType= 头（截前 40 字符）。"""
    m = re.search(r"DataType=([\d,\[\]~\-|]+)", text)
    return m.group(1)[:40] if m else ""


def _is_8901_heartbeat(body: bytes) -> bool:
    """8901 心跳：subtype hdr[7:11]==12 00 03 00，或文本含 tsi0=/tc=。"""
    if len(body) < 11:
        return False
    if body[7:11] == b"\x12\x00\x03\x00":
        return True
    text = body.decode("gbk", errors="replace")
    return ("tsi0=" in text) or ("tc=" in text and "10," in text)


def _is_9601_heartbeat(body: bytes) -> bool:
    """9601 心跳：5 字节 body，[0]=0x09，[4]=0x07。"""
    return len(body) == 5 and body[0] == 0x09 and body[4] == 0x07


def _classify_text_method(text: str) -> str:
    """按帧文本的 method=/动作关键词分类（pageid 提取不到时的补充判断）。
    返回非空字符串=已分类（infra 或 unknown-text 二选一），返回 None=交给 pageid 流程。"""
    if "method=pushrealorder" in text:
        return "pushrealorder-ack(9601)"
    if "method=subrealorder" in text:
        return "subrealorder(9601订阅)"
    if "method=subreal" in text:
        return "subreal(8901订阅)"
    if "method=qurealorder" in text:
        return "qurealorder(短线精灵历史查询)"
    if "method=statscalc" in text:
        return "statscalc(板块统计计算,9601独立节点)"
    if "method=calcext" in text:
        return "calcext(板块扩展计算,9601 REALORDER节点)"
    if "method=" in text and "method=s" not in text:
        # 其他 method= 开头的纯文本协议（非 sub/stats/qureal）
        m = re.search(r"method=(\w+)", text)
        if m:
            return f"{m.group(1)}(纯文本协议,未知)"
    if "StockLinkVer=" in text and "C-Version=" in text:
        return "init(启动初始化)"
    if "upstockname" in text.lower() or "StockNameVer=" in text:
        return "upstockname(名称同步)"
    return ""


def identify_frame(body: bytes) -> dict:
    """识别一个客户端请求帧，返回:
    {pageid, route, period, datatype, method, status, label, area, raw_text}
    status: "ok" | "gap" | "unknown" | "infra"(心跳/init/subreal等基础设施) | "text"
    """
    text = body.decode("gbk", errors="replace")
    info = {
        "pageid": _extract_pageid(text),
        "route": _extract_route(body),
        "period": _extract_period(text),
        "datatype": _extract_datatype(text),
        "method": "",
        "status": "unknown",
        "label": "",
        "area": "",
        "raw_text": text,
        "raw_body": body,   # 原始子帧字节（供 dump / hex 展示）
    }

    # 1) 基础设施类（心跳/init/subreal/名称同步）
    if _is_8901_heartbeat(body) or _is_9601_heartbeat(body):
        info["status"] = "infra"
        info["label"] = "心跳"
        return info
    method_label = _classify_text_method(text)
    if method_label:
        info["method"] = method_label
        # 已实现的基础设施/业务 vs 未知纯文本协议
        # statscalc/calcext 已实现（BoardStatsService，见 features/board_stats_protocol.py）
        if "未知" in method_label:
            info["status"] = "unknown"
        else:
            info["status"] = "infra"
        info["label"] = method_label
        # 归区：subreal→G(推送)；板块统计 calc→A(板块)；其余不定
        if "subreal" in method_label:
            info["area"] = "G"
        elif "statscalc" in method_label or "calcext" in method_label:
            info["area"] = "A"
        return info

    # 2) 纯文本帧（无 pageid、无子帧头），兜底标 text
    if not info["pageid"] and body[:1] != b"\x09" and body[0:4] != b"\x00\x16\x00\x00":
        info["status"] = "text"
        info["label"] = "文本帧(无pageid)"
        return info
    # 9601 等纯文本帧（\x09 开头但无 pageid 也无 method）—— 多为短线精灵控制帧
    if not info["pageid"] and body[:1] == b"\x09" and "method=" not in text \
            and "instid=" not in text:
        info["status"] = "infra"
        info["label"] = "控制/确认帧(9601短线精灵)"
        info["area"] = "F"
        return info

    # 3) pageid 驱动的业务识别
    pid = info["pageid"]
    if pid:
        if pid in GAP_PAGEIDS:
            info["status"] = "gap"
            info["label"] = GAP_PAGEIDS[pid]
        elif pid in KNOWN_PAGEIDS:
            label, status = KNOWN_PAGEIDS[pid]
            info["status"] = status
            info["label"] = label
        else:
            info["status"] = "unknown"
            info["label"] = f"新 pageid={pid}（未知协议，需逆向）"
        if pid == "4214":
            period_labels = {
                "7169": "逐笔成交回放",
                "7170": "买撤全量明细",
                "7171": "卖撤全量明细",
                "7173": "买一委托队列",
                "7174": "卖一委托队列",
                "7175": "挂单全量明细",
            }
            if info["period"] in period_labels:
                info["status"] = "ok"
                info["label"] = (
                    f"4214 {period_labels[info['period']]}"
                    f"(period={info['period']})"
                )
        info["area"] = _pageid_to_area(pid, info)
    else:
        # 有子帧头但无 pageid 文本 —— 可能是新协议
        info["status"] = "unknown"
        info["label"] = "子帧无pageid文本(疑似新协议)"

    # 4) route 未知标注（仅对真正未知协议才提示；已知 pageid 的 route 是会话内
    #    动态实例号，不是协议常量，标了会造成海量误报）
    if info["status"] == "unknown" and info["route"] and info["route"] not in KNOWN_ROUTES:
        info["route_unknown"] = True
    return info


def _pageid_to_area(pid: str, info: dict) -> str:
    """pageid → 看盘界面区域（A-G）。E=盘口(重点缺口区)。"""
    if pid in ("392", "5716"):           # 板块列表
        return "A"
    if pid in ("1334", "1335", "5716") and info.get("datatype", "").startswith("199"):
        return "B"                       # 排行榜/代码表翻页
    if pid in ("9354", "4214", "77", "6240"):  # 分时
        period = info.get("period", "")
        # 4214 period 7169 = 逐笔回放 → 盘口 E；8192=分时 → C
        if period in ("7169", "7170", "7171", "7173", "7174", "7175"):
            return "E"
        return "C"
    if pid == "9355":                    # K线/历史分时
        return "D"
    if pid == "4260":                    # 逐笔回放
        return "E"
    if pid in ("4180", "6000", "4181", "6002", "1341"):  # 板块成分股/历史
        return "A"
    if pid == "1333":                    # 五档盘口
        return "E"
    return ""


def _ip_role(ip: str, port: str) -> str:
    """按 IP/端口标注服务角色（粗判，IP 会轮换）。"""
    if port == "9601" or ip in REALORDER_HOSTS:
        return "9601短线精灵"
    if ip in MARKET_HOSTS:
        return "行情(MAIN?)"
    # 尝试 DNS 反查 fu4/shlv2/szlv2/main（带超时，失败即跳过）
    try:
        name = socket.gethostbyaddr(ip)[0].lower()
    except (socket.herror, socket.gaierror, OSError):
        name = ""
    if "fu4" in name:
        return "fu4板块网关"
    if "shlv2" in name:
        return "shlv2沪L2"
    if "szlv2" in name:
        return "szlv2深L2"
    if "main" in name or "ifindhq" in name:
        return "main行情"
    return ""


# =============================================================================
# 分析报告各章节
# =============================================================================

def _section_overview(pcap_path, account: str):
    """【0】连接概览。"""
    print(f"\n{'='*70}")
    print("【0】连接概览（8901 + 9601）")
    print(f"{'='*70}")
    out = _tshark(pcap_path, "tcp.payload",
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
        print("  ✗ 未抓到任何 TCP 流量 — 可能没启动同花顺，或选错网卡")
        return
    notes = {"8901": "← 行情/鉴权/代码表/盘口/板块/分时/K线", "9601": "← 短线精灵"}
    for port in sorted(port_ips.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
        ips = sorted(port_ips[port])
        shown = []
        for ip in ips:
            role = _ip_role(ip, port)
            tag = f"({role})" if role else ""
            shown.append(f"{ip}{tag}")
        print(f"  端口 {port}: {len(ips)} 个IP {shown[:6]} {notes.get(port, '')}")

    # SYN 时间线
    out = _tshark(pcap_path, "tcp.flags.syn==1 and tcp.flags.ack==0",
                  ["frame.number", "frame.time_relative", "ip.dst",
                   "tcp.dstport", "tcp.stream"])
    conns = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 5:
            conns.append((p[0], float(p[1] or 0), p[2], p[3], p[4]))
    conns.sort(key=lambda x: x[1])
    by_port = Counter(c[3] for c in conns)
    if conns:
        print(f"\n  共 {len(conns)} 个 SYN：8901={by_port.get('8901',0)} "
              f"9601={by_port.get('9601',0)}")
        ip_n = Counter(c[2] for c in conns)
        for ip, n in ip_n.most_common(8):
            role = _ip_role(ip, "8901")
            tag = f" [{role}]" if role else ""
            print(f"    {ip}{tag}: {n} 次连接")
        print(f"\n  SYN 时间线（前 15）:")
        for fr, t, dip, dport, stream in conns[:15]:
            print(f"    帧{fr} t={t:.3f}s {dip}:{dport} stream={stream}")
    else:
        print("  ✗ 未抓到 SYN（可能走了已建立的长连接，或抓包窗口不含建连）")

    if account == "normal":
        print("\n  ℹ 当前标注为普通账号：L2 专属协议（4214十档/4260逐笔/4417）抓不到，")
        print("    报告中若出现这些 pageid 的『未知』标注，可能是普通账号无权限所致。")


def _section_area_mapping(client_frames):
    """【1】看盘区域 ↔ 协议映射。"""
    print(f"\n{'='*70}")
    print("【1】看盘区域 ↔ 协议映射（看盘界面 7 区域各发了多少帧）")
    print(f"{'='*70}")
    area_frames = defaultdict(list)
    for fr, t, dip, dport, stream, body in client_frames:
        info = identify_frame(body)
        if info["status"] == "infra":   # 心跳/init 不计入区域
            continue
        area = info["area"] or "?"
        area_frames[area].append((fr, t, dip, stream, info))

    for code in ["A", "B", "C", "D", "E", "F", "G"]:
        name = PANEL_AREAS[code]
        items = area_frames.get(code, [])
        if not items:
            mark = " ★缺口重点（务必操作盘口子标签）" if code == "E" else ""
            print(f"  {code} {name}: ✗ 无流量{mark}")
            continue
        # 该区域涉及的 pageid/状态分布
        pids = Counter(i["pageid"] or "(无)" for _, _, _, _, i in items)
        stats = Counter(i["status"] for _, _, _, _, i in items)
        stat_str = " ".join(f"{s}={n}" for s, n in stats.most_common()
                            if s != "infra")
        mark = " ★" if code == "E" else ""
        print(f"  {code} {name}: {len(items)} 帧 [{stat_str}]{mark}")
        for pid, n in pids.most_common():
            label = next((i["label"] for _, _, _, _, i in items
                          if i["pageid"] == pid), "")
            print(f"        pageid={pid} ×{n}  {label}"[:100])
    unk = area_frames.get("?", [])
    if unk:
        print(f"  ? 未归区: {len(unk)} 帧（pageid/特征无法对应到 7 区域）")


def _section_known_identify(client_frames, account: str):
    """【2】已知协议识别（识别器核心）。"""
    print(f"\n{'='*70}")
    print("【2】已知协议识别（pageid+route+period 四元组判断）")
    print(f"{'='*70}")
    rows = []
    for fr, t, dip, dport, stream, body in client_frames:
        info = identify_frame(body)
        if info["status"] == "infra":
            continue
        rows.append((fr, t, dip, dport, stream, info))

    # 按状态分组统计
    by_status = defaultdict(list)
    for row in rows:
        by_status[row[5]["status"]].append(row)

    icons = {"ok": "✅", "gap": "❌", "unknown": "❓", "text": "📄"}
    for status in ("ok", "gap", "unknown", "text"):
        items = by_status.get(status, [])
        if not items:
            continue
        icon = icons.get(status, "?")
        title = {"ok": "已实现", "gap": "未实现(缺口)", "unknown": "未知协议",
                 "text": "文本帧"}[status]
        print(f"\n  {icon} {title}：{len(items)} 帧")
        # 去重按 (pageid, route, period)
        seen = {}
        for fr, t, dip, dport, stream, info in items:
            key = (info["pageid"], info["route"], info["period"])
            if key not in seen:
                seen[key] = (fr, t, dip, stream, info)
        for key, (fr, t, dip, stream, info) in seen.items():
            pid, route, period = key
            route_str = f"route=0x{route:04X}" if route else "route=-"
            ru = " ⚠未知route" if info.get("route_unknown") else ""
            period_str = f"period={period}" if period else ""
            line = (f"      帧{fr} t={t:.2f}s dst={dip} stream={stream} "
                    f"pageid={pid or '-'} {route_str}{ru} {period_str}")
            print(line[:110])
            print(f"          → {info['label']}")
            if info["datatype"]:
                print(f"          DataType≈{info['datatype']}")
            # gap/unknown 额外提示
            if status == "gap" and pid == "4260":
                print("          ★ 这是看盘『右上盘口·逐笔成交明细』的协议，路线图缺口")
                print("          参考 docs/handoffs/HANDOFF_SUPERORDER_20260726.md")
            if status == "unknown":
                print("          ★ 需逆向：dump 本帧样本，对照响应表格式")


def _section_gaps(client_frames, server_frames, account: str, pcap_path: str):
    """【3】缺口/未知协议发现（重点章节）+ dump 样本。"""
    print(f"\n{'='*70}")
    print("【3】缺口/未知协议发现（★最值得关注）")
    print(f"{'='*70}")

    unknowns = []
    gaps = []
    new_routes = set()
    for fr, t, dip, dport, stream, body in client_frames:
        info = identify_frame(body)
        if info["status"] == "infra":
            continue   # 心跳/init/subreal 的 route 从文本字节误解析，不计入
        if info["status"] == "unknown":
            unknowns.append((fr, t, dip, dport, stream, info))
        elif info["status"] == "gap":
            gaps.append((fr, t, dip, dport, stream, info))
        if info.get("route_unknown") and info["route"]:
            new_routes.add(info["route"])

    # 3a) 缺口协议（已知 pageid 但未实现）
    if gaps:
        print(f"\n  【3a】已知缺口协议（路线图标注未实现，已抓到真实请求）：{len(gaps)} 帧")
        seen = set()
        for fr, t, dip, dport, stream, info in gaps:
            key = (info["pageid"], info["period"])
            if key in seen:
                continue
            seen.add(key)
            print(f"    pageid={info['pageid']} period={info['period']} "
                  f"route=0x{info['route']:04X} → {info['label']}")
        print("    → 这些是 thspypc 当前未实现的功能，抓到了真实请求字节，")
        print("      可据此逆向补全。dump 样本见本节末尾。")
    else:
        print("\n  【3a】已知缺口协议：✗ 未抓到（4260 逐笔回放等）")
        if account == "level2":
            print("      你用的是 Level2 账号，应在【E 盘口】操作时点『逐笔成交明细』")
            print("      子标签才会触发 pageid=4260。如果没点到，重抓一次。")

    # 3b) 全新未知 pageid
    if unknowns:
        print(f"\n  【3b】全新未知 pageid/协议：{len(unknowns)} 帧 ★★★")
        seen = {}
        for fr, t, dip, dport, stream, info in unknowns:
            key = info["pageid"] or f"nopid_{fr}"
            if key not in seen:
                seen[key] = (fr, t, dip, stream, info)
        for key, (fr, t, dip, stream, info) in seen.items():
            route_str = f"route=0x{info['route']:04X}" if info["route"] else "route=-"
            print(f"\n    ▶ pageid={key} {route_str} period={info['period'] or '-'}")
            print(f"      帧{fr} t={t:.2f}s dst={dip} stream={stream}")
            print(f"      → {info['label']}")
            # 打印帧文本（截断）+ hex 前 80 字节
            txt = info["raw_text"]
            clean = " ".join(txt.split())
            print(f"      GBK文本: {clean[:160]}")
            if len(clean) > 160:
                print(f"               …({len(clean)} chars)")
            # hex（原始 body 前 64 字节）
            raw = info.get("raw_body")
            if raw:
                print(f"      hex(前64B): {raw[:64].hex(' ')}")
    else:
        print("\n  【3b】全新未知 pageid/协议：✓ 无（所有请求 pageid 均在已知集合）")

    # 3c) 未知 route
    if new_routes:
        print(f"\n  【3c】未知 route（pageid 已知但 route 不在已知集合）：{len(new_routes)} 个")
        for r in sorted(new_routes):
            print(f"    route=0x{r:04X}（可能是新页面组件实例，或 route 派生值）")
    else:
        print("\n  【3c】未知 route：✓ 无")

    # 3d) 新响应表标记（hd1.0/hd3.1/hd\x8d1.0 以外的）
    known_marks = {b"hd1.0", b"hd3.1", b"hd\x8d1.0"}
    new_marks = Counter()
    for fr, t, sip, sport, stream, body in server_frames:
        for m in re.finditer(rb"hd(.{1,4})1\.0", body):
            mark = m.group(0)
            if mark not in known_marks:
                new_marks[mark] += 1
    if new_marks:
        print(f"\n  【3d】新响应表标记（hd*1.0 家族以外）：")
        for mark, n in new_marks.most_common():
            print(f"    {mark!r} ×{n}  → 可能是新响应格式，需逆向解析")
    else:
        print("\n  【3d】新响应表标记：✓ 无（响应均为 hd1.0/hd3.1/hd8d1.0 已知格式）")

    # 3e) 委托队列/挂单明细线索
    queue_hits = []
    for fr, t, dip, dport, stream, body in client_frames:
        text = body.decode("gbk", errors="replace")
        if (
            re.search(r"(queue|队列|挂单明细|委托明细|买卖力|买卖盘明细)", text)
            or re.search(r"DateTime=(7170|7171|7173|7174|7175)\(", text)
        ):
            queue_hits.append((fr, dip, stream, text[:80]))
    if queue_hits:
        print(f"\n  【3e】委托队列/挂单明细线索：{len(queue_hits)} 帧")
        for fr, dip, stream, txt in queue_hits[:5]:
            print(f"    帧{fr} dst={dip} stream={stream}: {' '.join(txt.split())[:100]}")
    else:
        print("\n  【3e】委托队列/挂单明细线索：✓ 无（盘口区可能要点『委托队列』子标签触发）")

    # dump 未知/缺口帧样本
    _dump_unknown_samples(client_frames, server_frames)


def _dump_unknown_samples(client_frames, server_frames):
    """把 unknown/gap 帧及其对应响应 dump 成 bin 供离线逆向。"""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dumped = {}
    # 建立 stream -> 响应帧 映射
    stream_resp = defaultdict(list)
    for fr, t, sip, sport, stream, body in server_frames:
        stream_resp[stream].append(body)

    for fr, t, dip, dport, stream, body in client_frames:
        info = identify_frame(body)
        if info["status"] not in ("unknown", "gap"):
            continue
        pid = info["pageid"] or "nopid"
        route = info["route"]
        key = (pid, route)
        if key in dumped:
            continue
        # 拼接：请求帧 + 该 stream 的响应帧
        blob = bytearray()
        blob += b"=== REQUEST ===\n"
        blob += body
        blob += b"\n=== RESPONSE(s) ===\n"
        for rb in stream_resp.get(stream, []):
            blob += rb
            blob += b"\n--\n"
        dumped[key] = bytes(blob)

    if not dumped:
        print("\n  【dump】无未知/缺口帧样本可保存")
        return
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n  【dump】未知/缺口帧样本 → {PCAP_DIR}")
    for (pid, route), blob in sorted(dumped.items()):
        fname = f"kanpan_unknown_p{pid}_r{route:04x}_{ts}.bin"
        path = os.path.join(PCAP_DIR, fname)
        Path(path).write_bytes(blob)
        print(f"    {fname}  {len(blob):,}B (请求+响应)")


def _section_responses(server_frames):
    """【4】响应规模。"""
    print(f"\n{'='*70}")
    print("【4】响应规模（hd3.1/hd1.0 dc 记录数分布）")
    print(f"{'='*70}")
    resp_n = Counter()
    all_dc = Counter()
    big_dc = []
    for fr, t, sip, sport, stream, body in server_frames:
        if b"hd3.1\x00" in body:
            resp_n["hd3.1"] += 1
            pos = body.find(b"hd3.1\x00") + 6
            dc = _try_parse_dc(body, pos)
            if dc:
                all_dc[dc] += 1
                if dc >= 500:
                    big_dc.append((fr, t, sip, sport, stream, dc))
        elif b"hd1.0" in body:
            resp_n["hd1.0"] += 1
        elif b"hd\x8d1.0" in body:
            resp_n["hd8d1.0(逐笔变体)"] += 1
    print(f"    服务器响应：hd3.1={resp_n['hd3.1']} hd1.0={resp_n['hd1.0']} "
          f"hd8d1.0={resp_n.get('hd8d1.0(逐笔变体)', 0)}")
    if all_dc:
        dist = ", ".join(f"dc={d}×{n}" for d, n in all_dc.most_common(6))
        print(f"    hd3.1 dc 分布：{dist}")
    if big_dc:
        big_dc.sort(key=lambda x: -x[5])
        print(f"    ★ 大响应（dc≥500）{len(big_dc)} 个:")
        for fr, t, sip, sport, stream, dc in big_dc[:8]:
            print(f"      帧{fr} t={t:.2f}s {sip}:{sport} stream={stream} dc={dc}")
    elif all_dc:
        print("    （无 dc≥500 大响应；均为小 dc → 分页/翻页拉取）")
    else:
        print("    ✗ 未发现 hd3.1 响应（可能响应在抓包窗口外，或解析失败）")


def _section_dxjl(client_frames, server_frames):
    """【5】短线精灵(9601)。"""
    print(f"\n{'='*70}")
    print("【5】短线精灵（9601）")
    print(f"{'='*70}")
    # 推送
    pushes = [(fr, t, body) for fr, t, sip, sport, stream, body in server_frames
              if sport == "9601" and b"pushrealorder" in body]
    print(f"  pushrealorder 推送：{len(pushes)} 帧", end="")
    if pushes:
        times = [t for _, t, _ in pushes]
        span = max(times) - min(times)
        if span > 0:
            print(f"（≈ {len(pushes) / span * 60:.0f} 帧/分钟，跨 {span:.0f}s）")
        else:
            print()
    else:
        print("（✗ 无 — 可能非盘中，或同花顺没切到短线精灵页）")

    # 订阅确认
    sub_markets = Counter()
    for fr, t, dip, dport, stream, body in client_frames:
        text = body.decode("gbk", errors="replace")
        if "method=subrealorder" not in text:
            continue
        for m in re.finditer(rb"market=(\w+)", body):
            sub_markets[m.group(1).decode("ascii", errors="replace")] += 1
    if sub_markets:
        notes = {"16": "沪", "32": "深", "151": "北交所", "48": "板块"}
        print("  subrealorder 订阅：" + ", ".join(
            f"market={mk}({notes.get(mk, '')})×{n}" for mk, n in sub_markets.most_common()))
    else:
        print("  subrealorder 订阅：✗ 未抓到（可能已订阅过）")

    # 历史查询
    hist = [f for f in client_frames
            if b"method=qurealorder" in f[5]]
    print(f"  qurealorder 历史查询：{len(hist)} 帧")


def _section_conclusions(client_frames):
    """【6】结论。"""
    print(f"\n{'='*70}")
    print("【6】结论")
    print(f"{'='*70}")
    rows = [identify_frame(b) for *_, b in client_frames]
    rows = [r for r in rows if r["status"] != "infra"]
    by_status = Counter(r["status"] for r in rows)
    n_ok = by_status.get("ok", 0)
    n_gap = by_status.get("gap", 0)
    n_unk = by_status.get("unknown", 0)
    print(f"  · 协议帧总计 {len(rows)}（已过滤心跳/init）：")
    print(f"      ✅ 已实现={n_ok}  ❌ 未实现(缺口)={n_gap}  ❓ 未知={n_unk}")

    # 区域覆盖
    area_covered = sorted({r["area"] for r in rows if r["area"]})
    missing = [c for c in ["A", "B", "C", "D", "E", "F", "G"] if c not in area_covered]
    if missing:
        names = "、".join(PANEL_AREAS[c] for c in missing)
        print(f"  · 看盘 7 区域中 {len(missing)} 个区域无流量：{names}")
        print("    （可能操作时没点到，或该区域走 HTTPS 443 如自选股/动态板块）")
    else:
        print(f"  · 看盘 7 区域全部有流量 ✓")

    if n_gap or n_unk:
        print(f"\n  ★ 最值得优先逆向的协议：")
        seen = {}
        for r in rows:
            if r["status"] in ("gap", "unknown"):
                key = (r["pageid"], r["route"])
                if key not in seen:
                    seen[key] = r
        # 排序：gap 优先，然后 unknown
        ordered = sorted(seen.values(),
                         key=lambda r: (0 if r["status"] == "gap" else 1, r["pageid"]))
        for r in ordered[:8]:
            route_str = f"route=0x{r['route']:04X}" if r["route"] else "route=-"
            icon = "❌" if r["status"] == "gap" else "❓"
            print(f"    {icon} pageid={r['pageid'] or '-'} {route_str} → {r['label']}")
        print("\n  → 未知/缺口帧样本已 dump 到 captures_live/kanpan_unknown_*.bin，")
        print("    可用 parse_stock_list_response / parse_kline_hd3_response 等尝试解析，")
        print("    或对照 docs/handoffs/ 下相关 HANDOFF。")
    else:
        print("\n  ✓ 看盘界面抓到的协议 thspypc 基本都已实现，无明显缺口。")


# =============================================================================
# 主入口
# =============================================================================

def analyze(pcap_path: str, account: str = "level2"):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return
    print(f"\n{'='*70}")
    print(f"分析 {pcap_path}")
    print(f"{'='*70}")
    _section_overview(pcap_path, account)
    client_frames = _collect_client_frames(pcap_path)
    server_frames = _collect_server_frames(pcap_path)
    print(f"\n  客户端帧 {len(client_frames)}，服务器帧 {len(server_frames)}")
    if not client_frames and not server_frames:
        print("  ✗ 无任何帧 — 可能选错网卡，或同花顺没连 8901/9601")
        return
    _section_area_mapping(client_frames)
    _section_known_identify(client_frames, account)
    _section_gaps(client_frames, server_frames, account, pcap_path)
    _section_responses(server_frames)
    _section_dxjl(client_frames, server_frames)
    _section_conclusions(client_frames)
    print(f"\npcap 已保存：{pcap_path}")
    print(f"用 Wireshark 打开可 Follow TCP Stream 看具体内容")


def main():
    ap = argparse.ArgumentParser(
        description="抓同花顺看盘主界面全流量，自动分析未实现协议")
    ap.add_argument("--duration", type=int, default=240,
                    help="抓包时长（秒），默认 240")
    ap.add_argument("--iface", help="网卡编号（如 4=WLAN），不传则交互选择")
    ap.add_argument("--stop-file", metavar="PATH",
                    help="存在该文件时提前结束抓包（中途叫停用）")
    ap.add_argument("--analyze-only", metavar="PCAP",
                    help="只分析现有 pcap 不抓包")
    ap.add_argument("--account", choices=["level2", "normal"], default="level2",
                    help="账号类型（仅影响报告提示，不改抓包），默认 level2")
    args = ap.parse_args()

    print("=" * 70)
    print("抓同花顺「看盘主界面」全流量 + 协议缺口分析（8901 + 9601）")
    print("=" * 70)
    if args.analyze_only:
        analyze(args.analyze_only, args.account)
        return
    iface = args.iface
    desc = ""
    if iface is None:
        iface, desc = pick_interface()
        print(f"\n选用网卡 {iface}: {desc}")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"kanpan_{ts}.pcap")
    capture(iface, args.duration, pcap_path, stop_file=args.stop_file)
    analyze(pcap_path, args.account)


if __name__ == "__main__":
    main()
