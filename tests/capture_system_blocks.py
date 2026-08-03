#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺 PC 客户端的「系统板块」流量（板块发现 / 成分股 / 板块指数分时与历史 /
盘中实时板块指数），为 P0 系统板块协议逆向收集样本。

背景
----
系统板块只读 MVP 的数据源**必须是抓包到的同花顺 Windows 客户端数据形式**
（8901 协议），不能以 basic.10jqka.com.cn 等网页接口兜底。本地
``BlockUpdate/block_*.ini`` + ``industry.ini`` 已逆向（见
``thspypc.features.system_blocks``），可作为离线 oracle 校验抓包解析结果。

本脚本一次抓包覆盖四个流程：

    A. 板块发现/列表：板块页（行业/概念）的板块指数列表
    B. 板块成分股：点击某个板块后的成分股列表
    C. 板块指数分时/历史：板块指数（如 881121 半导体）的分时图 + 历史回忆
    D. 盘中实时：板块列表/板块指数的实时刷新（订阅或轮询）
    E. 板块列表表头排序与翻页：板块列表页点不同表头列排序、翻页

用法
----
    py tests/capture_system_blocks.py                  # 默认 240s
    py tests/capture_system_blocks.py --duration 300
    py tests/capture_system_blocks.py --duration 210 --iface 4   # 非交互指定网卡
    py tests/capture_system_blocks.py --duration 300 --stop-file captures_live/STOP
                                                               # 创建该文件即可中途叫停
    py tests/capture_system_blocks.py --analyze-only xxx.pcap

操作步骤（★严格按阶段做，阶段之间停 2-3 秒）：
    1. 启动同花顺并登录，把左侧导航切到【板块】（能看到 行业/概念/地域…）
    2. 运行本脚本，选网卡
    3. 抓包期间：
       A. 行业/概念板块列表页，上下滚动各一次（触发板块发现请求）
       B. 点进【半导体】（行业）→ 成分股列表，滚动一屏；
          返回，再点进 1-2 个【概念】板块 → 成分股列表
       C. 打开【半导体 881121】的【分时图】，停 3 秒；
          按 ← 方向键翻到昨天/前几天（历史回忆），每停 3-4 秒；
          （若客户端有日历，可直接选 2026-07-23 与 2026-06-30）
       D. 回到板块列表页，保持不动 60 秒（抓盘中实时刷新/订阅）
       E. 板块列表排序/翻页：在【行业】列表依次点表头 涨幅→1分钟涨速→4分钟涨速→
          主力净流入金额（每列点两次：先降序停 2-3 秒，再升序停 2-3 秒）；
          然后点【下一页】→停 3s→【下一页】→停 3s→【上一页】→停 3s；
          切到【概念】列表再重复一次排序+翻页
    4. 抓够后等待自动结束，脚本输出分析报告并 dump 样本

产物：captures_live/system_blocks_<时间戳>.pcap +
      system_blocks_<code>_<pageid>_<ts>.bin（按 代码×pageid 分帧 dump）
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import time
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

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符
PORT = 8901

# 板块指数代码前缀（行业 881xxx；概念 885xxx/301xxx 待抓包确认）
BOARD_CODE_PREFIXES = ("881", "885", "301", "302", "303", "304", "305", "306", "307", "308", "309")


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


def capture(iface, duration, pcap_path, stop_file=None):
    os.makedirs(PCAP_DIR, exist_ok=True)
    if stop_file and os.path.exists(stop_file):
        try:
            os.unlink(stop_file)
        except OSError:
            pass
    print(f"\n{'='*64}")
    print(f"开始抓包 {duration}s（端口 {PORT}，网卡 {iface}）")
    print(f"{'='*64}")
    print(">>> 抓包期间按阶段操作（每阶段间停 2-3 秒）：")
    print("  A【板块发现】左侧导航切到【板块】→ 行业/概念列表，上下滚动一次")
    print("  B【成分股】点进【半导体】→ 成分股列表滚动一屏；返回后再点 1-2 个概念板块")
    print("  C【板块指数】打开半导体 881121 的【分时图】停 3s；按 ← 翻历史日期")
    print("    ★ 建议翻到 2026-07-23 和 2026-06-30（每停 4 秒，便于按日期拆帧）")
    print("  D【盘中实时】回到板块列表页不动 60 秒")
    print("  E【排序/翻页】板块列表页依次点表头 涨幅→1分钟涨速→4分钟涨速→主力净流入金额")
    print("    （每列点两次：先降序停 2-3s，再升序停 2-3s）；然后 下一页→下一页→上一页（各停 3s）")
    print("    切到【概念】列表再重复一次排序+翻页")
    if stop_file:
        print(f"  中途叫停：创建 {stop_file} 即可提前结束（脚本每 1 秒检查一次）")
    print("-" * 64)
    proc = subprocess.Popen(
        [DUMPCAP, "-i", iface, "-f", f"tcp port {PORT}",
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


# ── 分析逻辑 ──

def _tshark_streams(pcap_path, port=PORT):
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
            frames.append(sub[8:])
    return frames


def _subframe_routes(frame_body):
    """提取双子帧请求的前缀/查询 route、seq 与 history flag（对齐 0x09 双子帧）。"""
    if len(frame_body) < 1 + 22 or frame_body[0:1] != b"\x09":
        return None
    prefix_route = int.from_bytes(frame_body[1 + 10:1 + 12], "little")
    prefix_seq = int.from_bytes(frame_body[1 + 4:1 + 6], "little")
    text_len = int.from_bytes(frame_body[1 + 18:1 + 22], "little")
    qh = 1 + 22 + text_len
    if len(frame_body) < qh + 22:
        return None
    query_route = int.from_bytes(frame_body[qh + 10:qh + 12], "little")
    query_seq = int.from_bytes(frame_body[qh + 4:qh + 6], "little")
    return {
        "prefix_route": f"0x{prefix_route:04X}",
        "query_route": f"0x{query_route:04X}",
        "prefix_seq": f"0x{prefix_seq:04X}",
        "query_seq": f"0x{query_seq:04X}",
        "history_flag": f"0x{frame_body[qh + 17]:02X}",
    }


def _parse_request(frame_body):
    """解析客户端请求，返回 dict 或 None。"""
    try:
        text = frame_body.decode("gbk", errors="replace")
    except Exception:
        return None
    if "pageid=" not in text and "CodeList=" not in text:
        return None
    info = {"raw": frame_body, "text": text}
    routes = _subframe_routes(frame_body)
    if routes:
        info.update(routes)
    m = re.search(r"pageid=(\d+)", text)
    if m:
        info["pageid"] = m.group(1)
    m = re.search(r"DateTime=(\d+)(?:\(([^)]*)\))?", text)
    if m:
        info["datetime_period"] = int(m.group(1))
        info["datetime_args"] = m.group(2) or ""
    m = re.search(r"CodeList=(\d+)\(([^)]*)\)", text)
    if m:
        info["market"] = m.group(1)
        codes = [c.strip() for c in m.group(2).split(",") if c.strip()]
        info["codes"] = codes
        info["code"] = codes[0] if codes else ""
    m = re.search(r"DataType=([\d,\[\]]+)", text)
    if m:
        info["datatype"] = m.group(1).rstrip(",")
    m = re.search(r"ReqFuquan=(\w*)", text)
    if m:
        info["reqfuquan"] = m.group(1)
    m = re.search(r"SortBegin=(\d+)", text)
    if m:
        info["sort_begin"] = m.group(1)
    sort_params: dict[str, str] = {}
    for m in re.finditer(r"(Sort[A-Za-z]+|OrderBy[A-Za-z]*)=([^,\r\n]*)", text):
        sort_params[m.group(1)] = m.group(2).rstrip()
    if sort_params:
        info["sort_params"] = sort_params
    return info


def _is_board_code(code: str) -> bool:
    return code.startswith(BOARD_CODE_PREFIXES) and len(code) == 6


def _decode_response(frame_body, codes):
    """解码一个响应帧；返回 (kind, parsed) 或 None。"""
    if b"hd3.1\x00" in frame_body or b"SortTotal" in frame_body:
        try:
            parsed = parse_stock_list_response(frame_body)
            if parsed.get("stocks"):
                return ("list", parsed)
        except Exception as exc:
            return ("list", {"error": str(exc)})
        try:
            recs = parse_kline_hd3_response(frame_body)
            if recs:
                return ("kline", {"records": recs})
        except Exception as exc:
            return ("kline", {"error": str(exc)})
        return ("list", {})
    if b"hd1.0\x00" in frame_body:
        for code in codes:
            try:
                recs = parse_history_timeline_response(frame_body, code=code)
                if recs:
                    return ("timeline", {"records": recs, "code": code})
            except Exception:
                continue
        return ("timeline", {})
    return None


def _print_req(info):
    sort_repr = info.get("sort_params") or {"SortBegin": info.get("sort_begin", "-")}
    route_repr = ""
    if info.get("query_route"):
        route_repr = (
            f" 前缀route={info.get('prefix_route')} "
            f"查询route={info.get('query_route')} "
            f"seq={info.get('query_seq')} h17={info.get('history_flag')}"
        )
    print(f"      pageid={info.get('pageid','?')}{route_repr} "
          f"codes={info.get('codes','?')} "
          f"DateTime={info.get('datetime_period','?')}({info.get('datetime_args','')}) "
          f"DataType={info.get('datatype','?')} "
          f"Sort={sort_repr}")


def analyze(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"✗ pcap 不存在: {pcap_path}")
        return
    print(f"\n{'='*64}\n分析 {pcap_path}\n{'='*64}")
    streams = _tshark_streams(pcap_path, PORT)
    print(f"共 {len(streams)} 条 {PORT} TCP 流\n")

    requests: list[tuple[int, dict, list[bytes]]] = []
    for sid, client_bytes, server_bytes in streams:
        sframes = _split_frames(server_bytes)
        for fb in _split_frames(client_bytes):
            parsed = _parse_request(fb)
            if parsed is not None:
                requests.append((sid, parsed, sframes))

    pageid_count: dict[str, int] = {}
    board_reqs = []
    for sid, info, sframes in requests:
        pid = info.get("pageid", "?")
        pageid_count[pid] = pageid_count.get(pid, 0) + 1
        codes = info.get("codes", [])
        if any(_is_board_code(c) for c in codes):
            board_reqs.append((sid, info, sframes))

    # ── 报告 1：pageid 分布 ──
    print("【1】请求 pageid 分布（找板块相关的新 pageid）")
    for pid, cnt in sorted(pageid_count.items(), key=lambda x: -x[1]):
        note = ""
        if pid in ("9354", "9355"):
            note = "  ← 行情查询"
        elif pid == "4214":
            note = "  ← L2 快照订阅"
        print(f"  pageid={pid}: {cnt} 次{note}")

    # ── 报告 2：板块代码请求 ──
    print(f"\n【2】含板块指数代码（{BOARD_CODE_PREFIXES[0]}xxx/885xxx/30xxxx）的请求")
    if not board_reqs:
        print("  ✗ 未抓到板块代码请求；请确认客户端打开过【板块】页面/板块指数分时图")
    else:
        seen: set[tuple] = set()
        for sid, info, sframes in board_reqs:
            key = (info.get("pageid"), tuple(info.get("codes", [])),
                   info.get("datetime_period"), info.get("datetime_args"))
            if key in seen:
                continue
            seen.add(key)
            _print_req(info)
            resp = None
            for sf in sframes:
                decoded = _decode_response(sf, info.get("codes", []))
                if decoded and decoded[1]:
                    resp = decoded
                    break
            if resp:
                kind, parsed = resp
                if kind == "list":
                    print(f"      → 列表响应 {len(parsed.get('stocks', []))} 条")
                elif kind == "timeline":
                    recs = parsed["records"]
                    print(f"      → 分时响应 code={parsed.get('code')} {len(recs)} 点")
                elif kind == "kline":
                    print(f"      → K线响应 {len(parsed['records'])} 根")
                else:
                    print(f"      → {parsed}")
            else:
                print("      → 未解出对应数据帧")

    # ── 报告 3：成分股请求特征（无板块代码但 SortBegin/页式查询）──
    print("\n【3】疑似成分股列表请求（含 SortBegin 的分页查询）")
    seen3 = set()
    for sid, info, sframes in requests:
        if "sort_begin" not in info:
            continue
        key = (info.get("pageid"), info.get("sort_begin"), tuple(info.get("codes", [])))
        if key in seen3:
            continue
        seen3.add(key)
        _print_req(info)

    # ── 报告 4：板块列表排序/翻页请求特征 ──
    BOARD_LIST_PAGEIDS = {"392", "4180", "4181", "5716", "6000", "6002", "1341"}
    print("\n【4】板块列表排序/翻页请求（pageid 家族；完整文本便于 diff 出排序/页码参数）")
    seen4: dict[str, int] = {}
    order4: list[str] = []
    for sid, info, sframes in requests:
        pid = info.get("pageid", "?")
        if pid not in BOARD_LIST_PAGEIDS and "sort_params" not in info:
            continue
        text = " ".join(info.get("text", "").split())
        if text not in seen4:
            seen4[text] = 0
            order4.append(text)
        seen4[text] += 1
    if not order4:
        print("  ✗ 未抓到板块 pageid 家族请求；请确认抓包期间打开过【板块】列表页并做过排序/翻页")
    for text in order4:
        mark = "  ★ 含 Sort/Order 参数" if ("Sort" in text or "Order" in text) else ""
        suffix = "…" if len(text) > 240 else ""
        print(f"  [{seen4[text]}x] {text[:240]}{suffix}{mark}")

    # ── 报告 4b：板块列表请求路由分布（08-03 复验后新增；区分新旧路由）──
    print("\n【4b】板块列表请求路由分布（pageid=392/5716，区分 0x0039 旧路由 / 0x006C、0x0052 新路由）")
    route_count: dict[tuple, int] = {}
    route_order: list[tuple] = []
    for sid, info, _sframes in requests:
        pid = info.get("pageid", "?")
        if pid not in ("392", "5716") or not info.get("query_route"):
            continue
        key = (
            pid,
            info.get("prefix_route"),
            info.get("query_route"),
            info.get("history_flag"),
        )
        if key not in route_count:
            route_order.append(key)
            route_count[key] = 0
        route_count[key] += 1
    if not route_order:
        print("  ✗ 未抓到 pageid=392/5716 列表请求；请确认抓包期间打开过【板块】列表页")
    for key in route_order:
        pid, pr, qr, h17 = key
        note = ""
        if qr in ("0x0139",):
            note = "  ← 旧路由（08-01 形态）"
        elif qr in ("0x016C", "0x0152"):
            note = "  ← 新路由（08-02 形态）"
        print(f"  [{route_count[key]}x] pageid={pid} 前缀route={pr} "
              f"查询route={qr} h17={h17}{note}")

    # ── dump 样本：按 代码×pageid 存原始响应帧 ──
    _dump_samples(streams, pcap_path)


def _dump_samples(streams, pcap_path):
    """把含板块代码的响应帧按 (code, pageid) dump 成 bin 供离线回归。"""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dumped: dict[tuple, list[bytes]] = {}
    for sid, client_bytes, server_bytes in streams:
        sframes = _split_frames(server_bytes)
        for fb in _split_frames(client_bytes):
            parsed = _parse_request(fb)
            if parsed is None:
                continue
            pid = parsed.get("pageid", "?")
            codes = [c for c in parsed.get("codes", []) if _is_board_code(c)]
            if not codes:
                continue
            key = (codes[0], pid)
            for sf in sframes:
                if MAGIC not in sf and (b"hd1.0" in sf or b"hd3.1" in sf or b"SortTotal" in sf):
                    dumped.setdefault(key, []).append(sf)

    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n【dump】板块响应样本 → {PCAP_DIR}")
    for (code, pid), frames in sorted(dumped.items()):
        path = os.path.join(PCAP_DIR, f"system_blocks_{code}_{pid}_{ts}.bin")
        Path(path).write_bytes(b"".join(frames))
        print(f"  system_blocks_{code}_{pid}_{ts}.bin  {len(frames)} 帧 "
              f"{sum(len(f) for f in frames):,}B")
    if not dumped:
        print("  （无板块响应可 dump）")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--duration", type=int, default=240)
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
    pcap_path = os.path.join(PCAP_DIR, f"system_blocks_{ts}.pcap")
    capture(iface, args.duration, pcap_path, stop_file=args.stop_file)
    analyze(pcap_path)


if __name__ == "__main__":
    main()
