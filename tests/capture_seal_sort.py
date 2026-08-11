#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺「封单额排序」的请求协议。

背景
----
thspypc 已实现 7 个 SortBy 排序键(涨幅/涨速/换手/量比/主力净流入/竞价金额/竞价涨幅),
封单额排序原先没逆向。封单额 = 一档买量×买价(涨停)或一档卖量×卖价(跌停),
此前只在 `quote()` 个股盘口查询里客户端本地算。

2026-08-11 抓包结论(SortBy=265260,已加入 SORT_BY_VALUES)
----------------------------------------------------------
**封单额排序走服务端 SortBy 路径,不是客户端查所有盘口本地排。**

  - pageid=1334(与涨幅榜同页面、同通道、同连接)
  - SortBy=265260、DataType=265260、SortDir=D(降序)
  - CodeList=17();22();151();(沪深京全市场)
  - 响应 SortTotal=2899(全市场 2899 只参与,非涨停股封单额为 0 排末尾)
  - 每页 SortCount=29(涨幅榜同款翻页游标 SortBegin)

抓到的两种请求形态(seal_sort_20260811_223801.pcap):
  1. 纯排序(DataType=265260,):拿封单榜代码列表,SortCount=29
  2. 带行情刷新(DataType=7,49,13,461256,70,27,...):CodeList=33(具体代码),
     其中 461256 疑似封单额字段的 dt 编号(待响应解码确认)

结论意义:同花顺不需要为封单排序请求所有股票盘口——服务端已聚合好封单额排序。
thspypc 端 ``client.stock_list_hot(sort_by=265260)`` 拿代码列表;
``with_values=True`` 时保留响应里的 dt 数值字段(封单额的 dt 编号待响应解码确认,
见 ``tests/verify_sort_values_online.py``)。

方法:被动监听,过滤**所有含 ``SortBy=`` 的请求帧**(不限 DataType),按时间排列,
让用户做 A/B 对比 —— 先记录基线,再去 hexin 里点封单列排序,看新出现的 SortBy 值。

用法
----
    1. 彻底退出同花顺(任务管理器确认 hexin.exe 没了)
    2. 运行本脚本,选网卡
    3. 看到"开始抓包"后,启动同花顺并登录
    4. 按脚本提示操作(下方"操作步骤"),关键是在能看到「封单」列的地方点它排序
    5. 结束后脚本输出所有排序请求的 SortBy/DataType/pageid 对照表
    6. 也可对已有 pcap 离线分析:设 PCAP_PATH 后调 collect_sort_requests/report

产物:captures_live/seal_sort_<时间戳>.pcap + 终端分析报告
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = ROOT / "captures_live"
MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符(见 protocol.py FRAME_MAGIC)

# 已知的 SortBy 编号(thspypc 已实现),用于在报告里标注「已知 / 未知」
KNOWN_SORTBY = {
    "199112": "涨幅",
    "48": "涨速",
    "1968584": "换手率",
    "1771976": "量比",
    "592890": "主力净流入",
    "68758": "竞价金额",
    "68762": "竞价涨幅",
    "265260": "封单额",  # 2026-08-11 抓包确认
    # 板块排序(HOT_BOARD)
    "527527": "1分钟涨速(板块)",
    "271": "涨停数(板块)",
    "38": "涨家数(板块)",
    "39": "跌家数(板块)",
    # DDE
    "592888": "DDE散户净流入",
    "592889": "DDE中户净流入",
}


def list_interfaces() -> dict[str, str]:
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    ifaces: dict[str, str] = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            ifaces[m.group(1)] = m.group(3)
    return ifaces


def pick_iface(default: str | None = None) -> str:
    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未检测到网卡")
        sys.exit(1)
    print("网卡列表:")
    for num, desc in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    if default is None:
        default = next((n for n, d in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    return choice if choice in ifaces else default


def _tshark(display_filter: str, fields: list[str]) -> str:
    cmd = [TSHARK, "-r", str(PCAP_PATH), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
    return subprocess.run(cmd, capture_output=True,
                          timeout=120).stdout.decode("utf-8", errors="replace")


def _split_frames(payload: bytes):
    """把 TCP payload 按 MAGIC 切成帧体(去 8B ASCII 长度头)。"""
    out = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            out.append(sub[8:])
    return out


def _extract_kv(text: str) -> dict:
    """从请求文本里精确提取排序相关 key=value。"""
    kv = {}
    keys = ["CodeList", "DataType", "SortType", "SortBy", "SortDir",
            "SortBegin", "SortCount", "FuncPeriod", "DateTime", "pageid"]
    for k in keys:
        m = re.search(rf"(?:^|[^A-Za-z0-9_-]){k}=([^\r\n]*)", text)
        if m:
            kv[k] = m.group(1).strip()
    return kv


def collect_sort_requests() -> list[dict]:
    """收集所有含 SortBy= 的客户端发出帧,按时间排列。

    不依赖 8901 MAGIC 帧切分 —— tshark -e tcp.payload 给的是单 TCP 段,
    请求文本可能跨段或不在帧头。直接在整个 payload 里正则提取。
    """
    out = _tshark('tcp.payload contains "SortBy=" and tcp.dstport == 8901',
                  ["frame.number", "frame.time_relative", "ip.dst", "tcp.dstport",
                   "tcp.stream", "tcp.payload"])
    reqs = []
    seen = set()  # (frame, SortBy) 去重
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
        text = payload.decode("gbk", errors="replace")
        if "SortBy=" not in text:
            continue
        kv = _extract_kv(text)
        if not kv.get("SortBy"):
            continue
        key = (fr, kv["SortBy"])
        if key in seen:
            continue
        seen.add(key)
        reqs.append({
            "frame": fr, "t": float(t) if t else 0.0,
            "dst": f"{dip}:{dport}", "stream": stream,
            "kv": kv, "text": text,
        })
    return reqs


def report(reqs: list[dict]) -> None:
    print(f"\n{'='*72}")
    print(f"【结果】抓到 {len(reqs)} 个排序请求")
    print(f"{'='*72}")
    if not reqs:
        print("  ✗ 没抓到任何含 SortBy= 的请求。可能原因:")
        print("    - 没在同花顺里点表头排序")
        print("    - 选错网卡(看不到同花顺流量)")
        print("    - 同花顺排序走的是本地缓存(不发请求)")
        return

    # 按 (pageid, SortBy, DataType) 聚合
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in reqs:
        key = (r["kv"].get("pageid", "?"),
               r["kv"].get("SortBy", "?"),
               r["kv"].get("DataType", "?")[:30])
        groups[key].append(r)

    print(f"\n按 (pageid × SortBy × DataType) 聚合,{len(groups)} 组:\n")
    print(f"{'pageid':>8} {'SortBy':>10} {'语义':>14} {'DataType':>20} {'次数':>4} {'方向':>4}")
    print("-" * 72)
    # 已知 SortBy 标注语义,未知的标 ★(可能就是封单)
    for (pid, sb, dt), items in sorted(groups.items()):
        sem = KNOWN_SORTBY.get(sb, "★未知")
        dirs = sorted({i["kv"].get("SortDir", "?") for i in items})
        mark = " ← 重点看这个" if sb not in KNOWN_SORTBY else ""
        print(f"{pid:>8} {sb:>10} {sem:>14} {dt[:20]:>20} {len(items):>4} {''.join(dirs):>4}{mark}")

    # 详细列出每个未知 SortBy 的完整请求
    unknown = [(k, v) for k, v in groups.items() if k[1] not in KNOWN_SORTBY]
    if unknown:
        print(f"\n{'='*72}")
        print(f"【★ 未知 SortBy 完整请求】(最可能含封单排序)")
        print(f"{'='*72}")
        for (pid, sb, dt), items in unknown:
            r = items[0]
            print(f"\n--- pageid={pid} SortBy={sb} (首次出现 t={r['t']:.2f}s) ---")
            print(f"  目的地: {r['dst']}  TCP stream {r['stream']}")
            for k in ["CodeList", "DataType", "SortType", "SortBy", "SortDir",
                      "SortBegin", "SortCount", "FuncPeriod", "DateTime", "pageid"]:
                if k in r["kv"]:
                    print(f"  {k:12} = {r['kv'][k]}")
    else:
        print("\n(没有未知 SortBy —— 封单排序可能走别的机制,见下)")


def main():
    global PCAP_PATH
    ap = argparse.ArgumentParser(description="抓封单额排序请求")
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--iface", default=None)
    args = ap.parse_args()

    PCAP_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    PCAP_PATH = PCAP_DIR / f"seal_sort_{ts}.pcap"

    iface = args.iface or pick_iface()
    print(f"\n{'='*72}")
    print(f"开始抓包 {args.duration}s,网卡 {iface}")
    print(f"{'='*72}")

    cmd = [DUMPCAP, "-i", iface, "-q", "-w", str(PCAP_PATH),
           "-a", f"duration:{args.duration}",
           "-f", "tcp port 8901 or tcp port 9605"]
    print(f"  {cmd}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    time.sleep(1.5)
    print(f"\n{'='*72}")
    print("现在操作同花顺(关键步骤,决定能不能抓到封单排序):")
    print(f"{'='*72}")
    print("""
  1. 启动同花顺并登录

  2. 【基线】先做几次已知排序,确认抓包工作:
     - A股涨幅榜(输 1+回车 或点「沪深A股」)
     - 点表头「涨幅」列(应发 SortBy=199112)
     - 停 2 秒,再点「换手率」或「量比」
     ★ 这一步只是为了确认脚本抓得到,基线 SortBy 见上面 KNOWN_SORTBY

  3. 【目标 A:涨幅榜封单列】(如果封单是表头列):
     - 在涨幅榜界面,右键表头 → 勾选「封单」列(让它显示出来)
     - 点「封单」列排序(先降序停 3 秒,再点升序停 3 秒)
     - 翻到下一页,停 3 秒

  4. 【目标 B:涨停板专题】(封单是涨停板核心列):
     - 找到「涨停板」/「涨停预测」/「盘中涨停」入口
       (通常在:顶部菜单「行情」→「涨停板」,或左下角专题)
     - 进入后,点「封单」列排序(降序 3 秒,升序 3 秒)
     - 翻页

  5. 【目标 C:DDE 决策】(备选):
     - 输 81/82/83 等快捷键,或找「DDE决策」入口
     - 看有没有封单相关列,点排序

  6. 全部操作完后,Ctrl+C 或等 {} 秒自动结束
""".format(args.duration))

    try:
        proc.wait(timeout=args.duration + 10)
    except subprocess.TimeoutExpired:
        proc.terminate()
    except KeyboardInterrupt:
        print("\n用户中断,停止抓包...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    reqs = collect_sort_requests()
    report(reqs)

    print(f"\n产物: {PCAP_PATH}")
    print("如需手动细看: tshark -r", PCAP_PATH, '-Y "tcp.payload contains \\"SortBy=\\""')


if __name__ == "__main__":
    main()
