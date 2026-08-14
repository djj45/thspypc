#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓同花顺客户端「沪深A股 涨幅/涨速排序」流量，诊断排序榜缺条目问题。

背景：MAIN 单请求 CodeList=17();22();33();151(); + SortBegin 翻页拿到的榜单
缺北交所（920083 金戈新材等 43/83/87/92 前缀 0 条），10~20% 区间缺 n 只，
疑似真实客户端用「SortBegin 恒 0 + SortCount 逐步放大」或「拆沪深两服务器」
的取榜方式。抓包确认客户端真实请求序列 + 响应结构。

操作步骤：
  1. 彻底退出同花顺（任务管理器确认 hexin.exe 已退出）
  2. 运行本脚本（交互选网卡，默认 WLAN），按 Enter 开始抓包
  3. 立即打开同花顺并登录
  4. 切到【沪深A股】列表 → 点表头『涨幅』排序（降序）→ 向下滚动 3-5 页
     （途中留意：榜首是否 920083 金戈新材？10%~20% 区间股票是否连续？）
  5. 再点表头『涨速』排序 → 滚动 2-3 页
  6. 等待脚本自动结束（默认 300s），脚本自动分析：
     - 客户端发的每个排序请求（CodeList/SortBy/SortCount/SortBegin/pageid/目标IP）
     - 每帧响应的记录数 dc 与市场分布
     - 是否含 920083 / 北交所前缀
     - dt 值字段 c0/40 两种编码分布（对应真值 mantissa/10000 的除/乘两态）

用法：
  py tests/capture_rank_sort.py                     # 默认 300s，交互选网卡
  py tests/capture_rank_sort.py --duration 600
  py tests/capture_rank_sort.py --iface 4           # 跳过交互（4=WLAN）
  py tests/capture_rank_sort.py --pcap captures_live/xxx.pcap   # 只分析已有 pcap
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── Wireshark portable 路径探测（本机已装 4.4.7 portable；保留旧候选）──
WS_CANDIDATES = [
    r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = os.environ.get("THS_WIRESHARK_DIR") or next(
    (c for c in WS_CANDIDATES if os.path.exists(os.path.join(c, "tshark.exe"))),
    WS_CANDIDATES[0],
)
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
os.makedirs(CAPTURE_DIR, exist_ok=True)

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符


# =============================================================================
# 抓包
# =============================================================================

def list_interfaces() -> list[tuple[int, str]]:
    out = subprocess.check_output([DUMPCAP, "-D"], stderr=subprocess.STDOUT)
    text = None
    for enc in ["utf-8", "gbk", "cp936", "latin-1"]:
        try:
            text = out.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = out.decode("utf-8", errors="replace")
    ifaces = []
    for line in text.strip().splitlines():
        m = re.match(r"^(\d+)\.\s*(.+)", line)
        if m:
            ifaces.append((int(m.group(1)), m.group(2).strip()))
    return ifaces


def capture(iface_idx: int, duration: int, pcap_path: str) -> None:
    cmd = [
        DUMPCAP, "-i", str(iface_idx),
        "-f", "tcp port 8901",
        "-a", f"duration:{duration}",
        "-w", pcap_path,
    ]
    print(f"抓包 {duration}s → {pcap_path}")
    print(f"命令: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd)
    try:
        while proc.poll() is None:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n★ Ctrl+C，提前结束抓包（已抓部分会保存）")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"✓ 抓包完成 ({size:,} bytes)")


# =============================================================================
# 分析
# =============================================================================

def _tshark_fields(pcap_path: str, y_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = [TSHARK, "-r", pcap_path, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, timeout=180)
    rows = []
    for ln in out.stdout.decode("utf-8", errors="replace").splitlines():
        if ln.strip():
            rows.append(ln.split("\t"))
    return rows


def _split_frames(payload: bytes) -> list[bytes]:
    out = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            out.append(sub[8:])
    return out


def analyze_pcap(pcap_path: str) -> None:
    from thspypc.features.stock_list_protocol import _parse_stock_list_hd31_records

    print(f"\n{'='*72}")
    print(f"分析 {pcap_path}")
    print(f"{'='*72}")

    # ── 1. 客户端排序请求 ──
    print("\n【1】客户端排序请求（→8901）")
    rows = _tshark_fields(
        pcap_path,
        "tcp.dstport==8901 and tcp.payload",
        ["frame.number", "frame.time_relative", "ip.dst", "tcp.payload"],
    )
    reqs = []
    for p in rows:
        if len(p) < 4:
            continue
        fr, t, dip, hx = p[:4]
        try:
            payload = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        for body in _split_frames(payload):
            text = body.decode("gbk", errors="replace")
            if "SortBy=" not in text:
                continue
            m_pid = re.search(r"pageid=(\d+)", text)
            m_cl = re.search(r"CodeList=([^\r\n]+)", text)
            m_by = re.search(r"SortBy=(\d+)", text)
            m_beg = re.search(r"SortBegin=(\d+)", text)
            m_cnt = re.search(r"SortCount=(\d+)", text)
            m_dir = re.search(r"SortDir=(\w)", text)
            m_dt = re.search(r"DataType=([^\r\n]+)", text)
            reqs.append({
                "fr": fr, "t": float(t or 0), "dip": dip,
                "pid": m_pid.group(1) if m_pid else "-",
                "codelist": m_cl.group(1) if m_cl else "-",
                "sortby": m_by.group(1) if m_by else "-",
                "begin": m_beg.group(1) if m_beg else "-",
                "count": m_cnt.group(1) if m_cnt else "-",
                "dir": m_dir.group(1) if m_dir else "-",
                "datatype": (m_dt.group(1)[:30] if m_dt else "-"),
            })
    if not reqs:
        print("  ✗ 未抓到排序请求（SortBy=）——确认操作了『涨幅/涨速』列头排序")
    for r in reqs:
        print(f"  帧{r['fr']:>5} t={r['t']:7.2f}s → {r['dip']:>15}  "
              f"pageid={r['pid']} SortBy={r['sortby']} {r['dir']} "
              f"Begin={r['begin']:>4} Count={r['count']:>4}")
        print(f"          CodeList={r['codelist']}")
        print(f"          DataType={r['datatype']}")

    # ── 2. 服务器响应 ──
    print("\n【2】服务器排序响应（←8901）")
    rows = _tshark_fields(
        pcap_path,
        "tcp.srcport==8901 and tcp.payload",
        ["frame.number", "frame.time_relative", "ip.src", "tcp.payload"],
    )
    resp_stats = Counter()
    total_recs = []
    for p in rows:
        if len(p) < 4:
            continue
        fr, t, sip, hx = p[:4]
        try:
            payload = bytes.fromhex(hx.replace(":", ""))
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"hd3.1\x00" not in body:
                continue
            recs = _parse_stock_list_hd31_records(body)
            if not recs:
                continue
            resp_stats[len(recs)] += 1
            enc = Counter("c0" if (r.get("dt200_raw") or 0) & 0x80000000
                          else "40" for r in recs
                          if isinstance(r.get("dt200_raw"), int))
            markets = Counter(str(r.get("market")) for r in recs)
            bse = [r["code"] for r in recs
                   if str(r.get("code", "")).startswith(("43", "83", "87", "92"))]
            has920083 = any(r.get("code") == "920083" for r in recs)
            total_recs.append((fr, t, sip, recs))
            try:
                t_f = float(t or 0)
            except (TypeError, ValueError):
                t_f = 0.0
            print(f"  帧{fr:>5} t={t_f:7.2f}s ← {sip:>15}  dc={len(recs):>3}  "
                  f"市场={dict(markets)}  编码[c0/40]={enc.get('c0',0)}/{enc.get('40',0)}"
                  f"  北交所={len(bse)}{' 含920083★' if has920083 else ''}")

    if not resp_stats:
        print("  ✗ 未抓到 hd3.1 排序响应")
        return
    print(f"\n  响应 dc 分布: {dict(sorted(resp_stats.items()))}")

    # ── 3. 完整榜单抽样（把抓到响应里的所有记录去重后看覆盖）──
    print("\n【3】客户端抓到的榜单覆盖检查（全部响应记录去重）")
    all_codes: dict[str, list] = {}
    for _fr, _t, _sip, recs in total_recs:
        for r in recs:
            code = r.get("code", "")
            if code and code not in all_codes:
                raw = r.get("dt200_raw")
                val = None
                if isinstance(raw, int):
                    val = (raw & 0x07FFFFFF) / 10000.0
                all_codes[code] = [val, raw]
    bse_all = [c for c in all_codes if c.startswith(("43", "83", "87", "92"))]
    mid = [c for c, (v, _) in all_codes.items() if v is not None and 10.0 < v < 20.0]
    print(f"  去重后共 {len(all_codes)} 条；北交所前缀 {len(bse_all)} 条 "
          f"{bse_all[:15] or ''}")
    print(f"  920083 金戈新材: {'★ 抓到' if '920083' in all_codes else '✗ 未出现'}")
    print(f"  涨幅 10%~20% 区间: {len(mid)} 条")
    if "920083" in all_codes:
        v, raw = all_codes["920083"]
        print(f"    920083 排序值: {v} (raw=0x{raw:08x})")
    # 10~20% 区间数值跳跃检测（找缺段）
    vals = sorted(v for v, _ in all_codes.values() if v is not None)
    jumps = []
    prev = None
    for v in vals:
        if prev is not None and v < prev - 1.2 and 10.0 < prev < 20.0:
            jumps.append((prev, v))
        prev = v
    if jumps:
        print(f"  10~20% 区间跳跃（疑似缺段）{len(jumps)} 处: {jumps[:8]}")
    else:
        print("  10~20% 区间数值连续（无 1.2% 以上跳跃）→ 客户端榜单完整")

    # ── 4. 结论提示 ──
    print("\n【4】结论要点（对照客户端观察）")
    if "920083" in all_codes:
        print("  · 客户端响应里含 920083 → 客户端拿到了北交所榜，差异在我们请求方式")
    else:
        print("  · 客户端响应里也没有 920083 → 北交所榜走了别的通道/请求，查请求帧 CodeList")
    print("  · 对比【1】请求帧：客户端 SortBegin 是否恒 0 / SortCount 是否放大，")
    print("    与 thspypc ranked() 的 SortBegin 递增翻页差异即缺条目的根因")


def main() -> None:
    ap = argparse.ArgumentParser(description="抓同花顺排序榜流量，诊断缺条目")
    ap.add_argument("--duration", type=int, default=300, help="抓包时长秒，默认 300")
    ap.add_argument("--iface", type=int, default=None, help="网卡编号（跳过交互）")
    ap.add_argument("--pcap", default=None, help="只分析已有 pcap")
    ap.add_argument("--account", choices=["level2", "normal"], default="level2",
                    help="账号类型（仅影响操作提示），默认 level2")
    args = ap.parse_args()

    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"pcap 不存在: {args.pcap}")
            raise SystemExit(1)
        analyze_pcap(args.pcap)
        return

    if not os.path.exists(DUMPCAP):
        print(f"✗ dumpcap 不可用: {DUMPCAP}")
        print("  可设 THS_WIRESHARK_DIR 环境变量指向 Wireshark 目录")
        raise SystemExit(1)

    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未找到可用网卡（检查 Wireshark/Npcap）")
        raise SystemExit(1)
    print("可用网卡:")
    for idx, name in ifaces:
        mark = " ← 推荐" if "WLAN" in name else ""
        print(f"  {idx}. {name}{mark}")

    if args.iface is not None:
        idx = args.iface
        if not any(idx == i for i, _ in ifaces):
            print(f"网卡编号 {idx} 不存在")
            raise SystemExit(1)
    else:
        default = next((i for i, n in ifaces if "WLAN" in n), ifaces[0][0])
        choice = input(f"\n选择网卡编号 [{default}]: ").strip() or str(default)
        try:
            idx = int(choice)
            if not any(idx == i for i, _ in ifaces):
                raise ValueError
        except ValueError:
            print("无效选择")
            raise SystemExit(1)

    ts = time.strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(CAPTURE_DIR, f"rank_sort_{ts}.pcap")

    acct_hint = {
        "level2": "当前为 Level2 账号：客户端会拆沪(17/22/151)/深(33)两条连接，pageid=1341",
        "normal": "当前为普通账号：请确认客户端登录的是普通账号（非 Level2）",
    }[args.account]
    print(f"\n⚠ 请先确认:")
    print(f"  1. 同花顺已彻底退出（任务管理器确认 hexin.exe 已退出）")
    print(f"  2. {acct_hint}")
    print(f"  3. 抓包开始后再启动同花顺并登录")
    print(f"\n抓包期间操作（抓包开始后立即执行）:")
    print(f"  1) 沪深A股 列表 → 点表头『涨幅』排序（降序）")
    print(f"  2) ★慢速向下滚动 5-10 屏（每滚一屏停 1-2 秒，触发翻页请求）★")
    print(f"  3) 点表头『涨速』排序 → 再慢速滚动 3-5 屏")
    print(f"  4) 其余时间保持界面不动")
    input(f"\n按 Enter 开始抓包（{args.duration}s）...")

    capture(idx, args.duration, pcap_path)
    analyze_pcap(pcap_path)


if __name__ == "__main__":
    main()
