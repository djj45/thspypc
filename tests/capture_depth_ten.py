#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""抓同花顺 PC 客户端的「十档盘口」流量，逆向 Level2 十档请求/响应形态。

背景
----
`depth_quote()` 目前只覆盖**五档**（pageid=1333、DataType=24~157 家族：
买一~买五/卖一~卖五各 10 对价量 + 122-125 封单字段）。十档只有 Level2 账号
有，普通账号仍为五档（五档即完整复刻口径）。本脚本抓包 + 分析，目标是：

1. 找出 L2 账号十档盘口请求的 **DataType / pageid / route / seq**；
2. 找出响应字段表里**五档之外的新字段**（六档~十档价量对），供离线逆向；
3. 普通账号对照一份，确认权限失败表现或仍返回五档。

用法
----
    py tests/capture_depth_ten.py --label l2                  # L2 账号，默认 180s
    py tests/capture_depth_ten.py --label normal --duration 180
    py tests/capture_depth_ten.py --analyze-only xxx.pcap --label l2

抓包期间操作（★按账号做对应步骤）：
    L2 账号：
      1. 同花顺登录后打开任意个股（如 600519/000938）的盘口视图
      2. 确认/切换到「十档」（Level2 盘口，买卖各 10 档；无十档开关时直接
         看盘口页默认档数，若只有五档请在客户端找 Level2 十档设置）
      3. 切换 2-3 只票，每只进出详情页 2-3 次（触发请求），可按 F5 刷新
      4. 每只票停留 3-5 秒，让盘口刷新/推送
    普通账号（对照）：
      1. 打开同一只票的盘口视图（应只显示五档）
      2. 同样切换 2-3 只票，进出详情页几次

产物：captures_live/depth10_<label>_*.pcap +
      depth10_req_<label>_<code>_<pageid>_<ts>.bin +
      depth10_resp_<label>_<code>_<pageid>_<ts>.bin（逐请求/响应样本）
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

from thspypc.protocol import decode_ths_float  # noqa: E402

# ── Wireshark 路径探测（与 capture_system_blocks.py 相同候选）──
WS_CANDIDATES = [
    r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark",
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark",
    r"C:\Program Files\Wireshark",
    r"D:\Program Files\Wireshark",
]
WS = next(
    (c for c in WS_CANDIDATES if os.path.exists(os.path.join(c, "tshark.exe"))),
    WS_CANDIDATES[0],
)
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = str(ROOT / "captures_live")
MAGIC = b"\xfd\xfd\xfd\xfd"
PORT = 8901

# 已知五档价量对（2026-07-23 抓包确认）；十档新增档位字段应在此集合之外
KNOWN_LEVEL_FIELDS = {
    24, 25, 26, 27, 28, 29, 150, 151, 154, 155,   # 买一~买五（价,量）
    30, 31, 32, 33, 34, 35, 152, 153, 156, 157,   # 卖一~卖五（价,量）
}
DEPTH_PAGEIDS = {"1333"}


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
        print(f"✗ 未检测到网卡（检查 Wireshark/Npcap，期望 tshark 在 {TSHARK}）")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    return choice if choice in ifaces else default


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
    """解析客户端请求文本，返回 dict 或 None。"""
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
    m = re.search(r"CodeList=(\d+)\(([^)]*)\)", text)
    if m:
        info["market"] = m.group(1)
        codes = [c.strip() for c in m.group(2).split(",") if c.strip()]
        info["codes"] = codes
        info["code"] = codes[0] if codes else ""
    m = re.search(r"DataType=([\d,\[\]]+)", text)
    if m:
        info["datatype"] = [
            int(x) for x in m.group(1).rstrip(",").split(",") if x.strip().isdigit()
        ]
    return info if info.get("pageid") or info.get("datatype") else None


def _decode_hd1_fields(frame_body):
    """解码 hd1.0 帧：返回 (fields, records) 或 (None, None)。"""
    pos = frame_body.find(b"hd1.0")
    if pos < 0:
        return None, None
    base = pos + 6
    if base + 10 > len(frame_body):
        return None, None
    dc = struct.unpack("<I", frame_body[base:base + 4])[0]
    hs = struct.unpack("<H", frame_body[base + 6:base + 8])[0]
    fc = struct.unpack("<H", frame_body[base + 8:base + 10])[0]
    if not (0 < dc < 100 and 0 < hs < 500 and 0 < fc < 60):
        return None, None
    ftoff = base + 10
    ft = frame_body[ftoff:ftoff + fc * 4]
    if len(ft) < fc * 4:
        return None, None
    fields = [(ft[i * 4], ft[i * 4 + 1], ft[i * 4 + 3]) for i in range(fc)]
    recoff = ftoff + fc * 4
    records = []
    for r in range(dc):
        row = frame_body[recoff + r * hs:recoff + (r + 1) * hs]
        if len(row) < hs:
            break
        rec = {}
        o = 0
        for dt, fmt, width in fields:
            chunk = row[o:o + width]
            o += width
            if dt == 5 and fmt == 0x20:
                rec["code"] = chunk[1:1 + 6].split(b"\x00")[0].decode(
                    "ascii", errors="replace"
                )
            elif width == 4:
                rec[f"dt{dt}"] = decode_ths_float(struct.unpack("<I", chunk)[0])
        records.append(rec)
    return fields, records


def _tshark_streams(pcap_path):
    r = subprocess.run(
        [TSHARK, "-r", pcap_path, "-Y", f"tcp.port=={PORT}",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, timeout=120,
    )
    stream_ids = [s for s in r.stdout.decode().split() if s]
    results = []
    for sid in sorted(set(stream_ids), key=lambda x: int(x)):
        rc = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.dstport=={PORT}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60,
        )
        client_hex = "".join(rc.stdout.decode().split())
        rs = subprocess.run(
            [TSHARK, "-r", pcap_path, "-Y",
             f"tcp.stream=={sid} and tcp.srcport=={PORT}",
             "-T", "fields", "-e", "tcp.payload"],
            capture_output=True, timeout=60,
        )
        server_hex = "".join(rs.stdout.decode().split())
        results.append((
            sid,
            bytes.fromhex(client_hex) if client_hex else b"",
            bytes.fromhex(server_hex) if server_hex else b"",
        ))
    return results


def analyze(pcap_path, label):
    print(f"\n{'=' * 64}\n分析 {pcap_path}（label={label}）\n{'=' * 64}")
    streams = _tshark_streams(pcap_path)
    print(f"共 {len(streams)} 条 {PORT} TCP 流\n")

    depth_requests: list[tuple[int, dict, list[bytes]]] = []
    for sid, client_bytes, server_bytes in streams:
        sframes = _split_frames(server_bytes)
        for fb in _split_frames(client_bytes):
            info = _parse_request(fb)
            if info is None:
                continue
            datatype = info.get("datatype") or []
            is_depth = (
                info.get("pageid") in DEPTH_PAGEIDS
                or 24 in datatype
                or 25 in datatype
            )
            if is_depth:
                depth_requests.append((sid, info, sframes))

    if not depth_requests:
        print("✗ 未抓到疑似盘口请求（pageid=1333 或 DataType 含 24/25）。")
        print("  请确认抓包期间打开过个股盘口视图；普通账号可能走别的 pageid，")
        print("  可改用 --analyze-only 前先看【全部请求】汇总。")

    # ── 汇总：盘口请求形态（去重）──
    print("【1】疑似盘口请求形态（pageid / DataType / 路由）")
    seen = set()
    for sid, info, _sframes in depth_requests:
        key = (
            info.get("pageid"),
            tuple(info.get("datatype") or []),
            info.get("query_route"),
            info.get("code"),
        )
        if key in seen:
            continue
        seen.add(key)
        dt_text = ",".join(str(x) for x in (info.get("datatype") or []))
        print(
            f"  pageid={info.get('pageid')} route={info.get('query_route')} "
            f"seq={info.get('query_seq')} code={info.get('code')} "
            f"DataType={dt_text}"
        )

    # ── 逐请求配对响应，标注五档之外的新字段 ──
    print("\n【2】盘口请求 → 响应字段表（★=五档之外，疑似十档新字段）")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dumped = set()
    for sid, info, sframes in depth_requests:
        code = info.get("code", "")
        pageid = info.get("pageid", "?")
        candidates = []
        for sf in sframes:
            fields, records = _decode_hd1_fields(sf)
            if fields is None:
                continue
            hit = [r for r in records if r.get("code") == code]
            if hit:
                candidates.append((sf, fields, records))
        if not candidates:
            print(f"  stream{sid} {code} pageid={pageid} → 未配对到含该代码的 hd1.0 响应")
            continue
        # 优先取字段表更完整的帧（>=8 个字段），避免把 2 字段推送帧当盘口响应
        candidates.sort(key=lambda item: -len(item[1]))
        for sf, fields, records in candidates:
            if len(fields) < 8 and len(candidates) > 1:
                continue
            field_list = [dt for dt, _fmt, _w in fields]
            # 疑似新档位：偶数价 + 奇数量的成对字段，且不在已知五档价量对里
            field_set = set(field_list)
            new_fields = sorted(
                dt for dt in field_set
                if dt % 2 == 0
                and (dt + 1) in field_set
                and dt not in KNOWN_LEVEL_FIELDS
            )
            mark = " ★" if new_fields else ""
            print(
                f"  stream{sid} {code} pageid={pageid} "
                f"字段[{','.join(map(str, field_list))}]{mark}"
            )
            if new_fields:
                pairs = ", ".join(f"{dt}/{dt + 1}" for dt in new_fields)
                print(f"    → 疑似十档新档位（价/量字段对）：{pairs}")
            first = next(r for r in records if r.get("code") == code)
            sample = first
            print(f"    首行样例: {sample}")
            req_key = (code, pageid)
            if req_key not in dumped:
                dumped.add(req_key)
                base = f"depth10_{label}_{code}_{pageid}_{ts}"
                Path(PCAP_DIR).mkdir(exist_ok=True)
                Path(PCAP_DIR, f"{base}_req.bin").write_bytes(
                    info["raw"]
                )
                Path(PCAP_DIR, f"{base}_resp.bin").write_bytes(sf)
                print(f"    → 已存样本: {base}_req.bin / {base}_resp.bin")
            break

    # ── 全部请求 pageid 分布（帮助确认普通账号盘口走哪个 pageid）──
    print("\n【3】全部请求 pageid 分布")
    counts = {}
    for sid, client_bytes, _server in streams:
        for fb in _split_frames(client_bytes):
            info = _parse_request(fb)
            if info and info.get("pageid"):
                pid = info["pageid"]
                counts[pid] = counts.get(pid, 0) + 1
    for pid, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        note = " ← 盘口" if pid in DEPTH_PAGEIDS else ""
        print(f"  pageid={pid}: {cnt} 次{note}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="l2", help="账号标签：l2 / normal")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--analyze-only", default="", help="只分析已有 pcap")
    args = parser.parse_args()

    if args.analyze_only:
        analyze(args.analyze_only, args.label)
        return 0

    os.makedirs(PCAP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(PCAP_DIR, f"depth10_{args.label}_{ts}.pcap")
    iface = pick_interface()
    print(f"\n{'=' * 60}")
    print(f"开始抓包 {args.duration}s（8901 端口，网卡 {iface}）")
    print(f"{'=' * 60}")
    print(">>> 抓包期间操作：")
    if args.label == "l2":
        print("    1. 打开任意个股（600519/000938 等）的盘口视图")
        print("    2. 确认/切换到「十档」（Level2 盘口买卖各 10 档）")
        print("    3. 切换 2-3 只票，每只进出详情页 2-3 次（可按 F5 刷新）")
        print("    4. 每只停留 3-5 秒")
    else:
        print("    1. 打开同一只票的盘口视图（普通账号应只有五档）")
        print("    2. 切换 2-3 只票，每只进出详情页 2-3 次")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", f"tcp port {PORT}",
             "-w", pcap_path, "-a", f"duration:{args.duration}"],
            timeout=args.duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        pass
    print(f"✓ pcap: {pcap_path}")
    analyze(pcap_path, args.label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
