#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""
抓同花顺「快速 K 线路径」的请求和完整响应字节,破解 DataType 路径的 OHLC 编码。

背景(2026-08-11 抓包已确认)
----------------------------
同花顺切股票时,K 线**不走 period 路径**,而是和 quote/depth 同通道的 DataType 多字段查询:

    pageid=1334, DataType=272,229,271,228,13,227,19

响应是 0x0a 压缩的 hd3.1 序列表(record_count≈529,每只股票一次,约 2 年日 K)。
实测请求→响应 ~35ms,而 thspypc 现有 ``build_kline_l2_query``(带 period 参数)要 ~2000ms,
**快 57 倍**。本脚本抓这条快路径的完整字节,破解 2 字段 12 字节怎么 packed OHLC+日期。

之前 capture_kline.py 失效的原因:它过滤 ``period=``/``qukline``,但 PC 版 K 线根本
不含这些关键词(它用 DataType 编号)。本脚本改用 **DataType=272,229,271,228** 作特征。

输出
----
- ``kline_fast_<ts>.pcap``:原始抓包
- ``kline_fast_<ts>_stream<N>.bin``:每个 TCP stream 的双向重组字节(供离线解析)
- 终端报告:每个 K 线请求的 code/DataType/record_count/响应耗时

操作步骤(★决定能否抓到关键数据)
--------------------------------
    1. 启动同花顺并登录,打开一只股票(如 600519)
    2. 运行本脚本,选网卡
    3. 抓包期间操作:
       a. 切到日 K 线图,等加载完(抓默认日 K,529 根)
       b. ★ 在日 K 图上按住 ← 方向键,连续翻页 5-10 次
          (触发"加载更早历史",看请求参数是否多 BeginTime/offset)
       c. 切到周 K 线图,等加载完(抓周 K 的 DataType)
       d. 切到月 K 线图(抓月 K 的 DataType)
       e. 切另一只股票,重复 a-d
    4. 等结束或 Ctrl+C

用法:
    py tests/capture_kline_fast.py                # 默认 120s
    py tests/capture_kline_fast.py --duration 180
    py tests/capture_kline_fast.py --analyze-only captures_live/xxx.pcap
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
WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = ROOT / "captures_live"

# K 线 DataType 路径的特征字段(272,229,271,228 是 OHLC 序列字段)
KLINE_DATATYPE_MARKER = "272,229,271,228"


def list_interfaces() -> dict[str, str]:
    r = subprocess.run([TSHARK, "-D"], capture_output=True,
                       encoding="gbk", errors="replace", timeout=15)
    out: dict[str, str] = {}
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)\s+\((.+?)\)", ln)
        if m:
            out[m.group(1)] = m.group(3)
    return out


def pick_iface() -> str:
    ifaces = list_interfaces()
    if not ifaces:
        print("✗ 未检测到网卡"); sys.exit(1)
    print("网卡列表:")
    for n, d in ifaces.items():
        print(f"  {n}. {d}{' ← 推荐' if d.strip() == 'WLAN' else ''}")
    default = next((n for n, d in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡 [{default}]: ").strip() or default
    return choice if choice in ifaces else default


def _tshark(pcap: Path, filt: str, fields: list[str]) -> str:
    cmd = [TSHARK, "-r", str(pcap), "-Y", filt, "-T", "fields"]
    for f in fields: cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
    return subprocess.run(cmd, capture_output=True, timeout=120).stdout.decode("utf-8", "replace")


def _extract_kv(text: str) -> dict:
    kv = {}
    for k in ["CodeList", "DataType", "DateTime", "pageid", "method",
              "BeginTime", "EndTime", "count", "period", "LackTime"]:
        m = re.search(rf"(?:^|[^A-Za-z0-9_-]){k}=([^\r\n]*)", text)
        if m: kv[k] = m.group(1).strip()[:50]
    return kv


def analyze(pcap: Path) -> None:
    """找所有 K 线请求(DataType 含 272,229,271,228),测响应耗时,导出 stream 字节。"""
    print(f"\n{'='*70}")
    print(f"分析 {pcap}")
    print(f"{'='*70}")

    # 1. 找 K 线请求
    out = _tshark(pcap,
                  f'tcp.payload contains "{KLINE_DATATYPE_MARKER}" and tcp.dstport == 8901',
                  ["frame.number", "frame.time_relative", "tcp.stream", "tcp.payload"])
    reqs = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) < 4 or not p[3]: continue
        payload = bytes.fromhex(p[3].replace(":", ""))
        text = payload.decode("gbk", errors="replace")
        kv = _extract_kv(text)
        m = re.search(r"CodeList=\d+\((\w+)", text)
        code = m.group(1) if m else "?"
        reqs.append({"frame": int(p[0]), "t": float(p[1]),
                     "stream": p[2], "code": code, "kv": kv})

    print(f"\nK 线请求(DataType 含 {KLINE_DATATYPE_MARKER}): {len(reqs)} 个\n")
    if not reqs:
        print("  ✗ 没抓到。检查:同花顺是否切到了 K 线图?是否选对网卡?")
        return

    # 2. 测每个请求的响应耗时(同 stream 里下一个 server 帧)
    print(f"{'code':>8} {'stream':>3} {'请求t':>8} {'Δ响应':>8}  DataType")
    print("-" * 75)
    for r in reqs:
        resp_out = _tshark(pcap,
                           f'tcp.stream == {r["stream"]} and tcp.srcport == 8901 and frame.number > {r["frame"]}',
                           ["frame.time_relative", "-c", "1"])  # -c 不支持 -e
        # 改用 tshark 直接取首个
        try:
            r2 = subprocess.run(
                [TSHARK, "-r", str(pcap),
                 "-Y", f'tcp.stream == {r["stream"]} and tcp.srcport == 8901 and frame.number > {r["frame"]}',
                 "-T", "fields", "-e", "frame.time_relative", "-c", "1"],
                capture_output=True, timeout=30).stdout.decode().strip()
            first_t = float(r2.split("\t")[0]) if r2 else r["t"]
            dt_ms = (first_t - r["t"]) * 1000
        except Exception:
            dt_ms = -1
        dt_str = f"{dt_ms:.0f}ms" if dt_ms >= 0 else "?"
        print(f"{r['code']:>8} {r['stream']:>3} {r['t']:>7.2f}s {dt_str:>8}  {r['kv'].get('DataType','?')[:40]}")

    # 3. 导出涉及的 stream 的完整重组字节(供离线解析)
    streams = sorted({r["stream"] for r in reqs})
    print(f"\n涉及的 TCP stream: {streams}")
    ts_tag = datetime.datetime.now().strftime("%H%M%S")
    for s in streams:
        out_path = pcap.parent / f"{pcap.stem}_stream{s}.bin"
        # 用 follow,tcp,raw 重组
        raw = subprocess.run(
            [TSHARK, "-r", str(pcap), "-qz", f"follow,tcp,raw,{s}"],
            capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
        bin_data = b""
        in_data = False
        for ln in raw.splitlines():
            if ln.startswith("==="): in_data = not in_data; continue
            if not in_data or not ln.strip(): continue
            h = ln.strip().replace("\t", "")
            if not re.match(r"^[0-9a-fA-F]+$", h) or len(h) < 2: continue
            try: bin_data += bytes.fromhex(h)
            except: pass
        out_path.write_bytes(bin_data)
        print(f"  stream {s}: {len(bin_data)} 字节 → {out_path.name}")

    # 4. 找响应里的 hd3.1 序列表(确认 K 线数据)
    print(f"\n=== 扫描 K 线响应里的 hd3.1 序列表 ===")
    sys.path.insert(0, str(ROOT / "src"))
    from thspypc.codecs.compression import normalize_8901_response
    import struct
    for s in streams:
        bin_path = pcap.parent / f"{pcap.stem}_stream{s}.bin"
        if not bin_path.exists(): continue
        data = bin_path.read_bytes()
        MAGIC = bytes([0xfd] * 4)
        segs = [seg[8:] for seg in data.split(MAGIC) if len(seg) > 8]
        kline_tables = []
        for body in segs:
            if not body: continue
            if body[0] == 0x0a:
                try: payload = normalize_8901_response(body)
                except: continue
            else:
                payload = body
            idx = payload.find(b"hd3.1\x00")
            if idx < 0: continue
            base = idx + 6
            if base + 10 > len(payload): continue
            rc, flag = struct.unpack_from("<HH", payload, base)
            if flag == 0x0100 and rc > 20:
                kline_tables.append(rc)
        if kline_tables:
            from collections import Counter
            print(f"  stream {s}: {len(kline_tables)} 个 hd3.1 序列表, "
                  f"record_count 分布 {dict(Counter(kline_tables))}")


def main():
    ap = argparse.ArgumentParser(description="抓同花顺快速 K 线路径(DataType 路径)")
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--analyze-only", default=None,
                    help="跳过抓包,直接分析已有 pcap")
    args = ap.parse_args()

    if args.analyze_only:
        analyze(Path(args.analyze_only))
        return

    PCAP_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap = PCAP_DIR / f"kline_fast_{ts}.pcap"
    iface = args.iface or pick_iface()

    print(f"\n{'='*70}")
    print(f"抓包 {args.duration}s,网卡 {iface}")
    print(f"{'='*70}")
    proc = subprocess.Popen(
        [DUMPCAP, "-i", iface, "-q", "-w", str(pcap),
         "-a", f"duration:{args.duration}", "-f", "tcp port 8901"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.5)
    print(f"""
现在操作同花顺(决定能否抓到关键数据):

  1. 打开一只股票(如 600519),切到【日 K 线图】等加载完
  2. ★ 在日 K 图上按住 ← 方向键,连续翻页 5-10 次(加载更早历史)
  3. 切到【周 K】图等加载完
  4. 切到【月 K】图等加载完
  5. 切另一只股票,重复 1-4

  操作完后 Ctrl+C 或等 {args.duration} 秒自动结束
""")
    try:
        proc.wait(timeout=args.duration + 10)
    except subprocess.TimeoutExpired:
        proc.terminate()
    except KeyboardInterrupt:
        print("\n用户中断..."); proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()

    print(f"\n抓包结束\n")
    analyze(pcap)


if __name__ == "__main__":
    main()
