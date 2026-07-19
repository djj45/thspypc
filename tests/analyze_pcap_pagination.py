#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
离线分析 captures_live/stock_list.pcap，重点搞清 hexin 客户端的 stock_list 翻页行为：
  - 翻页用的是哪个 IP / TCP stream？是不是同一连接翻页？
  - 每页请求的 SortBegin/SortCount/CodeList/DataType 真值（和我们构造的是否一致）
  - 服务器响应的分页元数据（SortTotal/SortBegin/SortCount）

用法：
    py tests/analyze_pcap_pagination.py            # 分析默认 pcap
    py tests/analyze_pcap_pagination.py --pcap X   # 指定 pcap
"""
import argparse
import os
import re
import subprocess
import sys
from collections import OrderedDict, defaultdict

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
TSHARK = os.path.join(WS, "tshark.exe")
DEFAULT_PCAP = os.path.join(os.path.dirname(__file__), "..", "captures_live", "stock_list.pcap")

MAGIC = b"\xfd\xdf\xdf\xfd"


def tshark(pcap, y_filter, fields, extra=None):
    cmd = [TSHARK, "-r", pcap, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if extra:
        cmd += extra
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def split_frames(payload: bytes):
    """把一个 TCP payload 切成 [fdfdfdfd 帧列表]，每帧返回 body（去掉 8B 长度头）。"""
    out = []
    parts = payload.split(MAGIC)
    for sub in parts:
        if len(sub) < 8:
            continue
        # 前 8 字节是 ASCII hex 长度（如 "00000066"），之后是 body
        out.append(sub[8:])
    return out


def decode_text(body: bytes) -> str:
    # body[0] 通常是 0x09（子帧标记），文本从某 offset 开始；直接整体 GBK decode
    return body.decode("gbk", errors="replace")


def extract_kv(text: str) -> dict:
    """从文本里提取 key=value（\r\n / \n / ; 分隔）。"""
    kv = {}
    # 把分隔符统一
    flat = text.replace("\r\n", "\n").replace("\r", "\n")
    for token in re.split(r"[\n;]", flat):
        if "=" in token:
            k, _, v = token.partition("=")
            kv[k.strip()] = v.strip()
    return kv


def analyze_requests(pcap):
    print("=" * 70)
    print("【1】stock_list 分页请求（含 SortBegin 的帧）")
    print("=" * 70)
    out = tshark(pcap, 'tcp.payload contains "SortBegin"',
                 ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
                  "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.payload"])
    requests = []
    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 8:
            continue
        fr, t, sip, dip, sport, dport, stream, hexstr = parts
        if not hexstr:
            continue
        payload = bytes.fromhex(hexstr.replace(":", ""))
        # 一个 TCP segment 可能含多个 fdfdfdfd 帧
        for body in split_frames(payload):
            text = decode_text(body)
            if "SortBegin" not in text:
                continue
            kv = extract_kv(text)
            requests.append({
                "frame": fr, "t": float(t) if t else 0.0,
                "src": sip, "dst": dip, "sport": sport, "dport": dport,
                "stream": stream, "kv": kv, "text": text,
                "body": body,  # 含二进制头
            })

    # 按时间排序
    requests.sort(key=lambda r: (r["t"], int(r["frame"])))
    if not requests:
        print("  ✗ pcap 中没有含 SortBegin 的请求")
        return [], {}, []

    # 按 (dst_ip, stream) 分组：判断是不是同一连接翻页
    by_conn = OrderedDict()
    for r in requests:
        key = (r["dst"], r["stream"])
        by_conn.setdefault(key, []).append(r)

    print(f"\n  共 {len(requests)} 个分页请求，分布在 {len(by_conn)} 个连接（dst_ip, tcp_stream）：")
    for (dip, stream), reqs in by_conn.items():
        t0 = reqs[0]["t"]
        t1 = reqs[-1]["t"]
        print(f"\n  ▶ 连接 dst={dip} stream={stream}：{len(reqs)} 个请求，时间 {t0:.2f}s ~ {t1:.2f}s（跨度 {t1-t0:.2f}s）")
        for r in reqs:
            kv = r["kv"]
            sort_fields = {k: kv.get(k, "") for k in
                           ("CodeList", "DataType", "SortType", "SortBy", "SortDir",
                            "SortAppend", "SortBegin", "SortCount", "FuncPeriod",
                            "DateTime", "LackTime", "pageid")}
            # 打印关键翻页字段
            print(f"    帧{r['frame']} t={r['t']:.3f}s "
                  f"CodeList={sort_fields['CodeList']!r} "
                  f"DT={sort_fields['DataType']!r} "
                  f"SortBy={sort_fields['SortBy']!r} "
                  f"SortDir={sort_fields['SortDir']!r} "
                  f"SortAppend={sort_fields['SortAppend']!r}")
            print(f"      SortBegin={sort_fields['SortBegin']!r} "
                  f"SortCount={sort_fields['SortCount']!r} "
                  f"FuncPeriod={sort_fields['FuncPeriod']!r} "
                  f"pageid={sort_fields['pageid']!r}")
            # 二进制头
            bh = r["body"][:23]
            print(f"      二进制头[0:23]: {bh.hex(' ')}")

    return requests, by_conn, []


def analyze_responses(pcap, requests):
    """找含 SortTotal 的响应帧，和请求按 stream/时间配对。"""
    print("\n" + "=" * 70)
    print("【2】stock_list 分页响应（含 SortTotal 的帧）")
    print("=" * 70)
    out = tshark(pcap, 'tcp.payload contains "SortTotal"',
                 ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
                  "tcp.stream", "tcp.payload"])
    responses = []
    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 6:
            continue
        fr, t, sip, dip, stream, hexstr = parts
        if not hexstr:
            continue
        payload = bytes.fromhex(hexstr.replace(":", ""))
        for body in split_frames(payload):
            text = decode_text(body)
            if "SortTotal" not in text:
                continue
            kv = extract_kv(text)
            responses.append({
                "frame": fr, "t": float(t) if t else 0.0,
                "src": sip, "dst": dip, "stream": stream,
                "kv": kv, "text": text, "body": body,
            })

    responses.sort(key=lambda r: r["t"])
    print(f"\n  共 {len(responses)} 个含 SortTotal 的响应帧")
    for r in responses[:30]:
        kv = r["kv"]
        # 是否含 OrderError
        oe = kv.get("OrderError", "")
        # 是否含 hd3.1 / hd1.0
        has_hd3 = b"hd3.1" in r["body"]
        has_hd1 = b"hd1.0" in r["body"]
        print(f"    帧{r['frame']} t={r['t']:.3f}s src={r['src']} stream={r['stream']}: "
              f"SortTotal={kv.get('SortTotal','?')} "
              f"SortBegin={kv.get('SortBegin','?')} "
              f"SortCount={kv.get('SortCount','?')} "
              f"SortDataCount={kv.get('SortDataCount','?')} "
              f"hd3={'Y' if has_hd3 else '-'} hd1={'Y' if has_hd1 else '-'} "
              f"OE={oe!r}")
    return responses


def analyze_connections(pcap):
    """8901 上所有 SYN，看 hexin 连了多少个 IP、什么时候连的。"""
    print("\n" + "=" * 70)
    print("【3】8901 TCP 连接（SYN）总览 — hexin 连了哪些 IP、什么时候")
    print("=" * 70)
    out = tshark(pcap, "tcp.port==8901 and tcp.flags.syn==1 and tcp.flags.ack==0",
                 ["frame.number", "frame.time_relative", "ip.dst", "tcp.stream"])
    conns = []
    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        fr, t, dip, stream = parts
        conns.append((fr, float(t) if t else 0.0, dip, stream))
    conns.sort(key=lambda x: x[1])
    ip_count = defaultdict(int)
    for fr, t, dip, stream in conns:
        ip_count[dip] += 1
    print(f"\n  共 {len(conns)} 个 SYN，{len(ip_count)} 个不同目标 IP：")
    for ip, n in sorted(ip_count.items(), key=lambda x: -x[1]):
        print(f"    {ip}: {n} 次连接")
    print(f"\n  SYN 时间线（前 30）：")
    for fr, t, dip, stream in conns[:30]:
        print(f"    帧{fr} t={t:.3f}s dst={dip} stream={stream}")
    return conns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=DEFAULT_PCAP)
    args = ap.parse_args()
    pcap = os.path.abspath(args.pcap)
    if not os.path.exists(pcap):
        print(f"✗ pcap 不存在: {pcap}")
        return 1
    print(f"分析 pcap: {pcap} ({os.path.getsize(pcap):,} bytes)\n")

    requests, by_conn, _ = analyze_requests(pcap)
    analyze_responses(pcap, requests)
    analyze_connections(pcap)

    # 关键结论汇总
    print("\n" + "=" * 70)
    print("【结论】")
    print("=" * 70)
    if by_conn:
        multi = [k for k, v in by_conn.items() if len(v) > 1]
        print(f"  - 分页请求连接数: {len(by_conn)}，其中 {len(multi)} 个连接发了 >1 个分页请求")
        if multi:
            print(f"    → 同连接翻页的 (ip,stream): {multi}  ← 说明 hexin 在同一连接翻页")
        # 看 CodeList 真值
        all_cls = set()
        all_dt = set()
        for r in requests:
            all_cls.add(r["kv"].get("CodeList", ""))
            all_dt.add(r["kv"].get("DataType", ""))
        print(f"  - CodeList 取值: {all_cls}")
        print(f"  - DataType 取值: {all_dt}")
        # 看 SortCount
        sc = sorted({r["kv"].get("SortCount", "") for r in requests})
        print(f"  - SortCount 取值: {sc}")
        sb = sorted({r["kv"].get("SortBegin", "") for r in requests}, key=lambda x: int(x) if x.isdigit() else -1)
        print(f"  - SortBegin 取值(排序): {sb[:20]}{'...' if len(sb)>20 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
