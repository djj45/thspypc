#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 hexin 的 HTTP 鉴权（80 端口），对比 mainverify 参数 + signature 格式。

用途：定位 VerifyCode=-1 / PromptText=-6 根因。thspypc 的 head128 由 signature
      经 _sig_to_nibbles 转换，算法移植自 thspy Mac 版（-0x51 偏移）。PC 版可能不同。
      本脚本抓 hexin 的 mainverify 响应里的 signature，用 thspypc 算法转换，
      对比 hexin Passport64 里的 head128[5:]，验证算法是否正确。

用法：
    py tests/capture_http_auth.py                # 默认 90s
    py tests/capture_http_auth.py --duration 60
    py tests/capture_http_auth.py --pcap xxx.pcap  # 分析已有 pcap

操作步骤：
    1. 彻底退出同花顺（任务管理器确认 hexin.exe 没了）
    2. 运行本脚本
    3. 启动同花顺并登录（触发 HTTP 鉴权）
    4. 等待自动结束
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

WS = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "http_auth.pcap")


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
        print("✗ 未检测到网卡")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")
    default = next((n for n, (_, d) in ifaces.items() if d.strip() == "WLAN"), "4")
    choice = input(f"\n选择网卡编号 [{default}]: ").strip() or default
    return choice if choice in ifaces else "4"


def capture(iface, duration):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"抓包 {duration}s（HTTP 80 端口 鉴权流量，网卡 {iface}）")
    print(f"{'='*60}")
    print(">>> 现在立即：")
    print("    1. 启动同花顺并登录（触发 HTTP 鉴权）")
    print("    2. 登录成功即可")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp port 80",
             "-w", PCAP, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"\n抓包完成：{PCAP} ({size:,} bytes)")


def _tshark_full(y_filter, pcap=None):
    """提取完整 HTTP 流（按 stream 重组）。"""
    pcap = pcap or PCAP
    # 用 tshark follow stream 模式
    cmd = [TSHARK, "-r", pcap, "-Y", y_filter, "-T", "fields",
           "-e", "tcp.stream", "-e", "http.request.uri", "-e", "http.response.code"]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _tshark_follow(stream_id, pcap=None):
    """follow 一个 TCP stream，返回原始 payload。"""
    pcap = pcap or PCAP
    cmd = [TSHARK, "-r", pcap, "-z", f"follow,tcp,ascii,{stream_id}"]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def analyze():
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return
    print(f"\n{'#'*60}")
    print(f"# 分析 HTTP 鉴权流量")
    print(f"{'#'*60}")

    # 【1】找 mainverify 请求
    print(f"\n{'='*60}")
    print("【1】HTTP 请求（含 mainverify/unified_login）")
    print(f"{'='*60}")
    out = _tshark_full("http.request", )
    streams = []
    for ln in out.splitlines():
        p = ln.split("\t")
        if len(p) >= 2 and p[1]:
            uri = p[1]
            sid = p[0]
            if "verify2" in uri or "mainverify" in uri or "unified_login" in uri:
                streams.append((sid, uri))
                # 显示请求参数
                print(f"\n  stream {sid}: {uri[:120]}")
    if not streams:
        print("  ✗ 未抓到 verify2 请求（可能同花顺走了缓存，或没冷启动）")
        return

    # 【2】提取 mainverify 响应里的 signature + passport
    print(f"\n{'='*60}")
    print("【2】mainverify 响应（signature + passport）")
    print(f"{'='*60}")
    # follow 每个 verify2 stream
    for sid, uri in streams:
        if "mainverify" not in uri:
            continue
        content = _tshark_follow(sid)
        # follow ascii 输出里含请求和响应
        # 找 <mainverify>...</mainverify> 段
        m = re.search(r"<mainverify>(.*?)</mainverify>", content, re.DOTALL)
        if not m:
            # 可能响应是二进制，找 signature=
            m2 = re.search(r"signature=([A-O]{256})", content)
            if m2:
                sig = m2.group(1)
                print(f"  hexin signature ({len(sig)} 字符): {sig[:60]}...")
                _verify_signature_algo(sig)
            continue
        body = m.group(1)
        # 解析 signature 和 passport
        sig_m = re.search(r"signature=([A-O]+)", body)
        if sig_m:
            sig = sig_m.group(1)
            print(f"  hexin signature ({len(sig)} 字符): {sig[:60]}...")
            _verify_signature_algo(sig, body)
        else:
            print(f"  未找到 signature，body 前 200 字符: {body[:200]}")


def _verify_signature_algo(hexin_sig, mainverify_body=""):
    """用 thspypc 的 _sig_to_nibbles 转换 hexin signature，验证算法。"""
    from thspypc.protocol import _sig_to_nibbles, ACCOUNT_TYPE
    print(f"\n  --- signature 算法验证 ---")
    nibbles = _sig_to_nibbles(hexin_sig)
    head128 = ACCOUNT_TYPE + nibbles[:123]
    prefix_5b = nibbles[123:128]
    print(f"  thspypc 算法转换的 head128[5:15]: {head128[5:15].hex(' ')}")
    print(f"  thspypc 算法转换的 prefix_5b: {prefix_5b.hex(' ')}")

    # 从同一 mainverify 响应里提取 passport_bytes，解码出 hexin 的 head128 对比
    if mainverify_body:
        # passport 在 mainverify body 里（| 分隔的字段流）
        # 找 passport 段
        pb_m = re.search(r"(\|signature=[^|]*\|.*?)(?=\||$)", mainverify_body)
        # 实际上 passport_bytes 是整个 <mainverify> 内容
        # 用 build_passport64 的逻辑：head128 + prefix_5b + fields
        # 但我们需要 hexin 实际构造的 Passport64——这个在 8901 login 帧里
        # 这里只能验证 signature 转换算法的内部一致性
        pass

    # 验证：hexin 的 signature 是不是 A-O 编码（每字符代表一个 nibble）
    chars = set(hexin_sig)
    valid = set("ABCDEFGHIJKLMNO")
    print(f"  signature 字符集: {sorted(chars)}")
    print(f"  是否全是 A-O: {chars <= valid}")
    if chars <= valid:
        print(f"  ✓ A-O 编码（A=0..O=15），与 thspypc _sig_to_nibbles 假设一致")
    else:
        print(f"  ⚠ 含非 A-O 字符！算法假设可能错误")

    # thspypc 自己的 signature 对比
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    user = pwd = ""
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("THS_USERNAME="):
            user = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("THS_PASSWORD="):
            pwd = line.split("=", 1)[1].strip().strip('"').strip("'")
    from thspypc.protocol import full_http_auth
    auth = full_http_auth(user, pwd)
    thspypc_sig = auth["signature"]
    print(f"\n  thspypc 自己的 signature ({len(thspypc_sig)} 字符): {thspypc_sig[:60]}...")
    print(f"  hexin signature ({len(hexin_sig)} 字符): {hexin_sig[:60]}...")
    print(f"  长度一致: {len(thspypc_sig) == len(hexin_sig)}")


def main():
    global PCAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--pcap", default=None)
    args = ap.parse_args()

    if args.pcap:
        PCAP = args.pcap
        analyze()
    else:
        iface = args.iface or pick_interface()
        capture(iface, args.duration)
        analyze()


if __name__ == "__main__":
    main()
