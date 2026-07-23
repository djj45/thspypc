#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓 hexin 冷启动的 8901 login 序列，与 thspypc 的 login 帧逐字段对比。

用途：定位"为什么 hexin 能登而 thspypc 全局 VerifyCode=-1"。
     账号本身没问题（hexin 客户端同账号能正常登录看行情），
     问题在 thspypc 的 login 帧被服务器拒。抓包是定位差异的唯一可靠方法。

⚠ 不要反复登录——一次冷启动 120 秒足够，反复登录反而加剧 -1。

用法：
    py tests/capture_login_compare.py                 # 默认 120s
    py tests/capture_login_compare.py --duration 90   # 抓 90s
    py tests/capture_login_compare.py --pcap xxx.pcap # 分析已有 pcap（不抓包）

操作步骤（严格按顺序）：
    1. 先彻底退出同花顺（任务管理器确认 hexin.exe 进程没了）
    2. 运行本脚本（选网卡后开始抓包）
    3. 看到「开始抓包」后，立即启动同花顺并登录
    4. 登录成功、看到行情页面即可（不需要做其他操作）
    5. 等待自动结束，脚本会做 4 维度对比分析

产物：captures_live/login_compare.pcap + 终端对比报告
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "login_compare.pcap")

MAGIC = b"\xfd\xfd\xfd\xfd"  # 8901 帧分隔符（见 protocol.py FRAME_MAGIC）


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
    if choice not in ifaces:
        print("无效编号，用默认 4")
        choice = "4"
    return choice


def capture(iface, duration):
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"开始抓包 {duration}s（仅 8901，网卡 {iface}）")
    print(f"{'='*60}")
    print(">>> 现在立即：")
    print("    1. 启动同花顺并登录")
    print("    2. 登录成功、看到行情页面即可（别反复退出重登！）")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface, "-f", "tcp port 8901",
             "-w", PCAP, "-a", f"duration:{duration}"],
            timeout=duration + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"\n抓包完成：{PCAP} ({size:,} bytes)")


def _tshark(y_filter, fields):
    cmd = [TSHARK, "-r", PCAP, "-Y", y_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    return r.stdout.decode("utf-8", errors="replace")


def _split_frames(payload):
    """8901 帧用 fdfdfdfd magic + 8字节hex长度。返回 body 列表。"""
    frames = []
    for sub in payload.split(MAGIC):
        if len(sub) >= 8:
            frames.append(sub[8:])
    return frames


def _parse_login_fields(body: bytes) -> dict:
    """从 login 帧 body 解析字段（GBK 文本部分）。返回 {字段名: 值}。

    body 结构：二进制头 + GBK 文本（Ask=login\\nC-Version=...）。
    文本部分从首个 Ask= 或 \x09\x41\x09 之后开始。这里暴力搜 'Ask=login'。
    """
    fields = {}
    # 找文本区起点（login 帧含 'Ask=login'）
    idx = body.find(b"Ask=login")
    if idx < 0:
        idx = body.find(b"Ask=")
    if idx < 0:
        return fields
    text = body[idx:].decode("gbk", errors="replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            # 截掉行尾可能的二进制残留
            v = v.split("\x00")[0].strip()
            if k:
                fields[k] = v
    return fields


def analyze_hexin_ips():
    """【1】hexin 连接的 8901 目标 IP 列表。"""
    print(f"\n{'='*60}")
    print("【1】hexin 连接的 8901 目标 IP")
    print(f"{'='*60}")
    # SYN 包（客户端→服务器，dstport=8901）的目标 IP
    out = _tshark("tcp.dstport==8901 and tcp.flags.syn==1 and tcp.flags.ack==0",
                  ["ip.dst"])
    ips = []
    seen = set()
    for ln in out.splitlines():
        ip = ln.strip()
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    if ips:
        for i, ip in enumerate(ips, 1):
            print(f"  {i}. {ip}")
        print(f"\n  共 {len(ips)} 个不同 IP")
    else:
        print("  ✗ 未抓到 8901 SYN（可能没选对网卡，或同花顺没重启走了缓存连接）")
    return ips


def analyze_login_requests():
    """【2】hexin login 请求帧逐字段解码。"""
    print(f"\n{'='*60}")
    print("【2】hexin login 请求帧（逐字段）")
    print(f"{'='*60}")
    out = _tshark("tcp.dstport==8901 and tcp.payload", ["tcp.payload"])
    login_frames = []
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"Ask=login" in body:
                login_frames.append(body)

    if not login_frames:
        print("  ✗ 未抓到 login 请求帧（可能同花顺走了缓存，没重新 login）")
        print("    解决：确保同花顺彻底退出后再抓（任务管理器确认进程没了）")
        return []

    print(f"  ★ 抓到 {len(login_frames)} 个 login 请求帧\n")
    # 用第一个 login 帧做详细解码（通常所有 login 帧字段集一致）
    fields = _parse_login_fields(login_frames[0])
    print(f"  login 帧 #1 字段（共 {len(fields)} 个）：")
    for k, v in fields.items():
        # Passport64/Mac64 很长，截断显示
        if len(v) > 60:
            print(f"    {k} = {v[:50]}... (len={len(v)})")
        else:
            print(f"    {k} = {v}")
    # 统计所有 login 帧字段集是否一致
    if len(login_frames) > 1:
        keys_sets = [set(_parse_login_fields(b).keys()) for b in login_frames]
        if all(ks == keys_sets[0] for ks in keys_sets):
            print(f"\n  （{len(login_frames)} 个 login 帧字段集完全一致）")
        else:
            print(f"\n  ⚠ {len(login_frames)} 个 login 帧字段集不一致！")
            for i, ks in enumerate(keys_sets):
                print(f"    帧{i+1}: {sorted(ks)}")
    return login_frames


def analyze_login_responses():
    """【3】hexin login 响应的 VerifyCode。"""
    print(f"\n{'='*60}")
    print("【3】hexin login 响应 VerifyCode")
    print(f"{'='*60}")
    out = _tshark("tcp.srcport==8901 and tcp.payload", ["tcp.payload"])
    reply_frames = []
    for ln in out.splitlines():
        hx = ln.strip().replace(":", "")
        if not hx:
            continue
        try:
            payload = bytes.fromhex(hx)
        except ValueError:
            continue
        for body in _split_frames(payload):
            if b"Reply=" in body:
                reply_frames.append(body)

    if not reply_frames:
        print("  ✗ 未抓到 login 响应（Reply=）")
        return {}

    # 解析每个响应的 VerifyCode
    vc_count = {}
    for body in reply_frames:
        idx = body.find(b"Reply=")
        text = body[idx:].decode("gbk", errors="replace")
        m = re.search(r"VerifyCode=(-?\d+)", text)
        vc = m.group(1) if m else "?"
        vc_count[vc] = vc_count.get(vc, 0) + 1

    print(f"  共 {len(reply_frames)} 个 login 响应：")
    for vc, n in sorted(vc_count.items()):
        mark = " ✅" if vc == "0" else (" ❌ -1" if vc == "-1" else " ⚠️")
        print(f"    VerifyCode={vc}: {n} 次{mark}")

    if vc_count.get("0", 0) > 0:
        print("\n  → hexin 的 VerifyCode 含 0，证明账号/IP/login 帧本身没问题")
        print("    thspypc 的 -1 是 login 帧内容差异导致（看【4】对比）")
    elif vc_count.get("-1", 0) > 0 and not vc_count.get("0"):
        print("\n  ⚠ hexin 自己也全是 -1！可能账号当前被临时封，需等待释放")
    return vc_count


def analyze_thspypc_compare(hexin_login_frames):
    """【4】thspypc login 帧本地生成 + 与 hexin 并排字段对比。"""
    print(f"\n{'='*60}")
    print("【4】thspypc login 帧 vs hexin login 帧（字段对比）")
    print(f"{'='*60}")
    from thspypc.protocol import build_login_body_pc, generate_mac64, MARKET_HOSTS

    # 用占位 Passport64（等长）生成 thspypc 的 login body，重点对比字段集和顺序
    # hexin 的 Passport64 ~2304 字符（见 protocol.build_passport64 docstring）
    placeholder_passport64 = "A" * 2304
    mac64 = generate_mac64()
    thspypc_body = build_login_body_pc(placeholder_passport64, mac64)
    thspypc_fields = _parse_login_fields(thspypc_body)

    print("  thspypc login 帧字段（本地生成，Passport64 为占位）：")
    for k, v in thspypc_fields.items():
        if len(v) > 60:
            print(f"    {k} = {v[:50]}... (len={len(v)})")
        else:
            print(f"    {k} = {v}")

    if not hexin_login_frames:
        print("\n  ⚠ 无 hexin login 帧，无法对比（看【2】为什么没抓到）")
        # 仍展示 thspypc 会连的 IP
        print(f"\n  thspypc MARKET_HOSTS（DNS 解析失败时回退）: {MARKET_HOSTS[:5]}...")
        return

    hexin_fields = _parse_login_fields(hexin_login_frames[0])

    # 字段集对比
    hexin_keys = set(hexin_fields.keys())
    thspypc_keys = set(thspypc_fields.keys())

    print(f"\n  {'─'*50}")
    print("  字段集差异：")
    only_hexin = hexin_keys - thspypc_keys
    only_thspypc = thspypc_keys - hexin_keys
    common = hexin_keys & thspypc_keys

    if only_hexin:
        print(f"  ⚠ hexin 有、thspypc 缺的字段（{len(only_hexin)} 个）:")
        for k in sorted(only_hexin):
            v = hexin_fields[k]
            if len(v) > 40:
                v = v[:40] + "..."
            print(f"      + {k} = {v}")
    else:
        print("  ✓ hexin 的字段 thspypc 都有（无缺失）")

    if only_thspypc:
        print(f"\n  thspypc 多出的字段（{len(only_thspypc)} 个，hexin 没有）:")
        for k in sorted(only_thspypc):
            print(f"      - {k}")

    # 共有字段值对比（Passport64 内容不同是预期的，跳过）
    print(f"\n  共有字段值对比（{len(common)} 个）:")
    for k in sorted(common):
        hv = hexin_fields[k]
        tv = thspypc_fields[k]
        if k in ("Passport64", "Mac64"):
            # 身份字段只比长度
            mark = "✓" if len(hv) == len(tv) else f"⚠ 长度不同 hexin={len(hv)} thspypc={len(tv)}"
            print(f"    {k}: {mark}")
        else:
            match = "✓" if hv == tv else f"⚠ 不同  hexin='{hv}' thspypc='{tv}'"
            print(f"    {k}: {match}")

    # IP 列表对比
    print(f"\n  {'─'*50}")
    print("  IP 列表对比：")
    print(f"    thspypc MARKET_HOSTS（DNS 回退）: {list(MARKET_HOSTS[:5])}")


def analyze():
    if not os.path.exists(PCAP):
        print(f"✗ pcap 不存在: {PCAP}")
        return
    size = os.path.getsize(PCAP)
    print(f"\n{'#'*60}")
    print(f"# 分析 {PCAP} ({size:,} bytes)")
    print(f"{'#'*60}")

    hexin_ips = analyze_hexin_ips()
    login_frames = analyze_login_requests()
    analyze_login_responses()
    analyze_thspypc_compare(login_frames)

    print(f"\n{'#'*60}")
    print(f"# pcap 已保存：{PCAP}")
    print(f"# 用 Wireshark 打开可 Follow TCP Stream 看完整 login 帧")
    print(f"{'#'*60}")


def main():
    ap = argparse.ArgumentParser(description="抓 hexin 8901 login 序列，与 thspypc 对比")
    ap.add_argument("--duration", type=int, default=120,
                    help="抓包时长（秒），默认 120")
    ap.add_argument("--iface", default=None,
                    help="网卡编号（默认交互选择）")
    ap.add_argument("--pcap", default=None,
                    help="分析已有 pcap（不抓包）")
    args = ap.parse_args()

    if args.pcap:
        global PCAP
        PCAP = args.pcap
        analyze()
    else:
        iface = args.iface or pick_interface()
        capture(iface, args.duration)
        analyze()


if __name__ == "__main__":
    main()
