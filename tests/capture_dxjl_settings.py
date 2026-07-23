#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓短线精灵阈值设置请求（qurealorder 里的 datatype 字段）。

用法：
    1. 打开同花顺，登录，切到短线精灵页面（先别改设置）
    2. 运行本脚本
    3. 在同花顺里改短线精灵的阈值设置（大于多少手/百万）→ 保存 → 刷新列表
    4. 等 30 秒自动结束，或 Ctrl+C 提前停
    5. 脚本自动提取所有 datatype= 字段并和当前默认值对比

产物：captures_live/dxjl_settings.pcap + 终端打印 datatype diff
"""
import os
import re
import subprocess
import sys

WS = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"
DUMPCAP = os.path.join(WS, "dumpcap.exe")
TSHARK = os.path.join(WS, "tshark.exe")
PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")
PCAP = os.path.join(PCAP_DIR, "dxjl_settings.pcap")
DURATION = 30

# 当前默认 datatype（src/thspypc/protocol.py:880）
DEFAULT_DATATYPE = (
    "1074269398{19[1000000~-]|17[5000000~-]},"
    "1074269399{19[1000000~-]|17[5000000~-]},"
    "1074269401,1074269403"
)


def list_interfaces():
    """列网卡，返回 {编号: 描述}。

    tshark -D 输出按系统 ANSI（中文 Windows=GBK）编码，用 errors='replace'
    容错：网卡名含特殊字符时不崩，只丢几个字符。
    """
    # text=True 在 Windows 默认用 GBK，遇到非法字节会让 stdout 变 None
    # 用 encoding + errors 兜底
    r = subprocess.run(
        [TSHARK, "-D"], capture_output=True,
        encoding="gbk", errors="replace", timeout=15,
    )
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
        print("✗ 未检测到网卡。请检查 Wireshark 安装。")
        sys.exit(1)
    print("网卡列表:")
    for num, (dev, desc) in ifaces.items():
        # 精确匹配 "WLAN"（非 WLAN 2/3/4 这种虚拟网卡）
        mark = " ← 推荐" if desc.strip() == "WLAN" else ""
        print(f"  {num}. {desc}{mark}")

    # 自动找纯 WLAN
    default = None
    for num, (dev, desc) in ifaces.items():
        if desc.strip() == "WLAN":
            default = num
            break
    if not default:
        # 退而求其次找第一个含 WLAN/以太网 的
        for num, (dev, desc) in ifaces.items():
            if "WLAN" in desc or "以太网" in desc or "ethernet" in desc.lower():
                default = num
                break
    if not default:
        default = list(ifaces.keys())[0]

    while True:
        choice = input(f"\n选择网卡编号 [{default}]: ").strip()
        if not choice:
            choice = default
        if choice in ifaces:
            return choice, ifaces[choice][1]
        print(f"  无效编号，重选")


def capture(iface_num):
    """抓包 DURATION 秒。"""
    os.makedirs(PCAP_DIR, exist_ok=True)
    print(f"\n开始抓包 {DURATION}s（9601 端口）...")
    print(">>> 现在请在同花顺里操作：改短线精灵阈值 → 保存 → 刷新列表")
    print("-" * 60)
    try:
        subprocess.run(
            [DUMPCAP, "-i", iface_num, "-f", "tcp port 9601",
             "-w", PCAP, "-a", f"duration:{DURATION}"],
            timeout=DURATION + 15,
        )
    except KeyboardInterrupt:
        print("\n抓包提前结束（已保存）")
    except subprocess.TimeoutExpired:
        print("\n抓包超时")
    size = os.path.getsize(PCAP) if os.path.exists(PCAP) else 0
    print(f"抓包完成：{PCAP} ({size:,} bytes)")


def extract_datatypes():
    """从 pcap 提取所有 qurealorder 请求里的 datatype= 字段。

    只认 method=qurealorder（短线精灵），忽略 statscalc/calcext 等其他 9601 请求
    （它们也有 datatype 字段但含义完全不同）。

    用 instid 去重：同一请求可能因 TCP 分段出现在多个包里，每个包都含
    datatype= 片段，会重复计数。按请求序列号 instid 去重，每个 instid 只算一次。

    返回 (qurealorder_datatypes, all_methods_summary, sample_request)
    """
    if not os.path.exists(PCAP):
        return [], {}, None
    r = subprocess.run(
        [TSHARK, "-r", PCAP, "-Y", "tcp.port==9601 and tcp.payload",
         "-T", "fields", "-e", "tcp.payload"],
        capture_output=True, timeout=60,
    )
    datatypes = []
    method_counter = {}
    seen_instids = set()   # 按请求 instid 去重
    sample_request = None  # 保存一个完整请求文本供展示
    for ln in r.stdout.split(b"\n"):
        hex_str = ln.replace(b":", b"").strip()
        if not hex_str:
            continue
        try:
            payload = bytes.fromhex(hex_str.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            continue
        text = payload.decode("gbk", errors="replace")
        # 统计所有 method（用 instid 去重避免分段重复计数）
        m_method = re.search(r"method=(\w+)", text)
        m_inst = re.search(r"instid=(\d+)", text)
        if m_method and m_inst:
            key = (m_method.group(1), m_inst.group(1))
            if key not in seen_instids:
                method_counter[m_method.group(1)] = method_counter.get(m_method.group(1), 0) + 1
        # 只从 qurealorder 里提取 datatype（用 instid 去重）
        if "method=qurealorder" not in text:
            continue
        if m_inst:
            instid = m_inst.group(1)
            if instid in seen_instids:
                continue
            seen_instids.add(instid)
        for m in re.finditer(r"datatype=([^\n\x00]+)", text):
            datatypes.append(m.group(1).strip())
        if sample_request is None:
            # 提取 \x09 后的完整请求体
            m_body = re.search(r"\x09(.+?)(?:\x00|$)", text, re.DOTALL)
            if m_body:
                sample_request = m_body.group(1)
    return datatypes, method_counter, sample_request


def analyze_category_ids(datatype: str) -> list[dict]:
    """解析 datatype 里的所有类别 ID，拆成 前缀 + 异动字节。

    类别 ID 结构（抓包+实测确认）：
        category_id = group_prefix | anomaly_byte
        其中 group_prefix 是某异动"组"的固定前缀（高 3 字节），
        低字节就是 ANOMALY_MAP_DXJL 里的异动字节（如 0xd6=大笔买入）。

    已知组前缀（全选抓包确认，见 protocol.py ANOMALY_GROUP_PREFIX）：
        0x40080c00 → 0xd1~0xf8 核心异动（大笔/涨跌停/急速/放量/封板，29个）
        0x00090a00 → 0xbc~0xbf   特大主动/被动买卖（4个）
        0x00020b00 → 0x66~0x6f   挂单/撤单（8个）
        0x00020a00 → 0xa2~0xa5   拖拉机/远价位（4个）
        0x003f0d00 → 0xab~0xb0   新版异动（含义未知，6个）
        0x000b0b00 → 0x99~0x9a   新版异动（含义未知，2个）

    Returns:
        list[dict]，每项 {cid, hex, prefix, prefix_hex, anomaly_byte, anomaly_name}
    """
    ANOMALY_NAMES = {
        0xbc: "特大主动买", 0xbd: "特大被动买", 0xbe: "特大主动卖", 0xbf: "特大被动卖",
        0xd1: "区间放量涨", 0xd2: "区间放量跌", 0xd6: "大笔买入", 0xd7: "大笔卖出",
        0xd8: "涨停封板", 0xd9: "打开涨停板", 0xda: "跌停封板", 0xdb: "打开跌停板",
        0xdc: "急速拉升", 0xdd: "猛烈打压", 0xe0: "逼近涨停", 0xe1: "逼近跌停",
        0xe2: "涨停大减", 0xe3: "跌停大减", 0xe4: "强势封涨停", 0xee: "强势封跌停",
        0x66: "特大挂买", 0x67: "特大挂卖", 0xa2: "拖拉机挂买", 0xa3: "拖拉机挂卖",
        0xa4: "远价位垫单", 0xa5: "远价位压单",
        0x6c: "撤特大买", 0x6d: "撤涨停买", 0x6e: "撤特大卖", 0x6f: "撤跌停卖",
        0xf0: "未知0xf0",
    }
    # 提取所有类别 ID（datatype 里逗号分隔，每段形如 "1234567{...}" 或 "1234567"）
    results = []
    for part in datatype.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"(\d+)", part)
        if not m:
            continue
        cid = int(m.group(1))
        prefix = cid & 0xFFFFFF00  # 高 3 字节
        anom_byte = cid & 0xFF     # 低字节
        results.append({
            "cid": cid,
            "hex": f"0x{cid:08x}",
            "prefix": prefix,
            "prefix_hex": f"0x{prefix:08x}",
            "anomaly_byte": anom_byte,
            "anomaly_name": ANOMALY_NAMES.get(anom_byte, f"未知0x{anom_byte:02x}"),
            "has_threshold": "{" in part,
        })
    return results


def diff_datatype(captured: str) -> None:
    """对比抓到的 datatype 和默认值，并分析类别 ID 结构。"""
    # 先分析类别 ID 结构（核心）
    cats = analyze_category_ids(captured)
    if cats:
        print(f"\n{'='*60}")
        print("类别 ID 结构分析（前缀 + 异动字节）")
        print(f"{'='*60}")
        # 按前缀分组
        by_prefix = {}
        for c in cats:
            by_prefix.setdefault(c["prefix_hex"], []).append(c)
        print(f"\n共 {len(cats)} 个类别，分 {len(by_prefix)} 组（按前缀）：")
        for prefix_hex, group in sorted(by_prefix.items()):
            print(f"\n  前缀 {prefix_hex}（{len(group)} 个类型）:")
            for c in group:
                thr = " 有阈值" if c["has_threshold"] else " 无阈值"
                print(f"    {c['cid']:>11} = {c['hex']}  "
                      f"低字节=0x{c['anomaly_byte']:02x} → {c['anomaly_name']}{thr}")

    print(f"\n{'='*60}")
    print("datatype 对比")
    print(f"{'='*60}")
    print(f"\n[默认值]（protocol.py:880）:")
    print(f"  {DEFAULT_DATATYPE}")
    print(f"\n[抓到值] {captured}")

    if captured == DEFAULT_DATATYPE:
        print("\n→ 完全一致，阈值没变。")
        return

    # 逐段对比（逗号分隔）
    print("\n→ 有差异！逐段对比:")
    old_parts = DEFAULT_DATATYPE.split(",")
    new_parts = captured.split(",")
    max_len = max(len(old_parts), len(new_parts))
    for i in range(max_len):
        old = old_parts[i] if i < len(old_parts) else "(无)"
        new = new_parts[i] if i < len(new_parts) else "(无)"
        mark = "  ✓ 一致" if old == new else f"  ★ 变化"
        print(f"  段{i}: {mark}")
        if old != new:
            print(f"      旧: {old}")
            print(f"      新: {new}")

    # 提取阈值数字
    print(f"\n阈值数字提取:")
    for label, val in (("旧(默认)", DEFAULT_DATATYPE), ("新(抓到)", captured)):
        nums = re.findall(r"(\d+)\[(\d+)~", val)
        for field, threshold in nums:
            print(f"  {label}: 字段{field} 阈值={int(threshold):,}")


def main():
    print("=" * 60)
    print("抓短线精灵阈值设置请求（qurealorder datatype）")
    print("=" * 60)

    iface_num, desc = pick_interface()
    print(f"\n选用网卡 {iface_num}: {desc}")

    capture(iface_num)

    datatypes, method_summary, sample_req = extract_datatypes()

    # 先报告抓到的所有请求类型（诊断用，按 instid 去重后的真实请求数）
    if method_summary:
        print(f"\n抓包期间 9601 端口的请求数（按 instid 去重）:")
        for mk, cnt in sorted(method_summary.items(), key=lambda x: -x[1]):
            mark = " ← 短线精灵" if mk == "qurealorder" else ""
            print(f"  {mk}: {cnt} 个请求{mark}")

    if not datatypes:
        print("\n✗ 未抓到 qurealorder（短线精灵）请求。")
        if "qurealorder" not in method_summary:
            print(f"\n  ★ 根因：抓包期间同花顺没发 qurealorder。")
            print(f"  其他 {list(method_summary.keys())} 是同花顺别的功能（板块/计算），")
            print(f"  它们的 datatype 字段含义完全不同，不能用来改短线精灵阈值。")
        print(f"\n  请确保在抓包期间触发短线精灵查询：")
        print(f"    1. 打开短线精灵窗口（不是在行情页里看）")
        print(f"    2. 修改异动阈值 → 确定 → 保存")
        print(f"    3. 在短线精灵列表里下拉刷新 / 翻页 / 切换市场")
        print(f"  （必须让短线精灵重新请求数据，才会发 qurealorder）")
        print(f"\n  pcap 已保存: {PCAP}（可用 Wireshark 复查）")
        return 1

    # 去重 datatype 值（跨请求去重）
    seen = []
    for d in datatypes:
        if d not in seen:
            seen.append(d)
    print(f"\n抓到 {len(datatypes)} 个 qurealorder 请求，{len(seen)} 种不同 datatype")

    # 展示一个完整请求样本（含 maxcount/endtime/market 等其他关键字段）
    if sample_req:
        print(f"\n{'='*60}")
        print("完整请求样本（一个 qurealorder）:")
        print(f"{'='*60}")
        print(sample_req.rstrip())

    for i, d in enumerate(seen):
        diff_datatype(d)
        if i < len(seen) - 1:
            print("\n" + "-" * 60)

    print(f"\npcap 已保存: {PCAP}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
