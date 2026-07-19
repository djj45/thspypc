#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
探针：构造 qustocklink 请求，实测能否拿到 A 股列表。

原理：Windows PC 客户端用 method=qustocklink（8901端口，纯文本帧）+ StockLinkVer
做股票列表增量同步。带 ConfigVer=0（表示本地无缓存）可能骗服务器发全量。

用法：
    py tests/probe_qustocklink.py                 # 默认：沪市A股 ConfigVer=0
    py tests/probe_qustocklink.py --stock 32_A_SO # 深市A股
    py tests/probe_qustocklink.py --ver 202607170840  # 用真实版本号
    py tests/probe_qustocklink.py --all           # 全部28个板块

产物：captures_live/qustocklink_resp.bin + 终端分析
"""
import argparse
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "captures_live")

from thspypc import THSClient
from thspypc.protocol import encode_frame, read_frame

# qustocklink 的控制字节（抓包确认）
B_BLOCK = b"\x02"   # ^b 块开始（StockLinkVer/Stock_XX 的开头）
B_SECT = b"\x01"    # ^B 节开始
B_REC = b"\x0e"     # ^n 记录/行结束
B_KEY = b"\x05"     # ^e 键值分隔
B_COL = b"\x03"     # ^c 列分隔
B_RT = b"\x12"      # ^r （成对出现，含义待定）

# 28 个 Stock 配置项（StockLinkVer 里客户端声明的全部板块）
ALL_STOCKS = [
    "Stock_176_H_QC", "Stock_176_H_QP", "Stock_16_A_SO", "Stock_16_F_SO",
    "Stock_16_B_SO", "Stock_16_Z_SO", "Stock_32_A_SO", "Stock_32_B_SO",
    "Stock_32_F_SO", "Stock_32_Z_SO", "Stock_68_C_DO", "Stock_69_C_ZO",
    "Stock_64_C_SO", "Stock_64_C_DO", "Stock_64_C_ZO", "Stock_144_P_SC",
    "Stock_144_Y_SC", "Stock_16_X_IO", "Stock_176_H_BULL", "Stock_176_H_BEAR",
    "Stock_88_H_QC", "Stock_88_H_QP", "Stock_88_H_BULL", "Stock_88_H_BEAR",
    "Stock_UGFF_F_O", "Stock_32_X_IO", "Stock_64_F_OS", "Stock_112_H_HF",
    "Stock_64_F_DL",
]

# Stock 配置项 → 中文说明
STOCK_NAMES = {
    "Stock_16_A_SO": "沪市A股", "Stock_32_A_SO": "深市A股",
    "Stock_16_B_SO": "沪市B股", "Stock_32_B_SO": "深市B股",
    "Stock_16_F_SO": "沪市基金", "Stock_32_F_SO": "深市基金",
    "Stock_16_Z_SO": "沪市指数", "Stock_32_Z_SO": "深市指数",
    "Stock_64_C_SO": "北交所", "Stock_144_P_SC": "创业板",
    "Stock_16_X_IO": "沪市指数?", "Stock_32_X_IO": "深市指数?",
}


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            if k.strip() and k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")


def build_stocklinkver(stocks: list[str], config_ver: str) -> bytes:
    """构造 stocklinkver 字段（含控制字节）。

    格式（抓包确认）：
      ^bConfigInfo^B^r^nConfigVer^e{ver}^r^n
      ^b{Stock_XX}^B^r^nConfigVer^e{ver}^r^n
      ...每个 Stock 重复
    """
    parts = [B_BLOCK + b"ConfigInfo" + B_SECT + B_RT + B_REC
             + b"ConfigVer" + B_KEY + config_ver.encode("gbk") + B_RT + B_REC]
    for stock in stocks:
        parts.append(B_BLOCK + stock.encode("gbk") + B_SECT + B_RT + B_REC
                     + b"ConfigVer" + B_KEY + config_ver.encode("gbk") + B_RT + B_REC)
    return b"".join(parts)


def build_qustocklink_query(instance: int, stocks: list[str],
                            config_ver: str) -> bytes:
    """构造 qustocklink 请求帧 body（含 \\x09 前缀，不含 FD magic）。

    抓包确认的请求结构：
      \\x09
      instid={instance}\\n
      method=qustocklink\\n
      c-version=E029.60.20.0031\\n
      stocklinkver={控制字节序列}
    """
    stocklinkver = build_stocklinkver(stocks, config_ver)
    header = (
        f"instid={instance}\n"
        f"method=qustocklink\n"
        f"c-version=E029.60.20.0031\n"
    ).encode("gbk")
    return b"\x09" + header + b"stocklinkver=" + stocklinkver


def send_and_recv(sock, body, timeout=15):
    """发送请求，循环读取所有响应帧（大响应会分多帧）。"""
    sock.sendall(encode_frame(body) + b"\n")
    sock.settimeout(timeout)
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            frame = read_frame(sock)
            chunks.append(frame)
            # 如果刚读到含数据的帧，缩短后续等待（判断是否还有后续）
            if len(chunks) >= 1:
                remaining = deadline - time.time()
                if remaining > 3:
                    sock.settimeout(3.0)  # 缩短，看还有没有后续帧
        except (socket.timeout, OSError, ConnectionError):
            break
    return b"".join(chunks)


def visualize_control_bytes(data: bytes) -> str:
    """把控制字节可视化，方便阅读响应结构。"""
    CTRL = {0x02: "^b", 0x01: "^B", 0x0e: "^n", 0x05: "^e",
            0x03: "^c", 0x12: "^r", 0x09: "^t", 0x00: "."}
    out = []
    for b in data:
        if b in CTRL:
            out.append(CTRL[b])
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def analyze_response(resp: bytes, target_stocks: list[str]) -> None:
    """分析响应内容。"""
    print(f"\n{'='*60}")
    print(f"响应分析（总 {len(resp)} 字节）")
    print(f"{'='*60}")

    if not resp:
        print("✗ 空响应（服务器没返回，可能请求格式错误或被拒）")
        return

    # 可视化前 1500 字节
    print(f"\n--- 前 1500 字节（控制字节可视化）---")
    vis = visualize_control_bytes(resp[:1500])
    print(vis)

    # 找所有 Stock_XX 块
    text = resp.decode("gbk", errors="replace")
    found_blocks = re.findall(r"Stock_\w+", text)
    from collections import Counter
    block_dist = Counter(found_blocks)
    print(f"\n--- 响应里的 Stock 块 ---")
    if block_dist:
        for blk, cnt in block_dist.most_common():
            name = STOCK_NAMES.get(blk, "")
            mark = " ★目标" if blk in target_stocks else ""
            print(f"  {blk} ({name}): {cnt} 次{mark}")
    else:
        print("  （无 Stock_ 块，可能返回了错误信息或纯文本）")
        # 看看返回了什么文本
        m = re.search(r"(Reply|Error|VerifyCode|S-)\w*[^\n]{0,80}", text)
        if m:
            print(f"  响应特征: {m.group(0)[:100]}")

    # 找明文 6 位代码（A股特征）
    codes = re.findall(r"\b([036]\d{5})\b", text)
    unique_codes = list(dict.fromkeys(codes))  # 去重保序
    print(f"\n--- 明文 6 位代码 ---")
    if unique_codes:
        print(f"  找到 {len(unique_codes)} 个唯一代码（去重前 {len(codes)} 个）")
        print(f"  样本: {unique_codes[:15]}")
        prefixes = Counter(c[0] for c in unique_codes)
        print(f"  首字分布: {dict(sorted(prefixes.items()))}")
    else:
        print(f"  （无明文 6 位代码）")

    # 找 token 格式（市场码:6字符）
    tokens = re.findall(r"\b(\d{2}):([0-9A-Za-z@_]{6})\b", text)
    if tokens:
        print(f"\n--- 市场码:token 格式 ---")
        print(f"  找到 {len(tokens)} 个 token")
        market_dist = Counter(m for m, _ in tokens)
        print(f"  市场码分布: {dict(market_dist.most_common())}")
        print(f"  样本: {tokens[:10]}")


def main():
    parser = argparse.ArgumentParser(description="qustocklink 探针")
    parser.add_argument("--stock", default="16_A_SO",
                        help="Stock 配置项后缀（如 16_A_SO=沪市A股, 32_A_SO=深市A股），默认 16_A_SO")
    parser.add_argument("--ver", default="0",
                        help="ConfigVer（0=骗全量，或真实版本号如 202607170840）")
    parser.add_argument("--all", action="store_true",
                        help="请求全部 28 个板块（数据量大）")
    args = parser.parse_args()

    load_dotenv()
    os.makedirs(DATA_DIR, exist_ok=True)
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()

    if args.all:
        stocks = ALL_STOCKS
        target = ALL_STOCKS
    else:
        stock_name = f"Stock_{args.stock}" if not args.stock.startswith("Stock_") else args.stock
        stocks = [stock_name]
        target = [stock_name]

    print("=" * 60)
    print(f"qustocklink 探针")
    print("=" * 60)
    print(f"请求板块: {stocks}")
    print(f"  含义: {', '.join(STOCK_NAMES.get(s, '?') for s in stocks)}")
    print(f"ConfigVer: {args.ver}")

    client = THSClient(username, password)
    r = client.connect()
    if not r.success:
        print(f"登录失败: {r.error}")
        return 1
    print(f"登录: {r.server}")

    # 构造请求
    instance = 200000  # 固定较大的 instid 避免和心跳冲突
    body = build_qustocklink_query(instance, stocks, args.ver)
    print(f"\n请求构造完成（{len(body)} 字节 body）")
    print(f"请求可视化（控制字节）:")
    print(f"  {visualize_control_bytes(body[:300])}...")

    # 发送并接收
    print(f"\n发送请求，等待响应（最多 15s）...")
    sock = client._sock
    if not sock:
        print("✗ 8901 未连接")
        return 1

    try:
        resp = send_and_recv(sock, body, timeout=15)
    except Exception as e:
        print(f"✗ 收响应失败: {e}")
        import traceback; traceback.print_exc()
        client.disconnect()
        return 1

    # dump 完整响应
    resp_path = os.path.join(DATA_DIR, "qustocklink_resp.bin")
    with open(resp_path, "wb") as f:
        f.write(resp)
    print(f"\n响应已保存: {resp_path} ({len(resp)} 字节)")

    # 分析
    analyze_response(resp, target)

    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
