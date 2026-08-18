#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""被动抓取同花顺客户端「A股列表页」的 8901 流量（统一列字段逆向）。

目的：确认官方客户端在 A股列表（含自选/自定义板块列表）上请求的
pageid + DataType 字段集与响应列布局，为 web 端统一 8 列表
（代码/名称/涨幅/竞价涨幅/竞价金额/成交额/4分钟涨速/主力净额）
提供协议真值。

本脚本不登录、不连接行情服务器：只调用 dumpcap 监听官方客户端，
结束后用 tshark 扫描请求（pageid/DataType/CodeList）并 dump 大响应帧。

★ Level2 账号不能同时登录：抓包前必须关闭 thspypc 后端（端口 8765）。
  本脚本启动时会检查 8765，仍监听则直接报错退出。

推荐操作顺序：

1. 关闭 thspypc 后端（确认 8765 无监听）；
2. 确认同花顺客户端已完全退出；
3. 运行本脚本，看到"抓包已经开始"后再启动同花顺客户端；
4. 打开「沪深A股」列表，等列表完全加载（行数/名称/数值都出来）；
5. 依次点击表头排序：涨幅 → 竞价涨幅 → 竞价金额 → 成交额 → 涨速 →
   主力净额，每列停留 3~5 秒（这是本次抓包的关键动作）；
6. 再打开「自选股」列表让它加载一次；
7. 等待自动结束，或按 Ctrl+C 提前结束并分析。

用法：

    py tests/capture_stock_list_page.py --duration 120
    py tests/capture_stock_list_page.py --iface 8 --duration 150
    py tests/capture_stock_list_page.py --analyze-only captures_live/stocklist_page_xxx.pcapng

pcap 可能包含登录和账户相关流量，不要直接公开上传。
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures_live"
PORT = 8901
FRAME_MAGIC = b"\xfd\xfd\xfd\xfd"

WIRESHARK_DIRS = (
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"),
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark"),
    Path(r"C:\Program Files\Wireshark"),
    Path(r"D:\Program Files\Wireshark"),
)


def _find_tool(name: str) -> Path:
    env_dir = os.environ.get("THS_WIRESHARK_DIR") or os.environ.get("WIRESHARK_DIR")
    candidates: list[Path] = []
    found = shutil.which(name) or shutil.which(f"{name}.exe")
    if found:
        candidates.append(Path(found))
    if env_dir:
        candidates.append(Path(env_dir) / f"{name}.exe")
    candidates.extend(directory / f"{name}.exe" for directory in WIRESHARK_DIRS)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = "\n  ".join(str(path) for path in candidates)
    raise FileNotFoundError(
        f"找不到 {name}.exe。请安装 Wireshark/Npcap，或设置 THS_WIRESHARK_DIR。"
        f"\n已检查：\n  {tried}"
    )


def _run_tool(args: list[str], timeout: int = 240) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise RuntimeError(f"命令失败 ({result.returncode}): {' '.join(args[:3])}\n{detail}")
    return result


def _backend_listening(port: int = 8765) -> bool:
    """检测 thspypc 后端是否仍在监听（不发送任何业务数据）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def list_interfaces(tshark: Path) -> dict[str, tuple[str, str]]:
    result = _run_tool([str(tshark), "-D"], timeout=20)
    text = result.stdout.decode("gbk", "replace")
    interfaces: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        match = re.match(r"(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if match:
            interfaces[match.group(1)] = (
                match.group(2),
                (match.group(3) or match.group(2)).strip(),
            )
    return interfaces


def pick_interface(tshark: Path, requested: str | None) -> str:
    interfaces = list_interfaces(tshark)
    if not interfaces:
        raise RuntimeError("没有检测到可抓包网卡，请检查 Npcap/Wireshark")
    if requested:
        if requested not in interfaces:
            known = ", ".join(f"{number}={item[1]}" for number, item in interfaces.items())
            raise ValueError(f"网卡编号 {requested!r} 不存在；当前网卡：{known}")
        return requested

    print("可用网卡：")
    for number, (_, description) in interfaces.items():
        preferred = any(
            token in description.lower()
            for token in ("wlan", "wi-fi", "wifi", "以太网", "ethernet")
        )
        print(f"  {number}. {description}{'  ← 建议' if preferred else ''}")
    default = next(
        (
            number
            for number, (_, description) in interfaces.items()
            if any(
                token in description.lower()
                for token in ("wlan", "wi-fi", "wifi", "以太网", "ethernet")
            )
        ),
        next(iter(interfaces)),
    )
    choice = input(f"选择实际联网的网卡编号 [{default}]: ").strip() or default
    if choice not in interfaces:
        raise ValueError(f"网卡编号 {choice!r} 不存在")
    return choice


def capture(dumpcap: Path, interface: str, duration: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(dumpcap),
        "-i",
        interface,
        "-f",
        f"tcp port {PORT} or udp port 53",
        "-w",
        str(output),
        "-a",
        f"duration:{duration}",
    ]
    print("\n抓包已经开始。现在请：")
    print("  1. 启动同花顺客户端并登录（确认 thspypc 后端仍处于关闭状态）；")
    print("  2. 打开「沪深A股」列表，等它完全加载；")
    print("  3. 依次点击表头排序：涨幅 → 竞价涨幅 → 竞价金额 → 成交额 → 涨速 →")
    print("     主力净额，每列停留 3~5 秒（关键动作）；")
    print("  4. 再打开「自选股」列表让它加载一次。")
    print(f"\n将抓取 {duration}s；可按 Ctrl+C 提前结束。输出：{output}")

    process = subprocess.Popen(command)
    try:
        return_code = process.wait(timeout=duration + 20)
    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，正在停止 dumpcap 并保留已抓数据……")
        process.terminate()
        try:
            return_code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        return_code = process.wait(timeout=10)
    if return_code not in (0, 1):
        raise RuntimeError(f"dumpcap 退出码 {return_code}，请检查管理员权限和网卡编号")
    size = output.stat().st_size if output.exists() else 0
    print(f"抓包完成：{output} ({size:,} bytes)")


def _stream_fields(tshark: Path, pcap: Path) -> list[tuple[str, str, str, str]]:
    """返回 [(time, stream, dst_ip, payload_hex)] 的客户端→服务器帧。"""
    result = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.port=={PORT} and tcp.dstport=={PORT} and tcp.payload",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_relative",
            "-e",
            "tcp.stream",
            "-e",
            "ip.dst",
            "-e",
            "tcp.payload",
        ],
        timeout=240,
    )
    rows = []
    for line in result.stdout.decode("ascii", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[3]:
            continue
        rows.append((parts[0], parts[1], parts[2], parts[3]))
    return rows


def _split_fdf_frames(blob: bytes):
    """从原始字节流中切出 FDF 帧体（magic + 8 位 hex 长度 + body）。"""
    frames = []
    offset = blob.find(FRAME_MAGIC)
    while offset != -1:
        try:
            body_len = int(blob[offset + 4 : offset + 12], 16)
        except ValueError:
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        if not 0 < body_len < 8 * 1024 * 1024:
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        start = offset + 12
        end = start + body_len
        if end > len(blob):
            offset = blob.find(FRAME_MAGIC, offset + 1)
            continue
        frames.append(blob[start:end])
        offset = blob.find(FRAME_MAGIC, end)
    return frames


def analyze(tshark: Path, pcap: Path) -> None:
    rows = _stream_fields(tshark, pcap)

    # 1) 客户端请求：按 (pageid, DataType) 聚合
    combos: Counter[tuple[str, str]] = Counter()
    codelist_samples: dict[tuple[str, str], str] = {}
    servers: set[str] = set()
    for time, stream, dst, payload_hex in rows:
        servers.add(dst)
        try:
            payload = bytes.fromhex(payload_hex.replace(":", ""))
        except ValueError:
            continue
        text = payload.decode("gbk", errors="replace")
        page = re.search(r"pageid=(\d+)", text)
        datatype = re.search(r"DataType=([\d,\[\]]+?)\r?\n", text)
        codelist = re.search(r"CodeList=([0-9A-Za-z();,.\-]{0,40})", text)
        if not datatype:
            continue
        pageid = page.group(1) if page else "?"
        dt_str = datatype.group(1)
        combos[(pageid, dt_str)] += 1
        if (pageid, dt_str) not in codelist_samples and codelist:
            codelist_samples[(pageid, dt_str)] = codelist.group(1)

    print(f"\n[请求字段集统计（pageid × DataType，按出现次数）]")
    for (pageid, dt_str), count in combos.most_common(20):
        sample = codelist_samples.get((pageid, dt_str), "")
        print(f"  x{count:<4} pageid={pageid:<6} DataType={dt_str}")
        if sample:
            print(f"        CodeList 示例: {sample}")

    print(f"\n[连接的 8901 服务器] {', '.join(sorted(servers))}")

    # 2) 响应帧 dump：每条 8901 流按 TCP 重组切 FDF 帧，写 ≥200B 的帧体
    streams = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.port=={PORT} and tcp.payload",
            "-T",
            "fields",
            "-e",
            "tcp.stream",
        ],
        timeout=120,
    )
    stream_ids = sorted(
        {line.strip() for line in streams.stdout.decode("ascii", "replace").splitlines() if line.strip()},
        key=int,
    )

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    dumped = 0
    for stream in stream_ids[:12]:
        try:
            raw = _run_tool(
                [
                    str(tshark),
                    "-r",
                    str(pcap),
                    "-q",
                    "-z",
                    f"follow,tcp,raw,{stream}",
                ],
                timeout=120,
            )
        except RuntimeError:
            continue
        text = raw.stdout.decode("ascii", "replace")
        # tshark raw 模式：客户端→服务器行顶格、服务器→客户端行带 \t 前缀；
        # Windows 输出为 CRLF，行尾 \r 必须显式容忍。
        hex_lines = re.findall(r"^\t?[0-9a-fA-F]+\r?$", text, re.M)
        blob = bytes.fromhex("".join(hex_lines)) if hex_lines else b""
        if len(blob) < 200:
            continue
        for idx, frame in enumerate(_split_fdf_frames(blob)):
            if len(frame) < 200:
                continue
            out = CAPTURE_DIR / f"stocklist_page_resp_s{stream}_{idx}_{len(frame)}B_{stamp}.bin"
            out.write_bytes(frame)
            dumped += 1
            if dumped <= 8:
                print(f"  dump: {out.name}  头部={frame[:24]!r}")
    print(f"\n[响应帧] 共 dump {dumped} 个 ≥200B 帧体到 captures_live/")
    print("下一步：用 parse_hd3_response / decode 工具离线解析列布局。")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="抓取同花顺 A股列表页 8901 流量（列字段逆向）")
    parser.add_argument("--duration", type=int, default=120, help="抓包秒数（默认 120）")
    parser.add_argument("--iface", help="tshark -D 显示的网卡编号")
    parser.add_argument("--output", type=Path, help="输出 pcapng 路径")
    parser.add_argument("--analyze-only", type=Path, metavar="PCAP", help="只分析已有 pcap/pcapng")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    tshark = _find_tool("tshark")

    if args.analyze_only:
        analyze(tshark, args.analyze_only.resolve())
        return 0

    if _backend_listening():
        raise RuntimeError(
            "检测到 thspypc 后端仍在 8765 监听。"
            "请先关闭后端：Level2 账号不能同时登录两个客户端。"
        )
    if args.duration <= 0:
        raise ValueError("--duration 必须大于 0")

    dumpcap = _find_tool("dumpcap")
    interface = pick_interface(tshark, args.iface)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = (
        args.output or CAPTURE_DIR / f"stocklist_page_{timestamp}.pcapng"
    ).resolve()
    capture(dumpcap, interface, args.duration, output)
    analyze(tshark, output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"\n错误：{exc}", file=sys.stderr)
        raise SystemExit(2)
