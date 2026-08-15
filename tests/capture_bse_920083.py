#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""被动抓取同花顺客户端访问北交所 920083 的 8901 流量。

本脚本不登录、不连接行情服务器：它只调用 dumpcap 监听官方同花顺客户端，
结束后用 tshark 快速扫描与 920083 / market=151 相关的请求与服务器。

★ Level2 账号不能同时登录：抓包前必须关闭 thspypc 后端（端口 8765）。
  本脚本启动时会检查 8765，仍监听则直接报错退出。

推荐操作顺序：

1. 关闭 thspypc 后端（关闭 dev.bat 窗口，确认 8765 无监听）；
2. 确认同花顺客户端已完全退出；
3. 运行本脚本，看到“抓包已经开始”后再启动同花顺客户端；
4. 打开 920083，依次切换 日K / 分时 / 盘口（五档），每页停留几秒；
5. 等待自动结束，或按 Ctrl+C 提前结束并分析。

用法：

    py tests/capture_bse_920083.py --duration 90
    py tests/capture_bse_920083.py --iface 8 --duration 120
    py tests/capture_bse_920083.py --analyze-only captures_live/bse_920083_xxx.pcapng

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
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures_live"
PORT = 8901

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
    print("  2. 打开 920083；")
    print("  3. 依次切换 日K / 分时 / 盘口（五档），每页停留几秒。")
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


def analyze(tshark: Path, pcap: Path) -> dict[str, int]:
    """扫描抓包：920083 请求、pageid、以及连接的 8901 服务器。"""
    result = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.port=={PORT} and tcp.payload",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_relative",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.payload",
        ],
        timeout=240,
    )
    text = result.stdout.decode("ascii", "replace")
    markers = {
        "CodeList=151": 0,
        "920083": 0,
        "pageid=9355": 0,
        "pageid=10443": 0,
        "pageid=1334": 0,
        "hd3.1": 0,
    }
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        try:
            payload = bytes.fromhex(parts[3])
        except ValueError:
            continue
        for marker in markers:
            if marker.encode("ascii") in payload:
                markers[marker] += 1

    print("\n[920083 相关帧统计]")
    for marker, count in markers.items():
        print(f"  {marker:<14} {count}")

    syn = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.port=={PORT} and tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.dst",
        ],
        timeout=120,
    )
    print("\n[客户端连接过的 8901 服务器]")
    for line in syn.stdout.decode("ascii", "replace").splitlines():
        if line.strip():
            print(f"  {line.replace(chr(9), '  ->  ')}")
    return markers


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="抓取同花顺客户端访问北交所 920083 的 8901 流量")
    parser.add_argument("--duration", type=int, default=90, help="抓包秒数（默认 90）")
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
        args.output or CAPTURE_DIR / f"bse_920083_{timestamp}.pcapng"
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
