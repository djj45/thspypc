#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""抓取并分析同花顺短线精灵（REALORDER/9601）的服务器发现过程。

目标不是解析 qurealorder 业务帧，而是回答：

    官方客户端在连接 106.14.65.90:9601 之前，从哪里得到了这个地址？

推荐用法：

    1. 完全退出同花顺，任务管理器确认没有 hexin.exe。
    2. 运行：
       py tests/capture_realorder_discovery.py --duration 150
    3. 脚本开始抓包后再启动、登录同花顺。
    4. 打开短线精灵并刷新一次，等待抓包自动结束。

也可以分析已有文件：

    py tests/capture_realorder_discovery.py --pcap captures_live/realorder_discovery.pcapng

抓包包含所选网卡上的完整 IP 流量，可能含账号、Cookie、访问地址等敏感信息。
不要直接上传 pcap；优先分享脚本生成的 ``*.report.txt`` 文本报告。
"""

from __future__ import annotations

import argparse
import csv
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Iterable


KNOWN_REALORDER_IP = "106.14.65.90"
REALORDER_PORT = "9601"
DEFAULT_DURATION = 150
DEFAULT_LOOKBACK = 30.0

ROOT = Path(__file__).resolve().parent.parent
CAPTURE_DIR = ROOT / "captures_live"
DEFAULT_PCAP = CAPTURE_DIR / "realorder_discovery.pcapng"

WIRESHARK_CANDIDATES = (
    Path(
        r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App"
    ),
    Path(r"C:\Program Files\Wireshark"),
)


def _find_executable(name: str) -> str:
    env_dir = os.environ.get("WIRESHARK_DIR")
    candidates = []
    if env_dir:
        candidates.append(Path(env_dir) / name)
    candidates.extend(path / name for path in WIRESHARK_CANDIDATES)

    from_path = shutil.which(name)
    if from_path:
        candidates.insert(0, Path(from_path))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    locations = "\n".join(f"  - {path}" for path in candidates)
    raise FileNotFoundError(
        f"找不到 {name}。请安装 Wireshark，或设置 WIRESHARK_DIR。\n"
        f"已检查：\n{locations}"
    )


def _run(
    command: list[str],
    *,
    timeout: float | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=check,
    )


def list_interfaces(tshark: str) -> dict[str, tuple[str, str]]:
    result = _run([tshark, "-D"], timeout=15)
    interfaces: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if match:
            number, device, description = match.groups()
            interfaces[number] = (device, description or device)
    return interfaces


def pick_interface(tshark: str) -> str:
    interfaces = list_interfaces(tshark)
    if not interfaces:
        raise RuntimeError("未检测到可抓包网卡，请检查 Npcap/Wireshark 安装")

    print("可用网卡：")
    recommended = None
    for number, (device, description) in interfaces.items():
        text = f"{device} {description}".lower()
        if recommended is None and any(
            token in text for token in ("wlan", "wi-fi", "ethernet", "以太网")
        ):
            recommended = number
        print(f"  {number}. {description}")

    default = recommended or next(iter(interfaces))
    choice = input(f"\n选择实际联网的网卡编号 [{default}]: ").strip() or default
    if choice not in interfaces:
        raise ValueError(f"无效网卡编号：{choice}")
    return choice


def capture(
    dumpcap: str,
    interface: str,
    pcap: Path,
    duration: int,
    max_mib: int,
) -> None:
    pcap.parent.mkdir(parents=True, exist_ok=True)
    print("\n开始全量 IP 抓包。现在请：")
    print("  1. 启动并登录同花顺")
    print("  2. 打开“短线精灵”并刷新一次")
    print("  3. 保持同花顺运行，等待脚本自动结束")
    print(f"\n抓包最长 {duration} 秒，文件上限 {max_mib} MiB：{pcap}")

    command = [
        dumpcap,
        "-i",
        interface,
        "-f",
        "ip or ip6",
        "-s",
        "0",
        "-w",
        str(pcap),
        "-a",
        f"duration:{duration}",
        "-a",
        f"filesize:{max_mib * 1024}",
    ]
    try:
        # dumpcap 自己输出实时进度，不能 capture_output。
        subprocess.run(command, timeout=duration + 30, check=True)
    except KeyboardInterrupt:
        print("\n用户提前结束抓包，继续分析已保存的数据。")
    except subprocess.TimeoutExpired:
        print("\ndumpcap 超过预期时间，继续分析已保存的数据。")

    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise RuntimeError(f"未生成有效抓包文件：{pcap}")
    print(f"抓包完成：{pcap}（{pcap.stat().st_size / 1024 / 1024:.1f} MiB）")


def tshark_rows(
    tshark: str,
    pcap: Path,
    display_filter: str,
    fields: Iterable[str],
) -> list[dict[str, str]]:
    field_list = list(fields)
    command = [
        tshark,
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
    ]
    for field in field_list:
        command.extend(("-e", field))
    result = _run(command, timeout=300)
    if not result.stdout.strip():
        return []
    return list(csv.DictReader(io.StringIO(result.stdout), delimiter="\t"))


def _address(row: dict[str, str], side: str) -> str:
    return row.get(f"ip.{side}") or row.get(f"ipv6.{side}") or "?"


def _port(row: dict[str, str], side: str) -> str:
    return row.get(f"tcp.{side}port") or row.get(f"udp.{side}port") or ""


def _event_description(row: dict[str, str]) -> str:
    src = _address(row, "src")
    dst = _address(row, "dst")
    dst_port = _port(row, "dst")
    dns_name = row.get("dns.qry.name", "")
    dns_answers = row.get("dns.a", "")
    http_host = row.get("http.host", "")
    http_method = row.get("http.request.method", "")
    http_uri = row.get("http.request.uri", "")
    tls_sni = row.get("tls.handshake.extensions_server_name", "")

    if dns_name:
        answer = f" -> {dns_answers}" if dns_answers else ""
        return f"DNS {dns_name}{answer}"
    if http_host or http_method:
        return f"HTTP {http_method} {http_host}{http_uri}"
    if tls_sni:
        return f"TLS SNI {tls_sni} -> {dst}:{dst_port}"
    return f"TCP SYN {src} -> {dst}:{dst_port}"


def _hex_bytes(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def analyze(
    tshark: str,
    pcap: Path,
    report_path: Path,
    lookback: float,
) -> bool:
    syn_fields = (
        "frame.number",
        "frame.time_epoch",
        "frame.time",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
    )
    syn_filter = (
        f"tcp.flags.syn == 1 && tcp.flags.ack == 0 && "
        f"tcp.dstport == {REALORDER_PORT}"
    )
    realorder_syns = tshark_rows(tshark, pcap, syn_filter, syn_fields)

    lines = [
        "同花顺 REALORDER/9601 地址发现报告",
        f"PCAP: {pcap}",
        f"已知实现地址: {KNOWN_REALORDER_IP}:{REALORDER_PORT}",
        "",
    ]
    if not realorder_syns:
        lines.extend(
            (
                "未发现任何发往 TCP/9601 的首次连接（SYN）。",
                "请确认抓包开始后打开了短线精灵，并选择了正确网卡。",
            )
        )
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))
        print(f"\n报告：{report_path}")
        return False

    lines.append("发现的 9601 连接：")
    for row in realorder_syns:
        lines.append(
            f"  frame={row['frame.number']} time={row['frame.time']} "
            f"{_address(row, 'src')}:{_port(row, 'src')} -> "
            f"{_address(row, 'dst')}:{_port(row, 'dst')} "
            f"stream={row.get('tcp.stream', '')}"
        )

    first = realorder_syns[0]
    first_epoch = float(first["frame.time_epoch"])
    window_start = max(0.0, first_epoch - lookback)
    window_end = first_epoch + 2.0
    timeline_filter = (
        f"frame.time_epoch >= {window_start:.6f} && "
        f"frame.time_epoch <= {window_end:.6f} && "
        "(dns || http.request || tls.handshake.extensions_server_name || "
        "(tcp.flags.syn == 1 && tcp.flags.ack == 0))"
    )
    timeline_fields = (
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "dns.qry.name",
        "dns.a",
        "http.host",
        "http.request.method",
        "http.request.uri",
        "tls.handshake.extensions_server_name",
    )
    events = tshark_rows(tshark, pcap, timeline_filter, timeline_fields)
    lines.extend(
        (
            "",
            f"首次 9601 SYN 前 {lookback:g} 秒至后 2 秒的发现时间线：",
        )
    )
    for row in events:
        offset = float(row["frame.time_epoch"]) - first_epoch
        lines.append(
            f"  {offset:+8.3f}s frame={row['frame.number']} "
            f"{_event_description(row)}"
        )

    ascii_ip = _hex_bytes(KNOWN_REALORDER_IP.encode("ascii"))
    packed_ip = _hex_bytes(bytes(int(part) for part in KNOWN_REALORDER_IP.split(".")))
    payload_filter = (
        f"frame.time_epoch >= {window_start:.6f} && "
        f"frame.time_epoch < {first_epoch:.6f} && "
        f"(tcp.payload contains {ascii_ip} || tcp.payload contains {packed_ip} || "
        f"udp.payload contains {ascii_ip} || udp.payload contains {packed_ip})"
    )
    payload_fields = (
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "tcp.payload",
        "udp.payload",
    )
    payload_hits = tshark_rows(tshark, pcap, payload_filter, payload_fields)
    lines.extend(("", "连接前载荷中的目标 IP 命中："))
    if payload_hits:
        for row in payload_hits:
            offset = float(row["frame.time_epoch"]) - first_epoch
            payload = row.get("tcp.payload") or row.get("udp.payload") or ""
            lines.append(
                f"  {offset:+8.3f}s frame={row['frame.number']} "
                f"{_address(row, 'src')}:{_port(row, 'src')} -> "
                f"{_address(row, 'dst')}:{_port(row, 'dst')} "
                f"stream={row.get('tcp.stream', '')} payload={payload[:240]}"
            )
    else:
        lines.append("  未在未加密 TCP/UDP 载荷中直接找到 ASCII 或四字节形式的目标 IP。")

    dns_target_filter = (
        f"frame.time_epoch < {first_epoch:.6f} && dns.a == "
        f"{KNOWN_REALORDER_IP}"
    )
    dns_target_rows = tshark_rows(
        tshark,
        pcap,
        dns_target_filter,
        ("frame.number", "frame.time_epoch", "dns.qry.name", "dns.a"),
    )
    lines.extend(("", "解析到目标 IP 的 DNS 记录："))
    if dns_target_rows:
        for row in dns_target_rows:
            offset = float(row["frame.time_epoch"]) - first_epoch
            lines.append(
                f"  {offset:+8.3f}s frame={row['frame.number']} "
                f"{row.get('dns.qry.name', '')} -> {row.get('dns.a', '')}"
            )
    else:
        lines.append("  未发现传统 DNS 响应把域名解析到该 IP。")

    lines.extend(
        (
            "",
            "初步判读提示：",
            "  - DNS 命中：优先把该域名作为动态 REALORDER 路由来源验证。",
            "  - 明文载荷命中：按 frame/stream 回看对应 HTTP 或 8901 响应。",
            "  - 两者都未命中：可能来自 HTTPS、加密/压缩配置、本地缓存或客户端内置地址。",
            "  - 若首次 SYN 几乎紧随某个 TLS/HTTP 请求，仍可用时间关系锁定候选配置服务。",
            "",
            "隐私提示：报告已避免展开完整业务载荷，但仍可能含域名和内网 IP；",
            "原始 pcap 的敏感程度更高，请不要直接公开或提交到 Git。",
        )
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n报告：{report_path}")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="抓取同花顺短线精灵 9601 地址的动态发现过程"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help=f"抓包时长（秒），默认 {DEFAULT_DURATION}",
    )
    parser.add_argument(
        "--max-mib",
        type=int,
        default=256,
        help="抓包文件大小上限（MiB），默认 256",
    )
    parser.add_argument(
        "--lookback",
        type=float,
        default=DEFAULT_LOOKBACK,
        help=f"首次 9601 连接前的分析窗口（秒），默认 {DEFAULT_LOOKBACK:g}",
    )
    parser.add_argument(
        "--interface",
        help="dumpcap 网卡编号；省略时交互选择",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_PCAP,
        help=f"新抓包输出路径，默认 {DEFAULT_PCAP}",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        help="只分析已有 pcap/pcapng，不执行抓包",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        tshark = _find_executable("tshark.exe" if os.name == "nt" else "tshark")
        pcap = args.pcap.resolve() if args.pcap else args.output.resolve()

        if args.pcap is None:
            dumpcap = _find_executable(
                "dumpcap.exe" if os.name == "nt" else "dumpcap"
            )
            interface = args.interface or pick_interface(tshark)
            capture(dumpcap, interface, pcap, args.duration, args.max_mib)
        elif not pcap.is_file():
            raise FileNotFoundError(f"抓包文件不存在：{pcap}")

        report_path = pcap.with_suffix(pcap.suffix + ".report.txt")
        return 0 if analyze(tshark, pcap, report_path, args.lookback) else 2
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        print(f"\n错误：{error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        print(f"\n外部命令执行失败：{detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
