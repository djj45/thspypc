#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""被动抓取同花顺冷启动/首次登录阶段的 hfd1.0 流量。

本脚本不登录、不连接行情服务器，也不删除缓存；它只调用 dumpcap 监听官方
客户端的 8901 流量，结束后用 tshark 重组 TCP 字节流并搜索 hfd1.0。

推荐操作顺序：

1. 在同花顺里按你原来的方式清理缓存，然后彻底退出客户端；
2. 确认任务管理器中没有 hexin.exe；
3. 运行本脚本，看到“抓包已经开始”后再启动同花顺并完成首次登录；
4. 登录后打开一次“A股”或“沪深A股”列表，停留 20~30 秒；
5. 等待自动结束，或按 Ctrl+C 提前结束并分析。

用法：

    uv run python tests/capture_hfd1_cold_start.py --duration 120
    uv run python tests/capture_hfd1_cold_start.py --iface 4 --duration 150
    uv run python tests/capture_hfd1_cold_start.py --analyze-only captures_live/x.pcapng

pcap 可能包含登录和账户相关流量，不要直接公开上传。脚本导出的 hfd1 body
和 report.txt 更适合用于后续离线分析。
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures_live"
PORT = 8901
MAGIC = b"\xfd\xfd\xfd\xfd"
MAX_FRAME_SIZE = 64 * 1024 * 1024

WIRESHARK_DIRS = (
    Path(r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark"),
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark"),
    Path(r"D:\software\Wireshark_4.6.7_Portable\Wireshark\App\Wireshark"),
    Path(r"C:\Program Files\Wireshark"),
    Path(r"D:\Program Files\Wireshark"),
)


@dataclass(slots=True)
class FrameEvent:
    time: float
    stream: int
    direction: str
    body: bytes


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
        preferred = any(token in description.lower() for token in ("wlan", "wi-fi", "wifi"))
        print(f"  {number}. {description}{'  ← 建议' if preferred else ''}")
    default = next(
        (
            number
            for number, (_, description) in interfaces.items()
            if any(token in description.lower() for token in ("wlan", "wi-fi", "wifi"))
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
        f"tcp port {PORT}",
        "-w",
        str(output),
        "-a",
        f"duration:{duration}",
    ]
    print("\n抓包已经开始。现在请：")
    print("  1. 启动同花顺并完成首次登录；")
    print("  2. 登录后打开一次“A股/沪深A股”列表；")
    print("  3. 在列表页停留 20~30 秒。")
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


def _packet_rows(tshark: Path, pcap: Path) -> list[tuple[float, int, int, int, bytes]]:
    display_filter = (
        f"tcp.port=={PORT} and tcp.payload and "
        "not tcp.analysis.retransmission and "
        "not tcp.analysis.fast_retransmission and "
        "not tcp.analysis.spurious_retransmission"
    )
    result = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            display_filter,
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
            "tcp.dstport",
            "-e",
            "tcp.payload",
        ]
    )
    rows: list[tuple[float, int, int, int, bytes]] = []
    for raw_line in result.stdout.splitlines():
        parts = raw_line.split(b"\t", 4)
        if len(parts) != 5:
            continue
        try:
            payload_hex = re.sub(rb"[^0-9A-Fa-f]", b"", parts[4])
            if payload_hex:
                rows.append(
                    (
                        float(parts[0]),
                        int(parts[1]),
                        int(parts[2]),
                        int(parts[3]),
                        bytes.fromhex(payload_hex.decode("ascii")),
                    )
                )
        except ValueError:
            continue
    return rows


def _stream_servers(tshark: Path, pcap: Path) -> dict[int, str]:
    result = _run_tool(
        [
            str(tshark),
            "-r",
            str(pcap),
            "-Y",
            f"tcp.port=={PORT}",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "tcp.stream",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
        ]
    )
    servers: dict[int, str] = {}
    for raw_line in result.stdout.splitlines():
        parts = raw_line.decode("ascii", "replace").split("\t")
        if len(parts) != 5:
            continue
        try:
            stream = int(parts[0])
        except ValueError:
            continue
        if parts[2] == str(PORT):
            servers[stream] = parts[1]
        elif parts[4] == str(PORT):
            servers[stream] = parts[3]
    return servers


def _take_frames(buffer: bytearray) -> list[bytes]:
    """从单向 TCP 字节流取完整 FDF body，残帧留在 buffer。"""
    frames: list[bytes] = []
    while True:
        start = buffer.find(MAGIC)
        if start < 0:
            if len(buffer) > len(MAGIC) - 1:
                del buffer[: -(len(MAGIC) - 1)]
            return frames
        if start:
            del buffer[:start]
        if len(buffer) < 12:
            return frames

        # 兼容服务端偶发的第 5 个或更多连续 0xfd。
        length_start = 4
        while length_start < len(buffer) and buffer[length_start] == 0xFD:
            length_start += 1
        if len(buffer) < length_start + 8:
            return frames
        length_raw = bytes(buffer[length_start : length_start + 8])
        if not re.fullmatch(rb"[0-9A-Fa-f]{8}", length_raw):
            del buffer[0]
            continue
        body_size = int(length_raw, 16)
        if body_size > MAX_FRAME_SIZE:
            del buffer[0]
            continue
        end = length_start + 8 + body_size
        if len(buffer) < end:
            return frames
        frames.append(bytes(buffer[length_start + 8 : end]))
        del buffer[:end]


def reconstruct(rows: list[tuple[float, int, int, int, bytes]]) -> tuple[list[FrameEvent], dict]:
    buffers: dict[tuple[int, str], bytearray] = defaultdict(bytearray)
    totals: dict[tuple[int, str], int] = defaultdict(int)
    events: list[FrameEvent] = []
    for timestamp, stream, source, destination, payload in rows:
        direction = "S2C" if source == PORT else "C2S" if destination == PORT else "?"
        if direction == "?":
            continue
        totals[(stream, direction)] += len(payload)
        buffer = buffers[(stream, direction)]
        buffer.extend(payload)
        for body in _take_frames(buffer):
            events.append(FrameEvent(timestamp, stream, direction, body))
    return sorted(events, key=lambda item: (item.time, item.stream)), totals


def _clean_request_text(body: bytes) -> str:
    text = body.decode("gbk", "replace")
    first_key = min(
        (position for key in ("instid=", "CodeList=", "DataType=") if (position := text.find(key)) >= 0),
        default=0,
    )
    text = text[first_key:].replace("\x00", "")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    result = " | ".join(lines)
    return result if len(result) <= 1200 else result[:1200] + " …[已截断]"


def _is_candidate_request(body: bytes) -> bool:
    text = body.decode("gbk", "replace")
    # hfd1.0 已知请求同时具有 [5],[55] 和空市场 CodeList。普通 Sort 请求也会
    # 使用 CodeList=17();，不能仅凭空括号判定。
    return (
        "DataType=[5],[55]" in text
        and bool(re.search(r"CodeList=[^\r\n]*\d+\(\)", text))
    )


def _empty_markets(body: bytes) -> list[int]:
    text = body.decode("gbk", "replace")
    return [int(value) for value in re.findall(r"(?:CodeList=|;)\s*(\d+)\(\)", text)]


def analyze(tshark: Path, pcap: Path) -> int:
    if not pcap.is_file():
        raise FileNotFoundError(f"pcap 不存在：{pcap}")
    rows = _packet_rows(tshark, pcap)
    events, totals = reconstruct(rows)
    servers = _stream_servers(tshark, pcap)
    candidates = [event for event in events if event.direction == "C2S" and _is_candidate_request(event.body)]
    hits = [event for event in events if event.direction == "S2C" and b"hfd1.0" in event.body.lower()]
    name_sync = [
        event
        for event in events
        if event.direction == "S2C" and b"[name_16_16]" in event.body.lower()
    ]
    # 旧 hfd1.0 样本的关键请求从 16() 开始，整组市场均为空。只有 144~151
    # 为空、而 16~20 已列出具体代码时，服务端实测会返回增量 hd3.1。
    full_hfd_candidates = [event for event in candidates if 16 in _empty_markets(event.body)]
    partial_hfd_candidates = [
        event
        for event in candidates
        if event not in full_hfd_candidates
        and {17, 18, 19, 20, 22, 144, 145, 146, 147, 150, 151}.intersection(
            _empty_markets(event.body)
        )
    ]

    lines = [
        "hfd1.0 冷启动抓包分析",
        f"pcap: {pcap}",
        f"8901 payload packets: {len(rows)}",
        f"reconstructed frames: {len(events)}",
        f"tcp streams: {len({stream for stream, _ in totals})}",
        f"last 8901 payload time: {max((row[0] for row in rows), default=0):.3f}s",
        "servers: " + ", ".join(f"stream {stream}={host}" for stream, host in sorted(servers.items())),
        "",
        "候选请求（DataType=[5],[55] + 空括号 CodeList）：",
    ]
    if candidates:
        for index, event in enumerate(candidates, 1):
            request_body_path = pcap.with_name(
                f"{pcap.stem}_stream{event.stream}_candidate{index}.request.bin"
            )
            request_body_path.write_bytes(event.body)
            lines.append(
                f"  [{index}] t={event.time:.3f}s stream={event.stream} "
                f"server={servers.get(event.stream, '?')} markets={_empty_markets(event.body)} "
                f"body={len(event.body):,}B"
            )
            lines.append(f"      {_clean_request_text(event.body)}")
            lines.append(f"      request body：{request_body_path}")
    else:
        lines.append("  未发现")

    lines.extend(("", "hfd1.0 响应："))
    exported: list[Path] = []
    for index, event in enumerate(hits, 1):
        output = pcap.with_name(f"{pcap.stem}_stream{event.stream}_hfd1_{index}.bin")
        output.write_bytes(event.body)
        exported.append(output)
        marker = event.body.lower().find(b"hfd1.0")
        previous = [
            candidate
            for candidate in candidates
            if candidate.stream == event.stream and candidate.time <= event.time
        ]
        request_note = ""
        if previous:
            delta = event.time - previous[-1].time
            request_note = f", 前一候选请求间隔={delta:.3f}s"
        lines.append(
            f"  [{index}] 命中：t={event.time:.3f}s stream={event.stream} "
            f"body={len(event.body):,}B marker_offset=0x{marker:x}{request_note}"
        )
        lines.append(f"      已导出：{output}")
    if not hits:
        lines.append("  未发现 hfd1.0")

    lines.extend(("", "冷启动名称同步："))
    if name_sync:
        for event in name_sync:
            lines.append(
                f"  [name_16_16] t={event.time:.3f}s stream={event.stream} "
                f"server={servers.get(event.stream, '?')} body={len(event.body):,}B"
            )
    else:
        lines.append("  未发现 [name_16_16]")

    lines.extend(("", "结论："))
    if hits:
        lines.append(f"  成功抓到 {len(hits)} 个 hfd1.0 响应；请保留导出的 .bin 和报告。")
    elif full_hfd_candidates:
        lines.append("  已复现从 16() 开始的完整沪市 [5],[55] 空括号请求，但服务端没有返回 hfd1.0。")
    elif partial_hfd_candidates:
        lines.append("  只触发了部分沪市市场空括号；16 市场仍是具体代码列表，未复现旧 HFD1 请求。")
        lines.append("  当前这种增量请求实测返回 hd3.1，而不是 hfd1.0。")
    elif candidates:
        lines.append("  只发现其他市场的 [5],[55] 空括号请求；没有触发旧样本中的沪市 HFD1 市场族请求。")
        lines.append("  建议完整退出后再次抓包，不再清缓存，登录后从“行情”进入“沪深A股”并停留。")
    else:
        lines.append("  既没有 [5],[55] 空括号请求，也没有 hfd1.0；优先检查网卡和页面操作。")

    report = pcap.with_suffix(".hfd1.report.txt")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n" + "\n".join(lines))
    print(f"\n分析报告：{report}")
    return len(hits)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="抓取并自动提取官方客户端 hfd1.0 流量")
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
    if args.duration <= 0:
        raise ValueError("--duration 必须大于 0")

    dumpcap = _find_tool("dumpcap")
    interface = pick_interface(tshark, args.iface)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = (args.output or CAPTURE_DIR / f"hfd1_cold_start_{timestamp}.pcapng").resolve()
    capture(dumpcap, interface, args.duration, output)
    analyze(tshark, output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"\n错误：{exc}", file=sys.stderr)
        raise SystemExit(2)
