#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""按真实包序分析 bse_920083_20260815 的 8901 type-02 命令族。

与早期版本不同，本脚本不会先按方向拼完整流再分别打印，而是：

1. 按 tshark 的帧号读取双向 TCP payload；
2. 分方向重组 FDF 外帧，并以“外帧完成包”的时间/帧号记录事件；
3. 拆出一个 FDF body 内捆绑的全部 22B 子帧；
4. 再按抓包帧号交错输出 C->S / S->C 时间线。

抓包只做离线读取。pcap 含登录/账户流量，报告仅输出命令摘要，不落原始票据。
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPDIR = os.path.join(ROOT, "captures_live")
PCAP = os.path.join(CAPDIR, "bse_920083_20260815_101552.pcapng")
OUT = os.path.join(CAPDIR, "_type02_timeline.txt")
TSHARK = (
    r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64"
    r"\App\Wireshark\tshark.exe"
)
PORT = 8901
MAGIC = b"\xfd\xfd\xfd\xfd"
MAX_FRAME_SIZE = 4_000_000
SUBFRAME_PREFIX = b"\x00\x16"

sys.path.insert(0, os.path.join(ROOT, "src"))
from thspypc.codecs.compression import normalize_8901_response  # noqa: E402
from thspypc.features.list_subscription_protocol import (  # noqa: E402
    parse_list_subscription_response,
)
from thspypc.features.index_push_protocol import is_index_push  # noqa: E402
from thspypc.features.snapshot_protocol import (  # noqa: E402
    is_depth_push,
    is_stock_depth_envelope,
    parse_depth_push_records,
)


@dataclass(frozen=True)
class PacketRow:
    number: int
    timestamp: float
    stream: int
    direction: str
    tcp_seq: int
    payload: bytes


@dataclass(frozen=True)
class FrameEvent:
    number: int
    timestamp: float
    stream: int
    direction: str
    body: bytes


@dataclass(frozen=True)
class SubframeEvent:
    number: int
    timestamp: float
    stream: int
    direction: str
    outer_index: int
    child_index: int
    wire_seq: int
    subtype: bytes
    cmd: int
    cmd_seq: int
    declared_size: int
    payload: bytes
    truncated: int


def _packet_rows(pcap: str = PCAP) -> list[PacketRow]:
    result = subprocess.run(
        [
            TSHARK,
            "-r",
            pcap,
            "-Y",
            f"tcp.port=={PORT} && tcp.len>0",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.seq_raw",
            "-e",
            "tcp.payload",
        ],
        capture_output=True,
        timeout=600,
        check=True,
    )
    rows: list[PacketRow] = []
    for line in result.stdout.splitlines():
        parts = line.split(b"\t", 6)
        if len(parts) != 7:
            continue
        try:
            srcport = int(parts[3])
            dstport = int(parts[4])
            direction = "S->C" if srcport == PORT else "C->S" if dstport == PORT else "?"
            payload_hex = re.sub(rb"[^0-9A-Fa-f]", b"", parts[6])
            if direction == "?" or not payload_hex:
                continue
            rows.append(
                PacketRow(
                    number=int(parts[0]),
                    timestamp=float(parts[1]),
                    stream=int(parts[2]),
                    direction=direction,
                    tcp_seq=int(parts[5]),
                    payload=bytes.fromhex(payload_hex.decode("ascii")),
                )
            )
        except (ValueError, IndexError):
            continue
    return rows


def _reassemble_direction(
    rows: list[PacketRow],
) -> tuple[bytes, list[tuple[int, int, PacketRow]]]:
    """按 raw TCP seq 重组一个方向，去掉重传并保留字节来源区间。"""
    ordered = sorted(rows, key=lambda row: (row.tcp_seq, row.number))
    if not ordered:
        return b"", []
    base = ordered[0].tcp_seq
    cursor = base
    data = bytearray()
    spans: list[tuple[int, int, PacketRow]] = []
    for row in ordered:
        start = row.tcp_seq
        payload = row.payload
        end = start + len(payload)
        if end <= cursor:
            continue
        if start > cursor:
            # 正常完整抓包不应有洞；占位可防止洞两侧字节被误拼成一帧。
            data.extend(b"\x00" * (start - cursor))
            cursor = start
        trim = max(0, cursor - start)
        chunk = payload[trim:]
        out_start = cursor - base
        data.extend(chunk)
        cursor += len(chunk)
        spans.append((out_start, cursor - base, row))
    return bytes(data), spans


def _walk_frames(data: bytes):
    pos = 0
    while pos + 12 <= len(data):
        start = data.find(MAGIC, pos)
        if start < 0:
            return
        length_start = start + 4
        while length_start < len(data) and data[length_start] == 0xFD:
            length_start += 1
        if length_start + 8 > len(data):
            return
        raw_size = data[length_start : length_start + 8]
        if not re.fullmatch(rb"[0-9A-Fa-f]{8}", raw_size):
            pos = start + 1
            continue
        size = int(raw_size, 16)
        body_start = length_start + 8
        end = body_start + size
        if not 0 < size <= MAX_FRAME_SIZE or end > len(data):
            pos = start + 1
            continue
        yield start, end, data[body_start:end]
        pos = end


def _reconstruct_frames(rows: list[PacketRow]) -> list[FrameEvent]:
    grouped: dict[tuple[int, str], list[PacketRow]] = defaultdict(list)
    for row in rows:
        grouped[(row.stream, row.direction)].append(row)
    events: list[FrameEvent] = []
    for (stream, direction), direction_rows in grouped.items():
        data, spans = _reassemble_direction(direction_rows)
        for start, end, body in _walk_frames(data):
            contributors = [row for lo, hi, row in spans if lo < end and hi > start]
            if not contributors:
                continue
            completed_by = max(contributors, key=lambda row: row.number)
            events.append(
                FrameEvent(
                    number=completed_by.number,
                    timestamp=completed_by.timestamp,
                    stream=stream,
                    direction=direction,
                    body=body,
                )
            )
    return sorted(events, key=lambda event: (event.number, event.stream))


def _split_subframes(event: FrameEvent, outer_index: int) -> list[SubframeEvent]:
    """拆 ``0x09 + N*(22B header + payload)`` 复合 body。

    C->S 的 declared_size 直接覆盖文本/二进制载荷；S->C 在 22B 头后另有
    LE32 载荷长度副本。抓包中的末子帧偶尔比声明少 1B，保留并标记，不丢帧。
    """
    body = event.body
    if len(body) < 23 or body[0] != 0x09:
        return []
    pos = 1
    children: list[SubframeEvent] = []
    while pos + 22 <= len(body) and body[pos : pos + 2] == SUBFRAME_PREFIX:
        header = body[pos : pos + 22]
        wire_seq = struct.unpack_from("<H", header, 4)[0]
        subtype = header[6:10]
        cmd = header[10]
        cmd_seq = struct.unpack_from("<I", header, 11)[0]
        declared = struct.unpack_from("<I", header, 18)[0]
        payload_start = pos + 22
        prefix_size = 0
        if event.direction == "S->C" and payload_start + 4 <= len(body):
            # 服务端固定多一个 LE32：纯 ACK 时恰好等于 declared；数据帧时
            # 它是前导状态文本长度（例如 94），不等于整个子帧载荷长度。
            prefix_size = 4
        data_start = payload_start + prefix_size
        expected_end = data_start + declared
        actual_end = min(expected_end, len(body))
        payload = body[data_start:actual_end]
        truncated = max(0, expected_end - len(body))
        children.append(
            SubframeEvent(
                number=event.number,
                timestamp=event.timestamp,
                stream=event.stream,
                direction=event.direction,
                outer_index=outer_index,
                child_index=len(children),
                wire_seq=wire_seq,
                subtype=subtype,
                cmd=cmd,
                cmd_seq=cmd_seq,
                declared_size=declared,
                payload=payload,
                truncated=truncated,
            )
        )
        if truncated:
            break
        pos = expected_end
    return children


def _extract_values(payload: bytes, key: bytes) -> list[str]:
    pattern = re.compile(rb"(?:^|\r?\n)" + re.escape(key) + rb"=([^\r\n]+)")
    return [m.group(1).decode("ascii", "replace") for m in pattern.finditer(payload)]


def _code_list(payload: bytes, key: bytes = b"CodeList") -> set[str]:
    values = _extract_values(payload, key)
    if not values:
        return set()
    result: set[str] = set()
    for group in re.finditer(r"\d+\(([^)]*)\)", values[0]):
        result.update(code for code in group.group(1).split(",") if code.isdigit())
    return result


def _summary(event: SubframeEvent) -> str:
    parts: list[str] = []
    for key in (
        b"AddCode",
        b"DelCode",
        b"CodeList",
        b"DataType",
        b"DateTime",
        b"pageid",
        b"CodeListSize",
        b"MarketTime",
        b"ServerCost",
    ):
        for value in _extract_values(event.payload, key):
            if len(value) > 96:
                value = value[:93] + "..."
            parts.append(f"{key.decode()}={value}")
    for marker in (b"hd1.0", b"hd3.1", b"hq1.0", b"hq3.1"):
        if marker in event.payload:
            parts.append(marker.decode("ascii"))
    if not parts:
        printable = re.sub(rb"[^\x20-\x7e]", b".", event.payload[:72]).decode("ascii")
        parts.append(printable or "<empty>")
    if event.truncated:
        parts.append(f"末尾缺{event.truncated}B")
    return " | ".join(parts)


def analyze(
    pcap: str = PCAP,
) -> tuple[list[PacketRow], list[FrameEvent], list[SubframeEvent]]:
    rows = _packet_rows(pcap)
    frames = _reconstruct_frames(rows)
    counters: Counter[tuple[int, str]] = Counter()
    children: list[SubframeEvent] = []
    for frame in frames:
        key = (frame.stream, frame.direction)
        counters[key] += 1
        children.extend(_split_subframes(frame, counters[key]))
    children.sort(key=lambda event: (event.number, event.child_index))
    return rows, frames, children


def render(
    rows: list[PacketRow], frames: list[FrameEvent], children: list[SubframeEvent]
) -> str:
    type02 = [event for event in children if event.subtype[2:4] == b"\x02\x00"]
    cmd_stats: dict[int, Counter[str]] = defaultdict(Counter)
    sizes: dict[int, list[int]] = defaultdict(list)
    for event in type02:
        cmd_stats[event.cmd][event.direction] += 1
        sizes[event.cmd].append(len(event.payload))

    lines = [
        f"TCP payload 包={len(rows)}  FDF外帧={len(frames)}  子帧={len(children)}  type02子帧={len(type02)}",
        "",
        "== type-02 命令分布（已拆复合外帧） ==",
    ]
    for cmd in sorted(cmd_stats):
        counts = cmd_stats[cmd]
        values = sizes[cmd]
        lines.append(
            f"cmd=0x{cmd:02x}  C->S={counts['C->S']:4d}  S->C={counts['S->C']:4d}  "
            f"payload={min(values)}~{max(values)}"
        )

    origin = min((row.timestamp for row in rows), default=0.0)
    e0_events = [event for event in type02 if event.cmd == 0xE0]
    lines.extend(["", "== cmd 0xe0 时段与方向 =="])
    for direction in ("C->S", "S->C"):
        group = [event for event in e0_events if event.direction == direction]
        if not group:
            lines.append(f"{direction}: 0 帧")
            continue
        unique = list(dict.fromkeys(_summary(event) for event in group))
        lines.append(
            f"{direction}: {len(group)} 帧，pkt {group[0].number}~{group[-1].number}，"
            f"t=+{group[0].timestamp-origin:.6f}~+{group[-1].timestamp-origin:.6f}s"
        )
        for summary in unique:
            lines.append(f"  - {summary}")

    cmd56_events = [event for event in type02 if event.cmd == 0x56]
    if e0_events and cmd56_events:
        last_e0 = max(e0_events, key=lambda event: event.number)
        first_56 = min(cmd56_events, key=lambda event: event.number)
        lines.append(
            f"最后 0xe0 → 首个 0x56：pkt {last_e0.number} → {first_56.number}，"
            f"间隔 {first_56.timestamp-last_e0.timestamp:.6f}s"
        )

    request_seqs = {
        (event.stream, event.wire_seq)
        for event in children
        if event.direction == "C->S" and event.wire_seq
    }
    envelope_frames = [
        frame
        for frame in frames
        if frame.direction == "S->C" and frame.body.startswith(b"\x0a")
    ]
    envelope_children = []
    for frame in envelope_frames:
        normalized = normalize_8901_response(frame.body)
        for response in parse_list_subscription_response(b"\x09" + normalized):
            envelope_children.append((frame, response))
    nonzero = [item for item in envelope_children if item[1].wire_seq]
    matched = [
        item
        for item in nonzero
        if (item[0].stream, item[1].wire_seq) in request_seqs
    ]
    lines.extend(
        [
            "",
            "== 0x0a 压缩批量响应核对 ==",
            f"外帧={len(envelope_frames)}  展开子帧={len(envelope_children)}  "
            f"nonzero-wire={len(nonzero)}  已匹配请求={len(matched)}  "
            f"未匹配={len(nonzero)-len(matched)}  zero-wire ACK={len(envelope_children)-len(nonzero)}",
        ]
    )
    command_counts = Counter(response.command for _, response in envelope_children)
    lines.append(
        "命令桶: "
        + ", ".join(
            f"0x{command:02x}={count}" for command, count in sorted(command_counts.items())
        )
    )

    depth_frames = [
        frame
        for frame in frames
        if frame.direction == "S->C" and is_depth_push(frame.body)
    ]
    depth_records = [
        (frame, record)
        for frame in depth_frames
        for record in parse_depth_push_records(frame.body)
    ]
    index_frames = [
        frame
        for frame in frames
        if frame.direction == "S->C"
        and not is_stock_depth_envelope(frame.body)
        and is_index_push(frame.body)
    ]
    unique_depth_codes = {
        str(record.get("code", "")) for _, record in depth_records if record.get("code")
    }
    lines.extend(["", "== 无 wire-seq 实时推送族 =="])
    if depth_records:
        first_depth = depth_records[0][0]
        last_depth = depth_records[-1][0]
        lines.append(
            f"0x0f7f 深度外帧={len(depth_frames)}  记录={len(depth_records)}  "
            f"代码={len(unique_depth_codes)}  "
            f"t=+{first_depth.timestamp-origin:.3f}~+{last_depth.timestamp-origin:.3f}s"
        )
    else:
        lines.append("0x0f7f 深度外帧=0")
    lines.append(f"指数推送外帧={len(index_frames)}")

    # 依包序维护已观察到的 CodeList 分组。这只是覆盖率线索：模式 0/2/3
    # 的精确关系尚未确认，不能把未命中直接解释为未订阅。
    state: dict[tuple[int, int, int], set[str]] = {}
    manage_events = [
        event
        for event in children
        if event.direction == "C->S"
        and event.subtype == b"\x12\x00\x02\x00"
        and event.cmd_seq in (0, 2, 3)
    ]
    ordered_items = sorted(
        [(event.number, 0, event) for event in manage_events]
        + [(frame.number, 1, (frame, record)) for frame, record in depth_records],
        key=lambda item: (item[0], item[1]),
    )
    matched_same_stream = 0
    matched_any_stream = 0
    checked = 0
    unmatched_codes: Counter[str] = Counter()
    for _, kind, item in ordered_items:
        if kind == 0:
            event = item
            assert isinstance(event, SubframeEvent)
            state[(event.stream, event.cmd, event.cmd_seq)] = _code_list(event.payload)
            continue
        frame, record = item
        code = str(record.get("code", ""))
        if not code:
            continue
        checked += 1
        same_stream = set().union(
            *(codes for (stream, _, _), codes in state.items() if stream == frame.stream)
        )
        all_streams = set().union(*state.values()) if state else set()
        matched_same_stream += code in same_stream
        matched_any_stream += code in all_streams
        if code not in all_streams:
            unmatched_codes[code] += 1
    if checked:
        lines.append(
            "CodeList 瞬时状态覆盖（仅线索）: "
            f"同 TCP stream={matched_same_stream}/{checked} "
            f"({matched_same_stream/checked:.1%})，"
            f"全 stream={matched_any_stream}/{checked} ({matched_any_stream/checked:.1%})"
        )
        if unmatched_codes:
            lines.append(
                "未覆盖代码: "
                + ", ".join(
                    f"{code}×{count}" for code, count in unmatched_codes.most_common()
                )
            )

    manage_timeline = [
        event
        for event in type02
        if event.direction == "C->S"
        and event.subtype == b"\x12\x00\x02\x00"
        and any(
            marker in event.payload
            for marker in (b"CodeList", b"AddCode", b"DelCode", b"pageid")
        )
    ]
    lines.extend(["", "== 全部列表管理帧时间线 =="])
    for event in manage_timeline:
        lines.append(
            f"pkt={event.number:4d} t=+{event.timestamp-origin:9.6f}s "
            f"s{event.stream} cmd=0x{event.cmd:02x} mode={event.cmd_seq} "
            f"size={len(event.payload)}/{event.declared_size} :: {_summary(event)}"
        )

    # 0x56 所在复合外帧的兄弟子帧也是因果链的一部分，一并展示。
    outer_keys = {
        (event.stream, event.direction, event.outer_index) for event in cmd56_events
    }
    relevant = [
        event
        for event in children
        if (event.stream, event.direction, event.outer_index) in outer_keys
    ]
    lines.extend(["", "== cmd 0x56 双向包序时间线（含同一复合外帧兄弟子帧） =="])
    for event in relevant:
        delta = event.timestamp - origin
        lines.append(
            f"pkt={event.number:4d} t=+{delta:9.6f}s s{event.stream} {event.direction} "
            f"outer={event.outer_index}.{event.child_index} cmd=0x{event.cmd:02x} "
            f"wire_seq=0x{event.wire_seq:04x} cmd_seq={event.cmd_seq} "
            f"subtype={event.subtype.hex()} size={len(event.payload)}/{event.declared_size} :: "
            f"{_summary(event)}"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", default=PCAP, help="待分析 pcap/pcapng")
    parser.add_argument("--output", default=OUT, help="完整报告输出路径")
    args = parser.parse_args()
    rows, frames, children = analyze(args.pcap)
    report = render(rows, frames, children)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(report)
    print(report)
    print(f"完整结果已写入 {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
