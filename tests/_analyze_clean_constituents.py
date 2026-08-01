#!/usr/bin/env python
"""Inspect route allocation and every hd3 table in clean board captures."""
from __future__ import annotations

import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import capture_system_blocks as capture  # noqa: E402
from thspypc.codecs.compression import normalize_8901_response  # noqa: E402
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    parse_board_constituents_response,
)


def outer_frames(data: bytes) -> list[bytes]:
    result = []
    for part in data.split(capture.MAGIC):
        if len(part) < 8:
            continue
        try:
            size = int(part[:8], 16)
        except ValueError:
            continue
        result.append(part[8 : 8 + size])
    return result


def nested_frames(body: bytes):
    starts = [m.start() for m in re.finditer(b"\x00\x16\x00\x00", body)]
    for index, start in enumerate(starts):
        if start + 22 > len(body):
            continue
        end = starts[index + 1] if index + 1 < len(starts) else len(body)
        header = body[start : start + 22]
        declared = struct.unpack_from("<I", header, 18)[0]
        payload = body[start + 22 : end]
        # The last nested request borrows the outer frame's trailing LF.
        payload = payload[: min(len(payload), declared)]
        yield {
            "subtype": struct.unpack_from("<H", header, 8)[0],
            "route": struct.unpack_from("<H", header, 10)[0],
            "seq": struct.unpack_from("<H", header, 4)[0],
            "declared": declared,
            "payload": payload,
            "text": payload.decode("gbk", errors="replace"),
        }


def summarize_requests(name: str, stream: str, client: bytes) -> None:
    print(f"\n=== {name} stream {stream} requests ===")
    first_by_route = {}
    for outer_index, body in enumerate(outer_frames(client)):
        nested = list(nested_frames(body))
        for item in nested:
            text = item["text"]
            route = item["route"]
            first_by_route.setdefault(route, outer_index)
            page = re.search(r"pageid=(\d+)", text)
            if not page or page.group(1) not in {"392", "4180", "4181", "5716", "6000", "6002"}:
                continue
            code_groups = re.findall(r"CodeList=(\d+)\(([^)]*)\)", text)
            count = sum(len([c for c in codes.split(",") if c]) for _, codes in code_groups)
            markets = ",".join(market for market, _ in code_groups)
            datatype = re.search(r"DataType=([^\r\n]*)", text)
            sort_begin = re.search(r"SortBegin=(\d+)", text)
            sort_count = re.search(r"SortCount=(\d+)", text)
            print(
                f"outer={outer_index:03d} sub=0x{item['subtype']:02x} "
                f"route=0x{route:03x} first={first_by_route[route]:03d} "
                f"seq=0x{item['seq']:04x} page={page.group(1)} "
                f"codes={count:3d} markets={markets or '-':12s} "
                f"sort={sort_begin.group(1) if sort_begin else '-'}:"
                f"{sort_count.group(1) if sort_count else '-'} "
                f"dt={(datatype.group(1)[:45] if datatype else '-')!r}"
            )


def summarize_responses(name: str, stream: str, server: bytes) -> None:
    print(f"\n=== {name} stream {stream} responses ===")
    for outer_index, body in enumerate(outer_frames(server)):
        try:
            norm = normalize_8901_response(body) if body.startswith(b"\x0a") else body
        except Exception as exc:
            print(f"outer={outer_index:03d} normalize-error={exc}")
            continue
        positions = [m.start() for m in re.finditer(b"hd3\.1\x00", norm)]
        if not positions:
            continue
        for table_index, pos in enumerate(positions):
            tail = norm[pos:]
            if len(tail) < 16:
                continue
            rc, flag, rec_size, fc = struct.unpack_from("<IHHH", tail, 6)
            records = parse_board_constituents_response(tail)
            codes = [r.get("code", "") for r in records]
            print(
                f"outer={outer_index:03d} table={table_index} pos={pos:6d} "
                f"norm={len(norm):6d} rc={rc:4d} flag=0x{flag:x} "
                f"rec={rec_size:3d} fields={fc:2d} parsed={len(records):3d} "
                f"codes={codes[:2]}..{codes[-2:]}"
            )


def main() -> None:
    captures = (
        ("normal", "system_blocks_20260801_163756.pcap"),
        ("level2", "system_blocks_20260801_164040.pcap"),
    )
    for name, filename in captures:
        path = ROOT / "captures_live" / filename
        for stream, client, server in capture._tshark_streams(str(path), 8901):
            target_page = b"pageid=6000" if name == "level2" else b"pageid=4180"
            if target_page not in client:
                continue
            summarize_requests(name, stream, client)
            summarize_responses(name, stream, server)


def timeline_normal() -> None:
    """Print packet-time ordering around the normal-account constituent transaction."""
    path = ROOT / "captures_live" / "system_blocks_20260801_163756.pcap"
    run = subprocess.run(
        [
            capture.TSHARK,
            "-r",
            str(path),
            "-Y",
            "tcp.stream==0 and tcp.len>0 and !tcp.analysis.retransmission",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.payload",
        ],
        capture_output=True,
        timeout=120,
        check=True,
    )
    buffers = {"C": bytearray(), "S": bytearray()}
    events = []
    outer_counts = {"C": 0, "S": 0}
    for line in run.stdout.decode().splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not parts[3]:
            continue
        packet, timestamp, dstport, payload_hex = parts
        direction = "C" if dstport == "8901" else "S"
        buffer = buffers[direction]
        buffer.extend(bytes.fromhex(payload_hex))
        while True:
            pos = buffer.find(capture.MAGIC)
            if pos < 0:
                if len(buffer) > 3:
                    del buffer[:-3]
                break
            if pos:
                del buffer[:pos]
            if len(buffer) < 12:
                break
            try:
                size = int(buffer[4:12], 16)
            except ValueError:
                del buffer[:4]
                continue
            if len(buffer) < 12 + size:
                break
            body = bytes(buffer[12 : 12 + size])
            del buffer[: 12 + size]
            if buffer[:1] == b"\n":
                del buffer[:1]
            index = outer_counts[direction]
            outer_counts[direction] += 1
            if direction == "C" and b"pageid=4180" in body:
                items = list(nested_frames(body))
                routes = ",".join(
                    f"{item['subtype']:x}@{item['route']:x}" for item in items
                )
                dts = ",".join(
                    re.search(r"DataType=([^\r\n]*)", item["text"]).group(1)[:8]
                    for item in items
                    if re.search(r"DataType=([^\r\n]*)", item["text"])
                )
                events.append((float(timestamp), packet, direction, index, routes, dts))
            elif direction == "S":
                try:
                    norm = normalize_8901_response(body) if body.startswith(b"\x0a") else body
                except Exception:
                    continue
                for match in re.finditer(b"hd3\.1\x00", norm):
                    tail = norm[match.start() :]
                    if len(tail) < 16:
                        continue
                    rc, flag, rec_size, _fc = struct.unpack_from("<IHHH", tail, 6)
                    if flag in {0x44, 0x50, 0x64, 0x18, 0x1C} and rc <= 100:
                        records = parse_board_constituents_response(tail)
                        codes = [record.get("code", "") for record in records]
                        events.append(
                            (
                                float(timestamp), packet, direction, index,
                                f"flag={flag:x}/rc={rc}/rec={rec_size}",
                                f"parsed={len(records)} {codes[:2]}",
                            )
                        )
    print("\n=== normal packet timeline >= first 4180 ===")
    first = next(time for time, *_ in events if _[1] == "C")
    for event in events:
        if event[0] >= first - 0.05:
            print(
                f"t={event[0]:9.6f} pkt={event[1]:5s} {event[2]} "
                f"outer={event[3]:03d} {event[4]} {event[5]}"
            )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "timeline-normal":
        timeline_normal()
    else:
        main()
