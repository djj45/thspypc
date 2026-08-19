from __future__ import annotations

import runpy
import struct
from pathlib import Path


_SCRIPT = runpy.run_path(str(Path(__file__).with_name("_type02_timeline.py")))
FrameEvent = _SCRIPT["FrameEvent"]
PacketRow = _SCRIPT["PacketRow"]
_reassemble_direction = _SCRIPT["_reassemble_direction"]
_split_subframes = _SCRIPT["_split_subframes"]


def _header(*, cmd: int, cmd_seq: int, subtype: bytes, size: int, wire_seq: int = 0) -> bytes:
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, wire_seq)
    header[6:10] = subtype
    header[10] = cmd
    struct.pack_into("<I", header, 11, cmd_seq)
    struct.pack_into("<I", header, 18, size)
    return bytes(header)


def test_split_subframes_handles_bundled_client_children_and_final_missing_lf():
    first = b"AddCode=151(920001,);\r\npageid=1334\r\n"
    second = b"CodeList=151(920001,);\r\npageid=1334\r\n"
    body = (
        b"\x09"
        + _header(cmd=0x56, cmd_seq=5, subtype=b"\x12\x00\x02\x00", size=len(first))
        + first
        + _header(
            cmd=0x56,
            cmd_seq=1,
            subtype=b"\x12\x00\x09\x00",
            size=len(second),
            wire_seq=0x125E,
        )
        + second[:-1]
    )
    event = FrameEvent(10, 1.0, 0, "C->S", body)

    children = _split_subframes(event, 7)

    assert [(child.cmd, child.cmd_seq) for child in children] == [(0x56, 5), (0x56, 1)]
    assert children[0].payload == first
    assert children[0].truncated == 0
    assert children[1].payload == second[:-1]
    assert children[1].truncated == 1
    assert children[1].wire_seq == 0x125E


def test_split_subframes_strips_server_payload_length_copy():
    payload = b"CodeListSize=30\r\n"
    header = _header(
        cmd=0x56,
        cmd_seq=5,
        subtype=b"\x12\x00\x02\x00",
        size=len(payload),
    )
    body = b"\x09" + header + struct.pack("<I", len(payload)) + payload
    event = FrameEvent(20, 2.0, 0, "S->C", body)

    children = _split_subframes(event, 3)

    assert len(children) == 1
    assert children[0].payload == payload
    assert children[0].declared_size == len(payload)
    assert children[0].truncated == 0


def test_reassemble_direction_orders_tcp_seq_and_drops_retransmission():
    rows = [
        PacketRow(1, 1.0, 0, "S->C", 103, b"def"),
        PacketRow(2, 2.0, 0, "S->C", 100, b"abc"),
        PacketRow(3, 3.0, 0, "S->C", 103, b"def"),
        PacketRow(4, 4.0, 0, "S->C", 106, b"ghi"),
    ]

    data, spans = _reassemble_direction(rows)

    assert data == b"abcdefghi"
    assert [(start, end, row.number) for start, end, row in spans] == [
        (0, 3, 2),
        (3, 6, 1),
        (6, 9, 4),
    ]
