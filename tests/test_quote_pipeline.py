from __future__ import annotations

import struct

from thspypc._transport import (
    ConnectionManager,
    ConnectionRole,
    OpenedConnection,
)
from thspypc.codecs.framing import encode_frame
from thspypc.features.quote_protocol import LIST_QUOTE_DATATYPE_DEFAULT
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services.quote import MARKET_VIEW_QUOTE_DATATYPE, QuoteService


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout = None

    def settimeout(self, value) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _size: int) -> bytes:
        return b""

    def close(self) -> None:
        pass


def hd1(fields: list[int], values: dict[int, bytes]) -> bytes:
    widths = {5: 7}
    row = bytearray()
    table = bytearray()
    for datatype in fields:
        width = widths.get(datatype, 4)
        fmt = 0x20 if datatype == 5 else 0x70
        table += bytes((datatype & 0xFF, fmt, 0, width))
        row += values.get(datatype, b"\x00" * width)
    header = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 1, 0x46, len(row), len(fields))
    )
    return header + table + row


def test_market_view_pipeline_sends_both_before_reading_and_dispatches():
    sock = FakeSocket()
    profile = AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={Capability.BASIC_QUOTE: Support.YES},
    )
    manager = ConnectionManager(
        profile,
        lambda spec: OpenedConnection(sock, initialized=True),
    )
    quote_fields = [5, *MARKET_VIEW_QUOTE_DATATYPE]
    quote = encode_frame(
        hd1(
            quote_fields,
            {
                5: b"!000001",
                6: struct.pack("<I", 123400),
                8: struct.pack("<I", 127800),
                9: struct.pack("<I", 122100),
                10: struct.pack("<I", 125600),
                19: struct.pack("<I", 98765432),
            },
        )
    )
    depth_fields = [5, 24, 25, 30, 31]
    depth = encode_frame(
        hd1(
            depth_fields,
            {
                5: b"!000001",
                24: struct.pack("<I", 125500),
                25: struct.pack("<I", 10000),
                30: struct.pack("<I", 125700),
                31: struct.pack("<I", 8000),
            },
        )
    )
    frames = iter((depth[12:], quote[12:]))

    def read_frame(_sock):
        # The second request must already be on the wire before the first recv.
        assert len(sock.sent) == 1
        assert b"pageid=1335" in sock.sent[0]
        assert b"pageid=1333" in sock.sent[0]
        assert b"DataType=7,49,13,48,10,17,6,66,1111,8,9,19," in sock.sent[0]
        return next(frames)

    service = QuoteService(manager, frame_reader=read_frame)
    quote_row, depth_row = service.market_view_pipeline(
        "000001", market=33
    )

    assert len(sock.sent) == 1
    assert b"pageid=1335" in sock.sent[0]
    assert b"pageid=1333" in sock.sent[0]
    assert quote_row is not None and quote_row["code"] == "000001"
    assert quote_row["dt8"] > quote_row["dt9"]
    assert quote_row["dt19"] > 0
    assert depth_row["code"] == "000001"
    assert depth_row["buy"] and depth_row["sell"]
    assert manager.peek(ConnectionRole.MAIN) is not None
