"""Pure Level2 snapshot-subscription request protocol."""
from __future__ import annotations

import struct

from ..codecs.framing import encode_frame


SNAPSHOT_PAGEID = 4214
SNAPSHOT_PAGEID_SUB = 5716
SNAPSHOT_SUBTYPE = b"\x12\x00\x02\x00"
SNAPSHOT_DATATYPE = [10, 24, 30, 69, 70, 127]
MARKET_SNAPSHOT_MARKETS = [
    16,
    17,
    18,
    19,
    20,
    22,
    144,
    145,
    146,
    147,
    150,
    151,
]
MARKET_SNAPSHOT_DATATYPE = [5, 55]


def build_market_snapshot_query(
    markets: list[int] | tuple[int, ...] | None = None,
    datatype: list[int] | None = None,
    pageid: int = 5716,
    seq: int = 0x0001,
) -> bytes:
    """Build the MAIN-channel query for a whole-market HFD1 snapshot."""
    if markets is None:
        markets = MARKET_SNAPSHOT_MARKETS
    if datatype is None:
        datatype = MARKET_SNAPSHOT_DATATYPE

    codelist = "".join(f"{market}();" for market in markets)
    datatype_text = ",".join(f"[{value}]" for value in datatype)
    text = (
        f"DataType={datatype_text}\r\n"
        f"CodeList={codelist}\r\n"
        f"DateTime=0\r\n"
        f"pageid={pageid}\r"
    ).encode("gbk")

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = b"\x12\x00\x09\x00"
    header[11:13] = b"\x00\x01"
    struct.pack_into("<H", header, 19, len(text) + 1)
    return encode_frame(bytes(header) + text)


def build_snapshot_subscribe(
    code: str,
    market: int = 17,
    pageid: int = SNAPSHOT_PAGEID,
    seq: int = 0x0086,
    datatype: list[int] | None = None,
    inner_seq: int = 0x0071,
) -> bytes:
    """Build the nested pageid=4214 registration and initial query."""
    if not code or not code.isdigit():
        raise ValueError(f"code 必须为纯数字: {code!r}")
    if datatype is None:
        datatype = SNAPSHOT_DATATYPE

    outer_text = (
        f"CodeList={market}({code},);\r\npageid={pageid}\r\n"
    ).encode("gbk")
    datatype_text = ",".join(str(value) for value in datatype) + ","
    inner_text = (
        f"CodeList={market}({code},);\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime=0(0-0)\r\n"
        f"LackTime=0,0,0,0,0,0,0,0\r\n"
        f"pageid={pageid}\r\n"
    ).encode("gbk")

    inner_header = bytearray(22)
    inner_header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", inner_header, 4, inner_seq & 0xFFFF)
    inner_header[6:10] = b"\x12\x00\x09\x00"
    inner_header[10:12] = b"\x00\x01"
    struct.pack_into("<I", inner_header, 18, len(inner_text))
    inner_frame = bytes(inner_header) + inner_text

    header = bytearray(23)
    header[0] = 0x09
    header[1:5] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 5, seq & 0xFFFF)
    header[7:11] = SNAPSHOT_SUBTYPE
    header[11:13] = b"\x02\x00"
    struct.pack_into("<I", header, 19, len(outer_text))
    return encode_frame(bytes(header) + outer_text + inner_frame)


def parse_snapshot_push(body: bytes) -> dict | None:
    """Parse the verified 71-byte Level2 tick snapshot variant."""
    if not is_snapshot_push(body):
        return None

    code = body[29:35].decode("ascii")
    market_flag = body[28]
    market = (
        "SH"
        if market_flag == 0x11
        else "SZ"
        if market_flag == 0x21
        else f"?{market_flag:#x}"
    )
    return {
        "code": code,
        "market": market,
        "price": struct.unpack("<H", body[58:60])[0] / 1000.0,
        "volume": struct.unpack("<H", body[62:64])[0],
        "tick_seq": body[39],
        "raw_len": len(body),
    }


def is_snapshot_push(body: bytes) -> bool:
    """Return whether ``body`` matches the verified 71-byte push shape."""
    return (
        len(body) == 71
        and body[0] == 0x09
        and body[14] == 0x80
        and all(0x30 <= value <= 0x39 for value in body[29:35])
    )


__all__ = [
    "MARKET_SNAPSHOT_DATATYPE",
    "MARKET_SNAPSHOT_MARKETS",
    "SNAPSHOT_DATATYPE",
    "SNAPSHOT_PAGEID",
    "SNAPSHOT_PAGEID_SUB",
    "SNAPSHOT_SUBTYPE",
    "build_market_snapshot_query",
    "build_snapshot_subscribe",
    "is_snapshot_push",
    "parse_snapshot_push",
]
