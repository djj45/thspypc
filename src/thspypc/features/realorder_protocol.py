"""Pure wire contracts for the 9601 real-order channel."""
from __future__ import annotations

import re
import socket
import struct

from ..codecs.framing import (
    FRAME_MAGIC,
    _read_frame_body_length,
    encode_frame,
    read_exact,
)
from ..codecs.numeric import decode_ths_float


REALORDER_HOST = "106.14.65.90"
REALORDER_PORT = 9601

DXJL_DATATYPE = (
    "1074269398{19[10000~-]|17[5000000~-]},"
    "1074269399{19[10000~-]|17[5000000~-]},"
    "1074269401,1074269403"
)

# 2026-07-29 普通账号 UI 可选的 23 类。编号来自官方客户端
# ShortGeniusFuncDetailInfo.ini，并由普通账号抓包确认该账号仍可登录、查询和订阅
# REALORDER；权限差异发生在异动类别，而不是 9601 通道本身。
STANDARD_REALORDER_CATEGORY_IDS = (
    1074269398,  # 大笔买入
    1074269399,  # 大笔卖出
    1074269396,  # 单笔冲涨
    1074269397,  # 单笔冲跌
    1074269393,  # 区间放量涨
    1074269394,  # 区间放量跌
    1074269395,  # 区间放量平
    1074269400,  # 涨停封板
    1074269401,  # 打开涨停板
    1074269402,  # 跌停封板
    1074269403,  # 打开跌停板
    1074269404,  # 急速拉升
    1074269405,  # 猛烈打压
    1074269410,  # 涨停大减
    1074269411,  # 跌停大减
    1074269412,  # 强势封涨停
    1074269422,  # 强势封跌停
    1074269408,  # 逼近涨停
    1074269409,  # 逼近跌停
    4132267,     # 笼子触涨停
    4132268,     # 笼子触跌停
    723865,      # 涨幅突破
    723866,      # 跌幅突破
)

# 2026-07-17 Level2 账号在短线精灵“全选”时抓到的完整 53 类请求顺序。
# 普通账号不展示/不支持其中另外 30 类，不能把它们混进普通账号的“全部”。
ALL_REALORDER_CATEGORY_IDS = (
    1074269398, 1074269399, 1074269396, 1074269397,
    592572, 592574, 592573, 592575,
    1074269393, 1074269394, 1074269395,
    1074269400, 1074269401, 1074269402, 1074269403,
    1074269404,
    1074269423, 1074269424, 1074269425, 1074269426, 1074269427,
    1074269405,
    1074269428, 1074269429, 1074269430, 1074269431, 1074269432,
    1074269410, 1074269411, 1074269412, 1074269422,
    133994, 133995,
    1074269408, 1074269409,
    133990, 133991, 133794, 133795, 133796, 133797,
    133996, 133998, 133997, 133999,
    4132267, 4132268, 4132269, 4132270, 4132271, 4132272,
    723865, 723866,
)

_STANDARD_REALORDER_CATEGORY_ID_SET = frozenset(
    STANDARD_REALORDER_CATEGORY_IDS
)
LEVEL2_ONLY_REALORDER_CATEGORY_IDS = tuple(
    category_id
    for category_id in ALL_REALORDER_CATEGORY_IDS
    if category_id not in _STANDARD_REALORDER_CATEGORY_ID_SET
)

ANOMALY_GROUP_PREFIX = {
    **{value: 0x40080C00 for value in range(0xD1, 0xF9)},
    **{value: 0x00090A00 for value in range(0xBC, 0xC0)},
    **{value: 0x00020B00 for value in range(0x66, 0x70)},
    **{value: 0x00020A00 for value in range(0xA2, 0xA6)},
    0x99: 0x000B0B00,
    0x9A: 0x000B0B00,
    **{value: 0x003F0D00 for value in range(0xAB, 0xB1)},
}

_BUY = b"\xff\x32\x32\x00"
_SELL = b"\x00\xe6\x00\x00"

ANOMALY_MAP_DXJL = {
    (0xBC, _BUY): "特大主动买",
    (0xBD, _BUY): "特大被动买",
    (0xBE, _SELL): "特大主动卖",
    (0xBF, _SELL): "特大被动卖",
    (0xD6, _BUY): "大笔买入",
    (0xD7, _SELL): "大笔卖出",
    (0xD1, _BUY): "区间放量涨",
    (0xD2, _SELL): "区间放量跌",
    (0xD8, _BUY): "涨停封板",
    (0xDA, _SELL): "跌停封板",
    (0xD9, _SELL): "打开涨停板",
    (0xDB, _BUY): "打开跌停板",
    (0xE0, _BUY): "逼近涨停",
    (0xE1, _SELL): "逼近跌停",
    (0xE2, _BUY): "涨停大减",
    (0xE3, _SELL): "跌停大减",
    (0xE4, _BUY): "强势封涨停",
    (0xEE, _SELL): "强势封跌停",
    (0xDC, _BUY): "急速拉升",
    (0xDD, _SELL): "猛烈打压",
    (0x6C, _BUY): "撤特大买",
    (0x6D, _BUY): "撤涨停买",
    (0x6E, _SELL): "撤特大卖",
    (0x6F, _SELL): "撤跌停卖",
    (0x66, _BUY): "特大挂买",
    (0x67, _SELL): "特大挂卖",
    (0xA2, _BUY): "拖拉机挂买",
    (0xA3, _SELL): "拖拉机挂卖",
    (0xA4, _BUY): "远价位垫单",
    (0xA5, _SELL): "远价位压单",
}

ANOMALY_BYTE_MAP = {
    0xD6: "大笔买入",
    0xD7: "大笔卖出",
    0xD1: "区间放量涨",
    0xD2: "区间放量跌",
    0xD3: "区间放量平",
    0xD4: "单笔冲涨",
    0xD5: "单笔冲跌",
    0xD8: "涨停封板",
    0xDA: "跌停封板",
    0xD9: "打开涨停板",
    0xDB: "打开跌停板",
    0xDC: "急速拉升",
    0xDD: "猛烈打压",
    0xE0: "逼近涨停",
    0xE1: "逼近跌停",
    0xE2: "涨停大减",
    0xE3: "跌停大减",
    0xE4: "强势封涨停",
    0xEE: "强势封跌停",
    0x66: "特大挂买",
    0x67: "特大挂卖",
    0xA2: "拖拉机挂买",
    0xA3: "拖拉机挂卖",
    0xA4: "远价位垫单",
    0xA5: "远价位压单",
    0x6C: "撤特大买",
    0x6D: "撤涨停买",
    0x6E: "撤特大卖",
    0x6F: "撤跌停卖",
    0xBC: "特大主动买",
    0xBD: "特大被动买",
    0xBE: "特大主动卖",
    0xBF: "特大被动卖",
    0xAB: "笼子触涨停",
    0xAC: "笼子触跌停",
    0x99: "涨幅突破",
    0x9A: "跌幅突破",
}

SUBREALORDER_MARKETS = [16, 32, 151, 48]

_PUSH_CODE_RE_A = re.compile(rb"[\x11\x21]([036]\d{5})")
_PUSH_CODE_RE_B = re.compile(rb"\x2d.{1,2}([036]\d{5})", re.DOTALL)


def build_category_id(anomaly_byte: int) -> int:
    """Build a real-order category id from its anomaly byte."""
    prefix = ANOMALY_GROUP_PREFIX.get(anomaly_byte, 0x40080C00)
    return prefix | anomaly_byte


def build_datatype(
    anomaly_bytes,
    volume_min: int | None = None,
    amount_min: int | None = None,
) -> str:
    """Build the comma-separated real-order datatype filter.

    ``"standard"`` means the 23 categories available to an ordinary account.
    ``"all"`` means the 53-category Level2 UI selection captured on wire.
    Explicit iterables continue to contain low-byte anomaly identifiers.
    """
    category_ids = None
    if anomaly_bytes == "standard":
        category_ids = STANDARD_REALORDER_CATEGORY_IDS
    elif anomaly_bytes == "all":
        category_ids = ALL_REALORDER_CATEGORY_IDS
    threshold = ""
    if volume_min is not None or amount_min is not None:
        parts = []
        if volume_min is not None:
            parts.append(f"19[{volume_min}~-]")
        if amount_min is not None:
            parts.append(f"17[{amount_min}~-]")
        threshold = "{" + "|".join(parts) + "}"
    if category_ids is None:
        category_ids = tuple(
            build_category_id(value) for value in anomaly_bytes
        )
    return ",".join(
        f"{category_id}{threshold}" for category_id in category_ids
    ) + ","


def read_frame_realorder(sock: socket.socket) -> bytes:
    """Read one 9601 response whose declared body length is actual length - 1."""
    magic = bytearray()
    while True:
        magic += read_exact(sock, 1)
        if len(magic) > len(FRAME_MAGIC):
            magic.pop(0)
        if bytes(magic) == FRAME_MAGIC:
            break
    body_len = _read_frame_body_length(sock) + 1
    return read_exact(sock, body_len)


def build_qurealorder_query(
    instance: int,
    market: int,
    endtime_us: int,
    maxcount: int = 80,
    datatype: str | None = None,
) -> bytes:
    """Build a qurealorder history-page request body."""
    if datatype is None:
        datatype = DXJL_DATATYPE
    text = (
        f"instid={instance}\n"
        f"method=qurealorder\nreqtype=4\nmaxcount={maxcount}\n"
        f"market={market}\n"
        f"datatype={datatype}\n"
        f"rettype=hqfile\nendtime={endtime_us}"
    )
    return b"\x09" + text.encode("gbk")


def parse_qurealorder_response(body: bytes, market: str) -> list[dict]:
    """Parse the hq1.0 payload returned by qurealorder."""
    hq_offset = body.find(b"hq1.0")
    if hq_offset < 0:
        return []
    payload = body[hq_offset:]
    if len(payload) < 28:
        return []

    header_length = struct.unpack("<I", payload[8:12])[0]
    record_count = struct.unpack("<I", payload[12:16])[0]
    field_count = struct.unpack("<I", payload[16:20])[0]
    record_length = struct.unpack("<I", payload[20:24])[0]
    if record_length == 0 or record_count == 0:
        return []
    if len(payload) - header_length < record_length:
        return []

    fields = []
    for index in range(field_count + 1):
        offset = 24 + index * 8
        if offset + 8 > header_length:
            break
        entry = payload[offset:offset + 8]
        datatype = struct.unpack("<I", entry[0:4])[0]
        width = struct.unpack("<H", entry[6:8])[0]
        if datatype:
            fields.append((datatype & 0xFF, width))

    field_offsets = {}
    offset = 0
    for field_id, width in fields:
        field_offsets[field_id] = (offset, width)
        offset += width

    records = []
    for index in range(record_count):
        record = payload[
            header_length + index * record_length:
            header_length + (index + 1) * record_length
        ]
        if len(record) < record_length:
            break
        parsed = _parse_dxjl_record(record, field_offsets, market)
        if parsed:
            records.append(parsed)
    return records


def _parse_dxjl_record(
    record: bytes,
    offsets: dict,
    market: str,
) -> dict | None:
    try:
        timestamp_offset, timestamp_width = offsets.get(199, (0, 8))
        timestamp_us = struct.unpack(
            "<Q",
            record[timestamp_offset:timestamp_offset + timestamp_width],
        )[0]

        code_offset, _ = offsets.get(5, (8, 17))
        code = record[
            code_offset + 1:code_offset + 7
        ].decode("ascii", errors="replace")

        anomaly_offset, _ = offsets.get(61, (25, 4))
        anomaly_code = record[anomaly_offset]

        direction_offset, direction_width = offsets.get(64, (29, 4))
        direction = record[
            direction_offset:direction_offset + direction_width
        ]

        amount_offset, amount_width = offsets.get(17, (37, 4))
        amount = decode_ths_float(
            struct.unpack(
                "<I",
                record[amount_offset:amount_offset + amount_width],
            )[0]
        )

        change_offset, change_width = offsets.get(18, (41, 4))
        change_pct = decode_ths_float(
            struct.unpack(
                "<I",
                record[change_offset:change_offset + change_width],
            )[0]
        )

        return {
            "时间": timestamp_us,
            "市场": market,
            "代码": code,
            "异动类型": ANOMALY_MAP_DXJL.get(
                (anomaly_code, direction),
                ANOMALY_BYTE_MAP.get(
                    anomaly_code,
                    f"未知0x{anomaly_code:02x}",
                ),
            ),
            "异动编码": anomaly_code,
            "金额": round(amount, 2),
            "涨跌幅": round(change_pct, 2),
        }
    except Exception:
        return None


def build_heartbeat_9601(seq: int) -> bytes:
    """Build the framed five-byte 9601 heartbeat."""
    body = b"\x09" + (seq & 0xFFFFFF).to_bytes(3, "big") + b"\x07"
    return encode_frame(body)


def build_subrealorder_query(
    instance: int,
    market: int,
    action: str = "add",
) -> bytes:
    """Build a subrealorder realtime subscription request body."""
    text = (
        f"instid={instance}\n"
        f"method=subrealorder\n"
        f"action={action}\n"
        f"market={market}\n"
        f"accept_ziptype=snappy\n"
        f"rettype=hqfile"
    )
    return b"\x09" + text.encode("gbk")


def parse_pushrealorder_response(body: bytes) -> list[dict]:
    """Parse one pushrealorder frame into anomaly records."""
    if b"pushrealorder" not in body:
        return []

    market = ""
    market_match = re.search(rb"market=(\d+)", body[:200])
    if market_match:
        market = market_match.group(1).decode("ascii", errors="replace")

    code_matches = []
    for pattern in (_PUSH_CODE_RE_A, _PUSH_CODE_RE_B):
        code_matches.extend(pattern.finditer(body))
    code_matches.sort(key=lambda match: match.start())

    records = []
    anomaly_bytes = {key[0] for key in ANOMALY_MAP_DXJL}
    for index, code_match in enumerate(code_matches):
        code = code_match.group(1).decode("ascii", errors="replace")
        # 0x11/0x21 marker before the code overrides the frame-header market:
        # pushrealorder frame market= can disagree with the record market.
        record_market = market
        marker_pos = code_match.start(1) - 1
        if marker_pos >= 0 and body[marker_pos] in (0x11, 0x21):
            record_market = "16" if body[marker_pos] == 0x11 else "32"
        record_end = (
            code_matches[index + 1].start()
            if index + 1 < len(code_matches)
            else len(body)
        )
        record = body[code_match.start():record_end]

        offset = 0
        while offset < len(record) - 7:
            anomaly_byte = record[offset]
            if (
                anomaly_byte not in anomaly_bytes
                or record[offset + 1:offset + 4] != b"\x0c\x08\x40"
            ):
                offset += 1
                continue

            direction = b""
            direction_region = record[offset + 4:offset + 20]
            for marker in (_BUY, _SELL):
                if marker in direction_region:
                    direction = marker
                    break
            anomaly_type = (
                ANOMALY_MAP_DXJL.get(
                    (anomaly_byte, direction),
                    ANOMALY_BYTE_MAP.get(
                        anomaly_byte,
                        f"未知0x{anomaly_byte:02x}",
                    ),
                )
                if direction
                else ANOMALY_BYTE_MAP.get(
                    anomaly_byte,
                    f"未知0x{anomaly_byte:02x}",
                )
            )

            change_pct = 0.0
            amount = 0.0
            for value_offset in range(
                offset + 4,
                min(offset + 25, len(record) - 3),
            ):
                if record[value_offset + 3] not in (0xA0, 0xA8):
                    continue
                value = decode_ths_float(
                    struct.unpack(
                        "<I",
                        record[value_offset:value_offset + 4],
                    )[0]
                )
                if not -50 < value < 50:
                    continue
                change_pct = round(value, 2)
                if value_offset >= 4:
                    amount_value = decode_ths_float(
                        struct.unpack(
                            "<I",
                            record[value_offset - 4:value_offset],
                        )[0]
                    )
                    if 10000 < amount_value < 1_000_000_000:
                        amount = round(amount_value, 2)
                break

            records.append(
                {
                    "代码": code,
                    "市场": record_market,
                    "异动类型": anomaly_type,
                    "异动编码": anomaly_byte,
                    "金额": amount,
                    "涨幅": change_pct,
                    "raw_bytes": record[offset:offset + 20].hex(),
                }
            )
            offset += 4
    return records


__all__ = [
    "ALL_REALORDER_CATEGORY_IDS",
    "ANOMALY_BYTE_MAP",
    "ANOMALY_GROUP_PREFIX",
    "ANOMALY_MAP_DXJL",
    "DXJL_DATATYPE",
    "LEVEL2_ONLY_REALORDER_CATEGORY_IDS",
    "REALORDER_HOST",
    "REALORDER_PORT",
    "SUBREALORDER_MARKETS",
    "STANDARD_REALORDER_CATEGORY_IDS",
    "build_category_id",
    "build_datatype",
    "build_heartbeat_9601",
    "build_qurealorder_query",
    "build_subrealorder_query",
    "parse_pushrealorder_response",
    "parse_qurealorder_response",
    "read_frame_realorder",
]
