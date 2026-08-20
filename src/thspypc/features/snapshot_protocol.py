"""Pure Level2 snapshot-subscription request protocol."""
from __future__ import annotations

import struct
from datetime import datetime

from ..codecs.framing import encode_frame
from ..codecs.numeric import decode_ths_float
from ..codecs.quote_stream import normalize_stock_depth_push


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


def parse_trade_tick_push(body: bytes) -> dict | None:
    """Parse a Level2 tick-by-tick trade push frame (single record).

    Two compatible wire layouts are known:

    * 2026-08-07 ``0x7f`` / 71-byte layout (002384);
    * 2026-08-20 ``0x60/0x04`` / 71-byte core layout (603334), optionally
      followed by one ``0x7d`` delimiter byte outside the frame length
      header.  The live runtime (``read_frame``) yields the 71-byte core;
      legacy stream splitters that cut on the magic delimiter yield 72
      bytes, so both extents are accepted.

    The ``0x60/0x04`` layout was captured immediately after the PC client
    requested the ``period=7169`` trade replay.  Its time, price, volume,
    direction, order ids, sequence and trade number align exactly with the
    7169 field table, proving that it is the live continuation of the
    visible trade list.

    Shared field offsets::

        [0]     0x09            帧类型标记
        [28]    市场标记         0x11=沪 0x21=深
        [29-34] ASCII 代码       6 位股票代码
        [47-50] ths_float        **成交价格**

    The ``0x60/0x04`` layout additionally exposes Unix ``time`` at 43,
    32-bit volume and direction at 51/55, delegate ids at 59/63, and
    sequence at 67.  The value at 39 was originally named ``trade_no``;
    interval truth proves that it is the *previous* record's 7169 ``dt18``.
    ``previous_trade_no`` is therefore authoritative, while ``trade_no`` is
    retained as a compatibility alias for the same wire value.

    Batch frames (multiple records) are recognised by
    :func:`is_trade_tick_batch_push` and parsed by
    :func:`parse_trade_tick_batch_push`.
    """
    if not is_trade_tick_push(body):
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
    result = {
        "code": code,
        "market": market,
        "price": decode_ths_float(struct.unpack("<I", body[47:51])[0]),
        "raw_len": len(body),
    }
    if _is_realtime_trade_tick_push(body):
        traded_timestamp = struct.unpack_from("<I", body, 43)[0]
        result.update(
            {
                "event": "trade",
                "time": datetime.fromtimestamp(traded_timestamp),
                "timestamp": traded_timestamp,
                "volume": struct.unpack_from("<I", body, 51)[0],
                "direction": struct.unpack_from("<I", body, 55)[0],
                "delegate_a": struct.unpack_from("<I", body, 59)[0],
                "delegate_b": struct.unpack_from("<I", body, 63)[0],
                "seq": struct.unpack_from("<I", body, 67)[0],
                "previous_trade_no": struct.unpack_from("<I", body, 39)[0],
                # Backward-compatible alias.  This is not the current trade's
                # 7169 dt18; see ``previous_trade_no`` above.
                "trade_no": struct.unpack_from("<I", body, 39)[0],
                "wire_subtype": "0x60/0x04",
            }
        )
    else:
        result.update(
            {
                "volume": struct.unpack_from("<H", body, 51)[0],
                "direction": body[55],
                "seq": struct.unpack_from("<I", body, 39)[0],
                "wire_subtype": "0x7f",
            }
        )
    return result


def _is_legacy_trade_tick_push(body: bytes) -> bool:
    return (
        len(body) == 71
        and body[0] == 0x09
        and body[1:5] == b"\x7b\xd0\x01\x7f"
        and all(0x30 <= value <= 0x39 for value in body[29:35])
    )


def _strip_trade_tick_delimiter(body: bytes) -> bytes:
    """Drop the optional trailing 0x7d delimiter byte.

    The 8901 frame length header excludes the delimiter, so the live
    ``read_frame`` path yields bodies without it while legacy
    magic-splitting capture tooling yields bodies with it appended.
    """
    return body[:-1] if body.endswith(b"\x7d") else body


def _is_realtime_trade_tick_push(body: bytes) -> bool:
    core = _strip_trade_tick_delimiter(body)
    return (
        len(core) == 71
        and core[0:7] == b"\x09\x7b\xd0\x01\x60\x04\x00"
        and core[28] in (0x11, 0x21)
        and core[29:35].isdigit()
        and struct.unpack_from("<I", core, 55)[0] in (1, 5)
    )


def is_trade_tick_push(body: bytes) -> bool:
    """Return whether ``body`` is a verified live trade-tick layout."""
    return _is_legacy_trade_tick_push(body) or _is_realtime_trade_tick_push(body)


# ── 0x60/0x04 变长批量逐笔推送（2026-08-20 603334 抓包破译）──
#
# 同一 ``09 7b d0 01 60 04 00`` 子类型还承载"一次多条成交"的批量帧。
# 结构（603334 全部 8 个批量帧, 8/8 验证）::
#
#     [0:39]  与单笔帧完全相同的头部(市场/代码/帧计数)
#     [36:38] 记录数 n (LE16), [38] = 0x80|n 回显校验
#     [39:..] n+1 个前缀 token（首值随帧长变化、第二个=-1、余下=0）
#     随后    8 个字段列；每列 = 4B LE 基值 + (n-1) 个有符号 delta token
#             列序为 previous_tno/time/price/vol/dir/a/b/seq
#     尾部    seq 的 (n-1) 个 +1 token（0x81）+ 2B 校验
#
# 与单笔帧拼接后, 603334 抓包的推送覆盖 7465→7508 全部序号, 缺口仅
# 7463/7464 两条未被推送 —— 与"批量帧记录总数 vs 单笔序号缺口"计数吻合。
# 7169 区间真值最终确认 token 是大端 7-bit 有符号补码：每字节低 7 位为
# payload，最高位表示终止；例如 00 e4=+100、7f 9c=-100、78 8d=-1011。
# 8/8 批量帧的 time/price/vol/dir/a/b/seq 均逐条匹配回放真值。
_TRADE_TICK_PREFIX = b"\x09\x7b\xd0\x01\x60\x04\x00"
_TRADE_TICK_BATCH_MAX_COUNT = 127


def _trade_batch_core(body: bytes) -> tuple[bytes, int] | None:
    """Validate a batch frame's structural invariants; return (core, n)."""
    candidates = (body, body[:-1]) if body.endswith(b"\x7d") else (body,)
    for core in candidates:
        if len(core) <= 71 or core[0:7] != _TRADE_TICK_PREFIX:
            continue
        if core[28] not in (0x11, 0x21) or not core[29:35].isdigit():
            continue
        count = struct.unpack_from("<H", core, 36)[0]
        if not 2 <= count <= _TRADE_TICK_BATCH_MAX_COUNT:
            continue
        if core[38] != (0x80 | count):
            continue
        length = len(core)
        ones_start = length - 2 - (count - 1)
        if (
            ones_start >= 39
            and core[ones_start : length - 2] == b"\x81" * (count - 1)
        ):
            return core, count
    return None


def is_trade_tick_batch_push(body: bytes) -> bool:
    """Return whether ``body`` is a multi-record ``0x60/0x04`` batch frame."""
    return _trade_batch_core(body) is not None


def _read_trade_batch_delta(
    data: bytes,
    position: int,
    limit: int,
) -> tuple[int, int]:
    """Read one signed big-end 7-bit delta terminated by a high bit."""
    unsigned = 0
    bits = 0
    while position < limit and bits < 35:
        value = data[position]
        position += 1
        unsigned = (unsigned << 7) | (value & 0x7F)
        bits += 7
        if value & 0x80:
            sign_bit = 1 << (bits - 1)
            if unsigned & sign_bit:
                unsigned -= 1 << bits
            return unsigned, position
    raise ValueError("unterminated trade-batch delta")


def _decode_trade_batch_columns(
    core: bytes,
    count: int,
) -> dict[str, list[int]] | None:
    """Decode the eight verified column-major fields in a batch frame."""
    limit = len(core) - 2
    position = 39
    try:
        prefix = []
        for _ in range(count + 1):
            value, position = _read_trade_batch_delta(core, position, limit)
            prefix.append(value)
        if prefix[1] != -1 or any(prefix[2:]):
            return None

        columns: dict[str, list[int]] = {}
        for name in (
            "previous_trade_no",
            "timestamp",
            "price_raw",
            "volume",
            "direction",
            "delegate_a",
            "delegate_b",
            "seq",
        ):
            if position + 4 > limit:
                return None
            base = struct.unpack_from("<I", core, position)[0]
            position += 4
            values = [base]
            for _ in range(count - 1):
                delta, position = _read_trade_batch_delta(
                    core,
                    position,
                    limit,
                )
                current = values[-1] + delta
                if not 0 <= current <= 0xFFFFFFFF:
                    return None
                values.append(current)
            columns[name] = values
    except (IndexError, struct.error, ValueError):
        return None

    if position != limit:
        return None
    seqs = columns["seq"]
    if seqs != list(range(seqs[0], seqs[0] + count)):
        return None
    if any(value not in (1, 5) for value in columns["direction"]):
        return None
    return columns


def parse_trade_tick_batch_push(body: bytes) -> dict | None:
    """Parse one multi-record trade-tick batch push.

    The returned ``records`` use the same public fields as a single
    ``0x60/0x04`` trade push.  All eight captured batch variants were checked
    row-by-row against a 7169 replay of the same sequence interval.
    """
    located = _trade_batch_core(body)
    if located is None:
        return None
    core, count = located
    columns = _decode_trade_batch_columns(core, count)
    if columns is None:
        return None
    code = core[29:35].decode("ascii")
    market = "SH" if core[28] == 0x11 else "SZ"
    records = []
    try:
        for index in range(count):
            timestamp = columns["timestamp"][index]
            previous_trade_no = columns["previous_trade_no"][index]
            records.append(
                {
                    "code": code,
                    "market": market,
                    "event": "trade",
                    "time": datetime.fromtimestamp(timestamp),
                    "timestamp": timestamp,
                    "price": decode_ths_float(columns["price_raw"][index]),
                    "volume": columns["volume"][index],
                    "direction": columns["direction"][index],
                    "delegate_a": columns["delegate_a"][index],
                    "delegate_b": columns["delegate_b"][index],
                    "seq": columns["seq"][index],
                    "previous_trade_no": previous_trade_no,
                    # Compatibility alias; see parse_trade_tick_push().
                    "trade_no": previous_trade_no,
                    "wire_subtype": "0x60/0x04-batch",
                }
            )
    except (OSError, OverflowError, ValueError):
        return None

    seq_start = columns["seq"][0]
    return {
        "code": code,
        "market": market,
        "event": "trade_batch",
        "count": count,
        "seq_start": seq_start,
        "seq_end": seq_start + count - 1,
        "seqs": list(range(seq_start, seq_start + count)),
        "records": records,
        "records_resolved": True,
        "wire_subtype": "0x60/0x04-batch",
        "raw_len": len(body),
    }


def parse_snapshot_push(body: bytes) -> dict | None:
    """Compatibility name for :func:`parse_trade_tick_push`."""
    return parse_trade_tick_push(body)


def is_snapshot_push(body: bytes) -> bool:
    """Compatibility name for :func:`is_trade_tick_push`."""
    return is_trade_tick_push(body)


_ORDER_CANCEL_SIDES = {0x08: "buy", 0x0C: "sell"}
_ORDER_QUEUE_SIDES = {0x14: "buy", 0x18: "sell"}


def _market_name(marker: int) -> str:
    return "SH" if marker == 0x11 else "SZ"


def _order_cancel_single_core(body: bytes) -> bytes | None:
    core = _strip_trade_tick_delimiter(body)
    if (
        len(core) == 70
        and core[0:5] == b"\x09\x7b\xd0\x01\x60"
        and core[5] in _ORDER_CANCEL_SIDES
        and core[28] in (0x11, 0x21)
        and core[43] == core[28]
        and core[29:35] == core[44:50]
        and core[29:35].isdigit()
    ):
        return core
    return None


def is_order_cancel_push(body: bytes) -> bool:
    """Return whether ``body`` is one single-record real-time cancel push.

    The ``0x60/0x08`` and ``0x60/0x0c`` shapes are distinct from both the
    legacy ``0x7f`` and current ``0x60/0x04`` trade-tick shapes.  Their two
    embedded code markers must agree; this prevents an adjacent or truncated
    payload from being accepted accidentally.  The live core is 70 bytes;
    capture splitters may append one out-of-length ``0x7d`` delimiter.

    The layout was first verified during the opening auction, but the
    2026-08-20 ``603334`` capture proves that the same subtype remains active
    during continuous trading.  It must therefore not be classified by
    session phase.
    """
    return _order_cancel_single_core(body) is not None


def parse_order_cancel_push(body: bytes) -> dict | None:
    """Parse one real-time order-cancellation event.

    Verified against the PC client's order/cancel view for ``002428`` on
    2026-08-10.  The UI's ``买撤``/``卖撤`` rows map to marker ``0x08``/
    ``0x0c`` respectively.  The UI suffix beside the cancel side is exactly
    ``cancelled_at - placed_at`` (for example ``30s`` or ``4m``).

    A continuous-session capture for ``603334`` on 2026-08-20 uses the same
    wire layout between 13:19:19 and 13:19:34.  ``event`` is consequently the
    phase-neutral ``order_cancel``.

    ``volume`` is expressed in shares, matching the rest of the public quote
    parsers; ``lots`` exposes the PC view's 100-share 手 unit.
    """
    core = _order_cancel_single_core(body)
    if core is None:
        return None

    market_flag = core[43]
    placed_timestamp = struct.unpack_from("<I", core, 50)[0]
    cancelled_timestamp = struct.unpack_from("<I", core, 54)[0]
    price_raw = struct.unpack_from("<I", core, 58)[0]
    volume = struct.unpack_from("<I", core, 62)[0]
    order_id = struct.unpack_from("<I", core, 66)[0]
    cancel_id = struct.unpack_from("<I", core, 39)[0]
    side_raw = core[5]
    return {
        "code": core[44:50].decode("ascii"),
        "market": _market_name(market_flag),
        "event": "order_cancel",
        "side": _ORDER_CANCEL_SIDES[side_raw],
        "side_raw": side_raw,
        "placed_at": datetime.fromtimestamp(placed_timestamp),
        "cancelled_at": datetime.fromtimestamp(cancelled_timestamp),
        "placed_timestamp": placed_timestamp,
        "cancelled_timestamp": cancelled_timestamp,
        "lifetime_seconds": cancelled_timestamp - placed_timestamp,
        "price": decode_ths_float(price_raw),
        "price_raw": price_raw,
        "volume": volume,
        "lots": volume / 100,
        # 7170/7171 truth proves this is dt37, the original order ID.
        "order_id": order_id,
        "aux_id": order_id,
        "cancel_id": cancel_id,
        "seq": cancel_id,
        "wire_subtype": f"0x60/0x{side_raw:02x}",
        "raw_len": len(body),
    }


def _order_cancel_batch_core(body: bytes) -> tuple[bytes, int] | None:
    candidates = (body, body[:-1]) if body.endswith(b"\x7d") else (body,)
    for core in candidates:
        if (
            len(core) <= 70
            or core[0:5] != b"\x09\x7b\xd0\x01\x60"
            or core[5] not in _ORDER_CANCEL_SIDES
            or core[28] not in (0x11, 0x21)
            or not core[29:35].isdigit()
        ):
            continue
        count = struct.unpack_from("<H", core, 36)[0]
        if 2 <= count <= 64 and core[38] == (0x80 | count):
            return core, count
    return None


def is_order_cancel_batch_push(body: bytes) -> bool:
    """Return whether ``body`` is a column-delta cancel batch."""
    return parse_order_cancel_batch_push(body) is not None


def parse_order_cancel_batch_push(body: bytes) -> dict | None:
    """Expand a variable-length ``0x60/08`` or ``0x60/0c`` cancel batch.

    The column order and signed big-endian 7-bit deltas were verified against
    7170/7171 truth.  ``order_id`` is the original 7175 dt1 referenced by the
    cancellation row's dt37; ``cancel_id`` is the 7170/7171 dt1.
    """
    located = _order_cancel_batch_core(body)
    if located is None:
        return None
    core, count = located
    limit = len(core) - 2
    position = 39
    try:
        # Per-record prefix metadata is not exposed by the PC truth table.
        for _ in range(count):
            _unused, position = _read_trade_batch_delta(
                core, position, limit
            )

        if position + 4 > limit:
            return None
        cancel_ids = [struct.unpack_from("<I", core, position)[0]]
        position += 4
        for _ in range(count - 1):
            delta, position = _read_trade_batch_delta(
                core, position, limit
            )
            cancel_ids.append(cancel_ids[-1] + delta)

        if position + 7 > limit:
            return None
        marker = core[position]
        code_bytes = core[position + 1 : position + 7]
        position += 7
        if marker not in (0x11, 0x21) or not code_bytes.isdigit():
            return None
        for _ in range(count - 1):
            context_delta, position = _read_trade_batch_delta(
                core, position, limit
            )
            if context_delta != 0:
                return None

        columns: dict[str, list[int]] = {}
        for name in (
            "placed_timestamp",
            "cancelled_timestamp",
            "price_raw",
            "volume",
            "order_id",
        ):
            if position + 4 > limit:
                return None
            values = [struct.unpack_from("<I", core, position)[0]]
            position += 4
            for _ in range(count - 1):
                delta, position = _read_trade_batch_delta(
                    core, position, limit
                )
                value = values[-1] + delta
                if not 0 <= value <= 0xFFFFFFFF:
                    return None
                values.append(value)
            columns[name] = values
    except (IndexError, OSError, OverflowError, struct.error, ValueError):
        return None
    if position != limit:
        return None

    side_raw = core[5]
    code = code_bytes.decode("ascii")
    market = _market_name(marker)
    records = []
    try:
        for index, cancel_id in enumerate(cancel_ids):
            placed_timestamp = columns["placed_timestamp"][index]
            cancelled_timestamp = columns["cancelled_timestamp"][index]
            order_id = columns["order_id"][index]
            volume = columns["volume"][index]
            price_raw = columns["price_raw"][index]
            records.append({
                "code": code,
                "market": market,
                "event": "order_cancel",
                "side": _ORDER_CANCEL_SIDES[side_raw],
                "side_raw": side_raw,
                "placed_at": datetime.fromtimestamp(placed_timestamp),
                "cancelled_at": datetime.fromtimestamp(cancelled_timestamp),
                "placed_timestamp": placed_timestamp,
                "cancelled_timestamp": cancelled_timestamp,
                "lifetime_seconds": cancelled_timestamp - placed_timestamp,
                "price": decode_ths_float(price_raw),
                "price_raw": price_raw,
                "volume": volume,
                "lots": volume / 100,
                "order_id": order_id,
                "aux_id": order_id,
                "cancel_id": cancel_id,
                "seq": cancel_id,
                "wire_subtype": f"0x60/0x{side_raw:02x}-batch",
            })
    except (OSError, OverflowError, ValueError):
        return None
    if cancel_ids != list(range(cancel_ids[0], cancel_ids[0] + count)):
        return None
    return {
        "code": code,
        "market": market,
        "event": "order_cancel_batch",
        "side": _ORDER_CANCEL_SIDES[side_raw],
        "side_raw": side_raw,
        "count": count,
        "cancel_id_start": cancel_ids[0],
        "cancel_id_end": cancel_ids[-1],
        "records": records,
        "records_resolved": True,
        "wire_subtype": f"0x60/0x{side_raw:02x}-batch",
        "raw_len": len(body),
    }


def parse_order_cancel_records(body: bytes) -> list[dict]:
    """Return zero or more normalized cancellation records from one push."""
    single = parse_order_cancel_push(body)
    if single is not None:
        return [single]
    batch = parse_order_cancel_batch_push(body)
    return batch["records"] if batch is not None else []


def _order_queue_core(body: bytes) -> tuple[bytes, int] | None:
    candidates = (body, body[:-1]) if body.endswith(b"\x7d") else (body,)
    for core in candidates:
        if (
            len(core) < 63
            or core[0:5] != b"\x09\x7b\xd0\x01\x60"
            or core[5] not in _ORDER_QUEUE_SIDES
            or core[28] not in (0x11, 0x21)
            or not core[29:35].isdigit()
            or core[35] != 0xC8
            or core[51:53] != b"\x00\x00"
            or core[54] != 0x10
            or struct.unpack_from("<I", core, 59)[0] != 0x0101
        ):
            continue
        visible_count = core[53]
        encoded_count = visible_count + 6
        if (
            len(core) == 63 + visible_count * 4
            and struct.unpack_from("<H", core, 36)[0] == encoded_count
            and core[38] == (0x80 | encoded_count)
        ):
            return core, visible_count
    return None


def is_order_queue_push(body: bytes) -> bool:
    """Return whether ``body`` is a compact best-price order queue update."""
    return _order_queue_core(body) is not None


def parse_order_queue_push(body: bytes) -> dict | None:
    """Parse ``0x60/0x14`` buy or ``0x60/0x18`` sell queue updates.

    The result mirrors :func:`parse_order_queue_response`: ``entries`` is the
    visible queue only, while ``total_order_count`` counts all orders at the
    current best price.  ``meta_value`` remains raw because its exact business
    label is not exposed by the client UI.
    """
    located = _order_queue_core(body)
    if located is None:
        return None
    core, visible_count = located
    timestamp = struct.unpack_from("<I", core, 39)[0]
    price_raw = struct.unpack_from("<I", core, 43)[0]
    meta_value = struct.unpack_from("<I", core, 47)[0]
    total_order_count = struct.unpack_from("<I", core, 55)[0]
    entries = []
    for index in range(visible_count):
        raw = struct.unpack_from("<I", core, 63 + index * 4)[0]
        shares = raw & 0x07FFFFFF
        entries.append({
            "index": index + 1,
            "raw": raw,
            "shares": shares,
            "hands": (shares + 50) // 100,
            "is_major": bool(raw & 0x08000000),
        })
    major_entries = [entry for entry in entries if entry["is_major"]]
    major_shares = sum(entry["shares"] for entry in major_entries)
    side_raw = core[5]
    return {
        "code": core[29:35].decode("ascii"),
        "market": _market_name(core[28]),
        "market_marker": core[28],
        "event": "order_queue",
        "side": _ORDER_QUEUE_SIDES[side_raw],
        "side_raw": side_raw,
        "period": 7173 if side_raw == 0x14 else 7174,
        "time": datetime.fromtimestamp(timestamp),
        "ts": timestamp,
        "price": round(decode_ths_float(price_raw), 3),
        "price_raw": price_raw,
        "meta_value": meta_value,
        "display_limit": visible_count,
        "total_order_count": total_order_count,
        "visible_count": visible_count,
        "truncated": total_order_count > visible_count,
        "entries": entries,
        "visible_major_order_count": len(major_entries),
        "visible_major_shares": major_shares,
        "visible_major_hands": major_shares / 100.0,
        "wire_subtype": f"0x60/0x{side_raw:02x}",
        "raw_len": len(body),
    }


def is_auction_cancel_push(body: bytes) -> bool:
    """Compatibility alias for :func:`is_order_cancel_push`.

    The historical name describes where the layout was first discovered,
    not a restriction on the trading phase.
    """
    return is_order_cancel_push(body)


def parse_auction_cancel_push(body: bytes) -> dict | None:
    """Compatibility wrapper preserving the legacy ``event`` value.

    New callers should use :func:`parse_order_cancel_push`, whose event name
    is valid in both auction and continuous sessions.
    """
    result = parse_order_cancel_push(body)
    if result is None:
        return None
    legacy = dict(result)
    legacy["event"] = "auction_cancel"
    return legacy


# ── 550B 十档盘口推送（2026-08-07 盘中破译）──
# magic = 09 7b d0 0f，含完整十档买卖价量。
# 布局（相对帧起点）：
#   [1:5]   magic 7b d0 0f 7f
#   [44]    市场标记 0x21=深 0x11=沪
#   [45:51] ASCII 代码
#   [51:67] 昨收/开盘/最高/最低/现价 (5×4B ths_float)
#   [67:95] 成交量/额等
#   [95:143] 买1买2买3 卖1卖2卖3 (6对×8B: 4B ths_float价 + 4B u32量)
#   [143:147] 4B 间隔
#   [147:179] 买4 卖4 买5 卖5 (4对×8B)
#   [179:195] 16B 间隔块
#   [195:267] 买6-买10 卖6-卖10 (10对×8B)
_DEPTH_PUSH_MAGIC = b"\x7b\xd0\x0f\x7f"
_DEPTH_PUSH_MARKETS = {0x11: "SH", 0x21: "SZ"}
_AUCTION_IMBALANCE_SELL = 0x08000000
_AUCTION_IMBALANCE_MASK = 0x07FFFFFF
# A complete continuous-book record originally ended 505 bytes after the
# first code byte (code at 45 in a 550B frame, or at 213 in a 718B prefixed
# frame).  The 2026-08-20 page4417/page4214 capture added a verified 614B
# variant: code at 61, the same quote/book offsets, plus a 48B suffix.  Keep
# the accepted extents explicit so compact/concatenated envelopes are not
# accidentally decoded with fixed offsets.
_CONTINUOUS_DEPTH_RECORD_ENDS = frozenset((505, 553))


def _find_depth_code(body: bytes) -> tuple[int, int, str] | None:
    """Locate ``market marker + six digit code`` inside a 0x0f push.

    The 2026-08-10 opening-auction capture showed that a push body may prepend
    status text or another compact record.  The stock block therefore starts
    at a variable offset even though fields relative to its code are stable.
    """
    for market_pos in range(5, max(5, len(body) - 6)):
        market_flag = body[market_pos]
        if market_flag not in _DEPTH_PUSH_MARKETS:
            continue
        code_raw = body[market_pos + 1 : market_pos + 7]
        if len(code_raw) != 6 or not all(0x30 <= value <= 0x39 for value in code_raw):
            continue
        return market_pos, market_pos + 1, code_raw.decode("ascii")
    return None


def _depth_float(body: bytes, offset: int) -> float:
    return decode_ths_float(struct.unpack_from("<I", body, offset)[0])


def _depth_u32(body: bytes, offset: int) -> int:
    return struct.unpack_from("<I", body, offset)[0]


def _is_auction_depth_block(body: bytes, code_pos: int) -> bool:
    """Recognize the three-row virtual-book layout used before 09:25."""
    if code_pos + 130 > len(body):
        return False
    auction_price = _depth_float(body, code_pos + 10)
    current_price = _depth_float(body, code_pos + 22)
    bid_price = _depth_float(body, code_pos + 26)
    ask_price = _depth_float(body, code_pos + 50)
    bid_matched = _depth_u32(body, code_pos + 30)
    ask_matched = _depth_u32(body, code_pos + 54)
    return (
        auction_price > 0
        and current_price == 0
        and bid_price == auction_price
        and ask_price == auction_price
        and bid_matched == ask_matched
    )


def _is_continuous_depth_block(body: bytes, code_pos: int) -> bool:
    """Recognize a complete continuous-auction ten-level record.

    Some 0x0f7f envelopes contain compact or concatenated records.  Merely
    finding a stock code is not enough: applying the ten-level offsets to
    those variants produced impossible prices in the 2026-08-10 capture.
    """
    if len(body) - code_pos not in _CONTINUOUS_DEPTH_RECORD_ENDS:
        return False
    shift = code_pos - 45
    prev_close = _depth_float(body, shift + 51)
    current_price = _depth_float(body, shift + 67)
    bid1_price = _depth_float(body, shift + 95)
    ask1_price = _depth_float(body, shift + 119)
    return (
        prev_close > 0
        and current_price > 0
        and bid1_price > 0
        and ask1_price > 0
    )


def is_stock_depth_envelope(body: bytes) -> bool:
    """Return whether a 0x0f7f envelope contains a stock-code marker.

    This is broader than :func:`is_depth_push`: unknown compact layouts are
    stock depth envelopes but are deliberately not accepted by the production
    parser until their record structure has been verified.
    """
    return bool(
        len(body) >= 5
        and body[0] == 0x09
        and body[1:5] == _DEPTH_PUSH_MAGIC
        and _find_depth_code(body)
    )


def is_auction_depth_push(body: bytes) -> bool:
    """Return whether ``body`` contains an opening-auction virtual book.

    The book has one matched row on each side plus an optional unmatched row
    on the dominant side.  It is not a truncated continuous-auction order
    book, even though it shares the ``09 7b d0 0f 7f`` envelope.
    """
    if not is_stock_depth_envelope(body):
        return False
    located = _find_depth_code(body)
    return bool(located and _is_auction_depth_block(body, located[1]))


def parse_auction_depth_push(body: bytes) -> dict | None:
    """Parse the variable-offset three-row opening-auction push.

    ``buy_unmatched_volume`` and ``sell_unmatched_volume`` correspond to the
    Level2 7176 oracle's dt27/dt33.  Their price slot is an absent-value
    sentinel, so ``display_levels`` uses ``price=None`` for the second row.
    The row order mirrors the PC client: dominant-side level 1/2 followed by
    the opposite-side level 1.
    """
    if not is_auction_depth_push(body):
        return None
    located = _find_depth_code(body)
    if located is None:
        return None
    market_pos, code_pos, code = located
    market = _DEPTH_PUSH_MARKETS[body[market_pos]]

    auction_price = round(_depth_float(body, code_pos + 10), 3)
    matched_volume = _depth_u32(body, code_pos + 30)
    buy_unmatched = _depth_u32(body, code_pos + 38)
    sell_unmatched = _depth_u32(body, code_pos + 62)
    direction_raw = _depth_u32(body, code_pos + 126)
    encoded_volume = direction_raw & _AUCTION_IMBALANCE_MASK
    encoded_side = "sell" if direction_raw & _AUCTION_IMBALANCE_SELL else "buy"

    # The explicit buy2/sell2 slots are authoritative.  The packed direction
    # word is a fallback for compact variants and a useful consistency field.
    if encoded_volume:
        if encoded_side == "sell" and not sell_unmatched:
            sell_unmatched = encoded_volume
        elif encoded_side == "buy" and not buy_unmatched:
            buy_unmatched = encoded_volume

    if sell_unmatched:
        imbalance_side = "sell"
        imbalance_volume = sell_unmatched
    elif buy_unmatched:
        imbalance_side = "buy"
        imbalance_volume = buy_unmatched
    else:
        imbalance_side = None
        imbalance_volume = 0

    bid1 = {
        "side": "buy",
        "level": 1,
        "price": auction_price,
        "volume": matched_volume,
        "kind": "matched",
    }
    ask1 = {
        "side": "sell",
        "level": 1,
        "price": auction_price,
        "volume": matched_volume,
        "kind": "matched",
    }
    buy2 = {
        "side": "buy",
        "level": 2,
        "price": None,
        "volume": buy_unmatched,
        "kind": "unmatched",
    }
    sell2 = {
        "side": "sell",
        "level": 2,
        "price": None,
        "volume": sell_unmatched,
        "kind": "unmatched",
    }
    if imbalance_side == "sell":
        display_levels = [ask1, sell2, bid1]
    elif imbalance_side == "buy":
        display_levels = [bid1, buy2, ask1]
    else:
        display_levels = [bid1, ask1]

    bids = [(auction_price, matched_volume)]
    asks = [(auction_price, matched_volume)]
    if buy_unmatched:
        bids.append((0.0, buy_unmatched))
    if sell_unmatched:
        asks.append((0.0, sell_unmatched))

    return {
        "code": code,
        "market": market,
        "phase": "auction",
        "price": auction_price,
        "auction_price": auction_price,
        "prev_close": round(_depth_float(body, code_pos + 6), 3),
        "open": 0.0,
        "high": 0.0,
        "low": 0.0,
        "volume": matched_volume,
        "matched_volume": matched_volume,
        "buy_unmatched_volume": buy_unmatched,
        "sell_unmatched_volume": sell_unmatched,
        "imbalance_side": imbalance_side,
        "imbalance_volume": imbalance_volume,
        "imbalance_raw": direction_raw,
        "bids": bids,
        "asks": asks,
        "display_levels": display_levels,
        "raw_len": len(body),
        "code_offset": code_pos,
    }


def is_depth_push(body: bytes) -> bool:
    """Return whether ``body`` contains a verified auction or ten-level book."""
    if normalize_stock_depth_push(body) is not None:
        return True
    if not is_stock_depth_envelope(body):
        return False
    located = _find_depth_code(body)
    if located is None:
        return False
    code_pos = located[1]
    return _is_auction_depth_block(body, code_pos) or _is_continuous_depth_block(
        body, code_pos
    )


def _parse_normalized_depth_records(body: bytes) -> list[dict]:
    """Parse every fixed 707-byte row produced by the native-style normalizer."""
    normalized = normalize_stock_depth_push(body)
    if normalized is None:
        return []
    marker = normalized.find(b"hd1.0\x00")
    if marker < 0 or len(normalized) < marker + 16:
        return []
    base = marker + 6
    record_count = struct.unpack_from("<I", normalized, base)[0]
    row_size = struct.unpack_from("<H", normalized, base + 6)[0]
    field_count = struct.unpack_from("<H", normalized, base + 8)[0]
    records_offset = base + 10 + field_count * 4
    if row_size != 707 or records_offset + record_count * row_size > len(normalized):
        return []

    parsed: list[dict] = []
    pair_offsets = [
        *range(95, 143, 8),
        *range(155, 187, 8),
        *range(279, 359, 8),
    ]
    for record_index in range(record_count):
        start = records_offset + record_index * row_size
        row = normalized[start : start + row_size]
        market_flag = row[0]
        code_raw = row[1:7]
        if market_flag not in _DEPTH_PUSH_MARKETS or not code_raw.isdigit():
            continue
        code = code_raw.decode("ascii")
        market = _DEPTH_PUSH_MARKETS[market_flag]

        current_price = _depth_float(row, 63)
        bid_price = _depth_float(row, 95)
        ask_price = _depth_float(row, 119)
        auction_price = current_price or bid_price
        bid_matched = _depth_u32(row, 99)
        ask_matched = _depth_u32(row, 123)
        if (
            auction_price > 0
            and all(_depth_float(row, offset) == 0 for offset in (51, 55, 59))
            and bid_price == auction_price
            and ask_price == auction_price
            and bid_matched == ask_matched
        ):
            buy_unmatched = _depth_u32(row, 107)
            sell_unmatched = _depth_u32(row, 131)
            if buy_unmatched in (0x80000000, 0xFFFFFFFF):
                buy_unmatched = 0
            if sell_unmatched in (0x80000000, 0xFFFFFFFF):
                sell_unmatched = 0
            direction_raw = (
                (_AUCTION_IMBALANCE_SELL | sell_unmatched)
                if sell_unmatched
                else buy_unmatched
            )
            encoded_volume = direction_raw & _AUCTION_IMBALANCE_MASK
            encoded_side = (
                "sell" if direction_raw & _AUCTION_IMBALANCE_SELL else "buy"
            )
            if encoded_volume:
                if encoded_side == "sell" and not sell_unmatched:
                    sell_unmatched = encoded_volume
                elif encoded_side == "buy" and not buy_unmatched:
                    buy_unmatched = encoded_volume
            imbalance_side = (
                "sell" if sell_unmatched else "buy" if buy_unmatched else None
            )
            imbalance_volume = sell_unmatched or buy_unmatched
            price = round(auction_price, 3)
            bid1 = {
                "side": "buy", "level": 1, "price": price,
                "volume": bid_matched, "kind": "matched",
            }
            ask1 = {
                "side": "sell", "level": 1, "price": price,
                "volume": bid_matched, "kind": "matched",
            }
            buy2 = {
                "side": "buy", "level": 2, "price": None,
                "volume": buy_unmatched, "kind": "unmatched",
            }
            sell2 = {
                "side": "sell", "level": 2, "price": None,
                "volume": sell_unmatched, "kind": "unmatched",
            }
            display_levels = (
                [ask1, sell2, bid1]
                if imbalance_side == "sell"
                else [bid1, buy2, ask1]
                if imbalance_side == "buy"
                else [bid1, ask1]
            )
            bids = [(price, bid_matched)]
            asks = [(price, bid_matched)]
            if buy_unmatched:
                bids.append((0.0, buy_unmatched))
            if sell_unmatched:
                asks.append((0.0, sell_unmatched))
            result = {
                "code": code,
                "market": market,
                "phase": "auction",
                "price": price,
                "auction_price": price,
                "prev_close": round(_depth_float(row, 47), 3),
                "open": 0.0,
                "high": 0.0,
                "low": 0.0,
                "volume": bid_matched,
                "matched_volume": bid_matched,
                "buy_unmatched_volume": buy_unmatched,
                "sell_unmatched_volume": sell_unmatched,
                "imbalance_side": imbalance_side,
                "imbalance_volume": imbalance_volume,
                "imbalance_raw": direction_raw,
                "bids": bids,
                "asks": asks,
                "display_levels": display_levels,
            }
        else:
            pairs = [
                (round(_depth_float(row, offset), 3), _depth_u32(row, offset + 4))
                for offset in pair_offsets
            ]
            result = {
                "code": code,
                "market": market,
                "phase": "continuous",
                "price": current_price,
                "prev_close": _depth_float(row, 47),
                "open": _depth_float(row, 51),
                "high": _depth_float(row, 55),
                "low": _depth_float(row, 59),
                "bids": [pairs[index] for index in [0, 1, 2, 6, 8, 10, 12, 14, 16, 18]],
                "asks": [pairs[index] for index in [3, 4, 5, 7, 9, 11, 13, 15, 17, 19]],
            }
        result.update(
            {
                "raw_len": len(body),
                "code_offset": None,
                "batch_index": record_index,
                "batch_size": record_count,
                "normalized": True,
            }
        )
        parsed.append(result)
    return parsed


def parse_depth_push_records(body: bytes) -> list[dict]:
    """Parse all stock records carried by one depth-push envelope."""
    records = _parse_normalized_depth_records(body)
    if records:
        return records
    parsed = parse_depth_push(body)
    return [parsed] if parsed is not None else []


def parse_depth_push(body: bytes) -> dict | None:
    """Parse a verified auction book or complete ten-level depth push.

    2026-08-07 盘中破译（002384 东山精密 ~200 元对照确认）。
    含完整十档买卖价量 + 昨收/开盘/最高/最低/现价。
    """
    normalized_records = _parse_normalized_depth_records(body)
    if normalized_records:
        return normalized_records[0]

    if not is_depth_push(body):
        return None

    auction = parse_auction_depth_push(body)
    if auction is not None:
        return auction

    located = _find_depth_code(body)
    if located is None:
        return None
    market_pos, code_pos, code = located
    market = _DEPTH_PUSH_MARKETS[body[market_pos]]
    shift = code_pos - 45
    if len(body) < shift + 267:
        return None

    def _f(off):
        return _depth_float(body, shift + off)

    def _u32(off):
        return _depth_u32(body, shift + off)

    # 十档：价量对，4B gap 后再继续
    def _pair(off):
        return round(_f(off), 3), _u32(off + 4)

    # 前 3 档买卖 (6对 @95-142)
    pairs = []
    off = 95
    for _ in range(6):
        pairs.append(_pair(off))
        off += 8
    off += 4  # 4B 间隔 @143
    # 买4 卖4 买5 卖5 (4对 @147-178)
    for _ in range(4):
        pairs.append(_pair(off))
        off += 8
    off += 16  # 16B 间隔块 @179-194
    # 买6-买10 卖6-卖10 (10对 @195-266)
    for _ in range(10):
        if off + 8 > len(body):
            break
        pairs.append(_pair(off))
        off += 8

    return {
        "code": code,
        "market": market,
        "phase": "continuous",
        "price": _f(67),       # 现价
        "prev_close": _f(51),  # 昨收
        "open": _f(55),        # 开盘
        "high": _f(59),        # 最高
        "low": _f(63),         # 最低
        # 十档：买1-买5 价/量, 卖1-卖5 价/量, 买6-买10, 卖6-卖10
        # pairs 顺序: 买1买2买3卖1卖2卖3 买4卖4买5卖5 买6卖6买7卖7买8卖8买9卖9买10卖10
        "bids": [pairs[i] for i in [0, 1, 2, 6, 8, 10, 12, 14, 16, 18] if i < len(pairs)],
        "asks": [pairs[i] for i in [3, 4, 5, 7, 9, 11, 13, 15, 17, 19] if i < len(pairs)],
        "raw_len": len(body),
        "code_offset": code_pos,
    }


__all__ = [
    "MARKET_SNAPSHOT_DATATYPE",
    "MARKET_SNAPSHOT_MARKETS",
    "SNAPSHOT_DATATYPE",
    "SNAPSHOT_PAGEID",
    "SNAPSHOT_PAGEID_SUB",
    "SNAPSHOT_SUBTYPE",
    "build_market_snapshot_query",
    "build_snapshot_subscribe",
    "is_order_cancel_push",
    "is_order_cancel_batch_push",
    "is_order_queue_push",
    "is_auction_cancel_push",
    "is_trade_tick_push",
    "is_trade_tick_batch_push",
    "is_snapshot_push",
    "parse_order_cancel_push",
    "parse_order_cancel_batch_push",
    "parse_order_cancel_records",
    "parse_order_queue_push",
    "parse_auction_cancel_push",
    "parse_trade_tick_push",
    "parse_trade_tick_batch_push",
    "parse_snapshot_push",
    "is_stock_depth_envelope",
    "is_auction_depth_push",
    "parse_auction_depth_push",
    "is_depth_push",
    "parse_depth_push",
    "parse_depth_push_records",
]
