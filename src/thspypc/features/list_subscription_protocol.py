"""Pure pageid list-subscription protocol builders and parsers.

The command byte identifies a subscription bucket (for example ``0x56``),
while the following LE32 value identifies a mode within that bucket.  Only
mode 5 has a payload that unambiguously means a delta; live captures show
modes 0/2/3 recurring as parallel CodeList groups, so they are deliberately
not named set/remove actions here.
This module intentionally contains no socket or authentication code.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping

from ..codecs.compression import normalize_8901_response
from ..codecs.framing import FRAME_MAGIC, encode_frame


LIST_SUBSCRIPTION_PAGEID = 1334
RANKING_LIST_PAGEID = 982
RANKING_LIST_COMMAND = 0x5F
LIST_SUBTYPE_MANAGE = b"\x12\x00\x02\x00"
LIST_SUBTYPE_QUERY = b"\x12\x00\x09\x00"

# 2026-08-19 官方客户端“涨幅排名”首屏的主行情字段集。排序辅助查询
# 527527/1968584 以及 DateTime=8192 的补充字段是独立查询，不混进最小订阅。
RANKING_LIST_DATATYPE = (
    7, 14, 49, 13, 127, 48, 12, 19, 69, 18, 25, 10, 17, 24, 31, 9,
    30, 8, 6, 45, 66, 666, 1719, 1002, 615, 665, 407, 1603, 1566,
    663, 1565, 1005, 402, 1111,
)

LIST_MODE_GROUP_0 = 0
LIST_MODE_QUERY = 1
LIST_MODE_GROUP_2 = 2
LIST_MODE_GROUP_3 = 3
LIST_MODE_CLEAR = 4
LIST_MODE_DELTA = 5

_CODE_LIST_SIZE_RE = re.compile(rb"CodeListSize=(\d+)")


@dataclass(frozen=True)
class ListSubscriptionResponse:
    command: int
    mode_raw: int
    wire_seq: int
    subtype: bytes
    declared_size: int
    payload: bytes
    code_list_size: int | None
    truncated: int = 0


def _validate_command(command: int) -> None:
    if not 0 <= command <= 0xFF:
        raise ValueError(f"command 必须在 0..255: {command!r}")


def _normalize_groups(
    groups: Mapping[int, Iterable[str]],
) -> list[tuple[int, list[str]]]:
    normalized: list[tuple[int, list[str]]] = []
    for market, raw_codes in groups.items():
        if not isinstance(market, int) or market < 0:
            raise ValueError(f"非法市场码: {market!r}")
        codes: list[str] = []
        for raw_code in raw_codes:
            code = str(raw_code).strip()
            if not code or not code.isdigit():
                raise ValueError(f"代码必须为纯数字: {raw_code!r}")
            codes.append(code)
        if codes:
            normalized.append((market, codes))
    return normalized


def _group_value(groups: Mapping[int, Iterable[str]]) -> str:
    normalized = _normalize_groups(groups)
    if not normalized:
        raise ValueError("代码集合不能为空")
    return "".join(
        f"{market}({','.join(codes)},);" for market, codes in normalized
    )


def _child(
    *,
    command: int,
    mode: int,
    subtype: bytes,
    payload: bytes,
    wire_seq: int = 0,
) -> bytes:
    _validate_command(command)
    if len(subtype) != 4:
        raise ValueError(f"subtype 必须为 4B: {subtype!r}")
    if not 0 <= wire_seq <= 0xFFFF:
        raise ValueError(f"wire_seq 必须在 0..65535: {wire_seq!r}")
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, wire_seq)
    header[6:10] = subtype
    header[10] = command
    struct.pack_into("<I", header, 11, mode)
    struct.pack_into("<I", header, 18, len(payload))
    return bytes(header) + payload


def _frame(children: Iterable[bytes]) -> bytes:
    body = b"\x09" + b"".join(children)
    if len(body) == 1:
        raise ValueError("至少需要一个订阅子帧")
    # PC 客户端声明逻辑文本包含末尾 LF，但整个 FDF body 省略最后一个 LF。
    if body.endswith(b"\n"):
        body = body[:-1]
    return encode_frame(body)


def _query_child(
    command: int,
    groups: Mapping[int, Iterable[str]],
    datatype: Iterable[int],
    wire_seq: int,
    pageid: int,
    datetime: str,
    lack_time: str,
) -> bytes:
    datatype_values = [int(value) for value in datatype]
    if not datatype_values:
        raise ValueError("datatype 不能为空")
    datatype_text = ",".join(str(value) for value in datatype_values) + ","
    text = (
        f"CodeList={_group_value(groups)}\r\n"
        f"DataType={datatype_text}\r\n"
        f"DateTime={datetime}\r\n"
        f"LackTime={lack_time}\r\n"
        f"pageid={pageid}\r\n"
    ).encode("ascii")
    return _child(
        command=command,
        mode=LIST_MODE_QUERY,
        subtype=LIST_SUBTYPE_QUERY,
        payload=text,
        wire_seq=wire_seq,
    )


def build_list_subscription_codes(
    command: int,
    groups: Mapping[int, Iterable[str]],
    *,
    mode: int = LIST_MODE_GROUP_0,
    pageid: int = LIST_SUBSCRIPTION_PAGEID,
    query_datatype: Iterable[int] | None = None,
    wire_seq: int = 0,
    query_datetime: str = "0(0-0)",
    query_lack_time: str = "0,0,0,0,0,0,0,0",
) -> bytes:
    """Build a captured CodeList group, optionally bundling its first query.

    Captures currently contain recurring group modes 0, 2 and 3.  Their exact
    product-level meaning is not yet known, so callers must select the mode
    explicitly when they need anything other than the common mode 0.
    """
    if mode not in (LIST_MODE_GROUP_0, LIST_MODE_GROUP_2, LIST_MODE_GROUP_3):
        raise ValueError(f"CodeList mode 必须是 0、2 或 3: {mode!r}")
    text = f"CodeList={_group_value(groups)}\r\npageid={pageid}\r\n".encode("ascii")
    children = [
        _child(
            command=command,
            mode=mode,
            subtype=LIST_SUBTYPE_MANAGE,
            payload=text,
        )
    ]
    if query_datatype is not None:
        children.append(
            _query_child(
                command,
                groups,
                query_datatype,
                wire_seq,
                pageid,
                query_datetime,
                query_lack_time,
            )
        )
    return _frame(children)


def build_list_subscription_delta(
    command: int,
    *,
    add: Mapping[int, Iterable[str]],
    remove: Mapping[int, Iterable[str]],
    pageid: int = LIST_SUBSCRIPTION_PAGEID,
    query_datatype: Iterable[int] | None = None,
    wire_seq: int = 0,
    query_datetime: str = "0(0-0)",
    query_lack_time: str = "0,0,0,0,0,0,0,0",
) -> bytes:
    """Apply AddCode/DelCode in one atomic bucket update."""
    lines: list[str] = []
    if add:
        lines.append(f"AddCode={_group_value(add)}")
    if remove:
        lines.append(f"DelCode={_group_value(remove)}")
    if not lines:
        raise ValueError("add/remove 不能同时为空")
    text = ("\r\n".join(lines) + f"\r\npageid={pageid}\r\n").encode("ascii")
    children = [
        _child(
            command=command,
            mode=LIST_MODE_DELTA,
            subtype=LIST_SUBTYPE_MANAGE,
            payload=text,
        )
    ]
    if query_datatype is not None:
        query_groups = add if add else remove
        children.append(
            _query_child(
                command,
                query_groups,
                query_datatype,
                wire_seq,
                pageid,
                query_datetime,
                query_lack_time,
            )
        )
    return _frame(children)


def build_list_subscription_clear(
    command: int,
    *,
    pageid: int = LIST_SUBSCRIPTION_PAGEID,
) -> bytes:
    """Build the captured empty mode-4 bucket reset."""
    text = f"\r\npageid={pageid}\r\n".encode("ascii")
    return _frame(
        [
            _child(
                command=command,
                mode=LIST_MODE_CLEAR,
                subtype=LIST_SUBTYPE_MANAGE,
                payload=text,
            )
        ]
    )


def build_list_subscription_query(
    command: int,
    groups: Mapping[int, Iterable[str]],
    datatype: Iterable[int],
    *,
    wire_seq: int,
    pageid: int = LIST_SUBSCRIPTION_PAGEID,
    datetime: str = "0(0-0)",
    lack_time: str = "0,0,0,0,0,0,0,0",
) -> bytes:
    """Query fields for the current/new codes using captured mode ``1``."""
    return _frame(
        [
            _query_child(
                command,
                groups,
                datatype,
                wire_seq,
                pageid,
                datetime,
                lack_time,
            )
        ]
    )


def _unwrap_fdf(frame_or_body: bytes) -> bytes:
    if not frame_or_body.startswith(FRAME_MAGIC):
        return frame_or_body
    if len(frame_or_body) < 12:
        raise ValueError("FDF 帧头不完整")
    try:
        size = int(frame_or_body[4:12], 16)
    except ValueError as exc:
        raise ValueError("FDF 长度字段非法") from exc
    body = frame_or_body[12 : 12 + size]
    if len(body) != size:
        raise ValueError("FDF 帧体不完整")
    return body


def parse_list_subscription_response(
    frame_or_body: bytes,
) -> list[ListSubscriptionResponse]:
    """Parse all children from a normal or compressed ``0x0a`` response."""
    body = _unwrap_fdf(frame_or_body)
    if body.startswith(b"\x0a"):
        body = b"\x09" + normalize_8901_response(body)
    if len(body) < 23 or body[0] != 0x09:
        return []
    responses: list[ListSubscriptionResponse] = []
    pos = 1
    while pos + 22 <= len(body) and body[pos : pos + 2] == b"\x00\x16":
        header = body[pos : pos + 22]
        wire_seq = struct.unpack_from("<H", header, 4)[0]
        subtype = header[6:10]
        command = header[10]
        mode_raw = struct.unpack_from("<I", header, 11)[0]
        declared = struct.unpack_from("<I", header, 18)[0]
        data_start = pos + 22
        if data_start + 4 <= len(body):
            # 服务端固定多一个 LE32。ACK 中它等于 declared；数据响应中
            # 它只声明前导状态文本长度，因此不能用相等判断是否剥离。
            data_start += 4
        expected_end = data_start + declared
        payload = body[data_start : min(expected_end, len(body))]
        match = _CODE_LIST_SIZE_RE.search(payload)
        responses.append(
            ListSubscriptionResponse(
                command=command,
                mode_raw=mode_raw,
                wire_seq=wire_seq,
                subtype=subtype,
                declared_size=declared,
                payload=payload,
                code_list_size=int(match.group(1)) if match else None,
                truncated=max(0, expected_end - len(body)),
            )
        )
        if expected_end > len(body):
            break
        pos = expected_end
    return responses


__all__ = [
    "LIST_SUBSCRIPTION_PAGEID",
    "RANKING_LIST_PAGEID",
    "RANKING_LIST_COMMAND",
    "RANKING_LIST_DATATYPE",
    "LIST_SUBTYPE_MANAGE",
    "LIST_SUBTYPE_QUERY",
    "LIST_MODE_GROUP_0",
    "LIST_MODE_QUERY",
    "LIST_MODE_GROUP_2",
    "LIST_MODE_GROUP_3",
    "LIST_MODE_CLEAR",
    "LIST_MODE_DELTA",
    "ListSubscriptionResponse",
    "build_list_subscription_codes",
    "build_list_subscription_delta",
    "build_list_subscription_clear",
    "build_list_subscription_query",
    "parse_list_subscription_response",
]
