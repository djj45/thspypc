"""Quote workflows composed from MAIN transport and pure protocol functions."""
from __future__ import annotations

import logging
import socket
import struct
import time
from collections.abc import Callable

from .._transport import (
    ConnectionManager,
    ConnectionRole,
    DispatchDecision,
    DispatchRequest,
    SocketLike,
)
from ..codecs.framing import read_frame
from ..codecs.hd import parse_hd1_response, parse_hd3_response
from ..errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.quote_protocol import (
    LIST_QUOTE_DATATYPE_DEFAULT,
    build_depth_quote_query,
    build_depth_ten_query,
    build_list_quote_query,
    parse_depth_quote_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..models import AccountKind, Capability, DepthQuote, Support
from .subscription import L2SubscriptionCoordinator


logger = logging.getLogger(__name__)
FrameReader = Callable[[SocketLike], bytes]

# The compact list quote is sufficient for rankings, but the stock header also
# displays today's high/low and turnover.  Keep those fields scoped to the
# single-stock first-paint pipeline so bulk quote payloads do not grow.
MARKET_VIEW_QUOTE_DATATYPE = [
    *LIST_QUOTE_DATATYPE_DEFAULT,
    8,
    9,
    19,
]


def _hd_field_ids(body: bytes) -> set[int]:
    """Return the hd field ids without touching the socket or record bytes."""
    marker = body.find(b"hd1.0")
    if marker < 0:
        marker = body.find(b"hd3.1")
    if marker < 0:
        return set()
    base = marker + 6
    if base + 10 > len(body):
        return set()
    field_count = struct.unpack("<H", body[base + 8 : base + 10])[0]
    table_start = base + 10
    table_end = table_start + field_count * 4
    if not 0 < field_count < 256 or table_end > len(body):
        return set()
    return {
        body[table_start + index * 4]
        for index in range(field_count)
    }


def _repair_short_record(
    sock,
    body: bytes,
    *,
    record_prefix_size: int = 0,
) -> bytes:
    """服务端 hd1.0 响应帧体比记录区少 1 字节（末记录末字节落在帧外）。

    2026-08-03 活网实测：十档盘口帧（dc=1/hs=191 但记录区 190B）与
    list_quotes hd1.0 单码/双码帧（dc=1~2，记录区比 dc*hs 少 1B）都存在
    此怪癖；缺失的 1 字节（末记录末字节）随后到达 socket。读取它补回 body，
    避免最后记录/档位丢失。``record_prefix_size`` 用于 K 线等在字段表与记录区
    之间带固定股票壳的 hd1.0 变体。
    """
    pos = body.find(b"hd1.0")
    if pos < 0:
        return body
    base = pos + 6
    if base + 10 > len(body):
        return body
    hs = struct.unpack("<H", body[base + 6:base + 8])[0]
    fc = struct.unpack("<H", body[base + 8:base + 10])[0]
    field_end = base + 10 + fc * 4
    dc = struct.unpack("<I", body[base:base + 4])[0]
    records_start = field_end + record_prefix_size
    if len(body) - records_start != dc * hs - 1:
        return body
    try:
        sock.settimeout(1.0)
        tail = sock.recv(1)
    except OSError:
        return body
    return body + tail if tail else body


class QuoteService:
    """Run basic quote requests on MAIN, and Level2 十档 on the per-market L2 connection."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        evidence: AccountEvidenceRecorder | None = None,
        subscriptions: L2SubscriptionCoordinator | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
        self._subscriptions = (
            subscriptions
            or L2SubscriptionCoordinator(frame_reader=frame_reader)
        )

    def _basic_role(
        self,
        market: int,
    ) -> tuple[ConnectionRole, Capability | None]:
        """MAIN 基础行情通道；北交所（151）Level2 账号改走沪 L2。

        2026-08-15 抓包确认：Level2 客户端在 shlv2 连接上用 pageid=1334
        查询 920083 的报价/五档，MAIN（尤其 ifindhq 节点）不返回北交所。
        """
        if (
            market == 151
            and self._connections.profile.kind is AccountKind.LEVEL2
        ):
            return ConnectionRole.SH_L2, Capability.L2_MARKET_ACCESS
        return ConnectionRole.MAIN, Capability.BASIC_QUOTE

    def list_quotes(
        self,
        codes: list[str],
        *,
        market: int = 17,
        datatype: list[int] | None = None,
        pageid: int = 1335,
        timeout: float = 15.0,
    ) -> list[dict]:
        if datatype is None:
            datatype = LIST_QUOTE_DATATYPE_DEFAULT
        role, capability = self._basic_role(market)
        if role is ConnectionRole.SH_L2:
            # Level2 北交所报价走 shlv2 pageid=1334（与真实客户端一致）
            pageid = 1334
        frame = build_list_quote_query(
            codes,
            market=market,
            datatype=datatype,
            pageid=pageid,
        )
        connection = self._connections.acquire(
            role,
            capability=capability,
        )

        # The default one-stock quote shape has fields which cannot be
        # confused with the depth table.  Route this hot path through the
        # connection dispatcher so an independently issued depth request may
        # be in flight at the same time.  Custom field sets retain the legacy
        # synchronous reader until their response signatures are proven.
        if len(codes) == 1 and datatype == LIST_QUOTE_DATATYPE_DEFAULT:
            code = codes[0]
            quote_only_fields = {
                "dt6", "dt7", "dt17", "dt48", "dt49", "dt66", "dt1111"
            }
            quote_only_field_ids = {6, 7, 17, 48, 49, 66, 1111 & 0xFF}

            def consume(response: bytes, sock) -> DispatchDecision:
                if b"hd1.0" not in response and b"hd3.1\x00" not in response:
                    return DispatchDecision(False)
                field_ids = _hd_field_ids(response)
                if field_ids:
                    if not quote_only_field_ids.intersection(field_ids):
                        return DispatchDecision(False)
                    response = _repair_short_record(sock, response)
                records = (
                    parse_hd3_response(response)
                    if b"hd3.1\x00" in response
                    else parse_hd1_response(response)
                )
                if not records:
                    raise ProtocolError("收到行情数据帧但无法解析")
                if records and not any(
                    row.get("code") == code
                    and quote_only_fields.intersection(row)
                    for row in records
                ):
                    if field_ids:
                        return DispatchDecision(False)
                return DispatchDecision(True, True, records)

            records = connection.dispatch(
                [
                    DispatchRequest(
                        frame,
                        consume,
                        name=f"quote:{code}",
                        fallback=[],
                    )
                ],
                frame_reader=self._read_frame,
                timeout=timeout,
                max_frames=self._max_frames,
            )[0]
            if self._evidence is not None:
                self._evidence.record_main_ready()
            return records

        saw_data_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                # 服务端偶发帧体比 hs*dc 少 1 字节（末记录末字节落在帧外、
                # 随后来到 socket）：先补读再解析，否则单码/双码 hd1.0 会因
                # 记录区不足返回空并超时（与十档盘口同型，2026-08-03 实测）。
                response = _repair_short_record(sock, response)
                if b"hd3.1\x00" in response:
                    saw_data_frame = True
                    records = parse_hd3_response(response)
                    if records:
                        if self._evidence is not None:
                            self._evidence.record_main_ready()
                        return records
                elif b"hd1.0" in response:
                    saw_data_frame = True
                    records = parse_hd1_response(response)
                    if records:
                        if self._evidence is not None:
                            self._evidence.record_main_ready()
                        return records

        if saw_data_frame:
            raise ProtocolError("收到行情数据帧但无法解析")
        return []

    def market_view_pipeline(
        self,
        code: str,
        *,
        market: int,
        timeout: float = 12.0,
    ) -> tuple[dict | None, DepthQuote]:
        """Fetch one-stock quote and five-level depth in one MAIN flight.

        Both requests are written before the first response is read.  This is
        the bounded first-paint pipeline used by the web UI: one caller owns
        the socket for the whole bundle, so unrelated responses cannot be
        consumed by competing service methods.
        """
        role, capability = self._basic_role(market)
        quote_pageid = 1334 if role is ConnectionRole.SH_L2 else 1335
        depth_pageid = 1334 if role is ConnectionRole.SH_L2 else 1333
        quote_frame = build_list_quote_query(
            [code],
            market=market,
            datatype=MARKET_VIEW_QUOTE_DATATYPE,
            pageid=quote_pageid,
        )
        depth_frame = build_depth_quote_query(
            code,
            market=market,
            pageid=depth_pageid,
        )
        connection = self._connections.acquire(
            role,
            capability=capability,
        )

        quote: dict | None = None
        depth: DepthQuote = {}
        # Fields which distinguish the compact quote table from the depth
        # table.  Both tables contain dt10, so price alone is not sufficient.
        quote_only_fields = {
            "dt6", "dt7", "dt17", "dt48", "dt49", "dt66", "dt1111"
        }
        quote_only_field_ids = {6, 7, 17, 48, 49, 66, 1111 & 0xFF}

        def consume_quote(response: bytes, sock) -> DispatchDecision:
            if b"hd1.0" not in response and b"hd3.1\x00" not in response:
                return DispatchDecision(False)
            if not quote_only_field_ids.intersection(_hd_field_ids(response)):
                return DispatchDecision(False)
            response = _repair_short_record(sock, response)
            records = (
                parse_hd3_response(response)
                if b"hd3.1\x00" in response
                else parse_hd1_response(response)
            )
            candidate = next(
                (
                    row
                    for row in records
                    if row.get("code") == code
                    and quote_only_fields.intersection(row)
                ),
                None,
            )
            return (
                DispatchDecision(True, True, candidate)
                if candidate is not None
                else DispatchDecision(False)
            )

        def consume_depth(response: bytes, sock) -> DispatchDecision:
            if 24 not in _hd_field_ids(response):
                return DispatchDecision(False)
            response = _repair_short_record(sock, response)
            candidate = parse_depth_quote_response(response)
            return (
                DispatchDecision(True, True, candidate)
                if candidate and candidate.get("code") == code
                else DispatchDecision(False)
            )

        quote, depth = connection.dispatch(
            [
                DispatchRequest(quote_frame, consume_quote, name="quote"),
                DispatchRequest(depth_frame, consume_depth, name="depth"),
            ],
            frame_reader=self._read_frame,
            timeout=timeout,
            max_frames=self._max_frames * 2,
        )

        if self._evidence is not None and (quote is not None or depth):
            self._evidence.record_main_ready()
        return quote, depth

    def depth_quote(
        self,
        code: str,
        *,
        market: int,
        timeout: float = 12.0,
        ten_levels: bool = False,
    ) -> DepthQuote:
        if ten_levels:
            return self._depth_ten(code, market=market, timeout=timeout)
        role, capability = self._basic_role(market)
        depth_pageid = 1334 if role is ConnectionRole.SH_L2 else 1333
        frame = build_depth_quote_query(
            code,
            market=market,
            pageid=depth_pageid,
        )
        connection = self._connections.acquire(
            role,
            capability=capability,
        )

        def consume(response: bytes, sock) -> DispatchDecision:
            field_ids = _hd_field_ids(response)
            if field_ids:
                if 24 not in field_ids:
                    return DispatchDecision(False)
                response = _repair_short_record(sock, response)
            elif b"hd1.0" not in response:
                return DispatchDecision(False)
            result = parse_depth_quote_response(response)
            if not result:
                raise ProtocolError("收到五档盘口帧但无法解析")
            if result and result.get("code") not in (None, "", code):
                return DispatchDecision(False)
            return DispatchDecision(True, True, result)

        result = connection.dispatch(
            [
                DispatchRequest(
                    frame,
                    consume,
                    name=f"depth:{code}",
                    fallback={},
                )
            ],
            frame_reader=self._read_frame,
            timeout=timeout,
            max_frames=self._max_frames,
        )[0]
        if self._evidence is not None:
            self._evidence.record_main_ready()
        return result

    def _depth_ten(
        self,
        code: str,
        *,
        market: int,
        timeout: float = 12.0,
    ) -> DepthQuote:
        """Level2 十档：走对应市场 L2 连接（沪 shlv2 / 深 szlv2），先 4214 注册。"""
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_SNAPSHOT_PUSH,
                "depth_quote:ten_levels",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "depth_quote:ten_levels",
                profile.kind,
                "账号类型未知，不能推断 L2 十档通道",
            )
        role = _depth_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_SNAPSHOT_PUSH,
        )
        self._subscriptions.ensure_registered(
            connection,
            code,
            market=market,
            timeout=min(timeout, 5.0),
        )
        frame = build_depth_ten_query(code, market=market)
        deadline = time.monotonic() + timeout
        unsolicited_count = 0
        with connection.request(frame, timeout=timeout) as sock:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "depth response timed out after "
                        f"{unsolicited_count} unsolicited frames"
                    )
                sock.settimeout(remaining)
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    raise TimeoutError(
                        "depth response timed out after "
                        f"{unsolicited_count} unsolicited frames"
                    ) from None
                response = _repair_short_record(sock, response)
                result = parse_depth_quote_response(response)
                if result:
                    if result.get("code") not in (None, "", code):
                        unsolicited_count += 1
                        self._subscriptions.deliver_unsolicited(response)
                        continue
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_SNAPSHOT_PUSH,
                            Support.YES,
                        )
                    return result
                unsolicited_count += 1
                self._subscriptions.deliver_unsolicited(response)


def _depth_l2_role(market: int) -> ConnectionRole:
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"十档盘口暂不支持市场码: {market}")
