"""Quote workflows composed from MAIN transport and pure protocol functions."""
from __future__ import annotations

import logging
import struct
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
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


def _repair_short_record(sock, body: bytes) -> bytes:
    """服务端 hd1.0 响应帧体比记录区少 1 字节（末记录末字节落在帧外）。

    2026-08-03 活网实测：十档盘口帧（dc=1/hs=191 但记录区 190B）与
    list_quotes hd1.0 单码/双码帧（dc=1~2，记录区比 dc*hs 少 1B）都存在
    此怪癖；缺失的 1 字节（末记录末字节）随后到达 socket。读取它补回 body，
    避免最后记录/档位丢失。
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
    if len(body) - field_end != dc * hs - 1:
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
        frame = build_list_quote_query(
            codes,
            market=market,
            datatype=datatype,
            pageid=pageid,
        )
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )

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
        frame = build_depth_quote_query(
            code,
            market=market,
        )
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )

        saw_depth_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is None:
                        continue
                    try:
                        recv(8192)
                    except OSError as exc:
                        raise ConnectionError("连接已关闭") from exc
                    continue
                response = _repair_short_record(sock, response)
                result = parse_depth_quote_response(response)
                if result:
                    if self._evidence is not None:
                        self._evidence.record_main_ready()
                    return result
                if b"hd1.0" in response:
                    saw_depth_frame = True

        if saw_depth_frame:
            raise ProtocolError("收到五档盘口帧但无法解析")
        return {}

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
        saw_depth_frame = False
        with connection.request(frame, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                response = self._read_frame(sock)
                response = _repair_short_record(sock, response)
                result = parse_depth_quote_response(response)
                if result:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_SNAPSHOT_PUSH,
                            Support.YES,
                        )
                    return result
                if b"hd1.0" in response:
                    saw_depth_frame = True
        if saw_depth_frame:
            raise ProtocolError("收到十档盘口帧但无法解析")
        return {}


def _depth_l2_role(market: int) -> ConnectionRole:
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"十档盘口暂不支持市场码: {market}")
