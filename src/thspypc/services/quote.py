"""Quote workflows composed from MAIN transport and pure protocol functions."""
from __future__ import annotations

import logging
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..codecs.hd import parse_hd1_response, parse_hd3_response
from ..errors import ProtocolError
from ..features.quote_protocol import (
    LIST_QUOTE_DATATYPE_DEFAULT,
    build_depth_quote_query,
    build_list_quote_query,
    parse_depth_quote_response,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..models import Capability, DepthQuote


logger = logging.getLogger(__name__)
FrameReader = Callable[[SocketLike], bytes]


class QuoteService:
    """Run basic quote requests on the account's MAIN connection."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence

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
    ) -> DepthQuote:
        frame = build_depth_quote_query(code, market=market)
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
