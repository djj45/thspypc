"""K-line workflows over the MAIN / L2 market connection."""
from __future__ import annotations

import socket
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import ProtocolError
from ..features.account_profile import AccountEvidenceRecorder
from ..features.kline_protocol import (
    build_kline_l2_query,
    build_kline_query,
    parse_kline_hd3_response,
)
from ..models import AccountKind, Capability


FrameReader = Callable[[SocketLike], bytes]


def _kline_l2_role(market: int) -> ConnectionRole:
    """Level2 K线连接角色（与 timeline/depth 的 L2 角色一致）。"""
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"K线暂不支持市场码: {market}")


class KlineService:
    """Execute one K-line request while holding the connection request lock.

    普通账号走 MAIN + pageid=9355；Level2 账号走 L2 连接 + pageid=1334
    （2026-08-05 抓包对齐，见 ``build_kline_l2_query``）。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 16,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence

    def kline(
        self,
        code: str,
        *,
        market: int,
        period: int,
        count: int = 2146,
        anchor: int = 0,
        fuquan: str = "Q",
        timeout: float = 12.0,
    ) -> list[dict]:
        """Return all K-line data frames belonging to one request."""
        profile = self._connections.profile
        use_l2 = profile.kind is AccountKind.LEVEL2
        if use_l2:
            request = build_kline_l2_query(
                code,
                market=market,
                period=period,
                fuquan=fuquan,
                count=count,
                anchor=anchor,
            )
            connection = self._connections.acquire(
                _kline_l2_role(market),
                capability=Capability.L2_TIMELINE,
            )
        else:
            request = build_kline_query(
                code,
                market=market,
                period=period,
                fuquan=fuquan,
                count=count,
                anchor=anchor,
            )
            connection = self._connections.acquire(
                ConnectionRole.MAIN,
                capability=Capability.BASIC_QUOTE,
            )
        records: list[dict] = []
        saw_kline_frame = False

        with connection.request(request, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    if records:
                        break
                    raise
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("connection closed") from exc
                    if records:
                        break
                    continue

                if b"hd3.1\x00" in response:
                    saw_kline_frame = True
                    parsed = parse_kline_hd3_response(response)
                    if parsed:
                        records.extend(parsed)
                        sock.settimeout(2.0)
                    continue
                if records:
                    break

        if records:
            if self._evidence is not None:
                self._evidence.record_main_ready()
            return records
        if saw_kline_frame:
            raise ProtocolError("received K-line frame but parsing failed")
        return []


__all__ = ["KlineService"]
