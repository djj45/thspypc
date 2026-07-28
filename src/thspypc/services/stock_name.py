"""Incremental stock-name synchronization over MAIN."""
from __future__ import annotations

import socket
import time
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..features.account_profile import AccountEvidenceRecorder
from ..features.stock_name_protocol import (
    build_upstockname_request,
    decode_name_frame,
)
from ..models import Capability


FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]


def empty_name_result() -> dict:
    return {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }


class StockNameService:
    """Fetch currently available upstockname increments on MAIN."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 256,
        evidence: AccountEvidenceRecorder | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
        self._clock = clock

    def fetch(
        self,
        *,
        market: str = "URS",
        stock_name_ver: str = ";;",
        timeout: float = 10.0,
        settle_timeout: float = 2.0,
    ) -> dict:
        """Send one incremental request and merge recognized response sections."""
        request = build_upstockname_request(market, stock_name_ver)
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        result = empty_name_result()
        started_at = self._clock()
        first_name_at: float | None = None
        request_timeout = min(2.0, max(timeout, 0.1))

        with connection.request(
            request,
            timeout=request_timeout,
            trailing_newline=False,
        ) as sock:
            for _ in range(self._max_frames):
                now = self._clock()
                if (
                    first_name_at is not None
                    and now - first_name_at >= settle_timeout
                ):
                    break
                if (
                    first_name_at is None
                    and now - started_at >= timeout
                ):
                    break
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    continue
                except OSError:
                    break
                except ValueError:
                    continue
                if not response:
                    continue
                if not any(
                    marker in response
                    for marker in (b"[name_", b"upnametype", b"MarketCode")
                ):
                    continue
                if first_name_at is None:
                    first_name_at = self._clock()
                decoded = decode_name_frame(response)
                result["names"].update(decoded["names"])
                result["by_segment"].update(decoded["by_segment"])
                result["skipped"].extend(decoded["skipped"])
                result["segments"].extend(decoded["segments"])

        if self._evidence is not None and result["segments"]:
            self._evidence.record_main_ready()
        return result


__all__ = ["StockNameService", "empty_name_result"]
