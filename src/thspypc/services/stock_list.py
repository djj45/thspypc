"""Stock-list workflows over the MAIN market connection."""
from __future__ import annotations

import socket
import time
from collections.abc import Callable
from importlib import resources

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import ProtocolError
from ..features.account_profile import AccountEvidenceRecorder
from ..features.stock_list_protocol import (
    build_stock_list_query,
    parse_init_response,
    parse_stock_list_replay,
    parse_stock_list_response,
)
from ..models import Capability


FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]
Sleep = Callable[[float], None]


class StockListService:
    """Fetch server-ranked stock-list pages using only MAIN."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        max_full_frames: int = 1024,
        evidence: AccountEvidenceRecorder | None = None,
        replay_segments: tuple[bytes, ...] | None = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._max_full_frames = max_full_frames
        self._evidence = evidence
        self._replay_segments = replay_segments
        self._clock = clock
        self._sleep = sleep

    def _get_replay_segments(self) -> tuple[bytes, ...]:
        if self._replay_segments is not None:
            return self._replay_segments
        data = (
            resources.files("thspypc")
            .joinpath("data", "stock_list_replay.bin")
            .read_bytes()
        )
        self._replay_segments = parse_stock_list_replay(data)
        return self._replay_segments

    def ranked(
        self,
        *,
        count: int = 29,
        timeout: float = 10.0,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """Fetch and de-duplicate ranked pages up to ``count`` records."""
        if count <= 0 or max_pages <= 0:
            return []

        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        stocks: list[dict] = []
        seen_codes: set[str] = set()
        sort_total = 0
        sort_begin = 0

        for _page in range(max_pages):
            request = build_stock_list_query(
                markets=(17, 22, 151),
                sort_begin=sort_begin,
                sort_count=59,
                datatype=[sort_by],
                sort_by=sort_by,
                sort_dir=sort_dir,
            )
            response = None
            try:
                with connection.request(
                    request,
                    timeout=timeout,
                ) as sock:
                    for _ in range(self._max_frames):
                        candidate = self._read_frame(sock)
                        if b"SortTotal" in candidate:
                            response = candidate
                            break
            except (socket.timeout, OSError):
                return stocks

            if response is None:
                break
            metadata = parse_stock_list_response(response)
            if not sort_total:
                sort_total = metadata["sort_total"]
            page_stocks = metadata["stocks"]
            data_count = metadata["sort_data_count"]
            if data_count > 0 and not page_stocks:
                raise ProtocolError(
                    "received stock-list data metadata but parsing failed"
                )

            for stock in page_stocks:
                code = stock.get("code", "")
                if code and code not in seen_codes:
                    seen_codes.add(code)
                    stocks.append(stock)

            if self._evidence is not None and page_stocks:
                self._evidence.record_main_ready()
            if (
                len(stocks) >= count
                or data_count == 0
                or (sort_total > 0 and len(stocks) >= sort_total)
            ):
                break
            sort_begin = len(stocks)

        return stocks

    def full_list(
        self,
        *,
        timeout: float = 30.0,
        replay_delay: float = 0.3,
        settle_timeout: float = 3.0,
    ) -> list[dict]:
        """Replay the captured startup sequence and select the largest table."""
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        try:
            segments = self._get_replay_segments()
        except (OSError, ValueError) as exc:
            raise ProtocolError(
                f"stock-list replay resource is invalid: {exc}"
            ) from exc
        if not segments:
            raise ProtocolError("stock-list replay resource is empty")

        best_stocks: list[dict] = []
        started_at = self._clock()
        full_table_at: float | None = None
        request_timeout = min(2.0, max(timeout, 0.1))
        with connection.request(
            segments[0],
            timeout=request_timeout,
            trailing_newline=False,
        ) as sock:
            self._sleep(replay_delay)
            for segment in segments[1:]:
                sock.sendall(segment)
                self._sleep(replay_delay)

            for _ in range(self._max_full_frames):
                now = self._clock()
                if (
                    full_table_at is not None
                    and now - full_table_at >= settle_timeout
                ):
                    break
                if (
                    full_table_at is None
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

                metadata = parse_init_response(response)
                stocks = metadata["stocks"]
                full_frames = [
                    frame
                    for frame in metadata["hd31_frames"]
                    if frame["unk"] == 0x18 and frame["dc"] > 5000
                ]
                if full_frames and not stocks:
                    raise ProtocolError(
                        "received full stock table but parsing failed"
                    )
                if len(stocks) > len(best_stocks):
                    best_stocks = stocks
                if full_frames:
                    full_table_at = self._clock()

        if self._evidence is not None and best_stocks:
            self._evidence.record_main_ready()
        return best_stocks


__all__ = ["StockListService"]
