"""Stock-list workflows over the MAIN market connection."""
from __future__ import annotations

import socket
import struct
import threading
import time
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import ProtocolError
from ..features.account_profile import AccountEvidenceRecorder
from ..features.stock_list_protocol import (
    DDE_LEVEL2_MARKETS,
    DDE_STANDARD_MARKETS,
    build_dde_query,
    build_full_stock_list_query,
    build_stock_list_query,
    parse_dde_response,
    parse_init_response,
    parse_stock_list_response,
    strip_to_identity,
)
from ..models import AccountKind, Capability, Support


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
        self._dde_sequence = 0x6000
        self._dde_sequence_lock = threading.Lock()

    def _next_dde_sequence(self) -> int:
        with self._dde_sequence_lock:
            self._dde_sequence = (self._dde_sequence + 1) & 0xFFFF
            if self._dde_sequence == 0:
                self._dde_sequence = 1
            return self._dde_sequence

    def _get_request_segments(self) -> tuple[bytes, ...]:
        if self._replay_segments is not None:
            return self._replay_segments
        return (build_full_stock_list_query(),)

    def ranked(
        self,
        *,
        count: int = 29,
        timeout: float = 10.0,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
        with_values: bool = False,
    ) -> list[dict]:
        """Fetch and de-duplicate ranked pages up to ``count`` records.

        ``with_values=False``(默认)只返回 ``code/name/market``,与历史行为一致。
        ``with_values=True`` 保留响应里的全部 ``dt<N>`` 字段(排序值、行情字段),
        供调用方拿到封单额(dt<响应字段>)、涨幅等数值,不必再走 list_quotes 回填。
        """
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

        return stocks if with_values else strip_to_identity(stocks)

    def dde_ranked(
        self,
        *,
        count: int = 58,
        timeout: float = 10.0,
        sort_by: int = 592888,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """Fetch the pageid=10723 DDE table for standard or Level2 accounts."""
        if count <= 0 or max_pages <= 0:
            return []
        direction = sort_dir.upper()
        if direction not in {"A", "D"}:
            raise ValueError("sort_dir must be 'A' or 'D'")

        if self._connections.profile.kind is AccountKind.LEVEL2:
            page_count = max(58, count)
            pages = [
                self._dde_page(
                    role=role,
                    markets=markets,
                    count=page_count,
                    begin=0,
                    sort_by=sort_by,
                    sort_dir=direction,
                    timeout=timeout,
                    level2=True,
                    capability=Capability.L2_MARKET_ACCESS,
                )
                for role, markets in (
                    (ConnectionRole.SH_L2, DDE_LEVEL2_MARKETS[0]),
                    (ConnectionRole.SZ_L2, DDE_LEVEL2_MARKETS[1]),
                )
            ]
            rows = _merge_dde_rows(
                [row for page in pages for row in page["rows"]],
                sort_dir=direction,
            )
            if self._evidence is not None and rows:
                self._evidence.record_l2_init(Support.YES)
            return rows[:count]

        rows: list[dict] = []
        seen_codes: set[str] = set()
        begin = 0
        total = 0
        for _page in range(max_pages):
            page = self._dde_page(
                role=ConnectionRole.MAIN,
                markets=DDE_STANDARD_MARKETS,
                count=58,
                begin=begin,
                sort_by=sort_by,
                sort_dir=direction,
                timeout=timeout,
                level2=False,
                capability=Capability.BASIC_QUOTE,
            )
            if not total:
                total = page["sort_total"]
            for row in page["rows"]:
                code = row["code"]
                if code not in seen_codes:
                    seen_codes.add(code)
                    rows.append(row)
            data_count = page["sort_data_count"]
            if len(rows) >= count or data_count == 0:
                break
            if total and begin + data_count >= total:
                break
            begin += data_count

        if self._evidence is not None and rows:
            self._evidence.record_main_ready()
        return rows[:count]

    def _dde_page(
        self,
        *,
        role: ConnectionRole,
        markets: tuple[int, ...],
        count: int,
        begin: int,
        sort_by: int,
        sort_dir: str,
        timeout: float,
        level2: bool,
        capability: Capability,
    ) -> dict:
        connection = self._connections.acquire(role, capability=capability)
        sequence = self._next_dde_sequence()
        request = build_dde_query(
            markets=markets,
            sort_by=sort_by,
            sort_dir=sort_dir,
            sort_begin=begin,
            sort_count=count,
            level2=level2,
            seq=sequence,
        )
        saw_data = False
        with connection.request(request, timeout=timeout) as sock:
            # Fresh L2 connections can still have a burst of initialization
            # responses queued ahead of this request.  Sequence matching keeps
            # them safe to skip, while the larger bound prevents a valid DDE
            # response from being abandoned after the legacy eight-frame cap.
            for _ in range(max(self._max_frames, 64)):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    break
                if (
                    len(response) < 7
                    or struct.unpack_from("<H", response, 5)[0] != sequence
                ):
                    continue
                if b"SortTotal" not in response:
                    continue
                page = parse_dde_response(response, sort_by=sort_by)
                if page["sort_data_count"] == 0:
                    return page
                saw_data = True
                if page["rows"] and page["has_value_field"]:
                    if level2 and sort_by == 592888:
                        for row in page["rows"]:
                            value = row.get("value")
                            if value is not None:
                                row["value"] = value / 100_000_000
                    return page
        if saw_data:
            raise ProtocolError("received DDE ranking data but parsing failed")
        raise ProtocolError("DDE ranking response timed out")

    def full_list(
        self,
        *,
        timeout: float = 30.0,
        replay_delay: float = 0.3,
        settle_timeout: float = 3.0,
    ) -> list[dict]:
        """Request all configured markets and select the largest table."""
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        generated_request = self._replay_segments is None
        try:
            segments = self._get_request_segments()
        except (OSError, ValueError) as exc:
            raise ProtocolError(
                f"stock-list request sequence is invalid: {exc}"
            ) from exc
        if not segments:
            raise ProtocolError("stock-list request sequence is empty")

        best_stocks: list[dict] = []
        started_at = self._clock()
        full_table_at: float | None = None
        request_timeout = min(2.0, max(timeout, 0.1))
        with connection.request(
            segments[0],
            timeout=request_timeout,
            trailing_newline=generated_request,
        ) as sock:
            for index, segment in enumerate(segments[1:]):
                if index == 0:
                    self._sleep(replay_delay)
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


def _merge_dde_rows(rows: list[dict], *, sort_dir: str) -> list[dict]:
    """Globally merge the independently sorted SH and SZ Level2 pages."""
    unique: dict[str, dict] = {}
    for row in rows:
        unique.setdefault(row["code"], row)

    def key(row: dict) -> tuple:
        value = row.get("value")
        if value is None:
            return (1, 0.0, row["code"])
        numeric = float(value)
        return (
            0,
            -numeric if sort_dir == "D" else numeric,
            row["code"],
        )

    return sorted(unique.values(), key=key)


__all__ = ["StockListService"]
