"""Capability-gated workflows for the shared 9601 real-order socket."""
from __future__ import annotations

import socket
import time
from collections import deque
from collections.abc import Callable, Iterable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import encode_frame
from ..features.realorder_protocol import (
    SUBREALORDER_MARKETS,
    build_heartbeat_9601,
    build_qurealorder_query,
    build_subrealorder_query,
    decode_realorder_frame,
    parse_pushrealorder_frame,
    parse_qurealorder_response,
    read_frame_realorder,
)
from ..models import Capability


FrameReader = Callable[[SocketLike], bytes]
InstanceFactory = Callable[[], int]


class RealOrderService:
    """Serialize history, subscription, push reads, and heartbeats on 9601."""

    def __init__(
        self,
        connections: ConnectionManager,
        next_instance: InstanceFactory,
        *,
        frame_reader: FrameReader = read_frame_realorder,
        max_query_frames: int = 8,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connections = connections
        self._next_instance = next_instance
        self._read_frame = frame_reader
        self._max_query_frames = max_query_frames
        self._clock = clock
        self._pending_pushes: deque[dict] = deque()
        self._subscribed_markets: set[int] = set()

    def _connection(self):
        return self._connections.acquire(
            ConnectionRole.REALORDER,
            capability=Capability.REALORDER,
        )

    def dxjl_page(
        self,
        market: int,
        endtime_us: int,
        *,
        maxcount: int = 80,
        datatype: str | None = None,
        timeout: float = 15.0,
    ) -> list[dict]:
        """Query one history page while retaining interleaved pushes."""
        body = build_qurealorder_query(
            self._next_instance(),
            market,
            endtime_us,
            maxcount=maxcount,
            datatype=datatype,
        )
        connection = self._connection()
        with connection.request(
            encode_frame(body),
            timeout=timeout,
        ) as sock:
            for _ in range(self._max_query_frames):
                response = decode_realorder_frame(self._read_frame(sock))
                pushes = parse_pushrealorder_frame(response)
                if pushes:
                    self._pending_pushes.extend(pushes)
                    continue
                if b"hq1.0" in response:
                    return parse_qurealorder_response(response, str(market))
        return []

    def dxjl_latest(
        self,
        *,
        markets: Iterable[int] = (32, 16),
        now_us: int | None = None,
        timeout: float = 15.0,
    ) -> list[dict]:
        """Return the latest page for each requested market."""
        cursor = now_us if now_us is not None else int(time.time() * 1_000_000)
        records = []
        for market in markets:
            records.extend(
                self.dxjl_page(market, cursor, timeout=timeout)
            )
        records.sort(key=lambda record: record["时间"], reverse=True)
        return records

    def dxjl_history(
        self,
        *,
        pages: int = 5,
        markets: Iterable[int] = (32, 16),
        now_us: int | None = None,
        timeout: float = 15.0,
    ) -> list[dict]:
        """Page backwards using the earliest timestamp as the next cursor."""
        cursor = now_us if now_us is not None else int(time.time() * 1_000_000)
        all_records = []
        market_values = tuple(markets)
        for _ in range(pages):
            page_records = []
            for market in market_values:
                page_records.extend(
                    self.dxjl_page(market, cursor, timeout=timeout)
                )
            if not page_records:
                break
            page_records.sort(key=lambda record: record["时间"])
            all_records.extend(page_records)
            cursor = page_records[0]["时间"]
        all_records.sort(key=lambda record: record["时间"], reverse=True)
        return all_records

    def subscribe_realtime(
        self,
        markets: Iterable[int] | None = None,
        *,
        timeout: float = 15.0,
    ) -> None:
        """Register realtime markets without starting a second socket reader."""
        market_values = (
            tuple(SUBREALORDER_MARKETS)
            if markets is None
            else tuple(markets)
        )
        connection = self._connection()
        for market in market_values:
            body = build_subrealorder_query(
                self._next_instance(),
                market,
            )
            with connection.request(
                encode_frame(body),
                timeout=timeout,
            ):
                pass
            self._subscribed_markets.add(market)

    def send_heartbeat(self, seq: int) -> bool:
        """Try a non-blocking heartbeat; busy query/read ownership wins."""
        connection = self._connections.peek(ConnectionRole.REALORDER)
        if connection is None:
            return False
        return connection.try_send(build_heartbeat_9601(seq))

    def observe_unsolicited(self, body: bytes) -> bool:
        """Retain a push consumed while a dispatcher-owned probe is pending."""
        pushes = parse_pushrealorder_frame(body)
        if not pushes:
            return False
        self._pending_pushes.extend(pushes)
        return True

    def receive_pushes(
        self,
        *,
        timeout: float = 10.0,
        callback=None,
        full_frame_callback=None,
        continue_on_timeout: bool = False,
    ) -> tuple[list[dict], int]:
        """Receive pushes under per-frame exclusive ownership."""
        if not self._subscribed_markets:
            raise RuntimeError("9601 未订阅，请先 subscribe_realtime()")
        connection = self._connection()
        records = []
        frame_count = 0

        while self._pending_pushes:
            record = self._pending_pushes.popleft()
            if callback is not None:
                callback(record)
            else:
                records.append(record)

        deadline = self._clock() + timeout
        while self._clock() < deadline:
            remaining = deadline - self._clock()
            if remaining <= 0:
                break
            try:
                with connection.receive(
                    timeout=min(remaining, 2.0),
                ) as sock:
                    response = self._read_frame(sock)
            except socket.timeout:
                if continue_on_timeout:
                    continue
                break
            except OSError:
                break

            pushes = parse_pushrealorder_frame(response)
            if not pushes:
                continue
            frame_count += 1
            if full_frame_callback is not None:
                full_frame_callback(response)
            if callback is not None:
                for record in pushes:
                    callback(record)
            else:
                records.extend(pushes)
        return records, frame_count
