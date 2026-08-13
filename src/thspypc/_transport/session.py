"""Single-flight request lifecycle for one socket."""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from ..errors import SupersededError
from .timing import add_request_timing
from .session_types import SocketLike
from .dispatcher import ResponseDispatcher


class MarketSession:
    """Serialize send and response-reading ownership for one connection."""

    def __init__(
        self,
        socket_getter: Callable[[], SocketLike | None],
        request_lock: threading.RLock,
        timing_name: str = "connection",
    ) -> None:
        self._socket_getter = socket_getter
        self._request_lock = request_lock
        self._timing_name = timing_name
        self._dispatcher = ResponseDispatcher(socket_getter)
        self._gate_lock = threading.Lock()
        self._latest_gate = 0

    @contextmanager
    def request(
        self,
        frame: bytes,
        *,
        timeout: float,
        trailing_newline: bool = True,
    ) -> Iterator[SocketLike]:
        waiting_started = time.perf_counter()
        self._request_lock.acquire()
        acquired = time.perf_counter()
        add_request_timing(
            f"{self._timing_name}_wait",
            (acquired - waiting_started) * 1000,
        )
        try:
            self._dispatcher.wait_idle()
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            yield sock
        finally:
            add_request_timing(
                f"{self._timing_name}_io",
                (time.perf_counter() - acquired) * 1000,
            )
            self._request_lock.release()

    @contextmanager
    def request_latest(
        self,
        frame: bytes,
        *,
        gate: int,
        timeout: float,
        trailing_newline: bool = True,
    ) -> Iterator[SocketLike]:
        """Latest-wins request: only the highest ``gate`` issued so far is sent.

        Callers issue monotonically increasing ``gate`` values.  When several
        such requests queue behind the connection lock, any request whose gate
        is lower than the most recently issued one is skipped with
        :class:`~thspypc.errors.SupersededError` before touching the socket; the
        newest request is the one actually sent.  This prevents a busy
        single-socket connection from serially replaying stale requests (e.g.
        rapid stock switching on the shared KLINE_FAST socket).
        """
        with self._gate_lock:
            self._latest_gate = max(self._latest_gate, gate)
        waiting_started = time.perf_counter()
        self._request_lock.acquire()
        acquired = time.perf_counter()
        add_request_timing(
            f"{self._timing_name}_wait",
            (acquired - waiting_started) * 1000,
        )
        try:
            self._dispatcher.wait_idle()
            with self._gate_lock:
                superseded = gate != self._latest_gate
            if superseded:
                raise SupersededError("request superseded by a newer one")
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            yield sock
        finally:
            add_request_timing(
                f"{self._timing_name}_io",
                (time.perf_counter() - acquired) * 1000,
            )
            self._request_lock.release()

    @contextmanager
    def receive(self, *, timeout: float) -> Iterator[SocketLike]:
        """Own response reading without sending a request first."""
        waiting_started = time.perf_counter()
        self._request_lock.acquire()
        acquired = time.perf_counter()
        add_request_timing(
            f"{self._timing_name}_wait",
            (acquired - waiting_started) * 1000,
        )
        try:
            self._dispatcher.wait_idle()
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            yield sock
        finally:
            add_request_timing(
                f"{self._timing_name}_io",
                (time.perf_counter() - acquired) * 1000,
            )
            self._request_lock.release()

    def try_send(
        self,
        frame: bytes,
        *,
        trailing_newline: bool = True,
    ) -> bool:
        if not self._request_lock.acquire(blocking=False):
            return False
        try:
            if self._dispatcher.busy:
                return False
            sock = self._socket_getter()
            if sock is None:
                return False
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            return True
        finally:
            self._request_lock.release()

    def dispatch(
        self,
        requests,
        *,
        frame_reader,
        timeout: float,
        max_frames: int = 32,
    ) -> list[Any]:
        """Run a bounded multi-flight bundle under this connection's lock."""
        waiting_started = time.perf_counter()
        self._request_lock.acquire()
        acquired = time.perf_counter()
        add_request_timing(
            f"{self._timing_name}_wait",
            (acquired - waiting_started) * 1000,
        )
        try:
            futures = self._dispatcher.submit(
                requests,
                frame_reader=frame_reader,
                timeout=timeout,
                max_frames=max_frames,
            )
        finally:
            self._request_lock.release()

        try:
            result = [
                future.result(timeout=timeout + 0.5)
                for future in futures
            ]
            sock = self._socket_getter()
            if sock is not None:
                sock.settimeout(timeout)
            return result
        finally:
            add_request_timing(
                f"{self._timing_name}_io",
                (time.perf_counter() - acquired) * 1000,
            )

    def close(self) -> None:
        self._dispatcher.close()
