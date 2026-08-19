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

    def _acquire_request_lock(self, deadline: float) -> float:
        """Acquire the socket lane within the caller's total time budget."""
        waiting_started = time.perf_counter()
        remaining = deadline - time.monotonic()
        acquired_lock = (
            remaining > 0
            and self._request_lock.acquire(timeout=remaining)
        )
        acquired = time.perf_counter()
        add_request_timing(
            f"{self._timing_name}_wait",
            (acquired - waiting_started) * 1000,
        )
        if not acquired_lock:
            raise TimeoutError(
                f"{self._timing_name} request lane wait timed out"
            )
        return acquired

    @staticmethod
    def _remaining(deadline: float, *, phase: str) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"request timed out while {phase}")
        return remaining

    @contextmanager
    def request(
        self,
        frame: bytes,
        *,
        timeout: float,
        trailing_newline: bool = True,
    ) -> Iterator[SocketLike]:
        deadline = time.monotonic() + timeout
        acquired = self._acquire_request_lock(deadline)
        try:
            remaining = self._remaining(deadline, phase="waiting for dispatcher")
            if not self._dispatcher.wait_idle(timeout=remaining):
                raise TimeoutError("dispatcher idle wait timed out")
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(
                self._remaining(deadline, phase="starting socket request")
            )
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
        deadline = time.monotonic() + timeout
        acquired = self._acquire_request_lock(deadline)
        try:
            remaining = self._remaining(deadline, phase="waiting for dispatcher")
            if not self._dispatcher.wait_idle(timeout=remaining):
                raise TimeoutError("dispatcher idle wait timed out")
            with self._gate_lock:
                superseded = gate != self._latest_gate
            if superseded:
                raise SupersededError("request superseded by a newer one")
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(
                self._remaining(deadline, phase="starting latest request")
            )
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
        deadline = time.monotonic() + timeout
        acquired = self._acquire_request_lock(deadline)
        try:
            remaining = self._remaining(deadline, phase="waiting for dispatcher")
            if not self._dispatcher.wait_idle(timeout=remaining):
                raise TimeoutError("dispatcher idle wait timed out")
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(
                self._remaining(deadline, phase="starting socket receive")
            )
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
        deadline = time.monotonic() + timeout
        acquired = self._acquire_request_lock(deadline)
        try:
            futures = self._dispatcher.submit(
                requests,
                frame_reader=frame_reader,
                timeout=self._remaining(
                    deadline,
                    phase="submitting dispatched request",
                ),
                max_frames=max_frames,
            )
        finally:
            self._request_lock.release()

        try:
            result = []
            for future in futures:
                remaining = self._remaining(
                    deadline,
                    phase="waiting for dispatched response",
                )
                result.append(future.result(timeout=remaining + 0.05))
            sock = self._socket_getter()
            if sock is not None:
                sock.settimeout(
                    max(deadline - time.monotonic(), 0.001)
                )
            return result
        finally:
            add_request_timing(
                f"{self._timing_name}_io",
                (time.perf_counter() - acquired) * 1000,
            )

    def close(self) -> None:
        self._dispatcher.close()
