"""Single-flight request lifecycle for one socket."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator, Protocol


class SocketLike(Protocol):
    def settimeout(self, value: float | None) -> None: ...

    def sendall(self, data: bytes) -> None: ...


class MarketSession:
    """Serialize send and response-reading ownership for one connection."""

    def __init__(
        self,
        socket_getter: Callable[[], SocketLike | None],
        request_lock: threading.RLock,
    ) -> None:
        self._socket_getter = socket_getter
        self._request_lock = request_lock

    @contextmanager
    def request(
        self,
        frame: bytes,
        *,
        timeout: float,
        trailing_newline: bool = True,
    ) -> Iterator[SocketLike]:
        with self._request_lock:
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            yield sock

    @contextmanager
    def receive(self, *, timeout: float) -> Iterator[SocketLike]:
        """Own response reading without sending a request first."""
        with self._request_lock:
            sock = self._socket_getter()
            if sock is None:
                raise ConnectionError("连接已关闭")
            sock.settimeout(timeout)
            yield sock

    def try_send(
        self,
        frame: bytes,
        *,
        trailing_newline: bool = True,
    ) -> bool:
        if not self._request_lock.acquire(blocking=False):
            return False
        try:
            sock = self._socket_getter()
            if sock is None:
                return False
            sock.sendall(frame + (b"\n" if trailing_newline else b""))
            return True
        finally:
            self._request_lock.release()
