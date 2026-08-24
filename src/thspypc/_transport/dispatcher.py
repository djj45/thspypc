"""Connection-scoped multi-flight response dispatcher."""
from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any, Callable

from .session_types import SocketLike


@dataclass(frozen=True)
class DispatchDecision:
    """Result of offering one wire frame to a pending request."""

    matched: bool
    done: bool = False
    value: Any = None


FrameConsumer = Callable[[bytes, SocketLike], DispatchDecision]
FrameReader = Callable[[SocketLike], bytes]
_MISSING = object()


@dataclass
class DispatchRequest:
    """One wire request and the consumer which recognizes its response."""

    frame: bytes
    consume: FrameConsumer
    name: str = "request"
    trailing_newline: bool = True
    fallback: Any = field(default=_MISSING, repr=False)
    future: Future = field(default_factory=Future, init=False, repr=False)


@dataclass
class _Pending:
    request: DispatchRequest
    deadline: float
    max_frames: int
    frames_seen: int = 0


class ResponseDispatcher:
    """One reader thread shared by concurrent requests on a connection.

    Registration and writes are performed by :class:`MarketSession` while it
    briefly owns the connection send lock.  Waiting does not hold that lock,
    allowing another caller to register another in-flight request.  Legacy
    synchronous requests call :meth:`wait_idle` before taking over ``recv``.
    A request expires by its monotonic deadline, not by the number of frames
    observed.  Market sockets multiplex unsolicited pushes with responses, so
    an active symbol can legitimately put dozens of unrelated frames ahead of
    a requested table.
    """

    def __init__(self, socket_getter: Callable[[], SocketLike | None]) -> None:
        self._socket_getter = socket_getter
        self._condition = threading.Condition(threading.RLock())
        self._pending: list[_Pending] = []
        self._reader: threading.Thread | None = None
        self._closed = False

    @property
    def busy(self) -> bool:
        with self._condition:
            return bool(self._pending) or self._reader is not None

    def submit(
        self,
        requests: list[DispatchRequest],
        *,
        frame_reader: FrameReader,
        timeout: float,
        max_frames: int,
    ) -> list[Future]:
        if not requests:
            raise ValueError("dispatcher requires at least one request")
        sock = self._socket_getter()
        if sock is None:
            raise ConnectionError("connection is closed")
        deadline = time.monotonic() + timeout
        with self._condition:
            if self._closed:
                raise ConnectionError("dispatcher is closed")
            for request in requests:
                if request.future.done():
                    raise ValueError("DispatchRequest instances cannot be reused")
                self._pending.append(
                    _Pending(request, deadline, max(1, max_frames))
                )

            try:
                # One syscall also means one TCP write for a bounded pipeline.
                # Besides reducing syscall overhead, it prevents the second
                # tiny request from being held behind Nagle/delayed-ACK state.
                payload = b"".join(
                    request.frame
                    + (b"\n" if request.trailing_newline else b"")
                    for request in requests
                )
                sock.sendall(payload)
            except BaseException as exc:
                for request in requests:
                    if not request.future.done():
                        request.future.set_exception(exc)
                self._pending = [
                    pending
                    for pending in self._pending
                    if pending.request not in requests
                ]
                self._condition.notify_all()
                raise

            if self._reader is None:
                self._start_reader_locked(frame_reader)
            self._condition.notify_all()
        return [request.future for request in requests]

    def wait_idle(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._pending or self._reader is not None:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def close(self) -> None:
        with self._condition:
            self._closed = True
            error = ConnectionError("connection dispatcher closed")
            for pending in self._pending:
                if not pending.request.future.done():
                    pending.request.future.set_exception(error)
            self._pending.clear()
            self._condition.notify_all()

    def _reader_loop(self, frame_reader: FrameReader) -> None:
        try:
            while True:
                with self._condition:
                    now = time.monotonic()
                    self._expire_locked(now)
                    if not self._pending or self._closed:
                        return
                    nearest = min(p.deadline for p in self._pending)
                    sock = self._socket_getter()
                if sock is None:
                    raise ConnectionError("connection is closed")
                sock.settimeout(min(max(nearest - now, 0.001), 0.25))
                try:
                    response = frame_reader(sock)
                except (socket.timeout, BlockingIOError):
                    continue
                except StopIteration:
                    with self._condition:
                        for pending in list(self._pending):
                            self._finish_exhausted_locked(pending)
                        self._condition.notify_all()
                    return

                with self._condition:
                    candidates = list(self._pending)
                for pending in candidates:
                    if pending.request.future.done():
                        continue
                    pending.frames_seen += 1
                    decision = pending.request.consume(response, sock)
                    if not decision.matched:
                        continue
                    if decision.done and not pending.request.future.done():
                        pending.request.future.set_result(decision.value)
                    break

                with self._condition:
                    for pending in list(self._pending):
                        if pending.request.future.done():
                            self._pending.remove(pending)
                    self._condition.notify_all()
        except BaseException as exc:
            with self._condition:
                for pending in self._pending:
                    if not pending.request.future.done():
                        pending.request.future.set_exception(exc)
                self._pending.clear()
                self._condition.notify_all()
        finally:
            with self._condition:
                self._reader = None
                # A submitter may have appended work after this reader decided
                # the queue was empty but before it reached ``finally``.
                if self._pending and not self._closed:
                    self._start_reader_locked(frame_reader)
                self._condition.notify_all()

    def _start_reader_locked(self, frame_reader: FrameReader) -> None:
        reader = threading.Thread(
            target=self._reader_loop,
            args=(frame_reader,),
            name="ths-response-dispatcher",
            daemon=True,
        )
        self._reader = reader
        reader.start()

    def _expire_locked(self, now: float) -> None:
        for pending in list(self._pending):
            if now < pending.deadline:
                continue
            if not pending.request.future.done():
                pending.request.future.set_exception(
                    TimeoutError(
                        f"dispatcher did not complete: {pending.request.name}"
                    )
                )
            self._pending.remove(pending)

    def _finish_exhausted_locked(self, pending: _Pending) -> None:
        request = pending.request
        if not request.future.done():
            if request.fallback is not _MISSING:
                request.future.set_result(request.fallback)
            else:
                request.future.set_exception(
                    TimeoutError(f"dispatcher frame limit: {request.name}")
                )
        if pending in self._pending:
            self._pending.remove(pending)
