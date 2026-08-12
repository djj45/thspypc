"""Lightweight request-local timing shared by HTTP and transport layers."""
from __future__ import annotations

import contextvars
import threading
from dataclasses import dataclass, field


@dataclass
class RequestTiming:
    """Mutable timing accumulator; one instance is shared with a request worker."""

    durations_ms: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, name: str, duration_ms: float) -> None:
        if duration_ms < 0:
            return
        with self._lock:
            self.durations_ms[name] = (
                self.durations_ms.get(name, 0.0) + duration_ms
            )

    def header(self, total_ms: float) -> str:
        with self._lock:
            items = [("total", total_ms), *self.durations_ms.items()]
        return ", ".join(
            f"{name};dur={duration:.1f}"
            for name, duration in items
        )


_CURRENT_TIMING: contextvars.ContextVar[RequestTiming | None] = (
    contextvars.ContextVar("thspypc_request_timing", default=None)
)


def current_request_timing() -> RequestTiming | None:
    return _CURRENT_TIMING.get()


def set_request_timing(timing: RequestTiming):
    return _CURRENT_TIMING.set(timing)


def reset_request_timing(token) -> None:
    _CURRENT_TIMING.reset(token)


def add_request_timing(name: str, duration_ms: float) -> None:
    timing = current_request_timing()
    if timing is not None:
        timing.add(name, duration_ms)


__all__ = [
    "RequestTiming",
    "add_request_timing",
    "current_request_timing",
    "reset_request_timing",
    "set_request_timing",
]
