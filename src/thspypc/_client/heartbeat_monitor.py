"""Thread-safe, connection-scoped heartbeat response accounting."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from ..features.heartbeat_protocol import is_heartbeat_ack


@dataclass
class _LaneState:
    socket: Any
    generation: int
    bound_at: float
    state: str = "idle"
    keepalive_sent: int = 0
    probes_sent: int = 0
    responses: int = 0
    explicit_acks: int = 0
    inbound_frames: int = 0
    skipped_busy: int = 0
    consecutive_misses: int = 0
    last_keepalive_at: float | None = None
    last_probe_at: float | None = None
    last_response_at: float | None = None
    last_ack_at: float | None = None
    last_rx_at: float | None = None
    pending_id: int | None = None
    pending_since: float | None = None
    pending_previous_probe_at: float | None = None


class HeartbeatMonitor:
    """Track probes without ever taking socket read ownership."""

    def __init__(
        self,
        *,
        response_timeout: float = 12.0,
        miss_threshold: int = 2,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.response_timeout = float(response_timeout)
        self.miss_threshold = max(1, int(miss_threshold))
        self._clock = clock
        self._lock = threading.RLock()
        self._lanes: dict[str, _LaneState] = {}
        self._next_probe_id = 0

    def bind(self, lane: str, sock: Any) -> int:
        """Bind a lane to the current socket and return its generation."""
        now = self._clock()
        with self._lock:
            current = self._lanes.get(lane)
            if current is not None and current.socket is sock:
                return current.generation
            generation = 1 if current is None else current.generation + 1
            self._lanes[lane] = _LaneState(sock, generation, now)
            return generation

    def bound_sockets(self) -> list[Any]:
        with self._lock:
            return [state.socket for state in self._lanes.values()]

    def note_keepalive(self, lane: str, sock: Any) -> None:
        now = self._clock()
        with self._lock:
            state = self._current_locked(lane, sock)
            if state is None:
                return
            state.keepalive_sent += 1
            state.last_keepalive_at = now

    def note_skipped(self, lane: str, sock: Any) -> None:
        with self._lock:
            state = self._current_locked(lane, sock)
            if state is not None:
                state.skipped_busy += 1

    def begin_probe(self, lane: str, sock: Any) -> int | None:
        now = self._clock()
        with self._lock:
            state = self._current_locked(lane, sock)
            if state is None or state.pending_id is not None:
                return None
            self._next_probe_id += 1
            probe_id = self._next_probe_id
            state.pending_previous_probe_at = state.last_probe_at
            state.probes_sent += 1
            state.last_probe_at = now
            state.pending_id = probe_id
            state.pending_since = now
            state.state = "pending"
            return probe_id

    def cancel_probe(self, lane: str, sock: Any, probe_id: int) -> None:
        with self._lock:
            state = self._matching_probe_locked(lane, sock, probe_id)
            if state is None:
                return
            state.probes_sent = max(0, state.probes_sent - 1)
            state.last_probe_at = state.pending_previous_probe_at
            state.pending_id = None
            state.pending_since = None
            state.pending_previous_probe_at = None
            state.state = "healthy" if state.last_rx_at is not None else "idle"

    def has_pending(self, lane: str, sock: Any, probe_id: int) -> bool:
        with self._lock:
            return self._matching_probe_locked(lane, sock, probe_id) is not None

    def observe(self, lane: str, sock: Any, body: bytes) -> bool:
        """Record one body read by an existing owner; return explicit ACK flag."""
        now = self._clock()
        ack = is_heartbeat_ack(body)
        with self._lock:
            state = self._current_locked(lane, sock)
            if state is None:
                return ack
            state.inbound_frames += 1
            state.last_rx_at = now
            if ack:
                state.explicit_acks += 1
                state.last_ack_at = now
            if state.pending_id is not None:
                state.responses += 1
                state.last_response_at = now
                state.pending_id = None
                state.pending_since = None
                state.pending_previous_probe_at = None
            state.consecutive_misses = 0
            state.state = "healthy"
        return ack

    def fail_probe(
        self,
        lane: str,
        sock: Any,
        probe_id: int,
    ) -> str | None:
        """Finish one still-pending probe as missed and return the new state."""
        with self._lock:
            state = self._matching_probe_locked(lane, sock, probe_id)
            if state is None:
                return None
            state.pending_id = None
            state.pending_since = None
            state.pending_previous_probe_at = None
            state.consecutive_misses += 1
            state.state = (
                "unresponsive"
                if state.consecutive_misses >= self.miss_threshold
                else "suspect"
            )
            return state.state

    def expire(self) -> list[tuple[str, Any, int, str]]:
        """Expire raw-socket probes which do not have dispatcher futures."""
        now = self._clock()
        expired: list[tuple[str, Any, int, str]] = []
        with self._lock:
            candidates = [
                (lane, state.socket, state.pending_id)
                for lane, state in self._lanes.items()
                if state.pending_id is not None
                and state.pending_since is not None
                and now - state.pending_since >= self.response_timeout
            ]
        for lane, sock, probe_id in candidates:
            if probe_id is None:
                continue
            new_state = self.fail_probe(lane, sock, probe_id)
            if new_state is not None:
                expired.append((lane, sock, probe_id, new_state))
        return expired

    def snapshot(self) -> dict[str, dict[str, object]]:
        now = self._clock()

        def age(value: float | None) -> int | None:
            if value is None:
                return None
            return max(0, int((now - value) * 1000))

        with self._lock:
            return {
                lane: {
                    "generation": state.generation,
                    "state": state.state,
                    "keepalive_sent": state.keepalive_sent,
                    "probes_sent": state.probes_sent,
                    "responses": state.responses,
                    "explicit_acks": state.explicit_acks,
                    "inbound_frames": state.inbound_frames,
                    "skipped_busy": state.skipped_busy,
                    "consecutive_misses": state.consecutive_misses,
                    "pending": state.pending_id is not None,
                    "bound_age_ms": age(state.bound_at),
                    "last_keepalive_age_ms": age(state.last_keepalive_at),
                    "last_probe_age_ms": age(state.last_probe_at),
                    "last_response_age_ms": age(state.last_response_at),
                    "last_ack_age_ms": age(state.last_ack_at),
                    "last_rx_age_ms": age(state.last_rx_at),
                }
                for lane, state in self._lanes.items()
            }

    def clear(self) -> None:
        with self._lock:
            self._lanes.clear()

    def _current_locked(self, lane: str, sock: Any) -> _LaneState | None:
        state = self._lanes.get(lane)
        if state is None or state.socket is not sock:
            return None
        return state

    def _matching_probe_locked(
        self,
        lane: str,
        sock: Any,
        probe_id: int,
    ) -> _LaneState | None:
        state = self._current_locked(lane, sock)
        if state is None or state.pending_id != probe_id:
            return None
        return state


__all__ = ["HeartbeatMonitor"]
