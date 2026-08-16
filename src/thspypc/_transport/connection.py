"""Role-aware managed connection."""
from __future__ import annotations

import socket
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from ..models import Capability
from .session import MarketSession, SocketLike


class CloseableSocket(SocketLike, Protocol):
    def close(self) -> None: ...


class ConnectionRole(str, Enum):
    MAIN = "main"
    KLINE_FAST = "kline_fast"
    SH_L2 = "sh_l2"
    SZ_L2 = "sz_l2"
    REALORDER = "realorder"
    BOARD = "board"
    BOARD_CONSTITUENT_SH = "board_constituent_sh"
    BOARD_CONSTITUENT_SZ = "board_constituent_sz"
    BOARD_STATS = "board_stats"


class LoginIdentity(str, Enum):
    STANDARD = "standard"
    MANUAL = "manual"
    REALORDER = "realorder"
    BOARD = "board"


@dataclass(frozen=True)
class ConnectionSpec:
    role: ConnectionRole
    identity: LoginIdentity
    port: int
    market_codes: tuple[int, ...] = ()
    required_capability: Capability | None = None
    init_market_codes: tuple[int, ...] = ()


CONNECTION_SPECS = {
    ConnectionRole.MAIN: ConnectionSpec(
        role=ConnectionRole.MAIN,
        identity=LoginIdentity.STANDARD,
        port=8901,
    ),
    ConnectionRole.KLINE_FAST: ConnectionSpec(
        role=ConnectionRole.KLINE_FAST,
        identity=LoginIdentity.STANDARD,
        port=8901,
        required_capability=Capability.BASIC_QUOTE,
    ),
    ConnectionRole.SH_L2: ConnectionSpec(
        role=ConnectionRole.SH_L2,
        identity=LoginIdentity.STANDARD,
        port=8901,
        market_codes=(17,),
        required_capability=Capability.L2_MARKET_ACCESS,
        init_market_codes=(16, 144),
    ),
    ConnectionRole.SZ_L2: ConnectionSpec(
        role=ConnectionRole.SZ_L2,
        identity=LoginIdentity.STANDARD,
        port=8901,
        market_codes=(33,),
        required_capability=Capability.L2_MARKET_ACCESS,
        init_market_codes=(32,),
    ),
    ConnectionRole.REALORDER: ConnectionSpec(
        role=ConnectionRole.REALORDER,
        identity=LoginIdentity.REALORDER,
        port=9601,
        required_capability=Capability.REALORDER,
    ),
    ConnectionRole.BOARD: ConnectionSpec(
        role=ConnectionRole.BOARD,
        identity=LoginIdentity.BOARD,
        port=8901,
    ),
    ConnectionRole.BOARD_CONSTITUENT_SH: ConnectionSpec(
        role=ConnectionRole.BOARD_CONSTITUENT_SH,
        identity=LoginIdentity.STANDARD,
        port=8901,
    ),
    ConnectionRole.BOARD_CONSTITUENT_SZ: ConnectionSpec(
        role=ConnectionRole.BOARD_CONSTITUENT_SZ,
        identity=LoginIdentity.MANUAL,
        port=8901,
        required_capability=Capability.L2_MARKET_ACCESS,
    ),
    ConnectionRole.BOARD_STATS: ConnectionSpec(
        role=ConnectionRole.BOARD_STATS,
        identity=LoginIdentity.STANDARD,
        port=9601,
        required_capability=Capability.BASIC_QUOTE,
    ),
}


class ManagedConnection:
    """Own one socket, role metadata, and its single-flight lock."""

    def __init__(
        self,
        spec: ConnectionSpec,
        sock: CloseableSocket,
        *,
        request_lock: threading.RLock | None = None,
        owns_socket: bool = True,
        initialized: bool = False,
    ) -> None:
        self.spec = spec
        self._socket: CloseableSocket | None = sock
        self._enable_low_latency(sock)
        self._lock = request_lock or threading.RLock()
        self._session = MarketSession(
            lambda: self._socket,
            self._lock,
            timing_name=spec.role.value,
        )
        self._owns_socket = owns_socket
        self.init_complete = initialized

    @staticmethod
    def _enable_low_latency(sock: CloseableSocket) -> None:
        """Disable Nagle on market-data streams when the socket supports it.

        Quote pipelines intentionally write several small protocol frames in
        quick succession.  With Nagle enabled, the second write can wait for
        the peer's delayed ACK, producing an otherwise unexplained 40 ms tail.
        Socket-like test doubles and wrappers may not expose ``setsockopt``;
        those are left unchanged.
        """
        setsockopt = getattr(sock, "setsockopt", None)
        if setsockopt is None:
            return
        try:
            setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, TypeError, ValueError):
            # A connected stream remains usable even when the platform or a
            # socket wrapper does not support this optional latency hint.
            pass

    @property
    def role(self) -> ConnectionRole:
        return self.spec.role

    @property
    def active(self) -> bool:
        return self._socket is not None

    @property
    def is_alive(self) -> bool:
        """Best-effort liveness probe for real TCP sockets.

        Test doubles and other socket-like objects are treated as alive;
        liveness enforcement is only meaningful for real market sockets.
        """
        sock = self._socket
        if not isinstance(sock, socket.socket):
            return True
        try:
            sock.setblocking(False)
            try:
                data = sock.recv(1, socket.MSG_PEEK)
            finally:
                sock.setblocking(True)
            return data != b""
        except BlockingIOError:
            return True
        except OSError:
            return False

    @property
    def socket(self) -> CloseableSocket | None:
        return self._socket

    @property
    def owns_socket(self) -> bool:
        return self._owns_socket

    def request(
        self,
        frame: bytes,
        *,
        timeout: float,
        trailing_newline: bool = True,
    ) -> AbstractContextManager[SocketLike]:
        return self._session.request(
            frame,
            timeout=timeout,
            trailing_newline=trailing_newline,
        )

    def request_latest(
        self,
        frame: bytes,
        *,
        gate: int,
        timeout: float,
        trailing_newline: bool = True,
    ) -> AbstractContextManager[SocketLike]:
        """Latest-wins request (see ``MarketSession.request_latest``)."""
        return self._session.request_latest(
            frame,
            gate=gate,
            timeout=timeout,
            trailing_newline=trailing_newline,
        )

    def try_send(
        self,
        frame: bytes,
        *,
        trailing_newline: bool = True,
    ) -> bool:
        return self._session.try_send(
            frame,
            trailing_newline=trailing_newline,
        )

    def receive(
        self,
        *,
        timeout: float,
    ) -> AbstractContextManager[SocketLike]:
        return self._session.receive(timeout=timeout)

    def dispatch(
        self,
        requests,
        *,
        frame_reader,
        timeout: float,
        max_frames: int = 32,
    ):
        return self._session.dispatch(
            requests,
            frame_reader=frame_reader,
            timeout=timeout,
            max_frames=max_frames,
        )

    def mark_initialized(self) -> None:
        self.init_complete = True

    def close(self) -> None:
        with self._lock:
            self._session.close()
            sock, self._socket = self._socket, None
            self.init_complete = False
            if sock is not None and self._owns_socket:
                sock.close()
