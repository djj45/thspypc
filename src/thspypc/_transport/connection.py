"""Role-aware managed connection."""
from __future__ import annotations

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
        self._lock = request_lock or threading.RLock()
        self._session = MarketSession(lambda: self._socket, self._lock)
        self._owns_socket = owns_socket
        self.init_complete = initialized

    @property
    def role(self) -> ConnectionRole:
        return self.spec.role

    @property
    def active(self) -> bool:
        return self._socket is not None

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

    def mark_initialized(self) -> None:
        self.init_complete = True

    def close(self) -> None:
        with self._lock:
            sock, self._socket = self._socket, None
            self.init_complete = False
            if sock is not None and self._owns_socket:
                sock.close()
