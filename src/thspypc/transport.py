"""Compatibility exports for transport primitives."""

from ._transport import (
    CONNECTION_SPECS,
    ConnectionManager,
    ConnectionRole,
    ConnectionSpec,
    LoginIdentity,
    ManagedConnection,
    MarketSession,
    OpenedConnection,
    SocketLike,
    DispatchDecision,
    DispatchRequest,
    ResponseDispatcher,
    probe_socket_alive,
)

__all__ = [
    "CONNECTION_SPECS",
    "ConnectionManager",
    "ConnectionRole",
    "ConnectionSpec",
    "LoginIdentity",
    "ManagedConnection",
    "MarketSession",
    "OpenedConnection",
    "SocketLike",
    "DispatchDecision",
    "DispatchRequest",
    "ResponseDispatcher",
    "probe_socket_alive",
]
