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
]
