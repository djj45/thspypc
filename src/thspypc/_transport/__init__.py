"""Internal connection primitives."""

from .connection import (
    CONNECTION_SPECS,
    ConnectionRole,
    ConnectionSpec,
    LoginIdentity,
    ManagedConnection,
)
from .connection_manager import ConnectionManager, OpenedConnection
from .session import MarketSession, SocketLike

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
]
