"""Small transport protocols shared without import cycles."""
from __future__ import annotations

from typing import Protocol


class SocketLike(Protocol):
    def settimeout(self, value: float | None) -> None: ...

    def sendall(self, data: bytes) -> None: ...
