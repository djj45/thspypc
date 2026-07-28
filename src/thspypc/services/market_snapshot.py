"""Whole-market snapshot workflow over the MAIN connection."""
from __future__ import annotations

import socket
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import ProtocolError
from ..features.account_profile import AccountEvidenceRecorder
from ..features.snapshot_protocol import build_market_snapshot_query
from ..models import Capability
from ..parse_hfd1 import parse_hfd1_response


FrameReader = Callable[[SocketLike], bytes]
SnapshotParser = Callable[[bytes], list[dict]]


class MarketSnapshotService:
    """Fetch one HFD1 whole-market snapshot using only MAIN."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        parser: SnapshotParser = parse_hfd1_response,
        max_frames: int = 8,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._parse = parser
        self._max_frames = max_frames
        self._evidence = evidence

    def snapshot(
        self,
        *,
        markets: list[int] | tuple[int, ...] | None = None,
        timeout: float = 10.0,
    ) -> list[dict]:
        """Return the first HFD1 response, skipping unrelated MAIN frames."""
        request = build_market_snapshot_query(markets=markets)
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )

        try:
            with connection.request(request, timeout=timeout) as sock:
                for _ in range(self._max_frames):
                    try:
                        response = self._read_frame(sock)
                    except ValueError:
                        continue
                    if not response or b"hfd1.0" not in response:
                        continue
                    try:
                        records = self._parse(response)
                    except Exception as exc:
                        raise ProtocolError(
                            f"failed to parse market snapshot: {exc}"
                        ) from exc
                    if not records:
                        raise ProtocolError(
                            "received HFD1 market snapshot but parsed no records"
                        )
                    if self._evidence is not None:
                        self._evidence.record_main_ready()
                    return records
        except (socket.timeout, OSError):
            return []
        return []


__all__ = ["MarketSnapshotService"]
