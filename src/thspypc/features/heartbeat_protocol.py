"""Wire contracts for the short heartbeat probe shared by 8901 and 9601."""
from __future__ import annotations

from ..codecs.framing import FRAME_MAGIC


HEARTBEAT_ACK_BODIES = frozenset(
    (
        b"\x09\x00\x00\x00",
        b"\x09\x00\x00\x00\x00",
    )
)


def build_heartbeat_probe(seq: int) -> bytes:
    """Build the official short liveness probe captured on 8901/9601.

    The client declares a four-byte payload but puts five bytes on the wire:
    ``09 + token_le24 + 00``.  The ordinary 8901 reader therefore returns the
    four-byte form of the server ACK while the 9601 reader, whose protocol has
    the same declared-length-minus-one quirk, returns all five bytes.
    """
    token = (seq & 0xFFFFFF).to_bytes(3, "little")
    return FRAME_MAGIC + b"00000004" + b"\x09" + token + b"\x00"


def is_heartbeat_ack(body: bytes) -> bool:
    """Return whether *body* is the zero-token server heartbeat ACK."""
    return body in HEARTBEAT_ACK_BODIES


__all__ = [
    "HEARTBEAT_ACK_BODIES",
    "build_heartbeat_probe",
    "is_heartbeat_ack",
]
