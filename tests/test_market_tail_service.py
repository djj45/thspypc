"""Offline regression evidence for market frame boundaries and safe tail repair."""

import hashlib
import json
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from thspypc._transport import ConnectionManager
from thspypc.codecs.framing import read_exact, read_frame
from thspypc.errors import ProtocolError
from thspypc.features.superorder_protocol import (
    _ORDER_DETAIL_FIELDS,
    _market_response_evidence,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services.superorder import SuperorderService, _repair_market_frame_tail


FIXTURES = Path(__file__).parent / "fixtures" / "market_tail"
BOUNDARIES = json.loads((FIXTURES / "boundaries.json").read_text())["frames"]


def order_body(*, kind_raw=513, volume=400):
    fields = _ORDER_DETAIL_FIELDS
    header = b"hd1.0\x00" + struct.pack("<IHHH", 1, 0x3A, 20, len(fields))
    field_bytes = b"".join(bytes((dt, fmt, 0, width)) for dt, fmt, width in fields)
    shell = b"\x16\x00\x01\x00\x21" + b"000001" + bytes(11)
    row = struct.pack("<5I", 16318240, 1788487260, 3221344672, volume, kind_raw)
    return header + field_bytes + shell + row


class TrackingSocket:
    def __init__(self, tail=b"", *, timeout=1.25, peek_error=None):
        self.tail = tail
        self.timeout = timeout
        self.peek_error = peek_error
        self.reads = []
        self.sent = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, count, flags=0):
        self.reads.append((count, flags))
        if flags & socket.MSG_PEEK and self.peek_error is not None:
            raise self.peek_error
        value = self.tail[:count]
        if not flags & socket.MSG_PEEK:
            self.tail = self.tail[count:]
        return value

    def sendall(self, body):
        self.sent.append(body)

    def close(self):
        pass


@pytest.mark.parametrize("entry", BOUNDARIES, ids=lambda entry: entry["file"])
def test_real_market_boundary_preserves_next_header(entry):
    wire = (FIXTURES / entry["file"]).read_bytes()
    assert hashlib.sha256(wire).hexdigest() == entry["sha256"]
    reader, writer = socket.socketpair()
    sender = threading.Thread(target=writer.sendall, args=(wire,), daemon=True)
    try:
        reader.settimeout(1.25)
        sender.start()
        body = read_frame(reader)
        assert len(body) == entry["declared_body_bytes"]
        original = _market_response_evidence(body, period=entry["period"])
        assert original["recognized"]
        assert original["complete"] == entry["original_complete"]
        repaired = _repair_market_frame_tail(reader, body, period=entry["period"])
        checked = _market_response_evidence(repaired, period=entry["period"])
        assert checked["complete"] and checked["errors"] == []
        assert checked["declared_count"] == checked["parsed_count"] == entry["declared_count"]
        tail = bytes.fromhex(entry["actual_tail_hex"])
        next_header = bytes.fromhex(entry["next_header_hex"])
        if original["complete"]:
            assert repaired == body
            pending = tail + next_header
        else:
            assert len(tail) == 1 and tail != b"\xfd"
            assert repaired == body + tail
            pending = next_header
        assert read_exact(reader, len(pending)) == pending
        assert reader.gettimeout() == 1.25
    finally:
        reader.close()
        writer.close()
        sender.join(timeout=1)


def test_real_trade_rows_start_with_the_current_trade_number():
    raw = (FIXTURES / "600519-trades-0930-0.market-frame").read_bytes()
    evidence = _market_response_evidence(raw, period=7169, code="600519")
    assert evidence["complete"] and not evidence["truncated"]
    assert evidence["declared_count"] == evidence["parsed_count"] == 2947
    first, last = evidence["rows"][0], evidence["rows"][-1]
    assert first["trade_no"] == first["dt18"] == 496782
    assert last["trade_no"] == last["dt18"] == 3348602
    assert first["dt1"] == 1788485400 and last["dt1"] == 1788485700
    assert [row["seq"] for row in evidence["rows"]] == list(range(172, 3119))


@pytest.mark.parametrize("fragment_length", range(1, 6))
def test_fd_header_fragment_is_never_consumed(fragment_length):
    body = order_body()[:-1]
    # FD would make this row structurally complete; frame ownership wins.
    assert _market_response_evidence(body + b"\xfd", period=7175)["complete"]
    reader, writer = socket.socketpair()
    pending = b"\xfd" * fragment_length
    try:
        reader.settimeout(1.25)
        writer.sendall(pending)
        assert _repair_market_frame_tail(reader, body, period=7175) == body
        assert read_exact(reader, len(pending)) == pending
        assert reader.gettimeout() == 1.25
    finally:
        reader.close()
        writer.close()


def test_two_missing_bytes_do_not_trigger_a_speculative_read():
    full = order_body()
    pending = full[-2:] + b"\xfd\xfd\xfd\xfd00000010"
    sock = TrackingSocket(pending)
    assert _repair_market_frame_tail(sock, full[:-2], period=7175) == full[:-2]
    assert sock.tail == pending
    assert sock.reads == [(1, socket.MSG_PEEK)]
    assert sock.gettimeout() == 1.25


@pytest.mark.parametrize("body", [order_body(), b"unrelated market response"])
def test_complete_or_unknown_response_does_not_peek(body):
    sock = TrackingSocket(b"\x00")
    assert _repair_market_frame_tail(sock, body, period=7175) == body
    assert sock.reads == [] and sock.tail == b"\x00"
    assert sock.gettimeout() == 1.25


def test_repair_consumes_one_real_byte_and_restores_timeout():
    full = order_body()
    pending = b"\xfd\xfd\xfd\xfd00000010"
    sock = TrackingSocket(full[-1:] + pending)
    assert _repair_market_frame_tail(sock, full[:-1], period=7175) == full
    assert sock.tail == pending
    assert sock.reads == [(1, socket.MSG_PEEK), (1, 0)]
    assert sock.gettimeout() == 1.25


@pytest.mark.parametrize("error", [socket.timeout(), OSError("read failed")])
def test_failed_peek_restores_timeout(error):
    body = order_body()[:-1]
    sock = TrackingSocket(b"\x00", peek_error=error)
    assert _repair_market_frame_tail(sock, body, period=7175) == body
    assert sock.tail == b"\x00" and sock.gettimeout() == 1.25


def test_expired_deadline_does_not_peek():
    body = order_body()[:-1]
    sock = TrackingSocket(b"\x00")
    assert _repair_market_frame_tail(
        sock, body, period=7175, deadline=time.monotonic() - 1,
    ) == body
    assert sock.reads == [] and sock.tail == b"\x00"
    assert sock.gettimeout() == 1.25


def test_unknown_order_side_does_not_consume_socket_data():
    body = order_body(kind_raw=4150502656, volume=131584)
    pending = b"\x00\xfd\xfd\xfd\xfd00000010"
    sock = TrackingSocket(pending)
    evidence = _market_response_evidence(body, period=7175)
    assert evidence["errors"] == ["unknown_order_side:000001"]
    assert not evidence["complete"] and not evidence["truncated"]
    assert _repair_market_frame_tail(sock, body, period=7175) == body
    assert sock.reads == [] and sock.tail == pending


def test_order_details_rejects_an_unknown_side_without_reading_more():
    body = order_body(kind_raw=4150502656, volume=131584)
    sock = TrackingSocket(b"\x00\xfd\xfd\xfd\xfd")
    profile = AccountProfile(kind=AccountKind.LEVEL2, capabilities={
        Capability.L2_MARKET_ACCESS: Support.YES,
        Capability.L2_TIMELINE: Support.YES,
    })
    manager = ConnectionManager(profile, lambda _spec: sock)
    service = SuperorderService(manager, frame_reader=lambda _sock: body)
    with pytest.raises(ProtocolError, match="unknown_order_side:000001"):
        service.order_details("000001", market=33)
    assert len(sock.sent) == 1
    assert sock.reads == [] and sock.tail == b"\x00\xfd\xfd\xfd\xfd"
