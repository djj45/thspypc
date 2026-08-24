"""Offline contracts for heartbeat wire shapes and response accounting."""
from __future__ import annotations

from thspypc._client.heartbeat_monitor import HeartbeatMonitor
from thspypc.codecs.framing import (
    encode_frame,
    read_frame,
    register_frame_observer,
    unregister_frame_observer,
)
from thspypc.features.heartbeat_protocol import (
    build_heartbeat_probe,
    is_heartbeat_ack,
)


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeSocket:
    def __init__(self, payload=b""):
        self.payload = bytearray(payload)

    def recv(self, size):
        if not self.payload:
            return b""
        chunk = bytes(self.payload[:size])
        del self.payload[:size]
        return chunk


def test_short_probe_matches_official_declared_length_quirk():
    assert build_heartbeat_probe(0x5AA717) == (
        b"\xfd\xfd\xfd\xfd00000004\x09\x17\xa7\x5a\x00"
    )
    assert is_heartbeat_ack(b"\x09\x00\x00\x00")
    assert is_heartbeat_ack(b"\x09\x00\x00\x00\x00")
    assert not is_heartbeat_ack(b"\x09\x00\x00\x01")


def test_monitor_accepts_any_inbound_and_counts_explicit_ack():
    clock = FakeClock()
    monitor = HeartbeatMonitor(clock=clock)
    sock = FakeSocket()
    monitor.bind("main", sock)

    first = monitor.begin_probe("main", sock)
    assert first is not None
    clock.advance(9.7)
    assert monitor.observe("main", sock, b"market-push") is False

    second = monitor.begin_probe("main", sock)
    assert second is not None
    clock.advance(8.0)
    assert monitor.observe("main", sock, b"\x09\x00\x00\x00") is True

    status = monitor.snapshot()["main"]
    assert status["state"] == "healthy"
    assert status["probes_sent"] == 2
    assert status["responses"] == 2
    assert status["explicit_acks"] == 1
    assert status["consecutive_misses"] == 0


def test_monitor_needs_two_consecutive_timeouts_and_ignores_old_socket():
    clock = FakeClock()
    monitor = HeartbeatMonitor(
        response_timeout=12,
        miss_threshold=2,
        clock=clock,
    )
    old = FakeSocket()
    new = FakeSocket()
    monitor.bind("main", old)

    first = monitor.begin_probe("main", old)
    clock.advance(12)
    assert monitor.expire()[0][3] == "suspect"

    second = monitor.begin_probe("main", old)
    clock.advance(12)
    assert monitor.expire()[0][3] == "unresponsive"
    assert monitor.snapshot()["main"]["consecutive_misses"] == 2

    assert monitor.bind("main", new) == 2
    assert monitor.observe("main", old, b"\x09\x00\x00\x00") is True
    status = monitor.snapshot()["main"]
    assert status["generation"] == 2
    assert status["state"] == "idle"
    assert status["explicit_acks"] == 0
    assert first != second


def test_cancelled_busy_probe_is_not_counted_as_sent():
    monitor = HeartbeatMonitor()
    sock = FakeSocket()
    monitor.bind("main", sock)
    probe_id = monitor.begin_probe("main", sock)
    assert probe_id is not None

    monitor.cancel_probe("main", sock, probe_id)
    monitor.note_skipped("main", sock)

    status = monitor.snapshot()["main"]
    assert status["probes_sent"] == 0
    assert status["skipped_busy"] == 1
    assert status["pending"] is False


def test_framing_notifies_registered_observer_without_changing_body():
    sock = FakeSocket(encode_frame(b"payload"))
    observed = []
    register_frame_observer(sock, lambda source, body: observed.append((source, body)))
    try:
        assert read_frame(sock) == b"payload"
    finally:
        unregister_frame_observer(sock)
    assert observed == [(sock, b"payload")]


def test_8901_reader_reports_four_byte_ack_and_skips_wire_tail_zero():
    ack = b"\xfd\xfd\xfd\xfd00000004\x09\x00\x00\x00\x00"
    sock = FakeSocket(ack + encode_frame(b"next"))
    observed = []
    register_frame_observer(sock, lambda _source, body: observed.append(body))
    try:
        assert read_frame(sock) == b"\x09\x00\x00\x00"
        assert read_frame(sock) == b"next"
    finally:
        unregister_frame_observer(sock)
    assert observed == [b"\x09\x00\x00\x00", b"next"]
