"""Tail validation may inspect buffered bytes without duplicating wire traces."""

import socket

import pytest

from thspypc._transport.tracing import TracingSocket


class RecordingTracer:
    def __init__(self):
        self.received = []

    def recv(self, data):
        self.received.append(data)


def test_peeking_tail_preserves_wire_and_records_each_received_byte_once():
    reader, writer = socket.socketpair()
    tracer = RecordingTracer()
    wrapped = TracingSocket(reader, tracer)
    try:
        reader.settimeout(1)
        writer.sendall(b"\x7b\xfd\xfd\xfd\xfd")

        assert wrapped.recv(1, socket.MSG_PEEK) == b"\x7b"
        assert wrapped.recv(1, socket.MSG_PEEK) == b"\x7b"
        assert tracer.received == []

        assert wrapped.recv(1) == b"\x7b"
        assert wrapped.recv(4) == b"\xfd\xfd\xfd\xfd"
        assert tracer.received == [b"\x7b", b"\xfd\xfd\xfd\xfd"]
    finally:
        reader.close()
        writer.close()


@pytest.mark.parametrize("explicit_zero", [False, True])
def test_normal_recv_supports_socket_adapters_without_flags(explicit_zero):
    class SocketWithoutFlags:
        def recv(self, size):
            assert size == 4
            return b"data"

    tracer = RecordingTracer()
    wrapped = TracingSocket(SocketWithoutFlags(), tracer)

    received = wrapped.recv(4, 0) if explicit_zero else wrapped.recv(4)

    assert received == b"data"
    assert tracer.received == [b"data"]


def test_non_peek_flags_are_forwarded_and_received_bytes_are_recorded():
    class FlaggedSocket:
        def recv(self, size, flags):
            assert size == 4
            assert flags == socket.MSG_WAITALL
            return b"data"

    tracer = RecordingTracer()
    wrapped = TracingSocket(FlaggedSocket(), tracer)

    assert wrapped.recv(4, socket.MSG_WAITALL) == b"data"
    assert tracer.received == [b"data"]
