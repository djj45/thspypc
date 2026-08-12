#!/usr/bin/env python
"""MarketSession 离线单元测试。"""
from __future__ import annotations

import os
import sys
import threading
import time
import unittest
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.transport import (
    CONNECTION_SPECS,
    ConnectionRole,
    ManagedConnection,
    MarketSession,
)
from thspypc.transport import DispatchDecision, DispatchRequest
from thspypc._transport.timing import (
    RequestTiming,
    reset_request_timing,
    set_request_timing,
)


class FakeSocket:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.sent: list[bytes] = []

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class RealisticFakeSocket(FakeSocket):
    def __init__(self) -> None:
        super().__init__()
        self.options: list[tuple[int, int, int]] = []
        self.closed = False

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def close(self) -> None:
        self.closed = True


class MarketSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sock = FakeSocket()
        self.lock = threading.RLock()
        self.session = MarketSession(lambda: self.sock, self.lock)

    def test_managed_connection_disables_nagle(self) -> None:
        sock = RealisticFakeSocket()
        connection = ManagedConnection(
            CONNECTION_SPECS[ConnectionRole.MAIN],
            sock,
        )

        self.assertEqual(
            sock.options,
            [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
        )
        connection.close()
        self.assertTrue(sock.closed)

    def test_request_sets_timeout_and_appends_newline(self) -> None:
        with self.session.request(b"query", timeout=3.5) as sock:
            self.assertIs(sock, self.sock)
            self.assertEqual(self.sock.timeout, 3.5)
            self.assertEqual(self.sock.sent, [b"query\n"])

    def test_request_lock_covers_entire_response_lifecycle(self) -> None:
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()

        def first_request() -> None:
            with self.session.request(b"first", timeout=1.0):
                first_entered.set()
                release_first.wait(timeout=2.0)

        def second_request() -> None:
            first_entered.wait(timeout=2.0)
            with self.session.request(b"second", timeout=1.0):
                second_entered.set()

        first = threading.Thread(target=first_request)
        second = threading.Thread(target=second_request)
        first.start()
        second.start()

        self.assertTrue(first_entered.wait(timeout=2.0))
        self.assertFalse(second_entered.wait(timeout=0.1))
        self.assertEqual(self.sock.sent, [b"first\n"])

        release_first.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertTrue(second_entered.is_set())
        self.assertEqual(self.sock.sent, [b"first\n", b"second\n"])

    def test_try_send_skips_busy_connection(self) -> None:
        request_entered = threading.Event()
        release_request = threading.Event()

        def active_request() -> None:
            with self.session.request(b"query", timeout=1.0):
                request_entered.set()
                release_request.wait(timeout=2.0)

        worker = threading.Thread(target=active_request)
        worker.start()
        self.assertTrue(request_entered.wait(timeout=2.0))

        self.assertFalse(self.session.try_send(b"heartbeat"))
        self.assertEqual(self.sock.sent, [b"query\n"])

        release_request.set()
        worker.join(timeout=2.0)
        self.assertTrue(self.session.try_send(b"heartbeat"))
        self.assertEqual(self.sock.sent, [b"query\n", b"heartbeat\n"])

    def test_request_rejects_closed_connection(self) -> None:
        session = MarketSession(lambda: None, threading.RLock())
        with self.assertRaisesRegex(ConnectionError, "连接已关闭"):
            with session.request(b"query", timeout=1.0):
                self.fail("closed connection must not yield")

    def test_request_records_wait_and_io_timing(self) -> None:
        timing = RequestTiming()
        token = set_request_timing(timing)
        try:
            session = MarketSession(
                lambda: self.sock,
                self.lock,
                timing_name="sh_l2",
            )
            with session.request(b"query", timeout=1.0):
                time.sleep(0.001)
        finally:
            reset_request_timing(token)

        self.assertIn("sh_l2_wait", timing.durations_ms)
        self.assertGreaterEqual(timing.durations_ms["sh_l2_io"], 1.0)

    def test_dispatch_sends_all_requests_before_reader_and_routes_out_of_order(self):
        reads = iter((b"depth-response", b"quote-response"))

        def read_frame(_sock):
            self.assertEqual(self.sock.sent, [b"quote\ndepth\n"])
            return next(reads)

        result = self.session.dispatch(
            [
                DispatchRequest(
                    b"quote",
                    lambda body, sock: DispatchDecision(
                        body == b"quote-response",
                        body == b"quote-response",
                        "quote-value",
                    ),
                    name="quote",
                ),
                DispatchRequest(
                    b"depth",
                    lambda body, sock: DispatchDecision(
                        body == b"depth-response",
                        body == b"depth-response",
                        "depth-value",
                    ),
                    name="depth",
                ),
            ],
            frame_reader=read_frame,
            timeout=1.0,
        )

        self.assertEqual(result, ["quote-value", "depth-value"])

    def test_dispatch_preserves_per_request_newline_policy_in_one_write(self):
        reads = iter((b"one-response", b"two-response"))

        def read_frame(_sock):
            self.assertEqual(self.sock.sent, [b"onetwo\n"])
            return next(reads)

        result = self.session.dispatch(
            [
                DispatchRequest(
                    b"one",
                    lambda body, sock: DispatchDecision(
                        body == b"one-response",
                        body == b"one-response",
                        "one",
                    ),
                    trailing_newline=False,
                ),
                DispatchRequest(
                    b"two",
                    lambda body, sock: DispatchDecision(
                        body == b"two-response",
                        body == b"two-response",
                        "two",
                    ),
                ),
            ],
            frame_reader=read_frame,
            timeout=1.0,
        )

        self.assertEqual(result, ["one", "two"])

    def test_dispatch_times_out_when_response_has_no_owner(self):
        def read_frame(_sock):
            raise socket.timeout()

        with self.assertRaisesRegex(TimeoutError, "quote"):
            self.session.dispatch(
                [
                    DispatchRequest(
                        b"quote",
                        lambda body, sock: DispatchDecision(False),
                        name="quote",
                    )
                ],
                frame_reader=read_frame,
                timeout=0.02,
            )

    def test_separate_dispatch_callers_can_share_one_reader(self):
        second_sent = threading.Event()
        first_read = threading.Event()
        reads = iter((b"second-response", b"first-response"))

        def read_frame(_sock):
            self.assertTrue(second_sent.wait(timeout=1.0))
            first_read.set()
            return next(reads)

        results = {}

        def call(name):
            results[name] = self.session.dispatch(
                [
                    DispatchRequest(
                        name.encode(),
                        lambda body, sock, name=name: DispatchDecision(
                            body == f"{name}-response".encode(),
                            body == f"{name}-response".encode(),
                            name,
                        ),
                        name=name,
                    )
                ],
                frame_reader=read_frame,
                timeout=1.0,
            )[0]

        first = threading.Thread(target=call, args=("first",))
        second = threading.Thread(target=call, args=("second",))
        first.start()
        while self.sock.sent != [b"first\n"]:
            time.sleep(0.001)
        second.start()
        while len(self.sock.sent) < 2:
            time.sleep(0.001)
        second_sent.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)

        self.assertTrue(first_read.is_set())
        self.assertEqual(results, {"first": "first", "second": "second"})
        self.assertEqual(self.sock.sent, [b"first\n", b"second\n"])


if __name__ == "__main__":
    unittest.main()
