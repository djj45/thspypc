#!/usr/bin/env python
"""MarketSession 离线单元测试。"""
from __future__ import annotations

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.transport import MarketSession


class FakeSocket:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.sent: list[bytes] = []

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class MarketSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sock = FakeSocket()
        self.lock = threading.RLock()
        self.session = MarketSession(lambda: self.sock, self.lock)

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


if __name__ == "__main__":
    unittest.main()
