#!/usr/bin/env python
"""THSClient.depth_quote 离线门面测试。"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient


class FakeSocket:
    def __init__(self) -> None:
        self.timeout = None
        self.sent: list[bytes] = []

    def settimeout(self, value) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def setblocking(self, flag: bool) -> None:
        pass

    def recv(self, size: int, flags: int = 0) -> bytes:
        raise BlockingIOError


class DepthQuoteClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = THSClient("", "", enable_heartbeat=False)
        self.sock = FakeSocket()
        self.client._sock = self.sock

    @patch("thspypc.client.parse_depth_quote_response")
    @patch("thspypc.client.read_frame")
    @patch("thspypc.client.build_depth_quote_query")
    def test_depth_quote_skips_notifications_and_infers_sh_market(
        self, build_query, read_frame, parse_response
    ) -> None:
        build_query.return_value = b"depth-query"
        read_frame.side_effect = [b"MarketTime=...", b"depth-response"]
        expected = {
            "code": "600519",
            "buy": [],
            "sell": [],
            "seal_amount": 0.0,
            "seal_type": None,
            "fields": {},
        }
        parse_response.side_effect = [{}, expected]

        result = self.client.depth_quote("600519", timeout=4.0, retries=0)

        self.assertEqual(result, expected)
        build_query.assert_called_once_with("600519", market=17)
        self.assertEqual(self.sock.timeout, 4.0)
        self.assertEqual(self.sock.sent, [b"depth-query\n"])
        self.assertEqual(read_frame.call_count, 2)

    @patch("thspypc.client.parse_depth_quote_response", return_value={})
    @patch("thspypc.client.read_frame", return_value=b"notification")
    @patch("thspypc.client.build_depth_quote_query", return_value=b"depth-query")
    def test_depth_quote_returns_empty_after_frame_limit(
        self, build_query, read_frame, parse_response
    ) -> None:
        result = self.client.depth_quote("000001", retries=0)

        self.assertEqual(result, {})
        build_query.assert_called_once_with("000001", market=33)
        self.assertEqual(read_frame.call_count, 8)
        self.assertEqual(parse_response.call_count, 8)


if __name__ == "__main__":
    unittest.main()
