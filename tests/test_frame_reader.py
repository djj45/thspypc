"""TCP 帧读取器的纯内存回归测试。"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.protocol import read_frame


class _MemorySocket:
    def __init__(self, data: bytes):
        self._data = bytearray(data)

    def recv(self, size: int) -> bytes:
        result = bytes(self._data[:size])
        del self._data[:size]
        return result


class ReadFrameTests(unittest.TestCase):
    def _read(self, magic: bytes) -> bytes:
        body = b"hello-world"
        wire = magic + f"{len(body):08x}".encode("ascii") + body
        return read_frame(_MemorySocket(wire))

    def test_standard_four_byte_magic(self) -> None:
        self.assertEqual(self._read(b"\xfd" * 4), b"hello-world")

    def test_server_five_byte_magic_variant(self) -> None:
        self.assertEqual(self._read(b"\xfd" * 5), b"hello-world")

    def test_leading_zero_padding(self) -> None:
        self.assertEqual(
            self._read(b"\x00\x00" + b"\xfd" * 4),
            b"hello-world",
        )


if __name__ == "__main__":
    unittest.main()
