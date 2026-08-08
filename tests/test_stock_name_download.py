"""Offline contracts for the concurrent stock-name download helpers."""

import struct
import socket
from pathlib import Path

import pytest
import thspypc.services.stock_name as mod
from thspypc.features.stock_name_bootstrap import build_group_frames


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def test_collect_group_merges_names_and_writes_cache(tmp_path, monkeypatch):
    sock = FakeSocket()
    frames = iter(
        [
            (
                b"[name_16_16]\r\nConfigVer=20260808_1\r\n"
                b"600000=TESTBANK\r\n"
            ),
            (
                b"[name_32_32]\r\nConfigVer=20260808_2\r\n"
                b"000001=PINGAN\r\n"
            ),
        ]
    )

    def fake_read(_sock):
        try:
            return next(frames)
        except StopIteration:
            raise socket.timeout()

    monkeypatch.setattr(mod, "read_frame", fake_read)
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)
    path = tmp_path / "stockname_test_0.txt"

    result = mod._collect_group(
        sock,
        "level2_16",
        timeout=2.0,
        settle_timeout=0.0,
        no_name_timeout=0.5,
        cache_path=str(path),
    )

    assert result["names"] == {
        "600000": "TESTBANK",
        "000001": "PINGAN",
    }
    assert path.exists()


def test_ifindhq_uses_stale_version_trigger_without_cache(tmp_path, monkeypatch):
    sock = FakeSocket()

    def fake_read(_sock):
        raise socket.timeout()

    monkeypatch.setattr(mod, "read_frame", fake_read)
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)

    result = mod._collect_group(
        sock,
        "ifindhq_120",
        timeout=0.5,
        settle_timeout=0.0,
        no_name_timeout=0.01,
    )

    assert result["names"] == {}
    sent = b"".join(sock.sent)
    assert b"MarketCode=104;\r\nStockNameVer=" in sent
    assert b"StockNameVer=;;" not in sent
    assert b"20260807_3540849890" in sent
    assert b"20260807_2709822740" in sent
    # The versioned trigger is pre-framed and must not be encoded twice.
    assert sent.count(b"\xfd\xfd\xfd\xfd") == len(
        build_group_frames("ifindhq_120")
    )


def test_collect_group_decodes_compressed_name_frame(tmp_path, monkeypatch):
    cipher = (
        Path(__file__).parents[1]
        / "captures_live"
        / "name_dump_20260808_105709"
        / "name16_cipher_mem.bin"
    )
    if not cipher.exists():
        pytest.skip("optional captured compressed name stream is unavailable")

    frame_header = bytes.fromhex(
        "0016ff0fda49121c013681d991a3260b0f0000"
    )
    body = (
        b"\x0a"
        + (0x00174828).to_bytes(4, "big")
        + frame_header
        + b"MarketCode=16\x00\r\n"
        + cipher.read_bytes()
    )
    sock = FakeSocket()
    monkeypatch.setattr(
        mod,
        "read_frame",
        lambda _sock: body,
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)

    result = mod._collect_group(
        sock,
        "level2_16",
        timeout=2.0,
        settle_timeout=0.0,
        no_name_timeout=1.0,
    )

    assert len(result["names"]) > 20000
    assert "600000" in result["names"]
