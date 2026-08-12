"""Offline MAIN routing contracts for KlineService."""

import socket

import pytest

from thspypc import AccountEvidenceRecorder
from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError, ProtocolError
from thspypc.features.kline_protocol import (
    KLINE_PERIOD_DAY,
    build_kline_l2_query,
    build_kline_query,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import KlineService
from thspypc.services.kline import KLINE_FRAGMENT_TAIL_TIMEOUT


class FakeSocket:
    def __init__(self):
        self.timeout = None
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        return b""

    def close(self):
        self.closed = True


def _profile(kind, support=Support.YES):
    caps = {Capability.BASIC_QUOTE: support}
    if kind is AccountKind.LEVEL2:
        caps[Capability.L2_MARKET_ACCESS] = support
        caps[Capability.L2_TIMELINE] = support
    return AccountProfile(
        kind=kind,
        capabilities=caps,
    )


def test_kline_standard_uses_main_and_merges_data_frames(monkeypatch):
    """普通账号 K线走 MAIN + pageid=9355。"""
    sock = FakeSocket()
    opened = []
    responses = iter(
        [
            b"MarketTime=closed",
            b"hd3.1\x00first",
            b"hd3.1\x00second",
            b"request-boundary",
        ]
    )
    parsed = {
        b"hd3.1\x00first": [{"code": "600519", "bar": 1}],
        b"hd3.1\x00second": [{"code": "600519", "bar": 2}],
    }
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda spec: opened.append(spec.role) or sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        parsed.__getitem__,
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=4,
    )

    result = service.kline(
        "600519",
        market=17,
        period=KLINE_PERIOD_DAY,
        count=2,
        timeout=4.0,
    )

    assert [record["bar"] for record in result] == [1, 2]
    assert opened == [ConnectionRole.MAIN]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert sock.timeout == KLINE_FRAGMENT_TAIL_TIMEOUT
    assert sock.sent == [
        build_kline_query(
            "600519",
            market=17,
            period=KLINE_PERIOD_DAY,
            count=2,
        )
        + b"\n"
    ]


def test_kline_level2_uses_l2_role_and_pageid_1334(monkeypatch):
    """Level2 账号 K线走 SH_L2 + pageid=1334（2026-08-05 抓包对齐）。"""
    sock = FakeSocket()
    opened = []
    responses = iter(
        [
            b"MarketTime=closed",
            b"hd3.1\x00first",
            b"hd3.1\x00second",
            b"request-boundary",
        ]
    )
    parsed = {
        b"hd3.1\x00first": [{"code": "600519", "bar": 1}],
        b"hd3.1\x00second": [{"code": "600519", "bar": 2}],
    }
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda spec: opened.append(spec.role) or sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        parsed.__getitem__,
    )
    evidence = AccountEvidenceRecorder()
    service = KlineService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=4,
        evidence=evidence,
    )

    result = service.kline(
        "600519",
        market=17,
        period=KLINE_PERIOD_DAY,
        count=2,
        timeout=4.0,
    )

    assert [record["bar"] for record in result] == [1, 2]
    assert opened == [ConnectionRole.SH_L2]
    assert manager.peek(ConnectionRole.MAIN) is None
    assert sock.timeout == KLINE_FRAGMENT_TAIL_TIMEOUT
    assert sock.sent == [
        build_kline_l2_query(
            "600519",
            market=17,
            period=KLINE_PERIOD_DAY,
            count=2,
        )
        + b"\n"
    ]
    assert b"pageid=1334" in sock.sent[0]
    assert evidence.profile().supports(Capability.L2_TIMELINE)


def test_kline_ifindhq_fast_uses_dedicated_role(monkeypatch):
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda spec: opened.append(spec.role) or sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        lambda _body: [{"code": "600519"}],
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: b"hd3.1\x00data",
        max_frames=1,
    )

    result = service.kline(
        "600519",
        market=17,
        period=KLINE_PERIOD_DAY,
        channel="ifindhq_fast",
    )

    assert result == [{"code": "600519"}]
    assert opened == [ConnectionRole.KLINE_FAST]
    assert manager.peek(ConnectionRole.MAIN) is None
    assert manager.peek(ConnectionRole.SH_L2) is None


def test_kline_timeout_after_data_finishes_successfully(monkeypatch):
    sock = FakeSocket()
    responses = iter([b"hd3.1\x00data"])
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        lambda _body: [{"code": "000001"}],
    )

    def read_response(_sock):
        try:
            return next(responses)
        except StopIteration:
            raise socket.timeout

    service = KlineService(manager, frame_reader=read_response)

    assert service.kline(
        "000001",
        market=33,
        period=KLINE_PERIOD_DAY,
    ) == [{"code": "000001"}]


def test_kline_complete_window_returns_without_tail_read(monkeypatch):
    """完整的 count+1 根响应应立即返回，不再固定等待尾读超时。"""
    sock = FakeSocket()
    read_count = 0
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        lambda _body: [
            {"code": "000001", "bar": 1},
            {"code": "000001", "bar": 2},
            {"code": "000001", "bar": 3},
        ],
    )

    def read_response(_sock):
        nonlocal read_count
        read_count += 1
        if read_count > 1:
            raise AssertionError("完整 K 线响应后不应继续读取")
        return b"hd3.1\x00complete"

    service = KlineService(manager, frame_reader=read_response)

    result = service.kline(
        "000001",
        market=33,
        period=KLINE_PERIOD_DAY,
        count=2,
        timeout=4.0,
    )

    assert len(result) == 3
    assert read_count == 1
    assert sock.timeout == 4.0


def test_kline_timeout_before_data_remains_transport_failure():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: (_ for _ in ()).throw(socket.timeout()),
    )

    with pytest.raises(socket.timeout):
        service.kline("000001", market=33, period=KLINE_PERIOD_DAY)


def test_kline_distinguishes_parser_failure(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        lambda _body: [],
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: b"hd3.1\x00broken",
        max_frames=1,
    )

    with pytest.raises(ProtocolError):
        service.kline("000001", market=33, period=KLINE_PERIOD_DAY)


def test_kline_returns_empty_when_only_notifications_arrive():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: b"MarketTime=closed",
        max_frames=2,
    )

    assert service.kline(
        "000001",
        market=33,
        period=KLINE_PERIOD_DAY,
    ) == []


def test_kline_stops_before_opening_without_basic_access():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, Support.NO),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(CapabilityUnavailableError):
        KlineService(manager).kline(
            "000001",
            market=33,
            period=KLINE_PERIOD_DAY,
        )

    assert opened == []


def test_kline_success_records_main_evidence(monkeypatch):
    sock = FakeSocket()
    recorder = AccountEvidenceRecorder()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.kline.parse_kline_hd3_response",
        lambda _body: [{"code": "000001"}],
    )
    service = KlineService(
        manager,
        frame_reader=lambda _sock: b"hd3.1\x00data",
        max_frames=1,
        evidence=recorder,
    )

    service.kline("000001", market=33, period=KLINE_PERIOD_DAY)

    assert recorder.profile().supports(Capability.BASIC_QUOTE)
