"""Offline workflows for QuoteService."""

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError, ProtocolError
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import QuoteService


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


def _service(responses):
    sock = FakeSocket()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.YES},
    )
    manager = ConnectionManager(profile, lambda _spec: sock)
    iterator = iter(responses)
    service = QuoteService(
        manager,
        frame_reader=lambda _sock: next(iterator),
        max_frames=len(responses),
    )
    return service, manager, sock


def test_list_quotes_uses_main_and_skips_notifications(monkeypatch):
    service, manager, sock = _service(
        [b"CodeListSize=1", b"hd1.0\x00payload"]
    )
    expected = [{"code": "600519", "dt10": 141.5}]
    monkeypatch.setattr(
        "thspypc.services.quote.parse_hd1_response",
        lambda _body: expected,
    )

    result = service.list_quotes(
        ["600519"], market=17, timeout=3.0
    )

    assert result == expected
    assert manager.peek(ConnectionRole.MAIN) is not None
    assert sock.timeout == pytest.approx(3.0, abs=0.05)
    assert len(sock.sent) == 1
    assert sock.sent[0].endswith(b"\n")


def test_list_quotes_distinguishes_parse_failure(monkeypatch):
    service, _manager, _sock = _service([b"hd3.1\x00broken"])
    monkeypatch.setattr(
        "thspypc.services.quote.parse_hd3_response",
        lambda _body: [],
    )

    with pytest.raises(ProtocolError):
        service.list_quotes(["600519"], market=17)


def test_beijing_level2_list_quotes_uses_sh_l2(monkeypatch):
    sock = FakeSocket()
    profile = AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.BASIC_QUOTE: Support.YES,
            Capability.L2_MARKET_ACCESS: Support.YES,
        },
    )
    manager = ConnectionManager(profile, lambda _spec: sock)
    service = QuoteService(
        manager,
        frame_reader=lambda _sock: b"hd1.0\x00payload",
        max_frames=1,
    )
    monkeypatch.setattr(
        "thspypc.services.quote.parse_hd1_response",
        lambda _body: [{"code": "920083", "dt10": 10.5}],
    )

    result = service.list_quotes(["920083"], market=151)

    assert result == [{"code": "920083", "dt10": 10.5}]
    assert manager.peek(ConnectionRole.MAIN) is None
    assert manager.peek(ConnectionRole.SH_L2) is not None
    assert b"pageid=1334" in sock.sent[0]


def test_list_quotes_returns_empty_when_only_notifications_arrive():
    service, _manager, _sock = _service(
        [b"CodeListSize=0", b"MarketTime=closed"]
    )

    assert service.list_quotes(["600519"], market=17) == []


def test_depth_quote_matches_first_recognized_response(monkeypatch):
    service, manager, sock = _service(
        [b"MarketTime=...", b"hd1.0\x00depth"]
    )
    expected = {
        "code": "000001",
        "buy": [],
        "sell": [],
        "seal_amount": 0.0,
        "seal_type": None,
        "fields": {},
    }
    monkeypatch.setattr(
        "thspypc.services.quote.parse_depth_quote_response",
        lambda body: expected if b"depth" in body else {},
    )

    result = service.depth_quote(
        "000001", market=33, timeout=4.0
    )

    assert result == expected
    assert manager.peek(ConnectionRole.MAIN) is not None
    assert sock.timeout == pytest.approx(4.0, abs=0.05)
    assert len(sock.sent) == 1


def test_depth_quote_distinguishes_parse_failure(monkeypatch):
    service, _manager, _sock = _service([b"hd1.0\x00broken-depth"])
    monkeypatch.setattr(
        "thspypc.services.quote.parse_depth_quote_response",
        lambda _body: {},
    )

    with pytest.raises(ProtocolError):
        service.depth_quote("000001", market=33)


def test_depth_quote_returns_empty_when_only_notifications_arrive():
    service, _manager, _sock = _service(
        [b"CodeListSize=0", b"MarketTime=closed"]
    )

    assert service.depth_quote("000001", market=33) == {}


def test_quote_service_checks_capability_before_opening():
    opened = []
    manager = ConnectionManager(
        AccountProfile(
            kind=AccountKind.STANDARD,
            capabilities={Capability.BASIC_QUOTE: Support.NO},
        ),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = QuoteService(manager, frame_reader=lambda _sock: b"")

    with pytest.raises(CapabilityUnavailableError):
        service.list_quotes(["600519"], market=17)

    assert opened == []
