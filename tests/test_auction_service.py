"""Offline account, role, and response contracts for call auctions."""

from datetime import date

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import AuctionService


def _profile(kind, auction, market_access):
    return AccountProfile(
        kind=kind,
        capabilities={
            Capability.L2_AUCTION: auction,
            Capability.L2_MARKET_ACCESS: market_access,
        },
    )


STANDARD_PROFILE = _profile(
    AccountKind.STANDARD,
    Support.NO,
    Support.NO,
)
LEVEL2_PROFILE = _profile(
    AccountKind.LEVEL2,
    Support.YES,
    Support.YES,
)


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


def test_standard_account_stops_before_opening():
    opened = []
    manager = ConnectionManager(
        STANDARD_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(CapabilityUnavailableError) as exc_info:
        AuctionService(manager).auction("000938", market=33)

    assert exc_info.value.capability is Capability.L2_AUCTION
    assert opened == []


def test_unknown_account_stops_before_opening():
    opened = []
    manager = ConnectionManager(
        AccountProfile(kind=AccountKind.UNKNOWN),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(UnsupportedAccountFeatureError) as exc_info:
        AuctionService(manager).auction("000938", market=33)

    assert exc_info.value.feature == "auction"
    assert opened == []


def test_unknown_auction_capability_stops_before_opening():
    opened = []
    profile = _profile(
        AccountKind.LEVEL2,
        Support.UNKNOWN,
        Support.YES,
    )
    manager = ConnectionManager(
        profile,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(UnsupportedAccountFeatureError):
        AuctionService(manager).auction("603118", market=17)

    assert opened == []


@pytest.mark.parametrize(
    ("market", "expected_role", "response"),
    [
        (17, ConnectionRole.SH_L2, b"\x0acompressed-auction"),
        (33, ConnectionRole.SZ_L2, b"prefix-hd1.0\x00auction"),
    ],
)
def test_level2_uses_market_role_and_matches_response(
    monkeypatch,
    market,
    expected_role,
    response,
):
    opened = []
    sock = FakeSocket()
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter([b"CodeListSize=1", response])
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )
    expected = [{"dt10": 12.34, "dt49": 1000.0}]
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: expected,
    )

    result = service.auction(
        "603118" if market == 17 else "000938",
        market=market,
        trade_date=date(2026, 7, 24),
        timeout=6.0,
    )

    assert result == expected
    assert opened == [expected_role]
    assert sock.timeout == 6.0
    assert len(sock.sent) == 2
    assert b"CodeList=" in sock.sent[0]
    assert b"pageid=4214" in sock.sent[1]
    assert b"DateTime=7176(" in sock.sent[1]


def test_level2_distinguishes_parser_failure(monkeypatch):
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda _spec: FakeSocket(),
    )
    responses = iter([b"CodeListSize=1", b"hd1.0\x00broken"])
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=1,
    )
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: [],
    )

    with pytest.raises(ProtocolError):
        service.auction("000938", market=33)


def test_invalid_market_stops_before_opening():
    opened = []
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(ValueError):
        AuctionService(manager).auction("000938", market=99)

    assert opened == []
