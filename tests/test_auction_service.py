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
    basic = Support.YES if kind is not AccountKind.UNKNOWN else Support.UNKNOWN
    return AccountProfile(
        kind=kind,
        capabilities={
            Capability.BASIC_AUCTION: basic,
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


def test_standard_account_uses_main_protocol(monkeypatch):
    opened = []
    manager = ConnectionManager(
        STANDARD_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    expected = [{"dt10": 12.34, "dt49": 1000.0}]
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: expected,
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: b"hd1.0\x00auction",
        max_frames=1,
    )

    assert service.auction("000938", market=33) == expected
    assert opened == [ConnectionRole.MAIN]
    assert b"pageid=9354" in manager.peek(
        ConnectionRole.MAIN
    ).socket.sent[0]


def test_index_auction_uses_t_url_and_parses_live_json():
    opened = []
    sock = FakeSocket()
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or sock,
    )
    response = (
        b'{"Auction":[{"markettime":"1786410922",'
        b'"newprice":"3962.208523","leadprice":"3965.410889",'
        b'"volume":"107894820.000000"}]}'
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: response,
        max_frames=1,
    )

    result = service.auction("1A0001", market=16)

    assert opened == [ConnectionRole.SH_L2]
    assert result[0]["dt10"] == 3962.208523
    assert result[0]["lead_price"] == 3965.410889
    assert result[0]["volume"] == 107894820
    assert b"CodeList=16(1A0001,)" in sock.sent[0]
    assert b"T_URL=/quote/auction/USH/USHI_1A0001.dat" in sock.sent[0]
    assert b"pageid=6240" in sock.sent[0]


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
    # 本测试验证实时路径(pageid=1334),强制"在竞价时段内"
    monkeypatch.setattr(
        "thspypc.services.auction._in_auction_session", lambda now=None: True
    )

    result = service.auction(
        "603118" if market == 17 else "000938",
        market=market,
        trade_date=date.today(),
        timeout=6.0,
    )

    assert result == expected
    assert opened == [expected_role]
    assert sock.timeout == 6.0
    assert len(sock.sent) == 2
    assert b"CodeList=" in sock.sent[0]
    assert b"pageid=1334" in sock.sent[1]
    assert b"DateTime=7176(" in sock.sent[1]


def test_level2_historical_opening_sends_4417_context_bundle(
    monkeypatch,
):
    sock = FakeSocket()
    manager = ConnectionManager(LEVEL2_PROFILE, lambda _spec: sock)
    responses = iter([
        b"CodeListSize=1",
        b"hd1.0\x00historical-opening",
    ])
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: [{"dt10": 12.4}],
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )

    service.auction(
        "603118",
        market=17,
        trade_date=date(2026, 7, 24),
    )

    bundle = sock.sent[1]
    assert bundle.count(b"\xfd\xfd\xfd\xfd") == 3
    assert bundle.count(b"\n\xfd\xfd\xfd\xfd") == 2
    assert b"DateTime=8192(" in bundle
    assert b"DateTime=8192(132629086-132629441)" in bundle
    assert b"DateTime=7424(" in bundle
    assert b"DateTime=6144(" in bundle
    assert bundle.count(b"pageid=4417") >= 5
    assert b"pageid=4214" not in bundle
    assert b"pageid=9355" not in bundle


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


def test_standard_closing_auction_uses_main_and_historical_page(
    monkeypatch,
):
    sock = FakeSocket()
    manager = ConnectionManager(STANDARD_PROFILE, lambda _spec: sock)
    expected = [{"dt10": 12.4, "dt49": 2000.0}]
    monkeypatch.setattr(
        "thspypc.services.auction.parse_closing_auction_response",
        lambda _body: expected,
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: b"hd1.0\x00closing",
        max_frames=1,
    )

    assert service.closing_auction(
        "000938",
        market=33,
        trade_date=date(2026, 5, 12),
    ) == expected
    assert b"DateTime=7424(" in sock.sent[0]
    assert b"pageid=9355" in sock.sent[0]


@pytest.mark.parametrize(
    ("market", "role", "code"),
    [
        (17, ConnectionRole.SH_L2, "603118"),
        (33, ConnectionRole.SZ_L2, "000938"),
    ],
)
def test_level2_closing_uses_only_market_l2_protocol(
    monkeypatch,
    market,
    role,
    code,
):
    profile = AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.BASIC_AUCTION: Support.NO,
            Capability.L2_AUCTION: Support.YES,
            Capability.L2_MARKET_ACCESS: Support.YES,
        },
    )
    opened = []
    sock = FakeSocket()
    manager = ConnectionManager(
        profile,
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter([
        b"CodeListSize=1",
        b"hd3.1\x00closing",
    ])
    expected = [{"dt10": 12.4, "dt49": 2000.0}]
    monkeypatch.setattr(
        "thspypc.services.auction.parse_closing_auction_response",
        lambda _body: expected,
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )

    result = service.closing_auction(
        code,
        market=market,
        trade_date=date(2026, 7, 24),
    )

    assert result == expected
    assert opened == [role]
    assert len(sock.sent) == 2
    bundle = sock.sent[1]
    assert bundle.count(b"\xfd\xfd\xfd\xfd") == 3
    assert bundle.count(b"\n\xfd\xfd\xfd\xfd") == 2
    assert b"pageid=4417" in bundle
    assert b"DateTime=8192(" in bundle
    assert b"DateTime=8192(132629086-132629441)" in bundle
    assert b"DateTime=7424(" in bundle
    assert b"DateTime=6144(" in bundle
    assert b"pageid=4214" not in bundle
    assert b"pageid=9354" not in bundle
    assert b"pageid=9355" not in bundle
    assert manager.peek(ConnectionRole.MAIN) is None


def test_level2_current_closing_uses_4214(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(LEVEL2_PROFILE, lambda _spec: sock)
    responses = iter([
        b"CodeListSize=1",
        b"hd3.1\x00closing",
    ])
    monkeypatch.setattr(
        "thspypc.services.auction.parse_closing_auction_response",
        lambda _body: [{"dt10": 12.4}],
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )

    service.closing_auction(
        "603118",
        market=17,
        trade_date=date.today(),
    )

    assert b"pageid=1334" in sock.sent[1]
    assert b"pageid=4417" not in sock.sent[1]


def test_index_closing_primes_opening_and_waits_for_close_root(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(LEVEL2_PROFILE, lambda _spec: sock)
    responses = iter([b"\x0aopening", b'{"CloseAuction":[]}'])
    opening = [{"auction_type": "opening", "lead_price": 3829.09}]
    closing = [{"auction_type": "closing", "lead_price": 3872.14}]
    monkeypatch.setattr(
        "thspypc.services.auction.parse_index_auction_response",
        lambda body: opening if body == b"\x0aopening" else closing,
    )
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=2,
    )

    result = service.closing_auction("1A0001", market=16)

    assert result == closing
    assert len(sock.sent) == 1
    bundle = sock.sent[0]
    assert bundle.count(b"\xfd\xfd\xfd\xfd") == 2
    assert b"/quote/auction/USH/USHI_1A0001.dat" in bundle
    assert b"/quote/auction/USH/USHI_CLOSE_1A0001.dat" in bundle


# ── 非竞价时段走 L2 历史路径(避免盘后死等)──


def test_in_auction_session_boundary():
    """_in_auction_session 在 9:15-9:25 内为 True,其它时段 False。"""
    from datetime import datetime
    from thspypc.services.auction import _in_auction_session

    assert _in_auction_session(datetime(2026, 8, 12, 9, 15, 0)) is True
    assert _in_auction_session(datetime(2026, 8, 12, 9, 25, 0)) is True
    assert _in_auction_session(datetime(2026, 8, 12, 9, 20, 0)) is True
    # 边界外
    assert _in_auction_session(datetime(2026, 8, 12, 9, 14, 59)) is False
    assert _in_auction_session(datetime(2026, 8, 12, 9, 25, 1)) is False
    assert _in_auction_session(datetime(2026, 8, 12, 12, 0, 0)) is False  # 午间休市
    assert _in_auction_session(datetime(2026, 8, 12, 22, 0, 0)) is False  # 盘后
    # 周末即使在 9:15-9:25 也 False
    assert _in_auction_session(datetime(2026, 8, 16, 9, 20, 0)) is False  # 周日


def test_level2_offsession_uses_historical_4417(monkeypatch):
    """非竞价时段(如盘后),L2 账号走历史路径 pageid=4417,而非实时 1334。

    修复背景:此前 trade_date=None 盘后走实时 1334,服务端不响应死等 timeout(12s+)。
    现在 9:25 之后(当日竞价已完整生成)改走 L2 历史路径,~39ms 拿完整序列。
    """
    sock = FakeSocket()
    manager = ConnectionManager(LEVEL2_PROFILE, lambda _spec: sock)
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _b: [{"dt10": 12.34}],
    )
    monkeypatch.setattr(
        "thspypc.services.auction._in_auction_session", lambda now=None: False
    )
    # 历史路径会读多帧(订阅+bundle),超出后返回空让循环退出
    responses = iter([b"CodeListSize=1", b"hd1.0\x00auction", b"", b""])

    def _reader(_sock, _it=iter(responses)):
        try:
            return next(_it)
        except StopIteration:
            return b""

    service = AuctionService(manager, frame_reader=_reader)

    service.auction("603118", market=17, trade_date=None, timeout=6.0)

    sent = b"".join(sock.sent)
    assert b"pageid=4417" in sent
    assert b"pageid=1334" not in sent


def test_level2_in_session_uses_realtime_1334(monkeypatch):
    """竞价时段(9:15-9:25),L2 账号仍走实时路径 pageid=1334 拿实时撮合。"""
    sock = FakeSocket()
    manager = ConnectionManager(LEVEL2_PROFILE, lambda _spec: sock)
    responses = iter([b"CodeListSize=1", b"hd1.0\x00auction"])
    service = AuctionService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _b: [{"dt10": 12.34}],
    )
    monkeypatch.setattr(
        "thspypc.services.auction._in_auction_session", lambda now=None: True
    )

    service.auction("603118", market=17, trade_date=None, timeout=6.0)

    sent = b"".join(sock.sent)
    assert b"pageid=1334" in sent
    assert b"pageid=4417" not in sent
