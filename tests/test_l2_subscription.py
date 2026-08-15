"""Offline lifecycle contracts for pageid=4214 registration."""

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import ChannelUnavailableError, ProtocolError
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import (
    AuctionService,
    L2SubscriptionCoordinator,
    TimelineService,
)


PROFILE = AccountProfile(
    kind=AccountKind.LEVEL2,
    capabilities={
        Capability.L2_MARKET_ACCESS: Support.YES,
        Capability.L2_TIMELINE: Support.YES,
        Capability.L2_AUCTION: Support.YES,
    },
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


def test_registration_accepts_positive_status_and_is_reused():
    sock = FakeSocket()
    manager = ConnectionManager(PROFILE, lambda _spec: sock)
    connection = manager.acquire(ConnectionRole.SZ_L2)
    responses = iter([b"CodeListSize=0", b"CodeListSize=2"])
    coordinator = L2SubscriptionCoordinator(
        frame_reader=lambda _sock: next(responses),
    )

    assert coordinator.ensure_registered(
        connection,
        "000938",
        market=33,
    )
    assert not coordinator.ensure_registered(
        connection,
        "000938",
        market=33,
    )

    assert len(sock.sent) == 1
    assert b"CodeList=33(000938,);" in sock.sent[0]
    assert coordinator.is_registered(
        connection,
        "000938",
        market=33,
    )


def test_zero_status_is_not_remembered():
    sock = FakeSocket()
    manager = ConnectionManager(PROFILE, lambda _spec: sock)
    connection = manager.acquire(ConnectionRole.SH_L2)
    coordinator = L2SubscriptionCoordinator(
        frame_reader=lambda _sock: b"CodeListSize=0",
        max_frames=2,
    )

    with pytest.raises(ProtocolError, match="CodeListSize=0"):
        coordinator.ensure_registered(
            connection,
            "603118",
            market=17,
        )

    assert not coordinator.is_registered(
        connection,
        "603118",
        market=17,
    )


def test_registration_retries_when_first_attempt_sees_only_noise(monkeypatch):
    import socket

    sock = FakeSocket()
    manager = ConnectionManager(PROFILE, lambda _spec: sock)
    connection = manager.acquire(ConnectionRole.SH_L2)
    calls = []

    def reader(_sock):
        calls.append(True)
        if len(calls) == 1:
            raise socket.timeout
        return b"CodeListSize=1"

    coordinator = L2SubscriptionCoordinator(frame_reader=reader)

    assert coordinator.ensure_registered(
        connection,
        "603118",
        market=17,
    )
    assert len(calls) == 2
    assert len(sock.sent) == 2


def test_uninitialized_adopted_connection_is_rejected_before_send():
    sock = FakeSocket()
    manager = ConnectionManager(PROFILE, lambda _spec: FakeSocket())
    connection = manager.adopt(
        ConnectionRole.SZ_L2,
        sock,
        initialized=False,
    )
    coordinator = L2SubscriptionCoordinator(
        frame_reader=lambda _sock: b"CodeListSize=1",
    )

    with pytest.raises(ChannelUnavailableError, match="尚未完成 init"):
        coordinator.ensure_registered(
            connection,
            "000938",
            market=33,
        )

    assert sock.sent == []


def test_replacement_connection_registers_again():
    sockets = []

    def opener(_spec):
        sock = FakeSocket()
        sockets.append(sock)
        return sock

    manager = ConnectionManager(PROFILE, opener)
    responses = iter([b"CodeListSize=1", b"CodeListSize=1"])
    coordinator = L2SubscriptionCoordinator(
        frame_reader=lambda _sock: next(responses),
    )

    first = manager.acquire(ConnectionRole.SH_L2)
    coordinator.ensure_registered(first, "603118", market=17)
    manager.close(ConnectionRole.SH_L2)
    second = manager.acquire(ConnectionRole.SH_L2)
    coordinator.ensure_registered(second, "603118", market=17)

    assert first is not second
    assert len(sockets) == 2
    assert len(sockets[0].sent) == 1
    assert len(sockets[1].sent) == 1


def test_timeline_and_auction_share_registration(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(PROFILE, lambda _spec: sock)
    responses = iter(
        [
            b"CodeListSize=1",
            b"hd3.1\x00timeline",
            b"hd1.0\x00auction",
        ]
    )
    frame_reader = lambda _sock: next(responses)
    coordinator = L2SubscriptionCoordinator(frame_reader=frame_reader)
    timeline = TimelineService(
        manager,
        frame_reader=frame_reader,
        max_frames=1,
        subscriptions=coordinator,
    )
    auction = AuctionService(
        manager,
        frame_reader=frame_reader,
        max_frames=1,
        subscriptions=coordinator,
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_l2_response",
        lambda _body: [{"dt10": 12.3}],
    )
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: [{"dt10": 12.4}],
    )
    # 本测试验证实时竞价路径(DateTime=7176),强制"在竞价时段内"
    monkeypatch.setattr(
        "thspypc.services.auction._in_auction_session", lambda now=None: True
    )

    assert timeline.timeline("000938", market=33)
    assert auction.auction("000938", market=33)

    assert len(sock.sent) == 3
    assert sock.sent[0].count(b"pageid=4214") == 2
    assert b"DateTime=8192(" in sock.sent[1]
    assert b"DateTime=7176(" in sock.sent[2]
