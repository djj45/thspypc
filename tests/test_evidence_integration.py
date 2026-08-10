"""Fake-I/O integration contracts for account evidence recording."""

import socket

import pytest

from thspypc import (
    AccountEvidenceRecorder,
    AccountKind,
    AccountProfile,
    Capability,
    Support,
)
from thspypc._transport import ConnectionManager
from thspypc.client import THSClient
from thspypc.errors import ProtocolError
from thspypc.services import (
    AuctionService,
    L2SubscriptionCoordinator,
    QuoteService,
    TimelineService,
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


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def test_main_login_success_records_basic_access(monkeypatch):
    client = _client()
    sock = FakeSocket()
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda _hosts, timeout=1.0, **_kw: ["127.0.0.1"],
    )
    monkeypatch.setattr(
        client,
        "_concurrent_login",
        lambda _hosts, _body: (
            "127.0.0.1",
            sock,
            {"VerifyCode": "0"},
        ),
    )
    monkeypatch.setattr(client, "_start_heartbeat", lambda: None)
    monkeypatch.setattr(client, "_send_init_handshake", lambda timeout=2.0: None)
    monkeypatch.setattr("thspypc.client.save_ip_state", lambda *_args, **_kw: None)

    result = client._do_tcp_login_raw(
        b"login",
        {"level2": "", "userclass": "captured"},
    )
    profile = client.observed_account_profile

    assert result.success
    assert profile.kind is AccountKind.UNKNOWN
    assert profile.supports(Capability.BASIC_QUOTE)
    assert profile.supports(Capability.BASIC_TIMELINE)
    assert profile.support(Capability.L2_MARKET_ACCESS) is Support.UNKNOWN
    assert profile.passport_fields["level2"] == ""


def test_manual_login_and_large_init_record_l2_access(monkeypatch):
    client = _client()
    sock = FakeSocket()
    responses = iter(
        [
            b"VerifyCode=0\r\nPromptText=\r\n",
            b"x" * 6000,
        ]
    )

    def read(_sock):
        try:
            return next(responses)
        except StopIteration:
            raise socket.timeout()

    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    monkeypatch.setattr("thspypc.client.read_frame", read)

    result = client._try_open_manual_sock(
        "127.0.0.1",
        "passport",
        "sz",
        "32;",
    )
    profile = client.observed_account_profile

    assert result is sock
    assert b"UserName=" not in sock.sent[0]
    assert b"VerifyType=1" in sock.sent[0]
    assert profile.kind is AccountKind.LEVEL2
    assert profile.supports(Capability.L2_MARKET_ACCESS)


def test_explicit_l2_permission_rejection_records_ordinary_account(
    monkeypatch,
):
    client = _client()
    sock = FakeSocket()
    response = (
        "VerifyCode=-1\r\nPromptText=没有Level2权限\r\n"
    ).encode("gbk")
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    monkeypatch.setattr(
        "thspypc.client.read_frame",
        lambda _sock: response,
    )

    result = client._try_open_manual_sock(
        "127.0.0.1",
        "passport",
        "sz",
        "32;",
    )
    profile = client.observed_account_profile

    assert result is None
    assert profile.kind is AccountKind.STANDARD
    assert profile.support(Capability.L2_MARKET_ACCESS) is Support.NO


def test_stale_passport_rejection_does_not_downgrade_capabilities(
    monkeypatch,
):
    client = _client()
    sock = FakeSocket()
    response = (
        "VerifyCode=-1\r\nPromptText=通行证有被修改的痕迹\r\n"
    ).encode("gbk")
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    monkeypatch.setattr(
        "thspypc.client.read_frame",
        lambda _sock: response,
    )

    result = client._try_open_manual_sock(
        "127.0.0.1",
        "passport",
        "sz",
        "32;",
    )

    assert result == "stale_passport"
    assert client.observed_account_profile.kind is AccountKind.UNKNOWN


def test_successful_l2_services_promote_only_observed_features(
    monkeypatch,
):
    profile = AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.YES,
            Capability.L2_TIMELINE: Support.YES,
            Capability.L2_AUCTION: Support.YES,
            Capability.L2_HISTORY_TIMELINE: Support.YES,
        },
    )
    sock = FakeSocket()
    manager = ConnectionManager(profile, lambda _spec: sock)
    evidence = AccountEvidenceRecorder()
    responses = iter(
        [
            b"CodeListSize=1",
            b"hd3.1\x00timeline",
            b"hd1.0\x00auction",
            b"hd1.0\x00history",
        ]
    )
    reader = lambda _sock: next(responses)
    subscriptions = L2SubscriptionCoordinator(
        frame_reader=reader,
        evidence=evidence,
    )
    timeline = TimelineService(
        manager,
        frame_reader=reader,
        max_frames=1,
        subscriptions=subscriptions,
        evidence=evidence,
    )
    auction = AuctionService(
        manager,
        frame_reader=reader,
        max_frames=1,
        subscriptions=subscriptions,
        evidence=evidence,
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_l2_response",
        lambda _body: [{"dt10": 12.3}],
    )
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: [{"dt10": 12.4}],
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_history_timeline_response",
        lambda _body, code, requested_codes: [
            {
                "code": code,
                "requested_codes": requested_codes,
                "dt10": 12.2,
            }
        ],
    )

    timeline.timeline("000938", market=33)
    auction.auction("000938", market=33)
    timeline.history_timeline(
        "000938",
        market=33,
        date="2026-07-24",
    )
    observed = evidence.profile()

    assert observed.supports(Capability.L2_SNAPSHOT_PUSH)
    assert observed.supports(Capability.L2_TIMELINE)
    assert observed.supports(Capability.L2_AUCTION)
    assert observed.supports(Capability.L2_HISTORY_TIMELINE)
    assert observed.support(Capability.BASIC_QUOTE) is Support.UNKNOWN


def test_parser_failure_does_not_promote_auction_capability(monkeypatch):
    profile = AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.YES,
            Capability.L2_AUCTION: Support.YES,
        },
    )
    sock = FakeSocket()
    manager = ConnectionManager(profile, lambda _spec: sock)
    evidence = AccountEvidenceRecorder()
    responses = iter([b"CodeListSize=1", b"hd1.0\x00broken"])
    reader = lambda _sock: next(responses)
    service = AuctionService(
        manager,
        frame_reader=reader,
        max_frames=1,
        subscriptions=L2SubscriptionCoordinator(
            frame_reader=reader,
            evidence=evidence,
        ),
        evidence=evidence,
    )
    monkeypatch.setattr(
        "thspypc.services.auction.parse_auction_response",
        lambda _body: [],
    )

    with pytest.raises(ProtocolError):
        service.auction("000938", market=33)

    observed = evidence.profile()
    assert observed.supports(Capability.L2_SNAPSHOT_PUSH)
    assert observed.support(Capability.L2_AUCTION) is Support.UNKNOWN
