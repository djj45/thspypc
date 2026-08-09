"""Offline routing and entitlement contracts for Level2 order queues."""

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError
from thspypc.features.superorder_protocol import build_order_queue_query
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import SuperorderService


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        return b""

    def close(self):
        pass


def _profile(kind):
    yes = Support.YES if kind is AccountKind.LEVEL2 else Support.NO
    return AccountProfile(
        kind=kind,
        capabilities={
            Capability.L2_MARKET_ACCESS: yes,
            Capability.L2_TIMELINE: yes,
        },
    )


def test_standard_account_rejected_before_opening_socket():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    with pytest.raises(CapabilityUnavailableError):
        SuperorderService(manager).order_queue(
            "688693",
            side="buy",
            market=17,
        )
    assert opened == []


def test_level2_empty_queue_uses_market_role_and_returns_empty():
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda spec: opened.append(spec.role) or sock,
    )
    service = SuperorderService(
        manager,
        frame_reader=lambda _sock: b"CodeListSize=1",
        max_frames=1,
    )
    result = service.order_queue(
        "688693",
        side="sell",
        market=17,
        timeout=6.0,
    )
    assert result["empty"] is True
    assert result["entries"] == []
    assert result["period"] == 7174
    assert opened == [ConnectionRole.SH_L2]
    assert sock.sent == [
        build_order_queue_query(
            "688693",
            market=17,
            side="sell",
            pageid=4214,
        ) + b"\n"
    ]


def test_historical_pair_builds_4096_context_once(monkeypatch):
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: FakeSocket(),
    )
    service = SuperorderService(manager)
    calls = []
    monkeypatch.setattr(
        service,
        "snapshot_replay",
        lambda code, **kwargs: calls.append(("4096", code, kwargs)) or [
            {"dt25": 1_069_767, "dt31": 0}
        ],
    )
    monkeypatch.setattr(
        service,
        "_order_queue_one",
        lambda code, **kwargs: {
            "code": code,
            "side": kwargs["side"],
            "total_order_count": 700 if kwargs["side"] == "buy" else 0,
        },
    )
    result = service.order_queues(
        "688693",
        market=17,
        context_start_ts=1786065000,
        context_end_ts=1786086060,
    )
    assert len(calls) == 1
    assert calls[0][0] == "4096"
    assert calls[0][2]["pageid"] == 4417
    assert result["buy"]["total_shares"] == 1_069_767
    assert result["buy"]["total_hands"] == 10_698
    assert result["buy"]["average_hands"] == pytest.approx(15.2824, rel=1e-3)
