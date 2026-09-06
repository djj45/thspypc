"""Offline routing and entitlement contracts for Level2 order queues."""

import socket
import struct

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError
from thspypc.features.superorder_protocol import build_order_queue_query
from thspypc.features.superorder_protocol import (
    BUY_CANCEL_PERIOD,
    ORDER_DETAIL_PERIOD,
    SELL_CANCEL_PERIOD,
    parse_order_detail_response,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import SuperorderService
from thspypc.services.superorder import _repair_order_detail_tail


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        return b""

    def close(self):
        pass


class TailSocket(FakeSocket):
    def __init__(self, tail):
        super().__init__()
        self.tail = tail

    def recv(self, size, flags=0):
        tail = self.tail[:size]
        if not flags & socket.MSG_PEEK:
            self.tail = self.tail[size:]
        return tail


def _trade_response(code, count=1):
    fields = bytes.fromhex(
        "01300004383000040a7000040d7000040c3000044a3000044b30000412700004"
    )
    shell = b"\x16\x00\x01\x00\x11" + code.encode("ascii") + bytes(11)
    row = struct.pack("<8I", 101, 1788485400, 0xC00FA3E8, 100, 1, 10, 20, 1)
    return (b"hd1.0\x00" + struct.pack("<IHHH", count, 0x46, 32, 8)
            + fields + shell + row * count)


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


def test_superorder_delivers_push_seen_before_query_response():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: sock,
    )
    responses = iter([b"market-push", _trade_response("603334")])
    unsolicited = []
    service = SuperorderService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=2,
        unsolicited=unsolicited.append,
    )
    result = service.superorder(
        "603334",
        market=17,
        start_ts=1,
        end_ts=2,
    )

    assert [row["code"] for row in result] == ["603334"]
    assert unsolicited == [b"market-push"]


def test_superorder_skips_same_protocol_response_for_other_code():
    sock = FakeSocket()
    manager = ConnectionManager(_profile(AccountKind.LEVEL2), lambda _spec: sock)
    other = _trade_response("600519")
    target = _trade_response("601318")
    responses = iter([other, target])
    unsolicited = []
    service = SuperorderService(
        manager,
        frame_reader=lambda _sock: next(responses),
        unsolicited=unsolicited.append,
    )
    result = service.superorder(
        "601318",
        market=17,
        start_ts=1,
        end_ts=2,
    )

    assert [(row["code"], row["seq"]) for row in result] == [("601318", 1)]
    assert unsolicited == [other]


def test_superorder_accepts_recognized_empty_table():
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: FakeSocket(),
    )
    target = _trade_response("601318", count=0)
    service = SuperorderService(manager, frame_reader=lambda _sock: target)

    assert service.superorder(
        "601318",
        market=17,
        start_ts=1,
        end_ts=2,
    ) == []


def test_snapshot_replay_waits_past_legacy_frame_budget(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: sock,
    )
    pushes = [f"market-push-{index}".encode() for index in range(100)]
    target = b"hd1.0-snapshot-replay"
    responses = iter([*pushes, target])
    unsolicited = []
    service = SuperorderService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=1,
        unsolicited=unsolicited.append,
    )
    monkeypatch.setattr(
        "thspypc.services.superorder.is_snapshot_replay_response",
        lambda body, **_kwargs: body == target,
    )
    monkeypatch.setattr(
        "thspypc.services.superorder.parse_snapshot_replay_response",
        lambda _body: [{"code": "000001", "ts": 1}],
    )

    result = service.snapshot_replay("000001", market=33, timeout=1.0)

    assert result == [{"code": "000001", "ts": 1}]
    assert unsolicited == pushes


def test_snapshot_replay_accepts_recognized_empty_table(monkeypatch):
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: FakeSocket(),
    )
    target = b"hd1.0-empty-snapshot-replay"
    service = SuperorderService(
        manager,
        frame_reader=lambda _sock: target,
        max_frames=1,
    )
    monkeypatch.setattr(
        "thspypc.services.superorder.is_snapshot_replay_response",
        lambda body, **_kwargs: body == target,
    )
    monkeypatch.setattr(
        "thspypc.services.superorder.parse_snapshot_replay_response",
        lambda _body: [],
    )

    assert service.snapshot_replay("000001", market=33) == []


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


def test_order_details_queries_three_feeds_and_links_cancels(monkeypatch):
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda _spec: FakeSocket(),
    )
    service = SuperorderService(manager)
    calls = []
    order = {
        "event": "order",
        "side": "buy",
        "ts": 100,
        "placed_ts": 100,
        "price_raw": 123,
        "volume": 500,
        "order_id": 42,
        "kind_raw": 0x0201,
    }
    cancel = {
        "event": "cancel",
        "side": "buy",
        "ts": 104,
        "placed_ts": 100,
        "price_raw": 123,
        "volume": 500,
        "order_id": 42,
    }

    def fake_one(code, **kwargs):
        calls.append((code, kwargs))
        if kwargs["period"] == ORDER_DETAIL_PERIOD:
            return [order]
        if kwargs["period"] == BUY_CANCEL_PERIOD:
            return [cancel]
        return []

    monkeypatch.setattr(service, "_order_detail_one", fake_one)
    result = service.order_details(
        "002428",
        market=33,
        start_ts=1786345007,
        end_ts=1786345199,
    )
    assert [call[1]["period"] for call in calls] == [
        ORDER_DETAIL_PERIOD,
        BUY_CANCEL_PERIOD,
        SELL_CANCEL_PERIOD,
    ]
    assert result["buy_cancels"][0]["linked_order"] is True
    assert result["buy_cancels"][0]["link_exact"] is True
    assert [event["event"] for event in result["events"]] == [
        "order",
        "cancel",
    ]


def test_standard_account_order_details_rejected_before_socket():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    with pytest.raises(CapabilityUnavailableError):
        SuperorderService(manager).order_details(
            "002428",
            market=33,
        )
    assert opened == []


def test_order_detail_live_short_tail_is_consumed_and_restored():
    fields = bytes.fromhex(
        "01300004383000040a7000040d7000040c300004"
    )
    shell = bytearray(22)
    shell[0:4] = b"\x16\x00\x01\x00"
    shell[4:11] = b"\x21" + b"002428"
    rows = b"".join((
        struct.pack("<IIIII", 1, 1786345013, 0xC00FA3E8, 100, 0x0201),
        struct.pack("<IIIII", 2, 1786345014, 0xC00FA7D0, 1000, 0x08000202),
    ))
    complete = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 2, 0x003A, 20, 5)
        + fields
        + bytes(shell)
        + rows
    )
    truncated = complete[:-1]
    # 纯解析调用至少保留第一条完整记录。
    assert len(parse_order_detail_response(truncated, period=7175)) == 1
    repaired = _repair_order_detail_tail(
        TailSocket(complete[-1:]),
        truncated,
        period=7175,
    )
    parsed = parse_order_detail_response(repaired, period=7175)
    assert len(parsed) == 2
    assert parsed[-1]["kind_raw"] == 0x08000202
