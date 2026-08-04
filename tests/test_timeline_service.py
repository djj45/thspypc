"""Offline account-routing contracts for timeline requests."""

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from thspypc.features.timeline_protocol import (
    build_timeline_l2_query,
    build_timeline_query,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services.timeline import (
    TimelineMode,
    TimelineService,
    build_timeline_request,
    select_timeline_plan,
)


def _profile(kind, capabilities):
    return AccountProfile(kind=kind, capabilities=capabilities)


STANDARD_PROFILE = _profile(
    AccountKind.STANDARD,
    {
        Capability.BASIC_TIMELINE: Support.YES,
        Capability.BASIC_HISTORY_TIMELINE: Support.YES,
        Capability.L2_MARKET_ACCESS: Support.NO,
        Capability.L2_TIMELINE: Support.NO,
    },
)
LEVEL2_PROFILE = _profile(
    AccountKind.LEVEL2,
    {
        Capability.BASIC_TIMELINE: Support.YES,
        Capability.L2_MARKET_ACCESS: Support.YES,
        Capability.L2_TIMELINE: Support.YES,
        Capability.L2_HISTORY_TIMELINE: Support.YES,
    },
)


def test_standard_auto_uses_main_and_pageid_9354():
    plan = select_timeline_plan(STANDARD_PROFILE, 33)
    frame = build_timeline_request(plan, "000938", market=33)

    assert plan.mode is TimelineMode.BASIC
    assert plan.role is ConnectionRole.MAIN
    assert frame == build_timeline_query("000938", market=33)
    assert b"pageid=9354" in frame


def test_level2_auto_uses_market_specific_role_and_pageid_1334():
    # 2026-08-05 抓包对齐：Level2 分时 pageid 改 1334
    sh_plan = select_timeline_plan(LEVEL2_PROFILE, 17)
    sz_plan = select_timeline_plan(LEVEL2_PROFILE, 33)

    assert sh_plan.role is ConnectionRole.SH_L2
    assert sz_plan.role is ConnectionRole.SZ_L2
    assert build_timeline_request(
        sh_plan, "603118", market=17
    ) == build_timeline_l2_query(
        "603118",
        market=17,
        extra_codelist="16(1A0002,);",
        pageid=1334,
    )
    assert b"pageid=1334" in build_timeline_request(
        sz_plan, "000938", market=33
    )


def test_level2_index_market_codes_use_their_market_l2_roles():
    assert select_timeline_plan(
        LEVEL2_PROFILE,
        16,
    ).role is ConnectionRole.SH_L2
    assert select_timeline_plan(
        LEVEL2_PROFILE,
        32,
    ).role is ConnectionRole.SZ_L2
    assert select_timeline_plan(
        LEVEL2_PROFILE,
        144,
    ).role is ConnectionRole.SH_L2
    plan = select_timeline_plan(LEVEL2_PROFILE, 16)
    assert build_timeline_request(
        plan,
        "1A0001",
        market=16,
    ) == build_timeline_l2_query("1A0001", market=16, pageid=1334)


def test_level2_account_can_force_basic_for_protocol_comparison():
    plan = select_timeline_plan(LEVEL2_PROFILE, 33, mode="basic")

    assert plan.role is ConnectionRole.MAIN
    assert not plan.level2
    assert build_timeline_request(
        plan, "000938", market=33
    ) == build_timeline_query("000938", market=33)


def test_standard_account_cannot_force_level2():
    with pytest.raises(CapabilityUnavailableError):
        select_timeline_plan(STANDARD_PROFILE, 33, mode="level2")


def test_unknown_account_is_not_silently_routed():
    with pytest.raises(UnsupportedAccountFeatureError):
        select_timeline_plan(
            AccountProfile(kind=AccountKind.UNKNOWN),
            33,
            mode="auto",
        )


def test_missing_level2_evidence_is_diagnostic():
    profile = _profile(
        AccountKind.LEVEL2,
        {Capability.BASIC_TIMELINE: Support.YES},
    )

    with pytest.raises(UnsupportedAccountFeatureError):
        select_timeline_plan(profile, 33, mode="auto")


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


def test_standard_workflow_uses_main_and_basic_parser(monkeypatch):
    opened = []
    manager = ConnectionManager(
        STANDARD_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: b"hd3.1\x00normal",
        max_frames=1,
    )
    expected = [{"code": "000938", "minute_index": 0, "dt10": 37.33}]
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_response",
        lambda _body: expected,
    )

    assert service.timeline("000938", market=33) == expected
    assert opened == [ConnectionRole.MAIN]


def test_level2_workflow_uses_selected_role_and_matches_response(monkeypatch):
    opened = []
    sock = FakeSocket()
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter([b"CodeListSize=1", b"hd3.1\x00timeline"])
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )
    expected = [{"code": "000938", "bar_index": 132_629_086}]
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_l2_response",
        lambda _body: expected,
    )

    result = service.timeline("000938", market=33, timeout=6.0)

    assert result == expected
    assert opened == [ConnectionRole.SZ_L2]
    assert sock.timeout == 6.0
    assert len(sock.sent) == 2
    assert b"CodeList=33(000938,);" in sock.sent[0]
    assert b"pageid=1334" in sock.sent[1]


def test_level2_index_workflow_skips_stock_snapshot_registration(monkeypatch):
    opened = []
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    expected = [{"code": "1A0001", "dt10": 3822.28, "dt40": 164}]
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: b"hd3.1\x00index",
        max_frames=1,
    )
    monkeypatch.setattr(
        service._subscriptions,
        "ensure_registered",
        lambda *_args, **_kwargs: pytest.fail(
            "index timeline must not use numeric-stock snapshot registration"
        ),
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_l2_response",
        lambda _body: expected,
    )

    assert service.timeline("1A0001", market=16) == expected
    assert opened == [ConnectionRole.SH_L2]


def test_level2_workflow_distinguishes_parser_failure(monkeypatch):
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda _spec: FakeSocket(),
    )
    responses = iter([b"CodeListSize=1", b"hd3.1\x00broken"])
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=1,
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_timeline_l2_response",
        lambda _body: [],
    )

    with pytest.raises(ProtocolError):
        service.timeline("603118", market=17)


def test_standard_history_uses_main_and_pageid_9355(monkeypatch):
    opened = []
    manager = ConnectionManager(
        STANDARD_PROFILE,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: b"hd1.0\x00normal-history",
        max_frames=1,
    )
    expected = [{"bar_index": 132_477_534, "dt10": 33.88}]
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_history_timeline_response",
        lambda _body, code, requested_codes: (
            expected
            if code == "000938" and requested_codes == ("000938",)
            else []
        ),
    )

    result = service.history_timeline(
        "000938",
        market=33,
        date="2026-05-14",
    )

    assert result == expected
    assert opened == [ConnectionRole.MAIN]
    assert b"pageid=9355" in manager.peek(
        ConnectionRole.MAIN
    ).socket.sent[0]


def test_level2_history_uses_market_role_and_matches_compressed_response(
    monkeypatch,
):
    opened = []
    sock = FakeSocket()
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter([b"MarketTime=...", b"\x0acompressed-history"])
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: next(responses),
    )
    expected = [{"bar_index": 132_477_534, "dt10": 33.88}]
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_history_timeline_response",
        lambda _body, code, requested_codes: (
            expected
            if code == "000938"
            and requested_codes == ("399002", "000938")
            else []
        ),
    )

    result = service.history_timeline(
        "000938",
        market=33,
        date="2026-05-14",
        timeout=7.0,
    )

    assert result == expected
    assert opened == [ConnectionRole.SZ_L2]
    assert sock.timeout == 7.0
    assert len(sock.sent) == 1
    assert b"pageid=4417" in sock.sent[0]


def test_level2_history_requires_explicit_capability():
    profile = _profile(
        AccountKind.LEVEL2,
        {
            Capability.L2_MARKET_ACCESS: Support.YES,
            Capability.L2_HISTORY_TIMELINE: Support.UNKNOWN,
        },
    )
    opened = []
    manager = ConnectionManager(
        profile,
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = TimelineService(manager, frame_reader=lambda _sock: b"")

    with pytest.raises(UnsupportedAccountFeatureError):
        service.history_timeline(
            "603118",
            market=17,
            date="2026-05-14",
        )

    assert opened == []


def test_level2_history_rejects_uninitialized_adopted_socket():
    sock = FakeSocket()
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda _spec: FakeSocket(),
    )
    manager.adopt(
        ConnectionRole.SZ_L2,
        sock,
        initialized=False,
    )
    service = TimelineService(manager, frame_reader=lambda _sock: b"")

    with pytest.raises(ChannelUnavailableError, match="尚未完成 init"):
        service.history_timeline(
            "000938",
            market=33,
            date="2026-05-14",
        )

    assert sock.sent == []


def test_level2_history_distinguishes_unsafe_state_variant(monkeypatch):
    manager = ConnectionManager(
        LEVEL2_PROFILE,
        lambda _spec: FakeSocket(),
    )
    service = TimelineService(
        manager,
        frame_reader=lambda _sock: b"hd1.0\x00unsafe",
        max_frames=1,
    )
    monkeypatch.setattr(
        "thspypc.services.timeline.parse_history_timeline_response",
        lambda _body, code, requested_codes: [],
    )

    with pytest.raises(ProtocolError):
        service.history_timeline(
            "000938",
            market=33,
            date="2026-05-14",
        )
