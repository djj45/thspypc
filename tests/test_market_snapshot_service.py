"""Offline MAIN routing contracts for MarketSnapshotService."""

from pathlib import Path

import pytest

from thspypc import AccountEvidenceRecorder
from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError, ProtocolError
from thspypc.features.snapshot_protocol import build_market_snapshot_query
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import MarketSnapshotService


FIXTURE = (
    Path(__file__).resolve().parents[1] / "data" / "hfd1_0_response.bin"
)


class FakeSocket:
    def __init__(self):
        self.timeout = None
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _profile(kind, support=Support.YES):
    return AccountProfile(
        kind=kind,
        capabilities={Capability.BASIC_QUOTE: support},
    )


@pytest.mark.parametrize("kind", [AccountKind.STANDARD, AccountKind.LEVEL2])
def test_snapshot_uses_only_main_and_skips_notifications(kind):
    sock = FakeSocket()
    opened = []
    responses = iter([b"MarketTime=closed", b"hfd1.0 payload"])
    manager = ConnectionManager(
        _profile(kind),
        lambda spec: opened.append(spec.role) or sock,
    )
    expected = [{"code": "600519", "name": "Kweichow Moutai"}]
    service = MarketSnapshotService(
        manager,
        frame_reader=lambda _sock: next(responses),
        parser=lambda _body: expected,
        max_frames=2,
    )

    result = service.snapshot(markets=[16, 151], timeout=4.0)

    assert result is expected
    assert opened == [ConnectionRole.MAIN]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert sock.timeout == 4.0
    assert sock.sent == [
        build_market_snapshot_query(markets=[16, 151]) + b"\n"
    ]


def test_snapshot_stops_before_opening_without_basic_access():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, Support.NO),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(CapabilityUnavailableError):
        MarketSnapshotService(manager).snapshot()

    assert opened == []


def test_snapshot_returns_empty_when_only_notifications_arrive():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = MarketSnapshotService(
        manager,
        frame_reader=lambda _sock: b"MarketTime=closed",
        max_frames=2,
    )

    assert service.snapshot() == []


def test_snapshot_distinguishes_parser_failure():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = MarketSnapshotService(
        manager,
        frame_reader=lambda _sock: b"hfd1.0 broken",
        parser=lambda _body: [],
    )

    with pytest.raises(ProtocolError, match="parsed no records"):
        service.snapshot()


def test_snapshot_success_records_main_evidence():
    sock = FakeSocket()
    recorder = AccountEvidenceRecorder()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = MarketSnapshotService(
        manager,
        frame_reader=lambda _sock: b"hfd1.0 payload",
        parser=lambda _body: [{"code": "600519"}],
        evidence=recorder,
    )

    service.snapshot()

    assert recorder.profile().supports(Capability.BASIC_QUOTE)


def test_captured_hfd1_snapshot_contract():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = MarketSnapshotService(
        manager,
        frame_reader=lambda _sock: FIXTURE.read_bytes(),
        max_frames=1,
    )

    records = service.snapshot()

    assert len(records) == 1209
    assert [record["code"] for record in records[:3]] == [
        "1A0001",
        "1B0017",
        "1B0018",
    ]
    assert [record["code"] for record in records[-3:]] == [
        "910001",
        "910005",
        "835185",
    ]
    quote_fields = {
        "price", "change_pct", "high", "low", "open",
        "amount", "volume", "prev_close",
    }
    assert all(not quote_fields.intersection(record) for record in records)
