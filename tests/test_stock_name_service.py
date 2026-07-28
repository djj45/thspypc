"""Offline MAIN routing contracts for StockNameService."""

import pytest

from thspypc import AccountEvidenceRecorder
from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import StockNameService


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
def test_fetch_uses_only_main_and_merges_partial_results(kind):
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile(kind),
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter(
        [
            (
                b"[name_96_96]\r\n"
                + "AUDUSD=澳元/美元|alias@0\r\n".encode("gbk")
            ),
            b"[name_16_16]\x00\xffbroken",
        ]
    )
    service = StockNameService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=2,
    )

    result = service.fetch(
        market="URS",
        stock_name_ver=";;",
        timeout=4.0,
        settle_timeout=99.0,
    )

    assert result["names"] == {"AUDUSD": "澳元/美元"}
    assert result["skipped"] == ["16_16"]
    assert [item[0] for item in result["segments"]] == [
        "96_96",
        "16_16",
    ]
    assert opened == [ConnectionRole.MAIN]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert sock.timeout == 2.0
    assert sock.sent == [
        (
            b"\x09instid=65536\nmethod=upstockname\nmarket=URS\n"
            b"StockNameVer=;;\nprototype=kvproto\npageid=5716\n"
        )
    ]


def test_fetch_stops_before_opening_without_basic_access():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, Support.NO),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = StockNameService(manager)

    with pytest.raises(CapabilityUnavailableError):
        service.fetch()

    assert opened == []


def test_fetch_returns_empty_result_when_only_notifications_arrive():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = StockNameService(
        manager,
        frame_reader=lambda _sock: b"MarketTime=closed",
        max_frames=2,
    )

    assert service.fetch() == {
        "names": {},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }


def test_fetch_success_records_main_evidence():
    sock = FakeSocket()
    recorder = AccountEvidenceRecorder()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = StockNameService(
        manager,
        frame_reader=lambda _sock: (
            b"[name_96_96]\r\nAUDUSD=Australian Dollar\r\n"
        ),
        max_frames=1,
        evidence=recorder,
    )

    service.fetch()

    assert recorder.profile().supports(Capability.BASIC_QUOTE)
