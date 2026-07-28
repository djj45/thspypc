"""Offline pagination contracts for StockListService."""

import pytest

from thspypc import AccountEvidenceRecorder
from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.errors import CapabilityUnavailableError, ProtocolError
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import StockListService


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
def test_ranked_pages_use_only_main_and_deduplicate(monkeypatch, kind):
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile(kind),
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter(
        [
            b"MarketTime=...",
            b"SortTotal=3 page-one",
            b"SortTotal=3 page-two",
        ]
    )
    metadata = {
        b"SortTotal=3 page-one": {
            "sort_total": 3,
            "sort_begin": 0,
            "sort_count": 2,
            "sort_data_count": 2,
            "stocks": [
                {"code": "600519", "name": "", "market": 17},
                {"code": "000001", "name": "", "market": 33},
            ],
        },
        b"SortTotal=3 page-two": {
            "sort_total": 3,
            "sort_begin": 2,
            "sort_count": 2,
            "sort_data_count": 2,
            "stocks": [
                {"code": "000001", "name": "", "market": 33},
                {"code": "300750", "name": "", "market": 33},
            ],
        },
    }
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        metadata.__getitem__,
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: next(responses),
        max_frames=2,
    )

    result = service.ranked(count=3, timeout=4.0)

    assert [item["code"] for item in result] == [
        "600519",
        "000001",
        "300750",
    ]
    assert opened == [ConnectionRole.MAIN]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert sock.timeout == 4.0
    assert len(sock.sent) == 2
    assert b"SortBegin=0\r\n" in sock.sent[0]
    assert b"SortBegin=2\r\n" in sock.sent[1]


def test_ranked_stops_before_opening_without_basic_access():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, Support.NO),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = StockListService(manager)

    with pytest.raises(CapabilityUnavailableError):
        service.ranked()

    assert opened == []


def test_ranked_distinguishes_parser_failure(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        lambda _body: {
            "sort_total": 10,
            "sort_begin": 0,
            "sort_count": 2,
            "sort_data_count": 2,
            "stocks": [],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"SortTotal=10 broken",
    )

    with pytest.raises(ProtocolError):
        service.ranked()


def test_ranked_empty_page_is_a_successful_empty_result(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        lambda _body: {
            "sort_total": 0,
            "sort_begin": 0,
            "sort_count": 0,
            "sort_data_count": 0,
            "stocks": [],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"SortTotal=0",
    )

    assert service.ranked() == []


def test_ranked_preserves_complete_last_page(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    page = [
        {"code": "600519", "name": "", "market": 17},
        {"code": "000001", "name": "", "market": 33},
    ]
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        lambda _body: {
            "sort_total": 2,
            "sort_begin": 0,
            "sort_count": 2,
            "sort_data_count": 2,
            "stocks": page,
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"SortTotal=2",
    )

    assert service.ranked(count=1) == page


def test_ranked_success_records_main_evidence(monkeypatch):
    sock = FakeSocket()
    recorder = AccountEvidenceRecorder()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        lambda _body: {
            "sort_total": 1,
            "sort_begin": 0,
            "sort_count": 1,
            "sort_data_count": 1,
            "stocks": [
                {"code": "600519", "name": "", "market": 17},
            ],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"SortTotal=1",
        evidence=recorder,
    )

    service.ranked(count=1)

    assert recorder.profile().supports(Capability.BASIC_QUOTE)


@pytest.mark.parametrize("kind", [AccountKind.STANDARD, AccountKind.LEVEL2])
def test_full_list_replays_raw_segments_on_main(monkeypatch, kind):
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile(kind),
        lambda spec: opened.append(spec.role) or sock,
    )
    responses = iter([b"MarketTime=...", b"full-table"])
    expected = [
        {"code": "600000", "name": "", "market": 0},
        {"code": "000001", "name": "", "market": 0},
    ]

    def parse_response(body):
        if body == b"full-table":
            return {
                "stocks": expected,
                "server_info": {},
                "hd31_frames": [
                    {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
                ],
            }
        return {"stocks": [], "server_info": {}, "hd31_frames": []}

    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_init_response",
        parse_response,
    )
    sleeps = []
    service = StockListService(
        manager,
        frame_reader=lambda _sock: next(responses),
        replay_segments=(b"segment-one", b"segment-two"),
        sleep=sleeps.append,
    )

    result = service.full_list(
        timeout=5.0,
        replay_delay=0.25,
        settle_timeout=0,
    )

    assert result == expected
    assert opened == [ConnectionRole.MAIN]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert sock.sent == [b"segment-one", b"segment-two"]
    assert sleeps == [0.25, 0.25]
    assert sock.timeout == 2.0


def test_full_list_distinguishes_large_table_parser_failure(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_init_response",
        lambda _body: {
            "stocks": [],
            "server_info": {},
            "hd31_frames": [
                {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
            ],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"broken-full-table",
        replay_segments=(b"segment",),
        sleep=lambda _delay: None,
    )

    with pytest.raises(ProtocolError):
        service.full_list(settle_timeout=0)


def test_full_list_rejects_invalid_replay_before_sending():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    service = StockListService(
        manager,
        replay_segments=(),
        sleep=lambda _delay: None,
    )

    with pytest.raises(ProtocolError, match="empty"):
        service.full_list()

    assert sock.sent == []


def test_full_list_loads_packaged_replay_resource(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    expected = [{"code": "600000", "name": "", "market": 0}]
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_init_response",
        lambda _body: {
            "stocks": expected,
            "server_info": {},
            "hd31_frames": [
                {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
            ],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"full-table",
        sleep=lambda _delay: None,
    )

    assert service.full_list(settle_timeout=0) == expected
    assert [len(segment) for segment in sock.sent] == [
        10690,
        5468,
        8223,
        2839,
    ]
