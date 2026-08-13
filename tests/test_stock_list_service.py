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


def test_full_list_builds_one_minimum_query(monkeypatch):
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
    # 常规市场表 + 沪市风险警示板(22) 两次查询，都在 MAIN 上。
    assert len(sock.sent) == 2
    assert len(sock.sent[0]) == 147
    assert b"DataType=[5],[55]" in sock.sent[0]
    assert b"CodeList=22();" in sock.sent[1]
    assert manager.peek(ConnectionRole.MAIN) is not None
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_full_list_rebuilds_minimum_query_with_newline_on_every_call(
    monkeypatch,
):
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
    assert service.full_list(settle_timeout=0) == expected
    assert len(sock.sent) == 4
    assert len(sock.sent[0]) == 147 and len(sock.sent[2]) == 147
    assert b"CodeList=22();" in sock.sent[1]
    assert b"CodeList=22();" in sock.sent[3]
    assert all(request.endswith(b"\n") for request in sock.sent)


def _profile_level2():
    return AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.BASIC_QUOTE: Support.YES,
            Capability.L2_MARKET_ACCESS: Support.YES,
        },
    )


def test_full_list_level2_merges_sz_table(monkeypatch):
    main_sock = FakeSocket()
    sz_sock = FakeSocket()
    opened = []

    def opener(spec):
        opened.append(spec.role)
        return sz_sock if spec.role is ConnectionRole.SZ_L2 else main_sock

    manager = ConnectionManager(_profile_level2(), opener)
    recorder = AccountEvidenceRecorder()

    def parse_response(body):
        if body == b"sz-full-table":
            return {
                "stocks": [
                    {"code": "000001", "name": "", "market": 0},
                    {"code": "300846", "name": "", "market": 0},
                ],
                "server_info": {},
                "hd31_frames": [
                    {"pos": 0, "dc": 3274, "unk": 0x18, "hs": 71, "fc": 2}
                ],
            }
        return {
            "stocks": [
                {"code": "600000", "name": "", "market": 0},
                {"code": "000001", "name": "", "market": 0},
            ],
            "server_info": {},
            "hd31_frames": [
                {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
            ],
        }

    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_init_response",
        parse_response,
    )
    service = StockListService(
        manager,
        frame_reader=lambda sock: (
            b"sz-full-table" if sock is sz_sock else b"main-full-table"
        ),
        sleep=lambda _delay: None,
        evidence=recorder,
    )

    result = service.full_list(settle_timeout=0)

    assert [item["code"] for item in result] == ["600000", "000001", "300846"]
    assert opened == [ConnectionRole.MAIN, ConnectionRole.SZ_L2]
    assert b"CodeList=32();33();" in sz_sock.sent[0]
    assert recorder.profile().supports(Capability.L2_MARKET_ACCESS)


def test_full_list_merges_st_board_table(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda _spec: sock,
    )
    responses = iter([b"main-full-table", b"st-full-table"])

    def parse_response(body):
        if body == b"st-full-table":
            return {
                "stocks": [
                    {"code": "600525", "name": "", "market": 0},
                    {"code": "600745", "name": "", "market": 0},
                ],
                "server_info": {},
                "hd31_frames": [
                    {"pos": 0, "dc": 84, "unk": 0x18, "hs": 71, "fc": 2}
                ],
            }
        return {
            "stocks": [{"code": "600000", "name": "", "market": 0}],
            "server_info": {},
            "hd31_frames": [
                {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
            ],
        }

    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_init_response",
        parse_response,
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: next(responses),
        sleep=lambda _delay: None,
    )

    result = service.full_list(settle_timeout=0)

    assert [item["code"] for item in result] == [
        "600000",
        "600525",
        "600745",
    ]


def test_ranked_queries_all_markets_on_main(monkeypatch):
    # 2026-08-14 活网验证：MAIN 单请求 CodeList=17();22();33();151(); 即返回
    # 沪深京全市场排序（SortTotal=5217），无需拆沪深再本地合并。
    sock = FakeSocket()
    opened = []
    manager = ConnectionManager(
        _profile_level2(),
        lambda spec: opened.append(spec.role) or sock,
    )

    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_stock_list_response",
        lambda _body: {
            "sort_total": 2,
            "sort_begin": 0,
            "sort_count": 59,
            "sort_data_count": 2,
            "stocks": [
                {"code": "300862", "name": "", "market": 0, "dt44": 1038104520.0},
                {"code": "601991", "name": "", "market": 0, "dt44": 377052580.0},
            ],
        },
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"SortTotal=2",
        sleep=lambda _delay: None,
    )

    result = service.ranked(count=10, sort_by=265260, with_values=True)

    assert [r["code"] for r in result] == ["300862", "601991"]
    assert opened == [ConnectionRole.MAIN]
    assert b"CodeList=17();22();33();151();" in sock.sent[0]
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_full_list_level2_sz_gate_failure_falls_back_to_main():
    main_sock = FakeSocket()
    opened = []

    def opener(spec):
        opened.append(spec.role)
        return main_sock

    manager = ConnectionManager(
        AccountProfile(
            kind=AccountKind.LEVEL2,
            capabilities={
                Capability.BASIC_QUOTE: Support.YES,
                Capability.L2_MARKET_ACCESS: Support.NO,
            },
        ),
        opener,
    )
    service = StockListService(
        manager,
        frame_reader=lambda _sock: b"main-full-table",
        sleep=lambda _delay: None,
    )
    import thspypc.services.stock_list as module

    original = module.parse_init_response
    module.parse_init_response = lambda _body: {
        "stocks": [{"code": "600000", "name": "", "market": 0}],
        "server_info": {},
        "hd31_frames": [
            {"pos": 0, "dc": 7479, "unk": 0x18, "hs": 71, "fc": 2}
        ],
    }
    try:
        result = service.full_list(settle_timeout=0)
    finally:
        module.parse_init_response = original

    assert [item["code"] for item in result] == ["600000"]
    assert opened == [ConnectionRole.MAIN]
