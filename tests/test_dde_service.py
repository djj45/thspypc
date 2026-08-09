"""Account-aware routing and merge contracts for DDE rankings."""

import struct

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import StockListService


class FakeSocket:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        pass


def _profile(kind):
    return AccountProfile(
        kind=kind,
        capabilities={
            Capability.BASIC_QUOTE: Support.YES,
            Capability.L2_MARKET_ACCESS: (
                Support.YES if kind is AccountKind.LEVEL2 else Support.NO
            ),
        },
    )


def _page(rows, *, total, begin=0):
    return {
        "sort_total": total,
        "sort_begin": begin,
        "sort_count": len(rows),
        "sort_data_count": len(rows),
        "stocks": [],
        "rows": rows,
        "response_field": 248,
        "has_value_field": True,
    }


def _row(code, market, value):
    return {
        "code": code,
        "name": "",
        "market": market,
        "value": value,
        "sort_by": 592888,
        "response_field": 248,
    }


def _response(sequence, label):
    header = bytearray(7)
    struct.pack_into("<H", header, 5, sequence)
    return bytes(header) + b"SortTotal " + label


def test_standard_dde_uses_main_and_offset_pages(monkeypatch):
    page_one = _response(0x6001, b"page-1")
    page_two = _response(0x6002, b"page-2")
    stale = _response(0x0025, b"stale-init-page")
    sock = FakeSocket([stale, page_one, page_two])
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD),
        lambda spec: opened.append(spec.role) or sock,
    )
    pages = {
        page_one: _page(
            [_row("600001", 17, 9.0), _row("000001", 33, 8.0)],
            total=4,
        ),
        page_two: _page(
            [_row("000001", 33, 8.0), _row("600002", 17, 7.0)],
            total=4,
            begin=2,
        ),
    }
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_dde_response",
        lambda body, **_kwargs: pages[body],
    )
    service = StockListService(
        manager,
        frame_reader=lambda current: current.responses.pop(0),
    )

    result = service.dde_ranked(count=3)

    assert [row["code"] for row in result] == [
        "600001",
        "000001",
        "600002",
    ]
    assert opened == [ConnectionRole.MAIN]
    assert len(sock.sent) == 2
    assert b"SortBegin=0\r\n" in sock.sent[0]
    assert b"SortBegin=2\r\n" in sock.sent[1]
    assert b"pageid=10723\r" in sock.sent[0]


def test_level2_dde_splits_routes_and_merges_numeric_rank(monkeypatch):
    sh_page = _response(0x6001, b"sh-page")
    sz_page = _response(0x6002, b"sz-page")
    sockets = {
        ConnectionRole.SH_L2: FakeSocket([sh_page]),
        ConnectionRole.SZ_L2: FakeSocket([sz_page]),
    }
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda spec: opened.append(spec.role) or sockets[spec.role],
    )
    pages = {
        sh_page: _page(
            [
                _row("600001", 17, 1_000_000_000.0),
                _row("600002", 17, 700_000_000.0),
            ],
            total=2317,
        ),
        sz_page: _page(
            [_row("000001", 33, 900_000_000.0), _row("000002", 33, None)],
            total=2898,
        ),
    }
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_dde_response",
        lambda body, **_kwargs: pages[body],
    )
    service = StockListService(
        manager,
        frame_reader=lambda current: current.responses.pop(0),
    )

    result = service.dde_ranked(count=3, sort_dir="D")

    assert [row["code"] for row in result] == [
        "600001",
        "000001",
        "600002",
    ]
    assert [row["value"] for row in result] == [10.0, 9.0, 7.0]
    assert opened == [ConnectionRole.SH_L2, ConnectionRole.SZ_L2]
    assert b"CodeList=17();22();\r\n" in sockets[ConnectionRole.SH_L2].sent[0]
    assert b"CodeList=33();\r\n" in sockets[ConnectionRole.SZ_L2].sent[0]
    assert all(
        b"\x49\x01" in sock.sent[0][12:25]
        for sock in sockets.values()
    )


def test_level2_dde_ascending_merge_places_missing_values_last(monkeypatch):
    sh_page = _response(0x6001, b"sh-page")
    sz_page = _response(0x6002, b"sz-page")
    sockets = {
        ConnectionRole.SH_L2: FakeSocket([sh_page]),
        ConnectionRole.SZ_L2: FakeSocket([sz_page]),
    }
    manager = ConnectionManager(
        _profile(AccountKind.LEVEL2),
        lambda spec: sockets[spec.role],
    )
    pages = {
        sh_page: _page(
            [_row("600001", 17, -200_000_000.0)],
            total=1,
        ),
        sz_page: _page(
            [_row("000001", 33, 100_000_000.0), _row("000002", 33, None)],
            total=2,
        ),
    }
    monkeypatch.setattr(
        "thspypc.services.stock_list.parse_dde_response",
        lambda body, **_kwargs: pages[body],
    )
    service = StockListService(
        manager,
        frame_reader=lambda current: current.responses.pop(0),
    )

    result = service.dde_ranked(count=3, sort_dir="A")

    assert [row["code"] for row in result] == [
        "600001",
        "000001",
        "000002",
    ]
