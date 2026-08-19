"""Contracts for borrowing legacy THSClient sockets into services."""

import concurrent.futures
import threading

import pytest

from thspypc._transport import ConnectionRole
from thspypc.client import LoginResult, THSClient
from thspypc.errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from thspypc.features.kline_protocol import KLINE_PERIOD_WEEK
from thspypc.models import AccountKind, AccountProfile, Capability, Support


LEVEL2_PROFILE = AccountProfile(
    kind=AccountKind.LEVEL2,
    capabilities={
        Capability.BASIC_QUOTE: Support.YES,
        Capability.L2_MARKET_ACCESS: Support.YES,
        Capability.L2_TIMELINE: Support.YES,
        Capability.L2_AUCTION: Support.YES,
        Capability.L2_SNAPSHOT_PUSH: Support.YES,
        Capability.L2_HISTORY_TIMELINE: Support.YES,
        Capability.REALORDER: Support.YES,
    },
)


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.sent = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def setblocking(self, _flag):
        pass

    def recv(self, _size, _flags=0):
        raise BlockingIOError

    def close(self):
        self.closed = True


def test_constituent_connections_are_independent_owned_fu4_roles(monkeypatch):
    client = _client()
    opened = []
    sockets = {"sh": FakeSocket(), "sz": FakeSocket()}
    monkeypatch.setattr(
        client,
        "_open_board_channel",
        lambda **kwargs: opened.append(kwargs["constituent_side"])
        or sockets[kwargs["constituent_side"]],
    )
    manager = client.configure_service_context(LEVEL2_PROFILE, allow_open=True)

    sh = manager.acquire(ConnectionRole.BOARD_CONSTITUENT_SH)
    sz = manager.acquire(ConnectionRole.BOARD_CONSTITUENT_SZ)

    assert opened == ["sh", "sz"]
    assert sh.socket is not sz.socket
    assert sh.owns_socket and sz.owns_socket
    assert client._board_sock is None
    client.disconnect()
    assert sockets["sh"].closed and sockets["sz"].closed


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def test_context_borrows_main_and_push_sockets_with_init_state():
    client = _client()
    main = FakeSocket()
    sh = FakeSocket()
    sz = FakeSocket()
    client._sock = main
    client._push_socks.update({"sh": sh, "sz": sz})
    client._push_initialized.add("sz")

    manager = client.configure_service_context(LEVEL2_PROFILE)

    main_connection = manager.peek(ConnectionRole.MAIN)
    sh_connection = manager.peek(ConnectionRole.SH_L2)
    sz_connection = manager.peek(ConnectionRole.SZ_L2)
    assert main_connection.socket is main
    assert sh_connection.socket is sh
    assert sz_connection.socket is sz
    assert not main_connection.owns_socket
    assert not sh_connection.init_complete
    assert sz_connection.init_complete
    assert (
        client._timeline_service._subscriptions
        is client._auction_service._subscriptions
        is client._service_subscriptions
    )


def test_repeated_sync_is_idempotent_and_replaces_borrowed_wrapper():
    client = _client()
    first_socket = FakeSocket()
    client._sock = first_socket
    manager = client.configure_service_context(LEVEL2_PROFILE)
    first_connection = manager.peek(ConnectionRole.MAIN)

    assert client.sync_service_connections() is manager
    assert manager.peek(ConnectionRole.MAIN) is first_connection

    replacement = FakeSocket()
    client._sock = replacement
    client.sync_service_connections()

    assert not first_connection.active
    assert not first_socket.closed
    assert manager.peek(ConnectionRole.MAIN).socket is replacement


def test_context_rejects_profile_replacement():
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)
    standard = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.YES},
    )

    with pytest.raises(ValueError):
        client.configure_service_context(standard)


def test_context_can_infer_profile_from_observed_evidence():
    client = _client()
    main = FakeSocket()
    client._sock = main
    client._account_evidence.record_main_ready({"userclass": "observed"})

    manager = client.configure_service_context()

    assert manager.profile == client.observed_account_profile
    assert manager.profile.kind is AccountKind.UNKNOWN
    assert manager.profile.supports(Capability.BASIC_QUOTE)
    assert manager.profile.passport_fields["userclass"] == "observed"
    assert manager.peek(ConnectionRole.MAIN).socket is main


def test_refresh_from_evidence_upgrades_unknown_profile():
    client = _client()
    manager = client.configure_service_context()
    assert manager.profile.kind is AccountKind.UNKNOWN

    client._account_evidence.record_main_ready()
    client._account_evidence.record_manual_login(Support.YES)
    client._account_evidence.record_l2_init(Support.YES)
    refreshed = client.refresh_service_profile_from_evidence()

    assert refreshed.kind is AccountKind.LEVEL2
    assert refreshed.supports(Capability.BASIC_QUOTE)
    assert refreshed.supports(Capability.L2_MARKET_ACCESS)
    assert manager.profile == refreshed


def test_refresh_from_evidence_retires_borrowed_l2_wrapper():
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client._push_initialized.add("sz")
    manager = client.configure_service_context(LEVEL2_PROFILE)
    connection = manager.peek(ConnectionRole.SZ_L2)

    client._account_evidence.record_main_ready()
    client._account_evidence.record_l2_entitlement(Support.NO)
    refreshed = client.refresh_service_profile_from_evidence()

    assert refreshed.kind is AccountKind.STANDARD
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert not connection.active
    assert not sock.closed
    assert client._push_socks["sz"] is sock


def test_reconfigure_without_profile_refreshes_existing_context():
    client = _client()
    manager = client.configure_service_context(LEVEL2_PROFILE)
    client._account_evidence.record_main_ready()
    client._account_evidence.record_l2_entitlement(Support.NO)

    same_manager = client.configure_service_context()

    assert same_manager is manager
    assert manager.profile.kind is AccountKind.STANDARD


def test_refresh_from_evidence_requires_service_context():
    client = _client()

    with pytest.raises(RuntimeError, match="configure_service_context"):
        client.refresh_service_profile_from_evidence()


def test_preheat_l2_connections_reuses_ready_market_roles():
    client = _client()
    sh = FakeSocket()
    sz = FakeSocket()
    client._push_socks.update({"sh": sh, "sz": sz})
    client._push_initialized.update({"sh", "sz"})
    client._account_evidence.record_l2_entitlement(Support.YES)
    client._account_evidence.record_manual_login(Support.YES)
    client._account_evidence.record_l2_init(Support.YES)
    client.configure_service_context(LEVEL2_PROFILE, allow_open=True)

    result = client.preheat_l2_connections()

    assert result == {
        "sh": {"ready": True, "initialized": True},
        "sz": {"ready": True, "initialized": True},
    }
    assert client._push_socks == {"sh": sh, "sz": sz}


def test_preheat_l2_connections_skips_non_level2_profile():
    client = _client()
    client._account_evidence.record_main_ready()
    client._account_evidence.record_l2_entitlement(Support.NO)

    assert client.preheat_l2_connections() == {
        "sh": {"ready": False, "skipped": True},
        "sz": {"ready": False, "skipped": True},
    }
    assert client._push_socks == {}


def test_preheat_service_connections_reuses_l2_roles_for_kline(monkeypatch):
    client = _client()
    client._account_evidence.record_l2_entitlement(Support.YES)
    client._account_evidence.record_manual_login(Support.YES)
    client._account_evidence.record_l2_init(Support.YES)
    manager = client.configure_service_context(LEVEL2_PROFILE, allow_open=True)

    sockets = {
        "sh": FakeSocket(),
        "sz": FakeSocket(),
    }
    auth_calls = []
    l2_calls = []

    class Material:
        passport64 = "passport-parallel"
        passport_bytes = b"passport-bytes"

    def fake_authenticate(*_args, **_kwargs):
        auth_calls.append(True)
        return Material()

    def fake_open_manual(market, **kwargs):
        # 并行预热必须给每条 L2 传独立材料，否则两路会共享全局最新 Passport。
        assert kwargs["material"].passport64 == "passport-parallel"
        l2_calls.append(market)
        return sockets["sh"] if market == 17 else sockets["sz"]

    monkeypatch.setattr(client, "authenticate", fake_authenticate)
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        fake_open_manual,
    )
    result = client.preheat_service_connections()

    assert result == {
        "sh": {"ready": True, "initialized": True},
        "sz": {"ready": True, "initialized": True},
    }
    assert sorted(l2_calls) == [17, 33]
    assert len(auth_calls) == 2  # sh / sz 各自独立一代 Passport
    assert manager.peek(ConnectionRole.SH_L2).socket is sockets["sh"]
    assert manager.peek(ConnectionRole.SZ_L2).socket is sockets["sz"]
    assert manager.peek(ConnectionRole.KLINE_FAST) is None
    assert client._push_socks == {
        "sh": sockets["sh"],
        "sz": sockets["sz"],
    }

    client.disconnect()


def test_concurrent_default_calls_keep_each_others_capability_lease():
    client = _client()
    client._account_evidence.record_l2_entitlement(Support.YES)
    client._account_evidence.record_manual_login(Support.YES)
    client._account_evidence.record_l2_init(Support.YES)
    both_entered = threading.Event()
    release_second = threading.Event()
    entered = 0
    entered_lock = threading.Lock()

    def enter():
        nonlocal entered
        with entered_lock:
            entered += 1
            if entered == 2:
                both_entered.set()
        assert both_entered.wait(timeout=1.0)

    def first_operation():
        enter()
        return "first"

    def second_operation():
        enter()
        assert release_second.wait(timeout=2.0)
        assert client._service_connections.profile.supports(
            Capability.L2_AUCTION
        )
        return "second"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            client._run_default_service,
            (Capability.L2_TIMELINE,),
            first_operation,
        )
        second = executor.submit(
            client._run_default_service,
            (Capability.L2_AUCTION,),
            second_operation,
        )
        assert first.result(timeout=2.0) == "first"
        release_second.set()
        assert second.result(timeout=2.0) == "second"


def test_standard_profile_cannot_adopt_accidental_l2_socket():
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.BASIC_QUOTE: Support.YES,
            Capability.L2_MARKET_ACCESS: Support.NO,
        },
    )

    with pytest.raises(CapabilityUnavailableError):
        client.configure_service_context(profile)

    assert (
        client._service_connections.peek(ConnectionRole.SZ_L2)
        is None
    )


def test_disconnect_invalidates_wrappers_and_legacy_owner_closes_sockets():
    client = _client()
    main = FakeSocket()
    sh = FakeSocket()
    client._sock = main
    client._push_socks["sh"] = sh
    client._push_initialized.add("sh")
    manager = client.configure_service_context(LEVEL2_PROFILE)

    client.disconnect()

    assert main.closed
    assert sh.closed
    assert manager.peek(ConnectionRole.MAIN) is None
    assert manager.peek(ConnectionRole.SH_L2) is None


def test_list_quotes_opt_in_delegates_without_changing_public_arguments(
    monkeypatch,
):
    client = _client()
    client._sock = FakeSocket()
    calls = []

    class FakeQuoteService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def list_quotes(self, codes, **kwargs):
            calls.append((codes, kwargs))
            return [{"code": "600519", "dt10": 1500.0}]

    monkeypatch.setattr(
        "thspypc.services.QuoteService",
        FakeQuoteService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)
    assert client._quote_service.connections is manager

    result = client.list_quotes(
        ["600519"],
        market=17,
        datatype=[7, 10],
        pageid=1335,
        timeout=4.0,
    )

    assert result == [{"code": "600519", "dt10": 1500.0}]
    assert calls == [
        (
            ["600519"],
            {
                "market": 17,
                "datatype": [7, 10],
                "pageid": 1335,
                "timeout": 4.0,
            },
        )
    ]


def test_list_quotes_opt_in_preserves_empty_result_on_protocol_error(
    monkeypatch,
):
    client = _client()
    client._sock = FakeSocket()

    class BrokenQuoteService:
        def __init__(self, _connections, *, evidence=None, subscriptions=None):
            pass

        def list_quotes(self, _codes, **_kwargs):
            raise ProtocolError("broken fixture")

    monkeypatch.setattr(
        "thspypc.services.QuoteService",
        BrokenQuoteService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    assert client.list_quotes(["600519"]) == []


def test_list_quotes_opt_in_enforces_basic_quote_capability():
    client = _client()
    sock = FakeSocket()
    client._sock = sock
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.NO},
    )
    client.configure_service_context(profile)

    with pytest.raises(CapabilityUnavailableError):
        client.list_quotes(["600519"])

    assert sock.sent == []


def test_depth_quote_opt_in_delegates_with_inferred_market(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = {
        "code": "600519",
        "buy": [],
        "sell": [],
        "seal_amount": 0.0,
        "seal_type": None,
        "fields": {},
    }

    class FakeQuoteService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def depth_quote(self, code, **kwargs):
            calls.append((code, kwargs))
            return expected

    monkeypatch.setattr(
        "thspypc.services.QuoteService",
        FakeQuoteService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.depth_quote(
        "600519",
        timeout=4.0,
        retries=2,
    )

    assert result is expected
    assert calls == [
        ("600519", {"market": 17, "timeout": 4.0, "ten_levels": False}),
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_depth_quote_opt_in_preserves_empty_on_protocol_error(monkeypatch):
    client = _client()
    client._sock = FakeSocket()

    class BrokenQuoteService:
        def __init__(self, _connections, *, evidence=None, subscriptions=None):
            pass

        def depth_quote(self, _code, **_kwargs):
            raise ProtocolError("broken depth fixture")

    monkeypatch.setattr(
        "thspypc.services.QuoteService",
        BrokenQuoteService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    assert client.depth_quote("000001", retries=0) == {}


def test_depth_quote_opt_in_enforces_basic_quote_capability():
    client = _client()
    sock = FakeSocket()
    client._sock = sock
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.NO},
    )
    client.configure_service_context(profile)

    with pytest.raises(CapabilityUnavailableError):
        client.depth_quote("000001", retries=0)

    assert sock.sent == []


def test_depth_quote_opt_in_preserves_transport_retry(monkeypatch):
    client = _client()
    first_socket = FakeSocket()
    replacement = FakeSocket()
    client._sock = first_socket
    calls = []
    connect_calls = []
    expected = {"code": "000001", "buy": [], "sell": [], "fields": {}}

    class FlakyQuoteService:
        def __init__(self, _connections, *, evidence=None, subscriptions=None):
            pass

        def depth_quote(self, code, **kwargs):
            calls.append((code, kwargs))
            if len(calls) == 1:
                raise OSError("connection lost")
            return expected

    def reconnect():
        connect_calls.append(True)
        client._sock = replacement
        return LoginResult(success=True)

    monkeypatch.setattr(
        "thspypc.services.QuoteService",
        FlakyQuoteService,
    )
    monkeypatch.setattr(client, "connect", reconnect)
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.depth_quote("000001", timeout=3.0, retries=1)

    assert result is expected
    assert len(calls) == 2
    assert connect_calls == [True]
    assert first_socket.closed
    assert client._sock is replacement


def test_market_view_pipeline_delegates_to_quote_service(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = (
        {"code": "000001", "dt10": 12.34},
        {"code": "000001", "buy": [], "sell": []},
    )

    class FakeQuoteService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def market_view_pipeline(self, code, **kwargs):
            calls.append((code, kwargs))
            return expected

    monkeypatch.setattr("thspypc.services.QuoteService", FakeQuoteService)
    client.configure_service_context(LEVEL2_PROFILE)

    assert client.market_view_pipeline("000001", timeout=3.0) is expected
    assert calls == [("000001", {"market": 33, "timeout": 3.0})]


def test_kline_opt_in_delegates_without_l2(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = [{"code": "600519", "close": 141.5}]

    class FakeKlineService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def kline(self, code, **kwargs):
            calls.append((code, kwargs))
            return expected

    monkeypatch.setattr(
        "thspypc.services.KlineService",
        FakeKlineService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.kline(
        "600519",
        period="week",
        count=20,
        fuquan="H",
        timeout=5.0,
        retries=0,
    )

    assert result is expected
    assert calls == [
        (
            "600519",
            {
                "market": 17,
                "period": KLINE_PERIOD_WEEK,
                "count": 20,
                "anchor": 0,
                "fuquan": "H",
                    "timeout": 5.0,
                    "channel": "auto",
                    "latest": False,
                },
        )
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_kline_opt_in_preserves_empty_on_protocol_error(monkeypatch):
    client = _client()
    client._sock = FakeSocket()

    class BrokenKlineService:
        def __init__(self, _connections, *, evidence=None):
            pass

        def kline(self, _code, **_kwargs):
            raise ProtocolError("broken K-line fixture")

    monkeypatch.setattr(
        "thspypc.services.KlineService",
        BrokenKlineService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    assert client.kline("000001", count=20, retries=0) == []


def test_kline_opt_in_enforces_basic_quote_capability():
    client = _client()
    sock = FakeSocket()
    client._sock = sock
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.NO},
    )
    client.configure_service_context(profile)

    with pytest.raises(CapabilityUnavailableError):
        client.kline("000001", count=20, retries=0)

    assert sock.sent == []


def test_stock_list_hot_opt_in_delegates_without_l2(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []

    class FakeStockListService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def ranked(self, **kwargs):
            calls.append(kwargs)
            return [{"code": "600519", "name": "", "market": 17}]

    monkeypatch.setattr(
        "thspypc.services.StockListService",
        FakeStockListService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.stock_list_hot(
        count=1,
        timeout=3.0,
        sort_by=48,
        sort_dir="D",
        max_pages=2,
    )

    assert result == [{"code": "600519", "name": "", "market": 17}]
    assert calls == [
        {
            "count": 1,
            "timeout": 3.0,
            "sort_by": 48,
            "sort_dir": "D",
            "max_pages": 2,
            "with_values": False,
        }
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_auction_amount_anchor_calibrates_rows_beyond_old_top_120(monkeypatch):
    client = _client()
    anchors: dict[str, float] = {}
    rows = []
    for index in range(130):
        code = f"{600000 + index:06d}"
        amount = float(200_000_000 - index * 1_000_000)
        anchors[code] = amount
        rows.append({"code": code, "market": 17, "dt150": amount})
    target = rows[129]["code"]
    rows[129]["dt150"] = anchors[target] * 1e8
    calls = []

    def fake_list_quotes(codes, *, market, datatype, pageid, timeout):
        calls.append((list(codes), market, list(datatype), pageid, timeout))
        return [
            {"code": code, "dt7": 1.0, "dt17": anchors[code]}
            for code in codes
        ]

    monkeypatch.setattr(client, "list_quotes", fake_list_quotes)

    result = client._anchor_correct_money_sort(
        rows,
        sort_by=68758,
        sort_dir="D",
        with_values=True,
        timeout=2.0,
    )

    corrected = next(row for row in result if row["code"] == target)
    assert corrected["dt150"] == anchors[target]
    assert corrected["auction_amount"] == anchors[target]
    assert len(calls) == 1
    assert len(calls[0][0]) == 130
    assert calls[0][2] == [5, 7, 17]


def test_stock_list_opt_in_delegates_full_replay(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []

    class FakeStockListService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def full_list(self, **kwargs):
            calls.append(kwargs)
            return [{"code": "600519", "name": "", "market": 0}]

    monkeypatch.setattr(
        "thspypc.services.StockListService",
        FakeStockListService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.stock_list(timeout=4.0)

    assert result == [{"code": "600519", "name": "", "market": 0}]
    assert calls == [{"timeout": 4.0}]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_fetch_stock_names_opt_in_delegates_incremental_request(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = {
        "names": {"AUDUSD": "Australian Dollar"},
        "by_segment": {},
        "skipped": [],
        "segments": [],
    }

    class FakeStockNameService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def fetch(self, **kwargs):
            calls.append(kwargs)
            return expected

    monkeypatch.setattr(
        "thspypc.services.StockNameService",
        FakeStockNameService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.fetch_stock_names(
        market="UNS",
        stock_name_ver="20260728;1;",
        timeout=5.0,
    )

    assert result is expected
    assert calls == [
        {
            "market": "UNS",
            "stock_name_ver": "20260728;1;",
            "timeout": 5.0,
        }
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_market_snapshot_opt_in_delegates_without_l2(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = [{"code": "600519", "name": "Kweichow Moutai"}]

    class FakeMarketSnapshotService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def snapshot(self, **kwargs):
            calls.append(kwargs)
            return expected

    monkeypatch.setattr(
        "thspypc.services.MarketSnapshotService",
        FakeMarketSnapshotService,
    )
    manager = client.configure_service_context(LEVEL2_PROFILE)

    result = client.market_snapshot(markets=[16, 151], timeout=5.0)

    assert result is expected
    assert calls == [{"markets": [16, 151], "timeout": 5.0}]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_auction_opt_in_delegates_with_inferred_market(monkeypatch):
    client = _client()
    client._push_socks["sh"] = FakeSocket()
    client._push_initialized.add("sh")
    calls = []

    class FakeAuctionService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections
            self.subscriptions = subscriptions

        def auction(self, code, **kwargs):
            calls.append((code, kwargs))
            return [{"dt10": 15.01}]

    monkeypatch.setattr(
        "thspypc.services.AuctionService",
        FakeAuctionService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.auction(
        "603118",
        trade_date="2026-07-24",
        timeout=7.0,
    )

    assert result == [{"dt10": 15.01}]
    assert calls == [
        (
            "603118",
            {
                "market": 17,
                "trade_date": "2026-07-24",
                "timeout": 7.0,
            },
        )
    ]


def test_index_auction_delegates_with_inferred_market(monkeypatch):
    client = _client()
    calls = []

    class FakeAuctionService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections

        def auction(self, code, **kwargs):
            calls.append((code, kwargs))
            return [{"dt10": 14289.804919}]

    monkeypatch.setattr(
        "thspypc.services.AuctionService",
        FakeAuctionService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.auction("399001", timeout=7.0)

    assert result == [{"dt10": 14289.804919}]
    assert calls == [
        (
            "399001",
            {
                "market": 32,
                "trade_date": None,
                "timeout": 7.0,
            },
        )
    ]


def test_closing_auction_level2_delegates_with_l2_profile(monkeypatch):
    client = _client()
    client._push_socks["sh"] = FakeSocket()
    client._push_initialized.add("sh")
    calls = []

    class FakeAuctionService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections

        def closing_auction(self, code, **kwargs):
            calls.append(
                (self.connections.profile.kind, code, kwargs)
            )
            return [{"dt10": 15.01}]

    monkeypatch.setattr(
        "thspypc.services.AuctionService",
        FakeAuctionService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.closing_auction(
        "603118",
        trade_date="2026-07-24",
        timeout=7.0,
    )

    assert result == [{"dt10": 15.01}]
    assert calls == [
        (
            AccountKind.LEVEL2,
            "603118",
            {
                "market": 17,
                "trade_date": "2026-07-24",
                "timeout": 7.0,
            },
        )
    ]


def test_auction_opt_in_standard_profile_fails_before_opening():
    client = _client()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.BASIC_AUCTION: Support.NO,
            Capability.L2_MARKET_ACCESS: Support.NO,
            Capability.L2_AUCTION: Support.NO,
        },
    )
    client.configure_service_context(profile)

    with pytest.raises(CapabilityUnavailableError):
        client.auction("000938")


def test_auction_opt_in_reports_missing_l2_socket():
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError):
        client.auction("000938")


def test_auction_opt_in_rejects_uninitialized_l2_socket():
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError, match="init"):
        client.auction("000938")

    assert sock.sent == []


def test_auction_opt_in_rejects_competing_snapshot_reader():
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()

    with pytest.raises(ChannelUnavailableError, match="后台快照线程"):
        client.auction("000938")


def test_timeline_opt_in_delegates_with_inferred_market(monkeypatch):
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    calls = []

    class FakeTimelineService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections
            self.subscriptions = subscriptions

        def timeline(self, code, **kwargs):
            calls.append((code, kwargs))
            return [{"dt10": 12.34}]

    monkeypatch.setattr(
        "thspypc.services.TimelineService",
        FakeTimelineService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.timeline("000938", timeout=6.0)

    assert result == [{"dt10": 12.34}]
    assert calls == [
        (
            "000938",
            {"market": 33, "timeout": 6.0},
        )
    ]


def test_timeline_opt_in_standard_delegates_to_basic_service(monkeypatch):
    client = _client()
    calls = []

    class FakeTimelineService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections

        def timeline(self, code, **kwargs):
            calls.append((code, kwargs))
            return [{"code": code, "dt10": 12.34}]

    monkeypatch.setattr(
        "thspypc.services.TimelineService",
        FakeTimelineService,
    )
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.BASIC_TIMELINE: Support.YES,
            Capability.L2_MARKET_ACCESS: Support.NO,
            Capability.L2_TIMELINE: Support.NO,
        },
    )
    client.configure_service_context(profile)

    result = client.timeline("000938")

    assert result == [{"code": "000938", "dt10": 12.34}]
    assert calls == [
        ("000938", {"market": 33, "timeout": 12.0})
    ]


def test_timeline_opt_in_reports_missing_l2_socket():
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError):
        client.timeline("000938")


def test_timeline_opt_in_rejects_uninitialized_l2_socket():
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError, match="尚未完成 init"):
        client.timeline("000938")

    assert sock.sent == []


def test_timeline_opt_in_rejects_competing_snapshot_reader():
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()

    with pytest.raises(ChannelUnavailableError, match="后台快照线程"):
        client.timeline("000938")


def test_intraday_combines_historical_phases_in_display_order(
    monkeypatch,
):
    client = _client()
    calls = []
    monkeypatch.setattr(
        client,
        "auction",
        lambda code, **kwargs: (
            calls.append(("opening", code, kwargs))
            or [{"time": "09:15"}]
        ),
    )
    monkeypatch.setattr(
        client,
        "history_timeline",
        lambda code, value, **kwargs: (
            calls.append(("continuous", code, value, kwargs))
            or [{"bar_index": 1}]
        ),
    )
    monkeypatch.setattr(
        client,
        "closing_auction",
        lambda code, **kwargs: (
            calls.append(("closing", code, kwargs))
            or [{"time": "14:57"}]
        ),
    )

    result = client.intraday(
        "603118",
        market=17,
        trade_date="2026-05-15",
        timeout=6.0,
        retries=1,
    )

    assert [row["phase"] for row in result] == [
        "opening_auction",
        "continuous",
        "closing_auction",
    ]
    assert calls[0][0] == "opening"
    assert calls[1][0] == "continuous"
    assert calls[2][0] == "closing"


def test_level2_historical_intraday_uses_one_service_workflow(monkeypatch):
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)
    expected = [
        {"phase": "opening_auction", "time": "09:15"},
        {"phase": "continuous", "bar_index": 0},
        {"phase": "closing_auction", "time": "14:57"},
    ]
    calls = []
    monkeypatch.setattr(
        client._auction_service,
        "intraday",
        lambda code, **kwargs: (
            calls.append((code, kwargs)) or expected
        ),
    )
    monkeypatch.setattr(
        client,
        "auction",
        lambda *_args, **_kwargs: pytest.fail("must not make a second request"),
    )
    monkeypatch.setattr(
        client,
        "history_timeline",
        lambda *_args, **_kwargs: pytest.fail("must not make a second request"),
    )
    monkeypatch.setattr(
        client,
        "closing_auction",
        lambda *_args, **_kwargs: pytest.fail("must not make a second request"),
    )

    result = client.intraday(
        "603118",
        market=17,
        trade_date="2026-07-24",
        timeout=6.0,
    )

    assert result == expected
    assert calls == [
        (
            "603118",
            {"market": 17, "trade_date": "2026-07-24", "timeout": 6.0},
        )
    ]


def test_st_intraday_uses_base_shanghai_l2_market(monkeypatch):
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)
    calls = []
    monkeypatch.setattr(client, "_market_for_code", lambda _code: 22)
    monkeypatch.setattr(
        client._auction_service,
        "intraday",
        lambda code, **kwargs: calls.append((code, kwargs)) or [],
    )

    assert client.intraday(
        "600745",
        trade_date="2026-07-24",
        timeout=6.0,
    ) == []
    assert calls == [
        (
            "600745",
            {"market": 17, "trade_date": "2026-07-24", "timeout": 6.0},
        )
    ]


def test_intraday_level2_retries_bundle_then_falls_back_to_timeline(monkeypatch):
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)
    attempts = []

    def flaky_bundle(code, **kwargs):
        attempts.append((code, kwargs))
        raise ProtocolError("4214 订阅注册被拒绝: CodeListSize=0")

    monkeypatch.setattr(client._auction_service, "intraday", flaky_bundle)
    monkeypatch.setattr(
        client,
        "timeline",
        lambda code, **kwargs: [{"dt10": 10.5}],
    )

    result = client.intraday(
        "603118",
        market=17,
        trade_date="2026-07-24",
        timeout=6.0,
    )

    assert result == [{"phase": "continuous", "dt10": 10.5}]
    assert len(attempts) == 2


def test_historical_index_intraday_has_no_auction_phases(monkeypatch):
    client = _client()
    monkeypatch.setattr(
        client,
        "auction",
        lambda *_args, **_kwargs: pytest.fail(
            "historical index has no opening auction series"
        ),
    )
    monkeypatch.setattr(
        client,
        "closing_auction",
        lambda *_args, **_kwargs: pytest.fail(
            "historical index has no closing auction series"
        ),
    )
    monkeypatch.setattr(
        client,
        "history_timeline",
        lambda *_args, **_kwargs: [{"bar_index": 1, "lead_price": 3919.23}],
    )

    result = client.intraday(
        "1A0001",
        trade_date="2026-07-23",
    )

    assert result == [
        {
            "phase": "continuous",
            "bar_index": 1,
            "lead_price": 3919.23,
        }
    ]


def test_beijing_stock_intraday_skips_auction_phases(monkeypatch):
    from datetime import date as date_type

    client = _client()
    monkeypatch.setattr(
        client,
        "auction",
        lambda *_args, **_kwargs: pytest.fail(
            "BSE intraday must not request opening auction"
        ),
    )
    monkeypatch.setattr(
        client,
        "closing_auction",
        lambda *_args, **_kwargs: pytest.fail(
            "BSE intraday must not request closing auction"
        ),
    )
    timeline_calls = []
    monkeypatch.setattr(
        client,
        "timeline",
        lambda code, **kwargs: (
            timeline_calls.append((code, kwargs))
            or [{"dt10": 10.5}]
        ),
    )

    result = client.intraday(
        "920083",
        market=151,
        trade_date=date_type.today().isoformat(),
    )

    assert result == [{"phase": "continuous", "dt10": 10.5}]
    assert timeline_calls == [
        ("920083", {"market": 151, "timeout": 12.0})
    ]

    # 非交易日/盘前同样走 timeline（服务端返回最近交易日序列），不请求竞价。
    result = client.intraday(
        "920083",
        market=151,
        trade_date="2026-07-23",
    )
    assert result == [{"phase": "continuous", "dt10": 10.5}]


def test_controlled_opener_builds_and_caches_borrowed_l2_socket(
    monkeypatch,
):
    client = _client()
    client.authenticate = lambda **_kwargs: object()
    sock = FakeSocket()
    opened_markets = []
    materials = []

    def open_manual(market, *, material):
        opened_markets.append(market)
        materials.append(material)
        return sock

    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        open_manual,
    )
    manager = client.configure_service_context(
        LEVEL2_PROFILE,
        allow_open=True,
    )

    first = manager.acquire(
        ConnectionRole.SZ_L2,
        capability=Capability.L2_AUCTION,
    )
    second = manager.acquire(
        ConnectionRole.SZ_L2,
        capability=Capability.L2_TIMELINE,
    )

    assert first is second
    assert opened_markets == [33]
    assert len(materials) == 1
    assert first.socket is sock
    assert not first.owns_socket
    assert first.init_complete
    assert client._push_socks["sz"] is sock

    client.disconnect()
    assert sock.closed
    assert not first.active


def test_controlled_opener_can_bridge_main_login(monkeypatch):
    client = _client()
    sock = FakeSocket()
    login_calls = []

    def connect_main():
        login_calls.append(True)
        client._sock = sock
        return LoginResult(success=True)

    monkeypatch.setattr(client, "connect_main", connect_main)
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.BASIC_QUOTE: Support.YES},
    )
    manager = client.configure_service_context(
        profile,
        allow_open=True,
    )

    connection = manager.acquire(
        ConnectionRole.MAIN,
        capability=Capability.BASIC_QUOTE,
    )

    assert login_calls == [True]
    assert connection.socket is sock
    assert not connection.owns_socket
    assert connection.init_complete


def test_controlled_opener_reports_l2_open_failure(monkeypatch):
    client = _client()
    client.authenticate = lambda **_kwargs: object()
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        lambda _market, *, material: None,
    )
    manager = client.configure_service_context(
        LEVEL2_PROFILE,
        allow_open=True,
    )

    with pytest.raises(ChannelUnavailableError, match="建连或 init 失败"):
        manager.acquire(ConnectionRole.SH_L2)

    assert client._push_socks == {}


def test_service_context_open_mode_cannot_change():
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ValueError, match="allow_open"):
        client.configure_service_context(
            LEVEL2_PROFILE,
            allow_open=True,
        )


def test_history_timeline_opt_in_delegates_to_l2_service(monkeypatch):
    client = _client()
    client._push_socks["sh"] = FakeSocket()
    client._push_initialized.add("sh")
    calls = []

    class FakeTimelineService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections
            self.subscriptions = subscriptions

        def history_timeline(self, code, **kwargs):
            calls.append((code, kwargs))
            return [{"dt10": 15.02}]

    monkeypatch.setattr(
        "thspypc.services.TimelineService",
        FakeTimelineService,
    )
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.history_timeline(
        "603118",
        "2026-07-24",
        timeout=8.0,
    )

    assert result == [{"dt10": 15.02}]
    assert calls == [
        (
            "603118",
            {
                "market": 17,
                "date": "2026-07-24",
                "timeout": 8.0,
            },
        )
    ]


def test_history_timeline_opt_in_standard_stops_before_opening():
    client = _client()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.NO,
            Capability.L2_HISTORY_TIMELINE: Support.NO,
        },
    )
    client.configure_service_context(profile)

    with pytest.raises(UnsupportedAccountFeatureError):
        client.history_timeline("000938", "2026-07-24")


def test_history_timeline_opt_in_rejects_uninitialized_l2_socket():
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError, match="尚未完成 init"):
        client.history_timeline("000938", "2026-07-24")

    assert sock.sent == []


def test_history_timeline_opt_in_rejects_competing_snapshot_reader():
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()

    with pytest.raises(ChannelUnavailableError, match="后台快照线程"):
        client.history_timeline("000938", "2026-07-24")


def test_snapshot_subscribe_opt_in_registers_and_starts_one_reader(
    monkeypatch,
):
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)
    client._service_subscriptions._read_frame = (
        lambda _sock: b"CodeListSize=1"
    )
    threads = []

    class FakeThread:
        def __init__(self, *, target, name, daemon):
            self.target = target
            self.name = name
            self.daemon = daemon
            self.started = False
            threads.append(self)

        def start(self):
            self.started = True

        def is_alive(self):
            return self.started

    monkeypatch.setattr("thspypc.client.threading.Thread", FakeThread)

    assert client.snapshot_subscribe("000938")
    assert client.snapshot_subscribe("000938")

    assert len(sock.sent) == 1
    assert b"CodeList=33(000938,);" in sock.sent[0]
    assert client._snapshot_codes == {"000938"}
    assert len(threads) == 1
    assert threads[0].started


def test_snapshot_subscribe_opt_in_standard_fails_before_opening():
    client = _client()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.NO,
            Capability.L2_SNAPSHOT_PUSH: Support.NO,
        },
    )
    client.configure_service_context(profile, allow_open=True)

    with pytest.raises(CapabilityUnavailableError):
        client.snapshot_subscribe("000938")

    assert client._push_socks == {}


def test_snapshot_subscribe_opt_in_unknown_fails_before_opening():
    client = _client()
    client.configure_service_context(
        AccountProfile(kind=AccountKind.UNKNOWN),
        allow_open=True,
    )

    with pytest.raises(UnsupportedAccountFeatureError):
        client.snapshot_subscribe("603118")

    assert client._push_socks == {}


def test_snapshot_subscribe_opt_in_reports_missing_l2_socket():
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError):
        client.snapshot_subscribe("000938")


def test_snapshot_subscribe_opt_in_rejects_uninitialized_l2_socket():
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    client.configure_service_context(LEVEL2_PROFILE)

    with pytest.raises(ChannelUnavailableError, match="尚未完成 init"):
        client.snapshot_subscribe("000938")

    assert sock.sent == []
    assert client._snapshot_thread is None


def test_snapshot_subscribe_opt_in_protocol_rejection_returns_false(
    monkeypatch,
):
    client = _client()
    sock = FakeSocket()
    client._push_socks["sh"] = sock
    client._push_initialized.add("sh")
    client.configure_service_context(LEVEL2_PROFILE)
    client._service_subscriptions._read_frame = (
        lambda _sock: b"CodeListSize=0"
    )

    assert not client.snapshot_subscribe("603118")
    assert client._snapshot_thread is None
    assert client._snapshot_codes == set()


def test_snapshot_loop_reads_under_market_request_lock(monkeypatch):
    client = _client()
    sock = FakeSocket()
    client._push_socks["sz"] = sock
    lock_state = {"held": False}
    callbacks = []

    class TrackingLock:
        def __enter__(self):
            assert not lock_state["held"]
            lock_state["held"] = True

        def __exit__(self, exc_type, exc, tb):
            lock_state["held"] = False

    client._push_request_locks["sz"] = TrackingLock()
    client._snapshot_cb = lambda *args: callbacks.append(args)
    monkeypatch.setattr(
        "select.select",
        lambda read, _write, _error, _timeout: (read, [], []),
    )

    def frame_reader(_sock):
        assert lock_state["held"]
        client._snapshot_stop.set()
        return b"snapshot"

    monkeypatch.setattr("thspypc.client.read_frame", frame_reader)
    monkeypatch.setattr("thspypc.client.is_snapshot_push", lambda _body: True)
    monkeypatch.setattr(
        "thspypc.client.parse_snapshot_push",
        lambda _body: {
            "code": "000938",
            "market": "sz",
            "price": 12.34,
            "volume": 100,
        },
    )

    client._snapshot_loop()

    assert not lock_state["held"]
    assert client.latest_price("000938") == 12.34
    assert callbacks == [("000938", "sz", 12.34, 100)]


def test_depth_subscribe_multi_market_and_local_unsubscribe_lifecycle(monkeypatch):
    client = _client()
    sh = FakeSocket()
    sz = FakeSocket()
    client._push_socks.update({"sh": sh, "sz": sz})
    client._push_initialized.update({"sh", "sz"})
    client.configure_service_context(LEVEL2_PROFILE)
    client._service_subscriptions._read_frame = lambda _sock: b"CodeListSize=1"
    threads = []

    class FakeThread:
        def __init__(self, *, target, name, daemon):
            self.target = target
            self.name = name
            self.daemon = daemon
            self.started = False
            self.joined = False
            threads.append(self)

        def start(self):
            self.started = True

        def is_alive(self):
            return self.started and not self.joined

        def join(self, timeout=None):
            self.joined = True

    monkeypatch.setattr("thspypc.client.threading.Thread", FakeThread)
    callback = lambda _record: None

    assert client.depth_subscribe("603118", callback=callback)
    assert client.depth_subscribe("000938")
    assert client.depth_subscribe("603118", callback=callback)

    assert len(sh.sent) == 1
    assert len(sz.sent) == 1
    assert client._connection_runtime.depth_codes == {"603118", "000938"}
    assert client._connection_runtime.depth_callbacks == {"603118": callback}
    assert len(threads) == 1

    client._connection_runtime.latest_depth["603118"] = {"code": "603118"}
    assert client.depth_unsubscribe("603118")
    assert not sh.closed and not sz.closed
    assert "603118" not in client._connection_runtime.latest_depth
    assert not client.depth_unsubscribe("603118")

    assert client.depth_unsubscribe("000938")
    assert sh.closed and sz.closed
    assert client._connection_runtime.depth_codes == set()
    assert client._snapshot_thread is None


def test_depth_subscribe_standard_account_is_rejected_before_opening():
    client = _client()
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.NO,
            Capability.L2_SNAPSHOT_PUSH: Support.NO,
        },
    )
    client.configure_service_context(profile, allow_open=True)

    with pytest.raises(CapabilityUnavailableError):
        client.depth_subscribe("000938")

    assert client._push_socks == {}


def test_snapshot_loop_dispatches_every_record_in_batched_depth_frame(monkeypatch):
    client = _client()
    sock = FakeSocket()
    client._push_socks["sh"] = sock
    runtime = client._connection_runtime
    runtime.depth_codes.update({"600000", "600012"})
    callbacks = []
    runtime.depth_callbacks["600012"] = callbacks.append
    records = [
        {
            "code": "600000",
            "market": "SH",
            "phase": "continuous",
            "price": 10.01,
            "bids": [(10.0, 100)],
            "asks": [(10.02, 200)],
        },
        {
            "code": "600012",
            "market": "SH",
            "phase": "continuous",
            "price": 7.89,
            "bids": [(7.88, 300)],
            "asks": [(7.9, 400)],
        },
    ]
    monkeypatch.setattr(
        "select.select",
        lambda read, _write, _error, _timeout: (read, [], []),
    )

    def frame_reader(_sock):
        runtime.snapshot_stop.set()
        return b"batched-depth"

    runtime.snapshot_loop(
        read_frame=frame_reader,
        is_snapshot_push=lambda _body: False,
        parse_snapshot_push=lambda _body: None,
        is_depth_push=lambda _body: True,
        parse_depth_push_records=lambda _body: records,
    )

    assert set(runtime.latest_depth) == {"600000", "600012"}
    assert callbacks == [records[1]]
    assert client.receive_depth(timeout=0) == records[0]
    assert client.receive_depth(timeout=0) == records[1]
    assert client.receive_depth(timeout=0) is None


def test_context_borrows_realorder_socket():
    client = _client()
    sock = FakeSocket()
    client._realorder_sock = sock

    manager = client.configure_service_context(LEVEL2_PROFILE)

    connection = manager.peek(ConnectionRole.REALORDER)
    assert connection.socket is sock
    assert not connection.owns_socket
    assert connection.init_complete


def test_realorder_public_methods_delegate_in_service_context(monkeypatch):
    calls = []

    class FakeRealOrderService:
        def __init__(self, connections, next_instance):
            self.connections = connections
            self.next_instance = next_instance

        def dxjl_page(self, market, endtime_us):
            calls.append(("page", market, endtime_us))
            return [{"时间": 3}]

        def dxjl_latest(self, *, markets):
            calls.append(("latest", markets))
            return [{"时间": 4}]

        def dxjl_history(self, *, pages, markets, now_us=None):
            calls.append(("history", pages, markets, now_us))
            return [{"时间": 2}]

        def subscribe_realtime(self, markets):
            calls.append(("subscribe", markets))

        def receive_pushes(
            self,
            *,
            timeout,
            callback=None,
            full_frame_callback=None,
            continue_on_timeout=False,
        ):
            calls.append(
                (
                    "receive",
                    timeout,
                    callback,
                    full_frame_callback,
                    continue_on_timeout,
                )
            )
            return ([{"代码": "000938"}], 7)

        def send_heartbeat(self, seq):
            calls.append(("heartbeat", seq))
            return True

    monkeypatch.setattr(
        "thspypc.services.RealOrderService",
        FakeRealOrderService,
    )
    client = _client()
    client.configure_service_context(LEVEL2_PROFILE)

    assert client.dxjl_page(32, 123) == [{"时间": 3}]
    assert client.dxjl_latest((32,)) == [{"时间": 4}]
    assert client.dxjl_history(2, (16,)) == [{"时间": 2}]
    # 前端上拉翻历史：endtime 游标透传为 now_us
    assert client.dxjl_history(1, (32, 16), 1755475200_000000) == [{"时间": 2}]
    client.subscribe_realtime([16, 32])
    assert client.receive_pushes(timeout=6.0) == [{"代码": "000938"}]
    assert client.receive_pushes_locked(timeout=4.0) == 7

    assert calls == [
        ("page", 32, 123),
        ("latest", (32,)),
        ("history", 2, (16,), None),
        ("history", 1, (32, 16), 1755475200_000000),
        ("subscribe", [16, 32]),
        ("receive", 6.0, None, None, False),
        ("receive", 4.0, None, None, True),
    ]


@pytest.mark.parametrize(
    ("profile", "error"),
    [
        (
            AccountProfile(
                kind=AccountKind.STANDARD,
                capabilities={Capability.REALORDER: Support.NO},
            ),
            CapabilityUnavailableError,
        ),
        (
            AccountProfile(kind=AccountKind.UNKNOWN),
            UnsupportedAccountFeatureError,
        ),
    ],
)
def test_realorder_opt_in_fails_before_opening(monkeypatch, profile, error):
    client = _client()
    opened = []
    monkeypatch.setattr(
        client,
        "_connect_realorder_server",
        lambda: opened.append(True),
    )
    client.configure_service_context(profile, allow_open=True)

    with pytest.raises(error):
        client.dxjl_page(32, 123)

    assert opened == []


def test_realorder_socket_is_not_adopted_without_explicit_yes():
    client = _client()
    sock = FakeSocket()
    client._realorder_sock = sock
    profile = AccountProfile(
        kind=AccountKind.STANDARD,
        capabilities={Capability.REALORDER: Support.NO},
    )

    manager = client.configure_service_context(profile)

    assert manager.peek(ConnectionRole.REALORDER) is None
    assert not sock.closed
