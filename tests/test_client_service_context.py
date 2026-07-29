"""Contracts for borrowing legacy THSClient sockets into services."""

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
        def __init__(self, connections, *, evidence=None):
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
        def __init__(self, _connections, *, evidence=None):
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
        def __init__(self, connections, *, evidence=None):
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
        ("600519", {"market": 17, "timeout": 4.0}),
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_depth_quote_opt_in_preserves_empty_on_protocol_error(monkeypatch):
    client = _client()
    client._sock = FakeSocket()

    class BrokenQuoteService:
        def __init__(self, _connections, *, evidence=None):
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
        def __init__(self, _connections, *, evidence=None):
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


def test_kline_opt_in_delegates_without_l2(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []
    expected = [{"code": "600519", "close": 141.5}]

    class FakeKlineService:
        def __init__(self, connections, *, evidence=None):
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
                "fuquan": "H",
                "timeout": 5.0,
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


def test_kline_opt_in_preserves_incomplete_data_retry(monkeypatch):
    client = _client()
    first_socket = FakeSocket()
    replacement = FakeSocket()
    client._sock = first_socket
    client._connected_ip = "bad-ip"
    responses = iter(
        [
            [{"code": "000001"}] * 10,
            [{"code": "000001"}] * 100,
        ]
    )
    calls = []
    connect_calls = []

    class PartialKlineService:
        def __init__(self, _connections, *, evidence=None):
            pass

        def kline(self, code, **kwargs):
            calls.append((code, kwargs))
            return next(responses)

    def reconnect():
        connect_calls.append(True)
        client._sock = replacement
        client._connected_ip = "good-ip"
        return LoginResult(success=True)

    monkeypatch.setattr(
        "thspypc.services.KlineService",
        PartialKlineService,
    )
    monkeypatch.setattr(client, "connect", reconnect)
    client.configure_service_context(LEVEL2_PROFILE)

    result = client.kline("000001", count=100, retries=1)

    assert len(result) == 100
    assert len(calls) == 2
    assert connect_calls == [True]
    assert "bad-ip" in client._bad_kline_ips
    assert first_socket.closed
    assert client._sock is replacement


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
        def __init__(self, connections, *, evidence=None):
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
        }
    ]
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert manager.peek(ConnectionRole.SZ_L2) is None


def test_stock_list_opt_in_delegates_full_replay(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    calls = []

    class FakeStockListService:
        def __init__(self, connections, *, evidence=None):
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
        def __init__(self, connections, *, evidence=None):
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
        def __init__(self, connections, *, evidence=None):
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


def test_controlled_opener_builds_and_caches_borrowed_l2_socket(
    monkeypatch,
):
    client = _client()
    client._auth = {}
    sock = FakeSocket()
    opened_markets = []

    def open_manual(market):
        opened_markets.append(market)
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
    client._auth = {}
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        lambda _market: None,
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

        def dxjl_history(self, *, pages, markets):
            calls.append(("history", pages, markets))
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
    client.subscribe_realtime([16, 32])
    assert client.receive_pushes(timeout=6.0) == [{"代码": "000938"}]
    assert client.receive_pushes_locked(timeout=4.0) == 7

    assert calls == [
        ("page", 32, 123),
        ("latest", (32,)),
        ("history", 2, (16,)),
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
