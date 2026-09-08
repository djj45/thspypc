"""Contracts for borrowing legacy THSClient sockets into services."""

import concurrent.futures
from pathlib import Path
import threading
import time
from types import SimpleNamespace

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


def test_seal_table_failure_is_negative_cached(monkeypatch):
    client = _client()
    calls = []

    def fail_rank(**kwargs):
        calls.append(kwargs)
        raise ProtocolError("drifted response")

    monkeypatch.setattr(client, "stock_list_hot", fail_rank)

    assert client._seal_table() == {}
    assert client._seal_table() == {}
    assert len(calls) == 1


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


def test_l2_stale_passport_refreshes_only_once(monkeypatch):
    client = _client()
    initial = SimpleNamespace(
        passport64="passport-initial",
        passport_bytes=b"passport-initial-bytes",
    )
    fresh = SimpleNamespace(
        passport64="passport-fresh",
        passport_bytes=b"passport-fresh-bytes",
    )
    auth_calls = []
    login_calls = []

    monkeypatch.setattr(
        "thspypc.protocol.resolve_l2_hosts_grouped",
        lambda _passport: {"sh": [], "sz": ["192.0.2.1"]},
    )
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda hosts, timeout, role: list(hosts),
    )
    monkeypatch.setattr(
        client,
        "_rotated_l2_batch",
        lambda hosts, _key: list(hosts),
    )
    monkeypatch.setattr(client, "_advance_l2_offset", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        client,
        "_try_open_manual_sock",
        lambda host, passport, *_args, **_kwargs: (
            login_calls.append((host, passport)) or "stale_passport"
        ),
    )
    monkeypatch.setattr(
        client,
        "authenticate",
        lambda *, force=False: auth_calls.append(force) or fresh,
    )

    assert client._open_manual_push_connection(33, material=initial) is None
    assert auth_calls == [True]
    assert login_calls == [
        ("192.0.2.1", "passport-initial"),
        ("192.0.2.1", "passport-fresh"),
    ]


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


def test_amount_sort_anchor_uses_light_dt19_table_for_full_list(monkeypatch):
    """成交额(19)虚值必须用 [5,19] 真值表全表锚定，不能退回 0xc4 近似。

    历史缺陷（2026-09-04）：19 走 0xc4 大表无 dt19，锚点是 dt13×dt10 的
    近似值，±0.1% 倍率窗匹配不上虚值 → 校正静默失效、全榜乱序。
    """
    client = _client()
    anchors: dict[str, float] = {}
    rows = []
    for index in range(130):
        code = f"{600000 + index:06d}"
        amount = float(200_000_000 - index * 1_000_000)
        anchors[code] = amount
        rows.append({"code": code, "market": 17, "dt19": amount})
    target = rows[129]["code"]
    rows[129]["dt19"] = anchors[target] * 1e4
    calls = []

    def fake_list_quotes(codes, *, market, datatype, pageid, timeout):
        calls.append((list(codes), market, list(datatype), pageid, timeout))
        return [{"code": code, "dt19": anchors[code]} for code in codes]

    monkeypatch.setattr(client, "list_quotes", fake_list_quotes)

    result = client._anchor_correct_money_sort(
        rows,
        sort_by=19,
        sort_dir="D",
        with_values=True,
        timeout=2.0,
    )

    corrected = next(row for row in result if row["code"] == target)
    assert corrected["dt19"] == anchors[target]
    assert calls[0][2] == [5, 19]
    # 全表锚定（不止头 120 行），且虚拟行按真值回到榜尾位置
    assert len(calls[0][0]) == 130
    assert result.index(corrected) == 129


def test_money_sort_anchor_cache_suppresses_repeat_batches(monkeypatch):
    """全表锚定按 TTL 缓存：5s 轮询不能每轮都在 MAIN 上重打全部批次。"""
    client = _client()
    anchors = {f"{600000 + i:06d}": float(1_000_000 + i) for i in range(20)}
    rows = [
        {"code": code, "market": 17, "dt19": value}
        for code, value in anchors.items()
    ]
    rows[0]["dt19"] = anchors[rows[0]["code"]] * 1e4
    calls = []

    def fake_list_quotes(codes, *, market, datatype, pageid, timeout):
        calls.append(list(codes))
        return [{"code": code, "dt19": anchors[code]} for code in codes]

    monkeypatch.setattr(client, "list_quotes", fake_list_quotes)

    for _ in range(3):
        result = client._anchor_correct_money_sort(
            [dict(r) for r in rows],
            sort_by=19,
            sort_dir="D",
            with_values=True,
            timeout=2.0,
        )
        assert result[0]["dt19"] == anchors[result[0]["code"]]

    # 三轮轮询只允许首批网络请求一次（TTL 内复用缓存锚点）
    assert len(calls) == 1

    # 覆盖率不足（锚点大部分失败）不得写缓存：下轮仍会重试
    calls.clear()

    def flaky_list_quotes(codes, *, market, datatype, pageid, timeout):
        calls.append(list(codes))
        return []  # 全部失败

    monkeypatch.setattr(client, "list_quotes", flaky_list_quotes)
    fresh = _client()
    monkeypatch.setattr(fresh, "list_quotes", flaky_list_quotes)
    fresh._anchor_correct_money_sort(
        [dict(r) for r in rows], sort_by=19, sort_dir="D",
        with_values=True, timeout=2.0,
    )
    fresh._anchor_correct_money_sort(
        [dict(r) for r in rows], sort_by=19, sort_dir="D",
        with_values=True, timeout=2.0,
    )
    assert len(calls) == 2


def test_stock_list_cached_backfills_unnamed_rows_on_cache_hit(monkeypatch, tmp_path):
    """当日 stocks2 缓存命中时补全空名称行（新股/首日同步竞态）并回写。"""
    import json

    from thspypc._client.stock_cache import save_stock_codes

    client = _client()
    cache_path = str(tmp_path / "stocks.json")
    save_stock_codes(
        [
            {"code": "600000", "name": "浦发银行", "market": 17},
            {"code": "920289", "name": "", "market": None},
        ],
        cache_path,
    )

    def fake_names(self, timeout=45.0):
        return {"names": {"920289": "N华汇"}}

    monkeypatch.setattr(type(client), "fetch_stock_names_full", fake_names)

    result = client.stock_list_cached(cache_path=cache_path)

    assert next(r for r in result if r["code"] == "920289")["name"] == "N华汇"
    with open(cache_path, encoding="utf-8") as f:
        assert next(
            r for r in json.load(f)["stocks"] if r["code"] == "920289"
        )["name"] == "N华汇"

    # 名称源补不上时不空转重写（saved_at 不变）
    with open(cache_path, encoding="utf-8") as f:
        saved_at = json.load(f)["saved_at"]
    monkeypatch.setattr(
        type(client), "fetch_stock_names_full", lambda self, timeout=45.0: {"names": {}}
    )
    client.stock_list_cached(cache_path=cache_path)
    with open(cache_path, encoding="utf-8") as f:
        assert json.load(f)["saved_at"] == saved_at


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


def test_auction_opt_in_shares_lane_with_snapshot_reader(monkeypatch):
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()
    monkeypatch.setattr(
        client._auction_service,
        "auction",
        lambda code, **kwargs: [{"code": code, "time": "09:15"}],
    )

    assert client.auction("000938") == [
        {"code": "000938", "time": "09:15"}
    ]


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


def test_timeline_opt_in_shares_lane_with_snapshot_reader(monkeypatch):
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()
    monkeypatch.setattr(
        client._timeline_service,
        "timeline",
        lambda code, **kwargs: [{"code": code, "dt10": 12.34}],
    )

    assert client.timeline("000938") == [
        {"code": "000938", "dt10": 12.34}
    ]


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

    class ActiveThread:
        def is_alive(self):
            return True

    # The WebSocket push reader may already be running when the page requests
    # its initial three-phase timeline.  Both paths must share the market lane
    # instead of rejecting the HTTP request.
    client._snapshot_thread = ActiveThread()
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


def test_beijing_stock_market_events_prepare_skips_l2_registration():
    # 北交所无 shlv2/szlv2 通道：stock-ready 门禁不得抛 500（2026-09-08 实测）。
    client = _client()
    assert client.market_events_prepare("920118", market=151) == 151
    assert client.market_events_prepare("920118") == 151


def test_beijing_stock_depth_quote_returns_empty_book():
    # 北交所盘口（10443 五档）未实现，返回空盘口而非抛错（前端显示无数据）。
    client = _client()
    assert client.depth_quote("920118", market=151) == {}
    assert client.depth_quote("920118", market=151, ten_levels=True) == {}


def test_beijing_stock_order_queues_return_empty():
    # 北交所无 7173/7174 队列通道：返回空队列而非抛错。
    client = _client()
    assert client.order_queues("920118", market=151) == {}


def test_beijing_stock_intraday_synthesizes_from_kline(monkeypatch):
    from datetime import date as date_type, datetime

    client = _client()
    monkeypatch.setattr(
        client,
        "auction",
        lambda *_args, **_kwargs: pytest.fail(
            "BSE intraday must not request SH/SZ opening auction"
        ),
    )
    monkeypatch.setattr(
        client,
        "closing_auction",
        lambda *_args, **_kwargs: pytest.fail(
            "BSE intraday must not request SH/SZ closing auction"
        ),
    )
    # BSE 早盘竞价走 6144 窗（_bse_opening_auction），不走沪深 auction()。
    auction_calls = []

    def fake_opening(code, *, market, trade_date, timeout):
        auction_calls.append((code, trade_date, timeout))
        return [
            {"time": datetime(2026, 9, 8, 9, 15, 5), "dt10": 22.19, "dt13": 100},
            {"time": datetime(2026, 9, 8, 9, 24, 44), "dt10": 22.09, "dt13": 205},
        ]

    monkeypatch.setattr(client, "_bse_opening_auction", fake_opening)

    # 1 分钟K夹带上一交易日尾巴（bar_index 隔夜大跳变），合成时应切除。
    minute_bars = [
        {"bar_index": 900, "open": 1.0, "high": 1.0, "low": 1.0,
         "close": 1.0, "volume": 10.0, "amount": 10.0},
        {"bar_index": 1900, "open": 10.0, "high": 11.0, "low": 9.5,
         "close": 10.5, "volume": 100.0, "amount": 1050.0},
        {"bar_index": 1901, "open": 10.5, "high": 10.8, "low": 10.2,
         "close": 10.6, "volume": 200.0, "amount": 2120.0},
    ]
    kline_calls = []

    def fake_kline(code, *, period, **kwargs):
        kline_calls.append((code, period, kwargs.get("fuquan")))
        if period == "day":
            return [
                {"time": "2026-07-23", "bar_index": 5100, "close": 9.9},
            ]
        return list(minute_bars)

    monkeypatch.setattr(client, "kline", fake_kline)

    result = client.intraday(
        "920083",
        market=151,
        trade_date=date_type.today().isoformat(),
    )

    assert [r["phase"] for r in result] == [
        "opening_auction", "opening_auction", "continuous", "continuous",
    ]
    first, second = result[-2:]
    assert first["dt10"] == 10.5 and first["dt13"] == 100 and first["dt19"] == 1050
    assert second["dt10"] == 10.6 and second["dt13"] == 300 and second["dt19"] == 3170
    assert "dt14" not in first and "dt227" not in first
    assert kline_calls[0] == ("920083", "1min", "N")
    assert auction_calls[0][0] == "920083"


def test_beijing_stock_intraday_historical_uses_8192_window(monkeypatch):
    from datetime import date as date_type

    import thspypc.services.timeline as timeline_svc

    client = _client()
    hist_calls = []

    def fake_hist(service, code, *, date, market, timeout):
        hist_calls.append((code, date, market))
        return [
            {"bar_index": 132719198, "dt10": 21.6, "dt13": 3100.0,
             "dt19": 66960.0, "dt22": 11400.0, "dt23": 7302.0},
            {"bar_index": 132719199, "dt10": 21.61, "dt13": 3300.0,
             "dt19": 71286.0, "dt22": 11500.0, "dt23": 7402.0},
            {"bar_index": 132719552, "dt10": 21.94, "dt13": 929425.0,
             "dt19": 20466813.0, "dt22": 9560.0, "dt23": 18861.0},
        ]

    monkeypatch.setattr(timeline_svc, "bse_history_timeline", fake_hist)
    monkeypatch.setattr(
        client,
        "_bse_opening_auction",
        lambda *a, **k: [
            {"time": "2026-09-04T09:15:02", "dt10": 21.19, "dt13": 500},
        ],
    )
    # 历史日期不得触发当日分钟K合成。
    monkeypatch.setattr(
        client,
        "kline",
        lambda *_a, **_k: pytest.fail("BSE 历史分时不得请求分钟K"),
    )

    result = client.intraday(
        "920118",
        market=151,
        trade_date="2026-09-04",
    )

    assert [r["phase"] for r in result] == [
        "opening_auction", "continuous", "continuous", "continuous",
    ]
    continuous = result[1:]
    assert [r["minute_index"] for r in continuous] == [0, 1, 2]
    assert continuous[0]["bar_index"] == 132719198
    assert continuous[0]["dt10"] == 21.6
    assert continuous[-1]["dt10"] == 21.94
    assert continuous[-1]["dt13"] == 929425
    # date 透传为 date 对象（intraday 内部已归一化）
    assert hist_calls == [
        ("920118", date_type(2026, 9, 4), 151),
    ]


def test_beijing_stock_intraday_historical_failure_returns_empty(monkeypatch):
    import thspypc.services.timeline as timeline_svc

    client = _client()
    monkeypatch.setattr(
        timeline_svc,
        "bse_history_timeline",
        lambda *a, **k: (_ for _ in ()).throw(ConnectionError("boom")),
    )
    monkeypatch.setattr(client, "_bse_opening_auction", lambda *a, **k: [])
    # 连接失败时关闭 MAIN 连接由 _service_connections 为 None 时跳过。
    result = client.intraday(
        "920118",
        market=151,
        trade_date="2026-09-04",
    )
    assert result == []


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


def test_history_timeline_opt_in_shares_lane_with_snapshot_reader(monkeypatch):
    client = _client()
    client._push_socks["sz"] = FakeSocket()
    client._push_initialized.add("sz")
    client.configure_service_context(LEVEL2_PROFILE)

    class ActiveThread:
        def is_alive(self):
            return True

    client._snapshot_thread = ActiveThread()
    monkeypatch.setattr(
        client._timeline_service,
        "history_timeline",
        lambda code, **kwargs: [{"code": code, "bar_index": 0}],
    )

    assert client.history_timeline("000938", "2026-07-24") == [
        {"code": "000938", "bar_index": 0}
    ]


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


def test_l2_heartbeat_skips_probe_while_request_lane_is_busy(monkeypatch):
    """The Windows liveness probe must not toggle a socket used by recv."""
    client = _client()
    sock = FakeSocket()
    client._push_socks["sh"] = sock

    class BusyLock:
        def __init__(self):
            self.acquire_calls = 0

        def acquire(self, *, blocking=True):
            assert blocking is False
            self.acquire_calls += 1
            return False

        def release(self):
            raise AssertionError("an unacquired busy lane cannot be released")

    class OneBeat:
        def __init__(self):
            self.wait_calls = 0

        def is_set(self):
            return self.wait_calls > 0

        def wait(self, _timeout):
            self.wait_calls += 1
            return False

    lock = BusyLock()
    client._push_request_locks["sh"] = lock
    client._connection_runtime._push_request_locks["sh"] = lock
    client._connection_runtime.heartbeat_stop = OneBeat()
    monkeypatch.setattr(
        "thspypc._client.connection_runtime._real_socket_alive",
        lambda _sock: (_ for _ in ()).throw(
            AssertionError("busy request lane must skip socket probing")
        ),
    )

    client._connection_runtime.heartbeat_loop(
        build_main_heartbeat=lambda _seq: b"heartbeat"
    )

    assert lock.acquire_calls == 1
    assert sock.sent == []


def test_main_heartbeat_probe_uses_dispatcher_and_records_ack():
    client = _client()
    sock = FakeSocket()
    client._sock = sock
    runtime = client._connection_runtime
    probe = b"framed-probe"

    assert runtime._schedule_dispatch_probe(
        "main",
        sock,
        client._market_session,
        probe,
        lambda _sock: b"\x09\x00\x00\x00",
    )

    deadline = time.monotonic() + 1.0
    while runtime.heartbeat_status()["lanes"]["main"]["pending"]:
        assert time.monotonic() < deadline
        time.sleep(0.005)
    status = runtime.heartbeat_status()["lanes"]["main"]
    assert runtime.heartbeat_status()["probe_interval_seconds"] == 60
    assert sock.sent == [probe]
    assert status["state"] == "healthy"
    assert status["probes_sent"] == 1
    assert status["responses"] == 1
    assert status["explicit_acks"] == 1


def test_heartbeat_dispatch_timeout_is_only_probe_silence():
    client = _client()
    sock = FakeSocket()
    runtime = client._connection_runtime
    runtime._bind_heartbeat_lane("main", sock)
    probe_id = runtime._heartbeat_monitor.begin_probe("main", sock)
    future = concurrent.futures.Future()
    future.set_exception(TimeoutError("probe response deadline"))

    runtime._finish_probe_future("main", sock, probe_id, future)

    status = runtime.heartbeat_status()["lanes"]["main"]
    assert status["state"] == "suspect"
    assert status["consecutive_misses"] == 1
    assert status["transport_failures"] == 0


def test_heartbeat_dispatch_connection_error_marks_unresponsive():
    client = _client()
    sock = FakeSocket()
    runtime = client._connection_runtime
    runtime._bind_heartbeat_lane("main", sock)
    probe_id = runtime._heartbeat_monitor.begin_probe("main", sock)
    future = concurrent.futures.Future()
    future.set_exception(ConnectionError("socket closed"))

    runtime._finish_probe_future("main", sock, probe_id, future)

    status = runtime.heartbeat_status()["lanes"]["main"]
    assert status["state"] == "unresponsive"
    assert status["transport_failures"] == 1


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
    assert records[0]["event"] == "depth"
    assert records[1]["event"] == "depth"
    assert callbacks == [records[1]]
    assert client.receive_depth(timeout=0) == records[0]
    assert client.receive_depth(timeout=0) == records[1]
    assert client.receive_depth(timeout=0) is None


def test_market_push_dispatches_every_trade_in_batch_frame():
    client = _client()
    runtime = client._connection_runtime
    body = bytes.fromhex(
        (
            Path(__file__).parent
            / "fixtures"
            / "depth_push"
            / "trade_batch_603334_174.hex"
        ).read_text(encoding="ascii")
    )
    callbacks = []
    runtime.snapshot_codes.add("603334")
    runtime.snapshot_callback = lambda *args: callbacks.append(args)

    assert runtime.deliver_market_push(body)

    assert len(callbacks) == 11
    assert callbacks[0] == ("603334", "SH", 34.85, 100)
    assert callbacks[-1] == ("603334", "SH", 34.85, 100)
    assert runtime.latest_prices["603334"] == 34.85


def test_market_event_stream_delivers_queue_and_cancel_without_price_pollution():
    client = _client()
    runtime = client._connection_runtime
    fixtures = Path(__file__).parent / "fixtures" / "depth_push"
    callbacks = []
    runtime.market_event_codes.add("603334")
    runtime.market_event_callbacks["603334"] = callbacks.append

    cancel = bytes.fromhex(
        (fixtures / "order_cancel_sell_batch_603334_87.hex").read_text(
            encoding="ascii"
        )
    )
    order_queue = bytes.fromhex(
        (fixtures / "order_queue_buy_603334_75.hex").read_text(
            encoding="ascii"
        )
    )

    assert runtime.deliver_market_push(cancel)
    assert runtime.deliver_market_push(order_queue)

    events = [client.receive_market_event(timeout=0) for _ in range(3)]
    assert [event["event"] for event in events] == [
        "cancel",
        "cancel",
        "order_queue",
    ]
    assert callbacks == events
    assert "603334" not in runtime.latest_prices


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
