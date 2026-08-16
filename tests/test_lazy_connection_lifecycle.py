"""Offline contracts for HTTP-only auth and role-lazy TCP connections."""

import pytest

from thspypc import (
    AccountKind,
    AccountProfile,
    AuthMaterial,
    Capability,
    LoginResult,
    Support,
    THSClient,
)
from thspypc.transport import ConnectionRole
from thspypc.errors import UnsupportedAccountFeatureError


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.sent = []

    def close(self):
        self.closed = True

    def sendall(self, data):
        self.sent.append(data)


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def _install_http_auth(client, calls):
    def authenticate(username, password, imei):
        calls.append((username, password, imei))
        return {
            "userid": "user-id",
            "sessionid": "session-id",
            "signature": "AB" * 128,
            "passport_bytes": (
                b"account=test|userclass=level2|"
                b"M_hqdns=\"ifindhq.123ths.com:8901:232;\""
            ),
        }

    client._auth_service._authenticator = authenticate
    client._init_blocks = lambda: None


def _level2_profile():
    return AccountProfile(
        kind=AccountKind.LEVEL2,
        capabilities={
            Capability.L2_MARKET_ACCESS: Support.YES,
            Capability.L2_TIMELINE: Support.YES,
        },
    )


def test_authenticate_is_http_only_and_reuses_one_generation():
    client = _client()
    calls = []
    _install_http_auth(client, calls)

    first = client.authenticate()
    second = client.authenticate()

    assert isinstance(first, AuthMaterial)
    assert second is first
    assert client.auth_material is first
    assert first.generation == 1
    assert client._sock is None
    assert client._push_socks == {}
    assert client._realorder_sock is None
    assert len(calls) == 1
    assert (
        client.observed_account_profile.support(Capability.BASIC_QUOTE)
        is Support.UNKNOWN
    )


def test_connect_main_reuses_existing_http_material(monkeypatch):
    client = _client()
    calls = []
    _install_http_auth(client, calls)
    material = client.authenticate()
    tcp_logins = []
    monkeypatch.setattr(
        client,
        "_do_tcp_login",
        lambda fields: (
            tcp_logins.append(dict(fields))
            or LoginResult(success=False, error="offline-stop")
        ),
    )

    result = client.connect_main()

    assert result.error == "offline-stop"
    assert len(calls) == 1
    assert tcp_logins == [dict(material.passport_fields)]


def test_default_main_call_creates_service_context(monkeypatch):
    client = _client()
    client._sock = FakeSocket()
    client._account_evidence.record_main_ready()
    calls = []

    class FakeQuoteService:
        def __init__(self, connections, *, evidence=None, subscriptions=None):
            self.connections = connections

        def list_quotes(self, codes, **kwargs):
            calls.append((codes, kwargs))
            return [{"code": codes[0], "dt10": 1.0}]

    monkeypatch.setattr("thspypc.services.QuoteService", FakeQuoteService)

    records = client.list_quotes(["600519"], market=17)

    assert records == [{"code": "600519", "dt10": 1.0}]
    assert client._service_connections is not None
    assert client._service_auto_profile
    assert calls[0][0] == ["600519"]


def test_l2_service_opener_authenticates_without_main_login(monkeypatch):
    client = _client()
    calls = []
    _install_http_auth(client, calls)
    l2_sock = FakeSocket()
    main_logins = []
    opened = []
    monkeypatch.setattr(
        client,
        "connect_main",
        lambda: main_logins.append(True),
    )
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        lambda market, *, material: opened.append((market, material))
        or l2_sock,
    )

    manager = client.configure_service_context(
        _level2_profile(),
        allow_open=True,
    )
    connection = manager.acquire(
        ConnectionRole.SH_L2,
        capability=Capability.L2_TIMELINE,
    )

    assert connection.socket is l2_sock
    assert len(calls) == 1
    assert opened == [(17, client.auth_material)]
    assert main_logins == []
    assert client._sock is None


def test_l2_service_opener_refreshes_passport_without_dropping_main(monkeypatch):
    client = _client()
    calls = []
    _install_http_auth(client, calls)
    client.authenticate()
    main_sock = FakeSocket()
    l2_sock = FakeSocket()
    client._sock = main_sock
    dropped = []
    opened = []
    monkeypatch.setattr(
        client,
        "_drop_connection",
        lambda: dropped.append(True),
    )
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        lambda market, *, material: opened.append((market, material))
        or l2_sock,
    )
    manager = client.configure_service_context(
        _level2_profile(),
        allow_open=True,
    )

    connection = manager.acquire(
        ConnectionRole.SH_L2,
        capability=Capability.L2_TIMELINE,
    )

    assert connection.socket is l2_sock
    assert len(calls) == 2
    assert opened == [(17, client.auth_material)]
    assert client._sock is main_sock
    assert not main_sock.closed
    assert dropped == []


def test_realorder_authenticates_without_main_login(monkeypatch):
    import thspypc.client as client_module

    client = _client()
    calls = []
    _install_http_auth(client, calls)
    realorder_sock = FakeSocket()
    main_logins = []
    monkeypatch.setattr(
        client,
        "connect_main",
        lambda: main_logins.append(True),
    )
    monkeypatch.setattr(
        client_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: realorder_sock,
    )
    monkeypatch.setattr(client_module, "read_frame", lambda _sock: b"login")
    monkeypatch.setattr(
        client_module,
        "parse_login_response",
        lambda _body: {"VerifyCode": "0"},
    )

    client._connect_realorder_server()

    assert client._realorder_sock is realorder_sock
    assert len(calls) == 1
    assert main_logins == []
    assert client._sock is None


def test_history_timeline_authenticates_without_main_login(monkeypatch):
    client = _client()
    calls = []
    _install_http_auth(client, calls)
    main_logins = []
    monkeypatch.setattr(
        client,
        "connect_main",
        lambda: main_logins.append(True),
    )

    class FakeTimelineService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            self.connections = connections

        def history_timeline(self, code, **_kwargs):
            return [{"code": code, "bar_index": 1}]

    monkeypatch.setattr(
        "thspypc.services.TimelineService",
        FakeTimelineService,
    )

    records = client.history_timeline(
        "600519",
        "2026-07-28",
        market=17,
        retries=0,
    )

    assert records == [{"code": "600519", "bar_index": 1}]
    assert len(calls) == 1
    assert main_logins == []
    assert client._sock is None


def test_verified_standard_passport_routes_timeline_to_main(monkeypatch):
    client = _client()
    auth_calls = []

    def authenticate(username, password, imei):
        auth_calls.append((username, password, imei))
        return {
            "userid": "user-id",
            "sessionid": "session-id",
            "signature": "AB" * 128,
            "passport_bytes": (
                b"account=test|userclass=10000|level2=255|"
                b"M_hqdns=\"ifindhq.123ths.com:8901:232;\""
            ),
        }

    client._auth_service._authenticator = authenticate
    client._init_blocks = lambda: None
    opened = []
    monkeypatch.setattr(
        client,
        "_open_manual_push_connection",
        lambda market: opened.append(market),
    )
    routed_roles = []

    class FakeTimelineService:
        def __init__(self, connections, *, subscriptions, evidence=None):
            routed_roles.append(connections.profile.kind)

        def timeline(self, code, **kwargs):
            return [{"code": code, "dt10": 10.0}]

    monkeypatch.setattr(
        "thspypc.services.TimelineService",
        FakeTimelineService,
    )

    result = client.timeline("600519", market=17)

    assert result == [{"code": "600519", "dt10": 10.0}]
    assert len(auth_calls) == 1
    assert client.observed_account_profile.kind is AccountKind.STANDARD
    assert routed_roles == [AccountKind.STANDARD]
    assert opened == []
