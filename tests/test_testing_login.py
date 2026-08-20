"""Offline contracts for thspypc.testing login helpers."""

import socket

import pytest
import thspypc.testing as testing

class FakeSocket:
    def __init__(self):
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        pass

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

@pytest.fixture(autouse=True)
def clear_client_cache():
    testing._clients.clear()
    yield
    testing._clients.clear()

def test_resolve_ips_deduplicates_across_domains(monkeypatch):
    def fake_getaddrinfo(domain, _port, _family, _socktype):
        if domain == "a.example.com":
            return [
                (2, 1, 6, "", ("10.0.0.1", 0)),
                (2, 1, 6, "", ("10.0.0.2", 0)),
            ]
        return [
            (2, 1, 6, "", ("10.0.0.2", 0)),
            (2, 1, 6, "", ("10.0.0.3", 0)),
        ]

    monkeypatch.setattr(testing.socket, "getaddrinfo", fake_getaddrinfo)
    assert testing.resolve_ips(["a.example.com", "b.example.com"]) == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]

def test_login_socket_returns_first_verify_code_zero(monkeypatch):
    monkeypatch.setattr(
        testing.socket,
        "create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        "thspypc.testing.read_frame",
        lambda _sock: b"Reply=login\r\nVerifyCode=0\r\n",
    )
    host, sock = testing.login_socket(
        b"login-body",
        ["10.0.0.1", "10.0.0.2"],
        probe=False,
        login_timeout=0.2,
        overall_timeout=2.0,
    )
    assert host in {"10.0.0.1", "10.0.0.2"}
    assert sock.closed is False

def test_login_socket_raises_when_all_replies_are_rejected(monkeypatch):
    monkeypatch.setattr(
        testing.socket,
        "create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        "thspypc.testing.read_frame",
        lambda _sock: b"Reply=login\r\nVerifyCode=-1\r\n",
    )
    with pytest.raises(testing.LoginFailed, match="all 2 hosts failed"):
        testing.login_socket(
            b"login-body",
            ["10.0.0.1", "10.0.0.2"],
            probe=False,
            login_timeout=0.2,
            overall_timeout=1.0,
        )

def test_login_socket_for_domains_uses_fallback_when_dns_empty(monkeypatch):
    monkeypatch.setattr(
        testing.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror()),
    )
    monkeypatch.setattr(
        testing.socket,
        "create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        "thspypc.testing.read_frame",
        lambda _sock: b"Reply=login\r\nVerifyCode=0\r\n",
    )
    host, _sock = testing.login_socket_for_domains(
        b"login-body",
        ["main.123ths.com"],
        fallback_hosts=["10.0.0.9"],
        probe=False,
        login_timeout=0.2,
        overall_timeout=2.0,
    )
    assert host == "10.0.0.9"

def test_get_client_reuses_cached_connected_instance(tmp_path, monkeypatch):
    calls = []

    class FakeClient:
        is_connected = True

        def connect(self):
            calls.append("connect")

        def disconnect(self):
            pass

    env_path = tmp_path / "account.env"
    env_path.write_text(
        "THS_USERNAME=u\nTHS_PASSWORD=p\n",
        encoding="utf-8",
    )
    key = str(env_path.resolve())
    testing._clients[key] = FakeClient()

    first = testing.get_client(env_path)
    second = testing.get_client(env_path)
    assert first is second
    assert calls == []


def test_get_client_forwards_configured_imei(tmp_path, monkeypatch):
    created = []

    class Result:
        success = True
        error = ""
        detail = ""

    class FakeClient:
        def __init__(self, username, password, *, imei=None):
            created.append((username, password, imei))
            self.is_connected = False

        def connect(self):
            self.is_connected = True
            return Result()

        def disconnect(self):
            pass

    env_path = tmp_path / "account.env"
    env_path.write_text(
        "THS_USERNAME=fixture-user\n"
        "THS_PASSWORD=fixture-password\n"
        "THS_IMEI=fixture-imei\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("THS_USERNAME", raising=False)
    monkeypatch.delenv("THS_PASSWORD", raising=False)
    monkeypatch.delenv("THS_IMEI", raising=False)
    monkeypatch.setattr("thspypc.client.THSClient", FakeClient)

    client = testing.get_client(env_path)

    assert client.is_connected is True
    assert created == [("fixture-user", "fixture-password", "fixture-imei")]

