"""Offline contracts for accepting a verified MAIN login connection."""

from thspypc.client import THSClient
from thspypc.models import Capability


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def test_main_login_does_not_send_l2_init(monkeypatch):
    client = _client()
    sock = FakeSocket()
    heartbeat_started = []
    monkeypatch.setattr(
        client,
        "_start_heartbeat",
        lambda: heartbeat_started.append(True),
    )

    result = client._finalize_main_login(
        "127.0.0.1",
        sock,
        {"VerifyCode": "0"},
        {"userclass": "captured"},
    )

    assert result.success
    assert client._sock is sock
    assert client._connected_ip == "127.0.0.1"
    assert client._last_connect_ts > 0
    assert sock.sent == []
    assert heartbeat_started == [True]
    assert client.observed_account_profile.supports(Capability.BASIC_QUOTE)


def test_main_login_replaces_previous_socket_without_writing_new_socket(
    monkeypatch,
):
    client = _client()
    previous = FakeSocket()
    current = FakeSocket()
    client._sock = previous
    monkeypatch.setattr(client, "_start_heartbeat", lambda: None)

    result = client._finalize_main_login(
        "127.0.0.2",
        current,
        {"VerifyCode": "0"},
        {},
    )

    assert result.success
    assert previous.closed
    assert client._sock is current
    assert current.sent == []
