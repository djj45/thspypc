"""Offline contracts for login host probing and cache isolation."""

import time

from thspypc.client import THSClient


class ProbeSocket:
    def close(self):
        pass


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def test_probe_cache_is_reused_only_within_current_candidates(monkeypatch):
    client = _client()
    client._probe_cache = (time.time(), ["10.0.0.1"])
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("valid cache must avoid probing")
        ),
    )

    assert client._probe_fastest_hosts(
        ["10.0.0.1", "10.0.0.2"],
    ) == ["10.0.0.1"]


def test_probe_cache_is_invalidated_when_dns_candidates_change(monkeypatch):
    client = _client()
    client._probe_cache = (time.time(), ["10.0.0.9"])
    probed = []

    def connect(address, timeout):
        probed.append((address, timeout))
        return ProbeSocket()

    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        connect,
    )
    monkeypatch.setattr("thspypc.client.save_ip_state", lambda *_args: None)

    result = client._probe_fastest_hosts(
        ["10.0.0.1", "10.0.0.2"],
    )

    assert set(result) == {"10.0.0.1", "10.0.0.2"}
    assert {address for address, _timeout in probed} == {
        ("10.0.0.1", 8901),
        ("10.0.0.2", 8901),
    }
