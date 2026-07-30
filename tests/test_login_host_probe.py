"""Offline contracts for login host probing and cache isolation."""

import json
import time

from thspypc.client import THSClient, load_ip_state, save_ip_state


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
    client._probe_cache = {"main": (time.time(), ["10.0.0.1"])}
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("valid cache must avoid probing")
        ),
    )

    assert client._probe_fastest_hosts(
        ["10.0.0.1", "10.0.0.2"], role="main",
    ) == ["10.0.0.1"]


def test_probe_cache_is_invalidated_when_dns_candidates_change(monkeypatch):
    client = _client()
    client._probe_cache = {"main": (time.time(), ["10.0.0.9"])}
    probed = []

    def connect(address, timeout):
        probed.append((address, timeout))
        return ProbeSocket()

    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        connect,
    )
    monkeypatch.setattr("thspypc.client.save_ip_state", lambda *_args, **_kwargs: None)

    result = client._probe_fastest_hosts(
        ["10.0.0.1", "10.0.0.2"], role="main",
    )

    assert set(result) == {"10.0.0.1", "10.0.0.2"}
    assert {address for address, _timeout in probed} == {
        ("10.0.0.1", 8901),
        ("10.0.0.2", 8901),
    }


def test_probe_cache_is_isolated_per_role(monkeypatch):
    """SH/SZ L2 must keep independent probe caches (IP sets do not overlap)."""
    client = _client()
    client._probe_cache = {
        "sh": (time.time(), ["10.0.0.1"]),
        "sz": (time.time(), ["10.0.0.9"]),
    }
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("per-role cache must avoid probing")
        ),
    )

    assert client._probe_fastest_hosts(["10.0.0.1"], role="sh") == ["10.0.0.1"]
    assert client._probe_fastest_hosts(["10.0.0.9"], role="sz") == ["10.0.0.9"]


def test_l2_rotation_offset_advances_and_persists(monkeypatch):
    """Building an L2 connection must advance the per-role rotation offset so
    repeated reconnects spread across IPs instead of hammering the same one."""
    client = _client()
    # reset offsets so the test does not depend on leftover ~/.ths_ip_state.json
    client._login_rr_offset = {"main": 0, "sh": 0, "sz": 0}
    client._probe_cache = {"sz": (time.time(), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])}
    monkeypatch.setattr(
        "thspypc.client.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cached probe must avoid probing")
        ),
    )

    # offset 0 → rotated batch starts at index 0
    assert client._rotated_l2_batch(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"], "sz",
    ) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    # advance by 2 → offset becomes 2
    client._advance_l2_offset("sz", tried=2, total=3)
    assert client._login_rr_offset["sz"] == 2
    # next rotated batch starts at index 2, wrapping
    assert client._rotated_l2_batch(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"], "sz",
    ) == ["10.0.0.3", "10.0.0.1", "10.0.0.2"]

    # all-failed path: tried == total must NOT snap back to the same offset.
    # Without force_advance, (offset + total) % total == offset, so repeated
    # failed reconnects would hammer the same IP batch and trigger -1.
    client._login_rr_offset["sz"] = 0
    client._advance_l2_offset("sz", tried=3, total=3, force_advance=True)
    assert client._login_rr_offset["sz"] == 1  # advanced past the original start


def test_ip_state_v2_roundtrip_and_role_isolation(tmp_path):
    """v2 persistence keeps each role's IPs and offset independent on disk."""
    path = str(tmp_path / "ip_state.json")
    save_ip_state(["10.0.0.1", "10.0.0.2"], 1, role="main", path=path)
    save_ip_state(["10.0.0.9"], 0, role="sz", path=path)

    loaded = load_ip_state(path=path)
    assert loaded is not None
    assert loaded["main"] == (["10.0.0.1", "10.0.0.2"], 1)
    assert loaded["sz"] == (["10.0.0.9"], 0)
    assert "sh" not in loaded  # never probed → absent


def test_ip_state_v1_flat_is_migrated_to_main(tmp_path):
    """Legacy v1 flat files must still load, migrated to the main bucket."""
    path = str(tmp_path / "ip_state.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "saved_at": int(time.time()),
                "sorted_ips": ["10.0.0.1", "10.0.0.2"],
                "rr_offset": 3,
            },
            f,
        )

    loaded = load_ip_state(path=path)
    assert loaded == {"main": (["10.0.0.1", "10.0.0.2"], 3)}
