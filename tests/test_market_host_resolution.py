"""Offline DNS-routing contracts for the MAIN A-share connection."""

import socket

from thspypc.protocol import resolve_market_hosts


def _passport(entries: str) -> bytes:
    return f'account=test|M_hqdns="{entries}"|userclass=0'.encode("ascii")


def test_main_host_resolution_uses_only_ifindhq(monkeypatch):
    resolved = {
        "ifindhq.123ths.com": ["10.0.0.1", "10.0.0.2"],
        "fu4.123ths.com": ["10.0.1.1"],
        "hkus.123ths.com": ["10.0.2.1"],
        "euhq.123ths.com": ["10.0.3.1"],
        "shlv2.123ths.com": ["10.0.4.1"],
    }
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], resolved[domain]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "fu4.123ths.com:8901:96;128;,"
        "hkus.123ths.com:8901:176;112;,"
        "ifindhq.123ths.com:8901:232;120;104;56;,"
        "euhq.123ths.com:8901:160;,"
        "shlv2.123ths.com:8901:16;144;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1", "10.0.0.2"]
    assert queried == ["ifindhq.123ths.com"]


def test_main_host_resolution_deduplicates_ifindhq_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda domain: (domain, [], ["10.0.0.1", "10.0.0.1", "10.0.0.2"]),
    )
    passport = _passport(
        "ifindhq.123ths.com:8901:232;120;104;56;,"
        "fu2.123ths.com:8901:64;80;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1", "10.0.0.2"]


def test_main_host_resolution_returns_empty_without_ifindhq(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda domain: (domain, [], ["10.0.0.1"]),
    )
    passport = _passport(
        "fu4.123ths.com:8901:96;128;,"
        "hkus.123ths.com:8901:176;112;"
    )

    assert resolve_market_hosts(passport) == []
