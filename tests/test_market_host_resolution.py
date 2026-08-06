"""Offline DNS-routing contracts for the MAIN A-share connection."""

import socket

from thspypc.protocol import resolve_market_hosts


def _passport(entries: str) -> bytes:
    return f'account=test|M_hqdns="{entries}"|userclass=0'.encode("ascii")


def test_main_host_resolution_prefers_main_over_ifindhq(monkeypatch):
    resolved = {
        "main.123ths.com": ["10.0.9.1", "10.0.9.2"],
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
        "main.123ths.com:8901:16;32;,"
        "ifindhq.123ths.com:8901:232;120;104;56;,"
        "euhq.123ths.com:8901:160;,"
        "shlv2.123ths.com:8901:16;144;"
    )

    assert resolve_market_hosts(passport) == ["10.0.9.1", "10.0.9.2"]
    assert queried == ["main.123ths.com"]


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


def test_main_host_resolution_uses_ifindhq_when_main_is_absent(
    monkeypatch,
):
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], ["10.0.0.1"]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "ifindhq.123ths.com:8901:232;120;104;56;,"
        "fu2.123ths.com:8901:64;80;"
    )

    # 2026-08-06: 即使 passport 不含 main，也硬编码补 main.123ths.com
    # （支持北交所 market 151），优先于 ifindhq。
    assert resolve_market_hosts(passport) == ["10.0.0.1"]
    assert queried == ["main.123ths.com"]


def test_main_host_resolution_returns_empty_without_ifindhq(monkeypatch):
    # 2026-08-06: main.123ths.com 总会被尝试（硬编码），所以不再返回空
    # 除非 DNS 解析失败
    def lookup(domain):
        if domain == "main.123ths.com":
            raise OSError("dns failed")
        return domain, [], ["10.0.0.1"]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "fu4.123ths.com:8901:96;128;,"
        "hkus.123ths.com:8901:176;112;"
    )

    # main DNS 失败 → fallback ifindhq，但 passport 也没 ifindhq → 空
    assert resolve_market_hosts(passport) == []
