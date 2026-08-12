"""Offline DNS-routing contracts for the MAIN A-share connection."""

import socket

from thspypc.protocol import resolve_market_hosts


def _passport(entries: str) -> bytes:
    return f'account=test|M_hqdns="{entries}"|userclass=0'.encode("ascii")


def test_main_host_resolution_prefers_ifindhq_over_main(monkeypatch):
    """2026-08-12 修正:优先 ifindhq(与官方客户端 DNS 抓包一致),main 仅回退。

    此前强制优先 main 导致解析出被服务端拒绝的 IP(VerifyCode=-1)。
    """
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

    # ifindhq 优先,main 作为回退追加
    assert resolve_market_hosts(passport) == ["10.0.0.1", "10.0.0.2", "10.0.9.1", "10.0.9.2"]
    assert queried[0] == "ifindhq.123ths.com"


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


def test_main_host_resolution_uses_ifindhq_directly(monkeypatch):
    """passport 含 ifindhq 时直接用,不硬编码补 main。"""
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], ["10.0.0.1"]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "ifindhq.123ths.com:8901:232;120;104;56;,"
        "fu2.123ths.com:8901:64;80;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1"]
    assert queried == ["ifindhq.123ths.com"]


def test_main_host_resolution_hardcoded_ifindhq_when_passport_has_neither(monkeypatch):
    """passport 既无 ifindhq 也无 main:硬编码 ifindhq(与官方客户端一致)。"""
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], ["10.0.0.1"]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "fu4.123ths.com:8901:96;128;,"
        "hkus.123ths.com:8901:176;112;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1"]
    assert queried == ["ifindhq.123ths.com"]
