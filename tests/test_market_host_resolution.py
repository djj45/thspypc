"""Offline DNS-routing contracts for the MAIN A-share connection."""

import socket

from thspypc.protocol import resolve_market_hosts


def _passport(entries: str) -> bytes:
    return f'account=test|M_hqdns="{entries}"|userclass=0'.encode("ascii")


def test_main_host_resolution_prefers_main_over_ifindhq(monkeypatch):
    """2026-08-14 抓包修正:优先 main.123ths.com(支持北交所 151),ifindhq 回退。

    普通账号排序榜客户端连 main.123ths.com 的 8.134.108.168 登录成功
    (VerifyCode=0) 且返回北交所 920083；ifindhq IP 不返回 151。
    2026-08-12 观察到的 main VerifyCode=-1 是 passport 过期/被消费的临时
    状态，重新 HTTP 鉴权即可恢复，非 main 节点封禁。
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

    # main 优先（含北交所），ifindhq 作为回退追加
    assert resolve_market_hosts(passport) == ["10.0.9.1", "10.0.9.2", "10.0.0.1", "10.0.0.2"]
    assert queried[0] == "main.123ths.com"


def test_main_host_resolution_deduplicates_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda domain: (domain, [], ["10.0.0.1", "10.0.0.1", "10.0.0.2"]),
    )
    passport = _passport(
        "main.123ths.com:8901:16;32;,"
        "fu2.123ths.com:8901:64;80;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1", "10.0.0.2"]


def test_main_host_resolution_uses_main_directly(monkeypatch):
    """passport 含 main 时直接用,不硬编码补 ifindhq。"""
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], ["10.0.0.1"]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "main.123ths.com:8901:16;32;,"
        "fu2.123ths.com:8901:64;80;"
    )

    assert resolve_market_hosts(passport) == ["10.0.0.1"]
    assert queried == ["main.123ths.com"]


def test_main_host_resolution_hardcoded_main_when_passport_has_neither(monkeypatch):
    """passport 既无 ifindhq 也无 main:硬编码 main(支持北交所)。"""
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
    assert queried == ["main.123ths.com"]


def test_main_host_resolution_ifindhq_only_when_main_missing(monkeypatch):
    """passport 只有 ifindhq 时用 ifindhq（main 缺失）。"""
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


def test_main_host_resolution_main_plus_ifindhq_fallback(monkeypatch):
    """main 与 ifindhq 都在时,main 优先、ifindhq 追加为回退。"""
    resolved = {
        "main.123ths.com": ["10.0.9.1"],
        "ifindhq.123ths.com": ["10.0.0.1"],
    }
    queried = []

    def lookup(domain):
        queried.append(domain)
        return domain, [], resolved[domain]

    monkeypatch.setattr(socket, "gethostbyname_ex", lookup)
    passport = _passport(
        "main.123ths.com:8901:16;32;,"
        "ifindhq.123ths.com:8901:232;120;104;56;,"
    )

    assert resolve_market_hosts(passport) == ["10.0.9.1", "10.0.0.1"]
    assert queried == ["main.123ths.com", "ifindhq.123ths.com"]