"""Offline contracts for accepting a verified MAIN login connection.

MAIN 登录成功后必须发送 init 握手激活行情通道（hexin 抓包确认
LOGIN→INIT→行情查询）。list_quotes 走 hd1.0/hd3.1 不强依赖 init，但 K线
（hd3.1 flag=0x0042/0x0046）要求 init 激活通道才响应——曾因重构误删 init
调用导致 kline 全超时而 list_quotes 仍正常，掩盖了回归。这两个契约锁定
MAIN 登录收尾必须触发 init，并正确替换旧 socket。
"""

from types import SimpleNamespace

from thspypc.client import LoginResult, THSClient
from thspypc.models import Capability, Support


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.closed = False
        self.timeouts = []

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


def _client():
    return THSClient(
        "offline-user",
        "offline-password",
        enable_heartbeat=False,
    )


def test_independent_main_uses_fresh_passport_and_concurrent_race(monkeypatch):
    client = _client()
    sock = FakeSocket()
    material = SimpleNamespace(
        passport64="fresh-passport",
        passport_bytes=b"passport-dns",
    )
    calls = []

    monkeypatch.setattr(
        client,
        "authenticate",
        lambda *, force=False: calls.append(("auth", force)) or material,
    )
    monkeypatch.setattr(
        client,
        "_resolve_market_hosts",
        lambda passport: calls.append(("resolve", passport))
        or ["192.0.2.1", "192.0.2.2"],
    )
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda hosts, timeout, role: calls.append(
            ("probe", tuple(hosts), role)
        )
        or list(hosts),
    )
    monkeypatch.setattr(
        client._auth_service,
        "login_body_for_passport",
        lambda passport: calls.append(("body", passport)) or b"login",
    )
    monkeypatch.setattr(
        client,
        "_concurrent_login",
        lambda hosts, body: calls.append(("race", tuple(hosts), body))
        or (hosts[0], sock, {"VerifyCode": "0"}),
    )
    monkeypatch.setattr(
        client,
        "_initialize_independent_main_socket",
        lambda current: calls.append(("init", current)),
    )

    assert client._open_independent_main_connection() is sock
    assert ("auth", True) in calls
    assert ("resolve", b"passport-dns") in calls
    assert ("body", "fresh-passport") in calls
    assert ("race", ("192.0.2.1", "192.0.2.2"), b"login") in calls
    assert ("init", sock) in calls
    assert client._sock is None


def test_main_login_sends_init_to_activate_channel(monkeypatch):
    """MAIN 登录后必须调用 _send_init_handshake 激活行情通道。

    init 握手是 hexin 协议的必要步骤（subtype 0x0001），服务器据此激活该
    连接的行情查询通道。K线查询依赖此通道；不发 init 会导致 kline 超时。
    """
    client = _client()
    sock = FakeSocket()
    heartbeat_started = []
    lifecycle = []
    monkeypatch.setattr(
        client,
        "stop_heartbeat",
        lambda: lifecycle.append("stop-heartbeat"),
    )
    monkeypatch.setattr(
        client,
        "_start_heartbeat",
        lambda: (heartbeat_started.append(True), lifecycle.append("heartbeat")),
    )
    # 拦截真实 init（避免 FakeSocket 无 recv 支持），仅记录被调用
    monkeypatch.setattr(
        client,
        "_send_init_handshake",
        lambda timeout=2.0: lifecycle.append("init"),
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
    assert heartbeat_started == [True]
    assert lifecycle == ["stop-heartbeat", "init", "heartbeat"]
    assert client.observed_account_profile.supports(Capability.BASIC_QUOTE)


def test_main_login_replaces_previous_socket(monkeypatch):
    """新 MAIN socket 登录成功后，旧 socket 必须被关闭并替换。"""
    client = _client()
    previous = FakeSocket()
    current = FakeSocket()
    client._sock = previous
    monkeypatch.setattr(client, "_start_heartbeat", lambda: None)
    monkeypatch.setattr(client, "_send_init_handshake", lambda timeout=2.0: None)

    result = client._finalize_main_login(
        "127.0.0.2",
        current,
        {"VerifyCode": "0"},
        {},
    )

    assert result.success
    assert previous.closed
    assert client._sock is current
    assert client._connected_ip == "127.0.0.2"


def test_main_login_rejects_socket_when_init_fails(monkeypatch):
    """VerifyCode=0 但 init 失败时不能暴露半初始化 MAIN 连接。"""
    client = _client()
    sock = FakeSocket()
    heartbeat_started = []
    monkeypatch.setattr(
        client,
        "_send_init_handshake",
        lambda timeout=2.0: (_ for _ in ()).throw(
            TimeoutError("等待 MAIN init 响应超时")
        ),
    )
    monkeypatch.setattr(
        client,
        "_start_heartbeat",
        lambda: heartbeat_started.append(True),
    )

    result = client._finalize_main_login(
        "127.0.0.3",
        sock,
        {"VerifyCode": "0"},
        {"userclass": "captured"},
    )

    assert not result.success
    assert result.error == "init_failed"
    assert result.verify_code == "0"
    assert "init" in result.detail
    assert sock.closed
    assert client._sock is None
    assert client._connected_ip is None
    assert client._last_connect_ts == 0
    assert heartbeat_started == []
    assert (
        client.observed_account_profile.support(Capability.BASIC_QUOTE)
        is Support.UNKNOWN
    )


def test_init_handshake_requires_first_response_frame(monkeypatch):
    """首帧超时必须向登录收尾传播，不能记录成 init 成功。"""
    import socket

    import pytest
    import thspypc.client as client_module

    client = _client()
    sock = FakeSocket()
    client._sock = sock
    monkeypatch.setattr(
        client_module,
        "read_frame",
        lambda _sock: (_ for _ in ()).throw(socket.timeout()),
    )

    with pytest.raises(TimeoutError, match="MAIN init"):
        client._send_init_handshake(timeout=0.01)

    assert len(sock.sent) == 1
    assert sock.timeouts == [0.01]


def test_init_handshake_requires_server_config_frame(monkeypatch):
    """普通 FDF 帧不足以证明通道激活，响应必须包含服务器配置。"""
    import socket

    import pytest
    import thspypc.client as client_module

    client = _client()
    sock = FakeSocket()
    client._sock = sock
    responses = iter([b"CodeListSize=0"])

    def read_then_timeout(_sock):
        try:
            return next(responses)
        except StopIteration:
            raise socket.timeout()

    monkeypatch.setattr(client_module, "read_frame", read_then_timeout)

    with pytest.raises(ValueError, match="服务器配置"):
        client._send_init_handshake(timeout=0.01)


def test_init_handshake_accepts_server_config_frame(monkeypatch):
    """包含服务器配置元数据的完整帧可以激活 MAIN 通道。"""
    import socket

    import thspypc.client as client_module

    client = _client()
    sock = FakeSocket()
    client._sock = sock
    responses = iter([b"S-OS=Linux\r\nS-Version=1.0\r\n"])

    def read_then_timeout(_sock):
        try:
            return next(responses)
        except StopIteration:
            raise socket.timeout()

    monkeypatch.setattr(client_module, "read_frame", read_then_timeout)

    client._send_init_handshake(timeout=0.01)

    assert len(sock.sent) == 1
    assert sock.timeouts == [0.01, 0.3]


def test_winner_init_failure_does_not_fallback_to_more_logins(monkeypatch):
    """认证成功后的 init 失败必须结束本次 connect，避免跨节点重复登录。"""
    import thspypc.client as client_module

    client = _client()
    hosts = [f"192.0.2.{index}" for index in range(1, 9)]
    winner_sock = FakeSocket()
    serial_attempts = []

    monkeypatch.setattr(client_module, "MARKET_HOSTS", hosts)
    monkeypatch.setattr(client_module, "save_ip_state", lambda *_args, **_kw: None)
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda candidates, timeout=1.0, **_kw: list(candidates),
    )
    monkeypatch.setattr(
        client,
        "_concurrent_login",
        lambda batch, login_body: (
            batch[0],
            winner_sock,
            {"VerifyCode": "0"},
        ),
    )
    monkeypatch.setattr(
        client,
        "_finalize_main_login",
        lambda host, sock, reply_fields, passport_fields: LoginResult(
            success=False,
            verify_code="0",
            server=f"{host}:8901",
            error="init_failed",
            detail="等待 MAIN init 响应超时",
        ),
    )
    monkeypatch.setattr(
        client_module.socket,
        "create_connection",
        lambda *args, **kwargs: serial_attempts.append(args),
    )

    result = client._do_tcp_login_raw(b"login", {})

    assert not result.success
    assert result.error == "init_failed"
    assert serial_attempts == []


def test_all_fail_triggers_passport_refresh_and_retry(monkeypatch):
    """全部 IP -1 时自动刷新 passport 重试一轮（和 L2/BOARD 通道一致）。

    MAIN 服务器对过期 passport 静默返回 -1（无 PromptText）。旧逻辑直接判
    session_conflict 放弃；新逻辑刷新 passport 后重试，通常即恢复。
    """
    import socket

    import thspypc.client as client_module

    client = _client()
    hosts = [f"192.0.2.{index}" for index in range(1, 9)]
    refresh_calls = []

    monkeypatch.setattr(client_module, "MARKET_HOSTS", hosts)
    monkeypatch.setattr(client_module, "save_ip_state", lambda *_args, **_kw: None)
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda candidates, timeout=1.0, **_kw: list(candidates),
    )

    # 第一轮 _concurrent_login 返回 None（全失败），第二轮返回 winner
    call_count = [0]

    def mock_concurrent_login(batch, login_body):
        call_count[0] += 1
        if call_count[0] == 1:
            return None  # 第一轮全失败
        return (batch[0], FakeSocket(), {"VerifyCode": "0"})  # 第二轮成功

    monkeypatch.setattr(client, "_concurrent_login", mock_concurrent_login)
    monkeypatch.setattr(
        client,
        "_finalize_main_login",
        lambda host, sock, reply_fields, passport_fields: LoginResult(
            success=True,
            verify_code="0",
            server=f"{host}:8901",
        ),
    )

    # 模拟 _refresh_auth_material 返回新 material
    from unittest.mock import MagicMock

    fresh_material = MagicMock()
    fresh_material.passport64 = "fresh_passport"

    def mock_refresh():
        refresh_calls.append(True)
        return fresh_material

    monkeypatch.setattr(client, "_refresh_auth_material", mock_refresh)
    monkeypatch.setattr(
        client._auth_service,
        "login_body_for_passport",
        lambda passport64, identity=None: b"fresh_login_body",
    )
    # 阻止串行 fallback 误创真实连接
    monkeypatch.setattr(
        client_module.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionRefusedError()),
    )

    result = client._do_tcp_login_raw(b"login", {})

    assert result.success
    assert result.error == ""
    assert len(refresh_calls) == 1  # 刷新了一次 passport
    assert call_count[0] == 2  # _concurrent_login 被调了两次（第一轮失败 + 第二轮成功）


def test_refresh_failure_returns_all_hosts_failed(monkeypatch):
    """刷新 passport 后仍全失败 → 返回 all_hosts_failed（不无限重试）。"""
    import socket

    import thspypc.client as client_module

    client = _client()
    hosts = [f"192.0.2.{index}" for index in range(1, 9)]

    monkeypatch.setattr(client_module, "MARKET_HOSTS", hosts)
    monkeypatch.setattr(client_module, "save_ip_state", lambda *_args, **_kw: None)
    monkeypatch.setattr(
        client,
        "_probe_fastest_hosts",
        lambda candidates, timeout=1.0, **_kw: list(candidates),
    )
    # 所有轮次都返回 None（全失败）
    monkeypatch.setattr(
        client, "_concurrent_login", lambda batch, login_body: None
    )
    monkeypatch.setattr(
        client_module.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionRefusedError()),
    )

    from unittest.mock import MagicMock

    fresh_material = MagicMock()
    fresh_material.passport64 = "fresh_passport"
    monkeypatch.setattr(
        client, "_refresh_auth_material", lambda: fresh_material
    )
    monkeypatch.setattr(
        client._auth_service,
        "login_body_for_passport",
        lambda passport64, identity=None: b"fresh_login_body",
    )

    result = client._do_tcp_login_raw(b"login", {})

    assert not result.success
    assert result.error == "all_hosts_failed"
