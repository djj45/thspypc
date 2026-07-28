"""Offline contracts for accepting a verified MAIN login connection.

MAIN 登录成功后必须发送 init 握手激活行情通道（hexin 抓包确认
LOGIN→INIT→行情查询）。list_quotes 走 hd1.0/hd3.1 不强依赖 init，但 K线
（hd3.1 flag=0x0042/0x0046）要求 init 激活通道才响应——曾因重构误删 init
调用导致 kline 全超时而 list_quotes 仍正常，掩盖了回归。这两个契约锁定
MAIN 登录收尾必须触发 init，并正确替换旧 socket。
"""

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


def test_main_login_sends_init_to_activate_channel(monkeypatch):
    """MAIN 登录后必须调用 _send_init_handshake 激活行情通道。

    init 握手是 hexin 协议的必要步骤（subtype 0x0001），服务器据此激活该
    连接的行情查询通道。K线查询依赖此通道；不发 init 会导致 kline 超时。
    """
    client = _client()
    sock = FakeSocket()
    heartbeat_started = []
    init_sent = []
    monkeypatch.setattr(
        client,
        "_start_heartbeat",
        lambda: heartbeat_started.append(True),
    )
    # 拦截真实 init（避免 FakeSocket 无 recv 支持），仅记录被调用
    monkeypatch.setattr(
        client,
        "_send_init_handshake",
        lambda timeout=2.0: init_sent.append(True),
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
    assert init_sent == [True], "MAIN 登录后必须发 init 握手激活行情通道"
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
