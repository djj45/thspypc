"""Offline ownership and capability contracts for RealOrderService."""

import socket
import threading

import pytest

from thspypc._transport import (
    ConnectionManager,
    ConnectionRole,
    OpenedConnection,
)
from thspypc.errors import (
    CapabilityUnavailableError,
    UnsupportedAccountFeatureError,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services import RealOrderService


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _profile(kind=AccountKind.LEVEL2, support=Support.YES):
    return AccountProfile(
        kind=kind,
        capabilities={Capability.REALORDER: support},
    )


def _instances(start=700000):
    current = start

    def next_instance():
        nonlocal current
        current += 1
        return current

    return next_instance


def test_history_query_uses_realorder_role_and_matches_response(monkeypatch):
    sock = FakeSocket()
    manager = ConnectionManager(_profile(), lambda _spec: sock)
    responses = iter([b"method=pushrealorder\nmarket=32", b"hq1.0-result"])
    service = RealOrderService(
        manager,
        _instances(),
        frame_reader=lambda _sock: next(responses),
    )
    monkeypatch.setattr(
        "thspypc.services.realorder.parse_pushrealorder_response",
        lambda body: [{"代码": "000001"}] if b"push" in body else [],
    )
    monkeypatch.setattr(
        "thspypc.services.realorder.parse_qurealorder_response",
        lambda body, market: [{"时间": 2, "市场": market}],
    )

    assert service.dxjl_page(32, 123) == [{"时间": 2, "市场": "32"}]
    assert b"method=qurealorder" in sock.sent[0]

    service.subscribe_realtime([32])
    records, frame_count = service.receive_pushes(timeout=0)
    assert records == [{"代码": "000001"}]
    assert frame_count == 0


@pytest.mark.parametrize(
    ("kind", "support", "error"),
    [
        (AccountKind.STANDARD, Support.NO, CapabilityUnavailableError),
        (AccountKind.UNKNOWN, Support.UNKNOWN, UnsupportedAccountFeatureError),
    ],
)
def test_capability_failure_happens_before_open(kind, support, error):
    opened = []
    manager = ConnectionManager(
        _profile(kind, support),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = RealOrderService(manager, _instances())

    with pytest.raises(error):
        service.dxjl_page(32, 123)

    assert opened == []


def test_standard_account_with_explicit_yes_can_route_realorder():
    opened = []
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, Support.YES),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    service = RealOrderService(
        manager,
        _instances(),
        frame_reader=lambda _sock: b"hq1.0-result",
    )

    assert service.dxjl_page(32, 123) == []
    assert opened == [ConnectionRole.REALORDER]


def test_subscription_and_heartbeat_share_request_lock():
    sock = FakeSocket()
    request_lock = threading.Lock()
    manager = ConnectionManager(
        _profile(),
        lambda _spec: OpenedConnection(
            socket=sock,
            request_lock=request_lock,
        ),
    )
    service = RealOrderService(manager, _instances())

    service.subscribe_realtime([16, 32])
    assert len(sock.sent) == 2
    assert all(b"method=subrealorder" in frame for frame in sock.sent)

    assert request_lock.acquire(blocking=False)
    try:
        assert not service.send_heartbeat(1)
    finally:
        request_lock.release()
    assert service.send_heartbeat(2)


def test_push_reader_holds_exclusive_socket_ownership():
    sock = FakeSocket()
    request_lock = threading.Lock()
    manager = ConnectionManager(
        _profile(),
        lambda _spec: OpenedConnection(
            socket=sock,
            request_lock=request_lock,
        ),
    )
    lock_was_held = []

    def read_frame(_sock):
        acquired = request_lock.acquire(blocking=False)
        lock_was_held.append(not acquired)
        if acquired:
            request_lock.release()
        raise socket.timeout()

    service = RealOrderService(
        manager,
        _instances(),
        frame_reader=read_frame,
    )

    service.subscribe_realtime([32])
    assert service.receive_pushes(timeout=1) == ([], 0)
    assert lock_was_held == [True]
