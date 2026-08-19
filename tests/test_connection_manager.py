"""Offline contracts for role-aware connection management."""

import threading

import pytest

import thspypc.transport as transport
from thspypc._transport import (
    ConnectionManager,
    ConnectionRole,
    LoginIdentity,
    OpenedConnection,
)
from thspypc.errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    UnsupportedAccountFeatureError,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support


class FakeSocket:
    def __init__(self) -> None:
        self.closed = False
        self.timeout = None
        self.sent = []

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _profile(kind, **capabilities):
    return AccountProfile(
        kind=kind,
        capabilities={
            Capability[name]: Support[value]
            for name, value in capabilities.items()
        },
    )


def test_standard_account_never_opens_l2_roles():
    opened = []
    manager = ConnectionManager(
        _profile(
            AccountKind.STANDARD,
            BASIC_TIMELINE="YES",
            L2_MARKET_ACCESS="NO",
            L2_TIMELINE="NO",
        ),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(CapabilityUnavailableError):
        manager.acquire(ConnectionRole.SH_L2)
    with pytest.raises(CapabilityUnavailableError):
        manager.acquire(ConnectionRole.SZ_L2)

    assert opened == []


def test_constituent_roles_preserve_captured_login_identities():
    opened = []
    standard = ConnectionManager(
        _profile(
            AccountKind.STANDARD,
            BASIC_QUOTE="YES",
            L2_MARKET_ACCESS="NO",
        ),
        lambda spec: opened.append(spec) or FakeSocket(),
    )

    sh = standard.acquire(
        ConnectionRole.BOARD_CONSTITUENT_SH,
        capability=Capability.BASIC_QUOTE,
    )
    assert sh.spec.identity is LoginIdentity.STANDARD
    with pytest.raises(CapabilityUnavailableError):
        standard.acquire(ConnectionRole.BOARD_CONSTITUENT_SZ)

    level2 = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            BASIC_QUOTE="YES",
            L2_MARKET_ACCESS="YES",
        ),
        lambda spec: opened.append(spec) or FakeSocket(),
    )
    sz = level2.acquire(ConnectionRole.BOARD_CONSTITUENT_SZ)
    assert sz.spec.identity is LoginIdentity.MANUAL


def test_unknown_account_does_not_probe_l2_roles():
    opened = []
    manager = ConnectionManager(
        AccountProfile(kind=AccountKind.UNKNOWN),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    with pytest.raises(UnsupportedAccountFeatureError):
        manager.acquire(ConnectionRole.SZ_L2)

    assert opened == []


def test_level2_connection_is_cached_and_owns_single_flight_session():
    opened = []
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
            L2_TIMELINE="YES",
        ),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    first = manager.acquire(
        ConnectionRole.SZ_L2,
        capability=Capability.L2_TIMELINE,
    )
    second = manager.acquire(
        ConnectionRole.SZ_L2,
        capability=Capability.L2_TIMELINE,
    )

    assert first is second
    assert opened == [ConnectionRole.SZ_L2]
    assert first.spec.identity is LoginIdentity.STANDARD
    assert first.spec.init_market_codes == (32,)
    assert first.init_complete
    with first.request(b"query", timeout=2.5):
        pass
    assert first.socket.sent == [b"query\n"]
    assert first.socket.timeout == pytest.approx(2.5, abs=0.05)


def test_structured_opener_applies_borrowed_lifecycle_metadata():
    sock = FakeSocket()
    request_lock = threading.RLock()
    opened = []

    def opener(spec):
        opened.append(spec.role)
        return OpenedConnection(
            socket=sock,
            owns_socket=False,
            initialized=False,
            request_lock=request_lock,
        )

    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, BASIC_QUOTE="YES"),
        opener,
    )
    first = manager.acquire(ConnectionRole.MAIN)
    second = manager.acquire(ConnectionRole.MAIN)

    assert first is second
    assert opened == [ConnectionRole.MAIN]
    assert not first.owns_socket
    assert not first.init_complete
    with first.request(b"query", timeout=1.5):
        pass
    assert sock.sent == [b"query\n"]

    manager.close_all()
    assert not first.active
    assert not sock.closed


def test_channel_failure_is_distinct_from_capability_failure():
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, BASIC_QUOTE="YES"),
        lambda _spec: (_ for _ in ()).throw(OSError("DNS failed")),
    )

    with pytest.raises(ChannelUnavailableError) as exc_info:
        manager.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )

    assert exc_info.value.channel == "main"


def test_close_and_close_all_release_cached_sockets():
    sockets = []

    def opener(_spec):
        sock = FakeSocket()
        sockets.append(sock)
        return sock

    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            BASIC_QUOTE="YES",
            L2_MARKET_ACCESS="YES",
            L2_TIMELINE="YES",
        ),
        opener,
    )
    main = manager.acquire(ConnectionRole.MAIN)
    l2 = manager.acquire(ConnectionRole.SH_L2)

    manager.close(ConnectionRole.MAIN)
    assert not main.active
    assert sockets[0].closed
    assert manager.peek(ConnectionRole.MAIN) is None

    manager.close_all()
    assert not l2.active
    assert sockets[1].closed
    assert manager.peek(ConnectionRole.SH_L2) is None


def test_adopt_borrows_authenticated_socket_and_shared_lock():
    opened = []
    sock = FakeSocket()
    request_lock = threading.RLock()
    manager = ConnectionManager(
        _profile(AccountKind.STANDARD, BASIC_QUOTE="YES"),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )

    connection = manager.adopt(
        ConnectionRole.MAIN,
        sock,
        capability=Capability.BASIC_QUOTE,
        request_lock=request_lock,
    )

    assert manager.acquire(ConnectionRole.MAIN) is connection
    assert opened == []
    assert not connection.owns_socket
    with connection.request(b"query", timeout=3.0):
        pass
    assert sock.sent == [b"query\n"]

    manager.close(ConnectionRole.MAIN)
    assert not connection.active
    assert not sock.closed


def test_adopt_can_take_socket_ownership_and_init_state():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
            L2_AUCTION="YES",
        ),
        lambda _spec: FakeSocket(),
    )

    connection = manager.adopt(
        ConnectionRole.SH_L2,
        sock,
        capability=Capability.L2_AUCTION,
        owns_socket=True,
        initialized=True,
    )

    assert connection.owns_socket
    assert connection.init_complete
    manager.close_all()
    assert sock.closed
    assert not connection.init_complete


def test_adopt_same_socket_is_idempotent_and_can_promote_init_state():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
        ),
        lambda _spec: FakeSocket(),
    )

    first = manager.adopt(ConnectionRole.SZ_L2, sock)
    second = manager.adopt(
        ConnectionRole.SZ_L2,
        sock,
        initialized=True,
    )

    assert first is second
    assert second.init_complete


def test_adopt_rejects_conflicting_role_or_socket_without_closing():
    first_sock = FakeSocket()
    second_sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            BASIC_QUOTE="YES",
            L2_MARKET_ACCESS="YES",
        ),
        lambda _spec: FakeSocket(),
    )
    manager.adopt(ConnectionRole.MAIN, first_sock)

    with pytest.raises(ChannelUnavailableError):
        manager.adopt(ConnectionRole.MAIN, second_sock)
    with pytest.raises(ChannelUnavailableError):
        manager.adopt(ConnectionRole.SH_L2, first_sock)

    assert not first_sock.closed
    assert not second_sock.closed


def test_standard_account_cannot_adopt_l2_socket():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.STANDARD,
            L2_MARKET_ACCESS="NO",
        ),
        lambda _spec: FakeSocket(),
    )

    with pytest.raises(CapabilityUnavailableError):
        manager.adopt(ConnectionRole.SZ_L2, sock)

    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert not sock.closed


def test_profile_upgrade_preserves_main_and_enables_l2_acquire():
    opened = []
    main_socket = FakeSocket()
    manager = ConnectionManager(
        AccountProfile(kind=AccountKind.UNKNOWN),
        lambda spec: opened.append(spec.role) or FakeSocket(),
    )
    main = manager.adopt(ConnectionRole.MAIN, main_socket)
    level2 = _profile(
        AccountKind.LEVEL2,
        BASIC_QUOTE="YES",
        L2_MARKET_ACCESS="YES",
        L2_TIMELINE="YES",
    )

    manager.update_profile(level2)
    l2 = manager.acquire(
        ConnectionRole.SH_L2,
        capability=Capability.L2_TIMELINE,
    )

    assert manager.profile is level2
    assert manager.peek(ConnectionRole.MAIN) is main
    assert main.active
    assert not main_socket.closed
    assert l2.active
    assert opened == [ConnectionRole.SH_L2]


def test_profile_downgrade_retires_borrowed_l2_but_keeps_main():
    main_socket = FakeSocket()
    l2_socket = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
        ),
        lambda _spec: FakeSocket(),
    )
    main = manager.adopt(ConnectionRole.MAIN, main_socket)
    l2 = manager.adopt(
        ConnectionRole.SZ_L2,
        l2_socket,
        initialized=True,
    )

    manager.update_profile(
        _profile(
            AccountKind.STANDARD,
            BASIC_QUOTE="YES",
            L2_MARKET_ACCESS="NO",
        )
    )

    assert manager.peek(ConnectionRole.MAIN) is main
    assert manager.peek(ConnectionRole.SZ_L2) is None
    assert not l2.active
    assert not l2_socket.closed
    assert main.active


def test_profile_downgrade_closes_owned_l2_socket():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
        ),
        lambda _spec: sock,
    )
    connection = manager.acquire(ConnectionRole.SH_L2)

    manager.update_profile(AccountProfile(kind=AccountKind.UNKNOWN))

    assert manager.peek(ConnectionRole.SH_L2) is None
    assert not connection.active
    assert sock.closed


def test_profile_downgrade_waits_for_in_flight_request():
    sock = FakeSocket()
    manager = ConnectionManager(
        _profile(
            AccountKind.LEVEL2,
            L2_MARKET_ACCESS="YES",
        ),
        lambda _spec: sock,
    )
    connection = manager.acquire(ConnectionRole.SH_L2)
    request_started = threading.Event()
    release_request = threading.Event()
    refresh_started = threading.Event()
    refresh_done = threading.Event()

    def hold_request():
        with connection.request(b"query", timeout=1.0):
            request_started.set()
            assert release_request.wait(1.0)

    request_thread = threading.Thread(target=hold_request)
    request_thread.start()
    assert request_started.wait(1.0)

    def downgrade():
        refresh_started.set()
        manager.update_profile(AccountProfile(kind=AccountKind.UNKNOWN))
        refresh_done.set()

    refresh_thread = threading.Thread(target=downgrade)
    refresh_thread.start()
    assert refresh_started.wait(1.0)
    assert not refresh_done.wait(0.05)

    release_request.set()
    request_thread.join(1.0)
    refresh_thread.join(1.0)

    assert not request_thread.is_alive()
    assert not refresh_thread.is_alive()
    assert refresh_done.is_set()
    assert manager.peek(ConnectionRole.SH_L2) is None
    assert sock.closed


def test_transport_compatibility_exports_internal_implementations():
    from thspypc._transport import MarketSession

    assert transport.MarketSession is MarketSession
    assert transport.ConnectionManager is ConnectionManager
