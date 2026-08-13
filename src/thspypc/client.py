"""
同花顺 PC 免费版行情客户端。

登录打通 + 个股列表行情查询 + 自定义板块管理 + 短线精灵（异动）查询。
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from .models import AccountKind, AccountProfile, Capability, Support
from .features.account_profile import AccountEvidenceRecorder
from .features.stock_name_protocol import is_st_name, st_market
from .services.auth import AuthMaterial, AuthService
from ._client.connection_runtime import ConnectionFactory, ConnectionRuntime
from ._client.connection_primitives import ConnectionPrimitives
from ._client.service_facade import ServiceFacade
from ._client.stock_cache import (
    default_stock_cache_path,
    is_stock_cache_expired,
    load_stock_codes,
    market_from_code,
    save_stock_codes,
)
from .transport import (
    ConnectionManager,
    ConnectionRole,
    MarketSession,
    OpenedConnection,
)
from .protocol import (
    MARKET_HOSTS,
    build_heartbeat_8901,
    build_heartbeat_9601,
    build_passport64,
    full_http_auth,
    generate_imei,
    generate_mac64,
    KLINE_PERIOD_1MIN, KLINE_PERIOD_5MIN, KLINE_PERIOD_15MIN,
    KLINE_PERIOD_30MIN, KLINE_PERIOD_60MIN,
    KLINE_PERIOD_DAY, KLINE_PERIOD_WEEK, KLINE_PERIOD_MONTH,
    KLINE_PERIOD_QUARTER, KLINE_PERIOD_YEAR,
    parse_snapshot_push,
    is_snapshot_push,
    parse_login_response,
    read_frame,
    resolve_market_hosts,
)

logger = logging.getLogger(__name__)


@dataclass
class LoginResult:
    """登录结果，含诊断信息。"""
    success: bool                          # VerifyCode == "0"
    verify_code: str = ""                  # 服务器返回的 VerifyCode
    server: str = ""                       # 实际连上的 8901 服务器 IP
    reply_fields: dict = field(default_factory=dict)   # 完整响应字段
    passport_fields: dict = field(default_factory=dict)  # passport 里的权限字段（诊断用）
    error: str = ""                        # 失败原因分类标签
    detail: str = ""                       # 失败详情（异常信息等）


class THSClient(ConnectionPrimitives, ServiceFacade):
    """同花顺 PC 免费版行情客户端。

    Args:
        username: 同花顺账号
        password: 密码
        imei: 设备 ID（32 字符十六进制，hexin.exe 本地生成的硬件指纹）。
              算法已逆向（见 protocol.generate_imei）：MD5(MAC大写连字符 + "0"*30)。
              None 时自动生成（脱离抓包运行）。
        mac64: login 帧的 Mac64 字段值。None 时自动生成（base64(0x18 + 前4网卡MAC)，
               已逆向验证，与 hexin.exe 一致）。

    Mac64 与 imei 都已逆向，均可自动生成，thspypc 完全脱离抓包运行。
    """

    _login_result_type = LoginResult

    @staticmethod
    def _persist_ip_state(sorted_ips: list[str], rr_offset: int,
                          role: str = "main") -> None:
        """Compatibility hook for persisted host-probe state."""
        save_ip_state(sorted_ips, rr_offset, role=role)

    @staticmethod
    def _connection_read_frame(sock) -> bytes:
        """Compatibility hook for diagnostics that replace ``client.read_frame``."""
        return read_frame(sock)

    @staticmethod
    def _market_host_candidates() -> tuple[str, ...] | list[str]:
        """Compatibility hook for diagnostics that replace ``MARKET_HOSTS``."""
        return MARKET_HOSTS

    @staticmethod
    def _parse_connection_login_response(body: bytes) -> dict:
        """Compatibility hook for diagnostics replacing the login parser."""
        return parse_login_response(body)

    @staticmethod
    def _resolve_market_hosts(passport: bytes) -> list[str]:
        """Compatibility hook for diagnostics replacing host resolution."""
        return resolve_market_hosts(passport)

    def __init__(self, username: str, password: str, imei: str | None = None, mac64: str | None = None,
                 enable_heartbeat: bool = True):
        self.username = username
        self.password = password
        # ⚠ 空串视为 None：部分测试脚本从 .env 读 THS_IMEI 时若该值为空（如
        # THS_IMEI=''），会得到空串而非 None。空串 imei 会导致 HTTP 鉴权拿到
        # 坏 passport → 所有 TCP login VerifyCode=-1。用 `imei or None` 把空串
        # 归一化为 None，触发自动生成，杜绝这类脚本踩坑。
        self.imei = imei or None
        self.imei = self.imei if self.imei is not None else generate_imei()
        self.mac64 = mac64 if mac64 is not None else generate_mac64()
        self.enable_heartbeat = enable_heartbeat
        self._sock: socket.socket | None = None
        self._auth: dict | None = None
        self._auth_service = AuthService(
            username,
            password,
            self.imei,
            self.mac64,
            # Resolve the module global at call time so existing monkeypatch and
            # diagnostic hooks around full_http_auth remain effective.
            authenticator=lambda account, secret, imei_value: full_http_auth(
                account,
                secret,
                imei_value,
            ),
        )
        self._auth_lock = threading.RLock()
        # 板块/自选股管理（HTTPS，登录后初始化）
        self._blocks = None              # BlockManager 实例
        self._system_blocks = None       # SystemBlocksService 实例（本地缓存，无需登录）
        self._http_cookies: dict | None = None
        # 短线精灵（9601 TCP，懒连接）
        self._realorder_sock: socket.socket | None = None
        # 板块专用通道（fu4 8901，懒连接；BoardService 查询走这条独立连接）
        self._board_sock: socket.socket | None = None
        # 板块统计通道（statscalc 独立 9601 节点，懒连接；与 REALORDER 不同服）
        self._board_stats_sock: socket.socket | None = None
        self._connected_ip: str = ""     # 当前 8901 连接的 IP（诊断用）
        self._bad_kline_ips: set[str] = set()  # K线查询失败过的 IP（重连时跳过）
        self._instance = 700000          # 请求序列号
        # 心跳（后台线程，connect 成功后自动启动）
        # 8901 没有可直接关联请求/响应的 request id，必须串行化完整请求生命周期。
        # 保留 _sock_lock 名称兼容已有诊断脚本；语义从“只保护 send”升级为
        # “保护 send + 全部响应读取”。RLock 允许连接治理代码在同线程内复用。
        self._sock_lock = threading.RLock()
        self._market_session = MarketSession(lambda: self._sock, self._sock_lock)
        self._realorder_lock = threading.Lock()         # 保护 9601 socket send
        self._board_lock = threading.RLock()            # 保护板块通道 socket
        self._board_stats_lock = threading.Lock()       # 保护 statscalc 9601 socket send
        # 实时分时推送（8901 pageid=4214 订阅后的逐 tick 快照）
        # L2 推送连接池，按沪深分服（shlv2=沪, szlv2=深）。
        # ★ 2026-07-24 实测：沪深 L2 是两套独立服务器，IP 0 重叠。沪市票必须连
        # shlv2 的 IP + init(16;144)，深市票必须连 szlv2 的 IP + init(32)，连错
        # 市会导致 init 只回 210B、4214 注册 CodeListSize=0。详见
        # resolve_l2_hosts_grouped() 与
        # docs/handoffs/HANDOFF_PUSH_INVESTIGATION_20260724.md §沪深分服突破。
        self._push_socks: dict = {}               # {"sh": sock, "sz": sock}
        self._push_lock = threading.Lock()        # 保护 _push_socks 并发（预热线程 vs 主线程）
        self._push_request_locks = {
            "sh": threading.RLock(),
            "sz": threading.RLock(),
        }
        self._push_initialized: set[str] = set()
        self._preheat_threads: dict[str, threading.Thread] = {}  # 预热线程（主流程可 join 等待）
        self._service_connections: ConnectionManager | None = None
        # 只保护 service registry 的懒创建/连接收编；网络请求仍由每条
        # ManagedConnection 自己的 single-flight 锁保护并可跨角色并行。
        self._service_context_lock = threading.RLock()
        # 显式请求允许对尚无证据的 capability 做一次乐观探测。并发调用时必须
        # 保留所有在途请求的授权并集，不能让先结束的调用撤销另一调用的授权。
        self._service_capability_leases: Counter[Capability] = Counter()
        self._service_allow_open = False
        self._service_auto_profile = False
        self._account_evidence = AccountEvidenceRecorder()
        self._service_subscriptions = None
        self._kline_service = None
        self._market_snapshot_service = None
        self._quote_service = None
        self._stock_list_service = None
        self._stock_name_service = None
        self._timeline_service = None
        self._auction_service = None
        self._superorder_service = None
        self._realorder_service = None
        self._board_service = None
        self._board_stats_service = None
        # 连接治理（避免反复 connect 触发 VerifyCode=-1）
        self._last_connect_ts: float = 0.0   # 上次成功 connect 的时刻
        self._CONNECT_COOLDOWN = 20.0        # 同 IP 会话冲突窗口（秒）
        # 测速缓存 + IP 轮换（减少反复 connect 的 login 次数，降低单点登录会话冲突）。
        # 按「连接角色」分桶：main/sh/sz 各自独立——shlv2 与 szlv2 是两套 IP 零重叠
        # 的服务器，测速结果和轮换偏移不能混用。
        self._probe_cache: dict[str, tuple[float, list[str]]] = {}
        self._PROBE_CACHE_TTL = 300.0        # 测速缓存有效期（秒），5 分钟
        self._login_rr_offset: dict[str, int] = {
            "main": 0,
            "kline": 0,
            "sh": 0,
            "sz": 0,
        }
        # 从磁盘加载跨进程共享的测速状态 + 轮换偏移（避免每个进程都 offset=0）
        _disk = load_ip_state()
        if _disk is not None:
            for _role, (_ips, _off) in _disk.items():
                self._login_rr_offset[_role] = _off
                self._probe_cache[_role] = (time.time(), _ips)
            logger.debug("从磁盘加载 IP 状态：%s",
                         {r: len(ips) for r, (ips, _) in _disk.items()})
        self._connection_factory = ConnectionFactory(
            result_type=LoginResult,
            is_connected=lambda: self.is_connected,
            last_connect_ts=lambda: self._last_connect_ts,
            connect_cooldown=self._CONNECT_COOLDOWN,
            authenticate=lambda *args, **kwargs: self.authenticate(
                *args,
                **kwargs,
            ),
            do_tcp_login=lambda fields: self._do_tcp_login(fields),
            main_socket=lambda: self._sock,
            connect_main=lambda: self.connect_main(),
            main_lock=self._sock_lock,
            current_auth=lambda: self._auth,
            drop_main=lambda: self._drop_connection(),
            open_manual=lambda market: self._open_manual_push_connection(
                market
            ),
            push_sockets=self._push_socks,
            push_lock=self._push_lock,
            push_initialized=self._push_initialized,
            push_request_locks=self._push_request_locks,
            connect_realorder=lambda: self._connect_realorder_server(),
            realorder_socket=lambda: self._realorder_sock,
            realorder_lock=self._realorder_lock,
            board_socket=lambda: self._board_sock,
            set_board_socket=lambda value: self._assign_board_socket(value),
            open_board=lambda: self._open_board_channel(),
            board_lock=self._board_lock,
            open_board_constituent=lambda side: self._open_board_channel(
                constituent_side=side,
            ),
            connect_board_stats=lambda: self._connect_board_stats_server(),
            board_stats_socket=lambda: self._board_stats_sock,
            board_stats_lock=self._board_stats_lock,
        )
        self._connection_runtime = ConnectionRuntime(
            enable_heartbeat=self.enable_heartbeat,
            main_socket=lambda: self._sock,
            realorder_socket=lambda: self._realorder_sock,
            market_session=self._market_session,
            realorder_lock=self._realorder_lock,
            realorder_service=lambda: self._realorder_service,
            push_sockets=self._push_socks,
            push_lock=self._push_lock,
            push_request_locks=self._push_request_locks,
            push_initialized=self._push_initialized,
            preheat_threads=self._preheat_threads,
            service_connections=lambda: self._service_connections,
            close_owned_sockets=self._close_owned_sockets,
            board_stats_socket=lambda: self._board_stats_sock,
            board_stats_lock=self._board_stats_lock,
        )

    @property
    def _heartbeat_thread(self):
        return self._connection_runtime.heartbeat_thread

    @_heartbeat_thread.setter
    def _heartbeat_thread(self, value):
        self._connection_runtime.heartbeat_thread = value

    @property
    def _heartbeat_stop(self):
        return self._connection_runtime.heartbeat_stop

    @property
    def _hb_seq_8901(self):
        return self._connection_runtime.heartbeat_seq_main

    @_hb_seq_8901.setter
    def _hb_seq_8901(self, value):
        self._connection_runtime.heartbeat_seq_main = value

    @property
    def _hb_seq_9601(self):
        return self._connection_runtime.heartbeat_seq_realorder

    @_hb_seq_9601.setter
    def _hb_seq_9601(self, value):
        self._connection_runtime.heartbeat_seq_realorder = value

    @property
    def _snapshot_thread(self):
        return self._connection_runtime.snapshot_thread

    @_snapshot_thread.setter
    def _snapshot_thread(self, value):
        self._connection_runtime.snapshot_thread = value

    @property
    def _snapshot_stop(self):
        return self._connection_runtime.snapshot_stop

    @property
    def _snapshot_codes(self):
        return self._connection_runtime.snapshot_codes

    @property
    def _snapshot_cb(self):
        return self._connection_runtime.snapshot_callback

    @_snapshot_cb.setter
    def _snapshot_cb(self, value):
        self._connection_runtime.snapshot_callback = value

    @property
    def _latest_price(self):
        return self._connection_runtime.latest_prices

    @property
    def _latest_depth(self):
        return self._connection_runtime.latest_depth

    def configure_service_context(
        self,
        profile: AccountProfile | None = None,
        *,
        allow_open: bool = False,
    ) -> ConnectionManager:
        """Create or refresh the internal service registry from legacy sockets."""
        inferred_profile = profile is None
        if profile is None:
            profile = self.observed_account_profile

        if self._service_connections is None:
            def unavailable_opener(spec):
                raise OSError(
                    f"旧 client 尚未向 service 提供建连器: {spec.role.value}"
                )

            self._service_allow_open = allow_open
            self._service_connections = ConnectionManager(
                profile,
                (
                    self._open_service_connection
                    if allow_open
                    else unavailable_opener
                ),
            )
            from .services import (
                AuctionService,
                BoardService,
                BoardStatsService,
                KlineService,
                L2SubscriptionCoordinator,
                MarketSnapshotService,
                QuoteService,
                RealOrderService,
                StockListService,
                StockNameService,
                SuperorderService,
                TimelineService,
            )

            self._service_subscriptions = L2SubscriptionCoordinator(
                evidence=self._account_evidence,
            )
            self._kline_service = KlineService(
                self._service_connections,
                evidence=self._account_evidence,
            )
            self._market_snapshot_service = MarketSnapshotService(
                self._service_connections,
                evidence=self._account_evidence,
            )
            self._quote_service = QuoteService(
                self._service_connections,
                evidence=self._account_evidence,
                subscriptions=self._service_subscriptions,
            )
            self._stock_list_service = StockListService(
                self._service_connections,
                evidence=self._account_evidence,
            )
            self._stock_name_service = StockNameService(
                self._service_connections,
                evidence=self._account_evidence,
            )
            self._timeline_service = TimelineService(
                self._service_connections,
                subscriptions=self._service_subscriptions,
                evidence=self._account_evidence,
            )
            self._auction_service = AuctionService(
                self._service_connections,
                subscriptions=self._service_subscriptions,
                evidence=self._account_evidence,
            )
            self._superorder_service = SuperorderService(
                self._service_connections,
                subscriptions=self._service_subscriptions,
                evidence=self._account_evidence,
            )
            self._realorder_service = RealOrderService(
                self._service_connections,
                self._next_request_instance,
            )
            self._board_service = BoardService(
                self._service_connections,
            )
            self._board_stats_service = BoardStatsService(
                self._service_connections,
                self._next_request_instance,
            )
        elif self._service_allow_open != allow_open:
            raise ValueError("service context 的 allow_open 模式不可中途切换")
        elif inferred_profile:
            self._service_connections.update_profile(profile)
            return self._service_connections
        elif self._service_connections.profile != profile:
            raise ValueError("service context 已绑定其他 AccountProfile")

        self.sync_service_connections()
        return self._service_connections

    @property
    def observed_account_profile(self) -> AccountProfile:
        """Return the profile derived only from evidence observed by this client."""
        return self._account_evidence.profile()

    def refresh_service_profile_from_evidence(self) -> AccountProfile:
        """Apply current observations without re-adopting retired sockets."""
        manager = self._service_connections
        if manager is None:
            raise RuntimeError("configure_service_context() has not been called")
        profile = self.observed_account_profile
        manager.update_profile(profile)
        return profile

    def preheat_l2_connections(self) -> dict[str, dict[str, object]]:
        """建立并保留沪、深两条 Level2 行情连接，不发送股票业务请求。

        MAIN 登录后的账号证据必须明确为 Level2；普通或未知账号不会进行权限
        探测。两条 L2 socket 顺序建立，每条都由 ConnectionFactory 刷新独立的
        Passport64，并完成对应市场 init。失败按市场记录，不影响另一市场。
        """
        profile = self.observed_account_profile
        if profile.kind is not AccountKind.LEVEL2:
            return {
                "sh": {"ready": False, "skipped": True},
                "sz": {"ready": False, "skipped": True},
            }

        roles = (
            ("sh", ConnectionRole.SH_L2),
            ("sz", ConnectionRole.SZ_L2),
        )

        def operation():
            results: dict[str, dict[str, object]] = {}
            manager = self._service_connections
            if manager is None:
                raise RuntimeError("service context 尚未初始化")
            for key, role in roles:
                try:
                    connection = manager.acquire(
                        role,
                        capability=Capability.L2_TIMELINE,
                    )
                    results[key] = {
                        "ready": bool(connection.active),
                        "initialized": bool(connection.init_complete),
                    }
                except Exception as exc:
                    results[key] = {
                        "ready": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
            return results

        return self._run_default_service(
            (Capability.L2_TIMELINE,),
            operation,
        )

    def preheat_service_connections(self) -> dict[str, dict[str, object]]:
        """Pre-open the L2 lanes and the optional fast K-line lane."""
        results = self.preheat_l2_connections()
        try:
            connection = self._run_default_service(
                (Capability.BASIC_QUOTE,),
                lambda: self._service_connections.acquire(
                    ConnectionRole.KLINE_FAST,
                    capability=Capability.BASIC_QUOTE,
                ),
            )
            results["kline"] = {
                "ready": bool(connection.active),
                "initialized": bool(connection.init_complete),
            }
        except Exception as exc:
            results["kline"] = {
                "ready": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        return results

    def _ensure_default_service_context(
        self,
        *capabilities: Capability,
    ) -> ConnectionManager:
        """Return the single default service registry for an explicit call.

        Unknown capabilities may be probed only because the caller explicitly
        requested that feature.  The optimistic routing profile is temporary:
        after the call it is replaced by the evidence actually observed.
        Explicit contexts created through :meth:`configure_service_context`
        retain their caller-supplied conservative profile.
        """
        profile = self._default_service_profile(capabilities)
        if self._service_connections is None:
            manager = self.configure_service_context(
                profile,
                allow_open=True,
            )
            self._service_auto_profile = True
            return manager

        if self._service_auto_profile:
            self._service_connections.update_profile(profile)
        return self._service_connections

    def _default_service_profile(
        self,
        capabilities,
    ) -> AccountProfile:
        """Combine observed evidence with capabilities leased by active calls."""
        observed = self.observed_account_profile
        support = dict(observed.capabilities)
        l2_capabilities = {
            Capability.L2_TIMELINE,
            Capability.L2_AUCTION,
            Capability.L2_SNAPSHOT_PUSH,
            Capability.L2_HISTORY_TIMELINE,
        }
        requested = tuple(capabilities)
        requested_l2 = any(
            capability in l2_capabilities
            for capability in requested
        )
        for capability in requested:
            if support.get(capability, Support.UNKNOWN) is Support.UNKNOWN:
                support[capability] = Support.YES
        if (
            requested_l2
            and support.get(
                Capability.L2_MARKET_ACCESS,
                Support.UNKNOWN,
            )
            is Support.UNKNOWN
        ):
            support[Capability.L2_MARKET_ACCESS] = Support.YES
        kind = observed.kind
        if requested_l2 and kind is AccountKind.UNKNOWN:
            kind = AccountKind.LEVEL2
        return AccountProfile(
            kind=kind,
            capabilities=support,
            passport_fields=observed.passport_fields,
        )

    def _run_default_service(
        self,
        capabilities: tuple[Capability, ...],
        operation,
    ):
        """Execute one explicit business call and commit observed evidence."""
        manager = None
        with self._service_context_lock:
            self._service_capability_leases.update(capabilities)
        try:
            with self._service_context_lock:
                active = tuple(self._service_capability_leases)
                manager = self._ensure_default_service_context(*active)
            return operation()
        finally:
            with self._service_context_lock:
                self._service_capability_leases.subtract(capabilities)
                self._service_capability_leases += Counter()
                if self._service_auto_profile and manager is not None:
                    manager.update_profile(
                        self._default_service_profile(
                            tuple(self._service_capability_leases)
                        )
                    )

    def _open_service_connection(self, spec) -> OpenedConnection:
        """Compatibility delegate to the role-aware connection factory."""
        if spec.role is ConnectionRole.KLINE_FAST:
            return OpenedConnection(
                socket=self._open_independent_main_connection(),
                owns_socket=True,
                initialized=True,
            )
        return self._connection_factory.open(spec)

    def _assign_board_socket(self, sock) -> None:
        """收编板块通道 socket（ConnectionFactory 在 board_lock 内调用）。"""
        self._board_sock = sock

    def sync_service_connections(self) -> ConnectionManager:
        """Synchronize borrowed wrappers with the sockets currently held here."""
        manager = self._service_connections
        if manager is None:
            raise RuntimeError("请先调用 configure_service_context(profile)")

        with self._push_lock:
            push_sockets = dict(self._push_socks)
            initialized = set(self._push_initialized)
        with self._sock_lock:
            main_socket = self._sock
        with self._realorder_lock:
            realorder_socket = self._realorder_sock
        with self._board_lock:
            board_socket = self._board_sock
        with self._board_stats_lock:
            board_stats_socket = self._board_stats_sock

        for key, role in (
            ("sh", ConnectionRole.SH_L2),
            ("sz", ConnectionRole.SZ_L2),
        ):
            self._sync_service_role(
                manager,
                role,
                push_sockets.get(key),
                request_lock=self._push_request_locks[key],
                initialized=key in initialized,
            )
        self._sync_service_role(
            manager,
            ConnectionRole.MAIN,
            main_socket,
            request_lock=self._sock_lock,
            initialized=main_socket is not None,
        )
        self._sync_service_role(
            manager,
            ConnectionRole.BOARD,
            board_socket,
            request_lock=self._board_lock,
            initialized=board_socket is not None,
        )
        # statscalc 独立统计节点（懒连接）：socket 在首次查询时才建立，这里只
        # 同步已建立的连接；未建立时传 None 让 ConnectionManager 在 acquire 时建连。
        self._sync_service_role(
            manager,
            ConnectionRole.BOARD_STATS,
            board_stats_socket,
            request_lock=self._board_stats_lock,
            initialized=board_stats_socket is not None,
        )
        if (
            manager.profile.support(Capability.REALORDER)
            is Support.YES
        ):
            self._sync_service_role(
                manager,
                ConnectionRole.REALORDER,
                realorder_socket,
                request_lock=self._realorder_lock,
                initialized=realorder_socket is not None,
            )
        else:
            manager.close(ConnectionRole.REALORDER)
        return manager

    def _next_request_instance(self) -> int:
        self._instance += 1
        return self._instance

    @staticmethod
    def _sync_service_role(
        manager: ConnectionManager,
        role: ConnectionRole,
        sock,
        *,
        request_lock,
        initialized: bool,
    ) -> None:
        current = manager.peek(role)
        if current is not None and current.socket is not sock:
            manager.close(role)
            current = None
        if sock is None:
            if current is not None:
                manager.close(role)
            return
        manager.adopt(
            role,
            sock,
            request_lock=request_lock,
            owns_socket=False,
            initialized=initialized,
        )

    @property
    def auth_material(self) -> AuthMaterial | None:
        """Return the current HTTP-authenticated passport generation."""
        return self._auth_service.current

    def authenticate(
        self,
        *,
        force: bool = False,
        account: str | None = None,
        password: str | None = None,
    ) -> AuthMaterial:
        """只执行 HTTP 鉴权并缓存 Passport64，不建立任何行情 TCP 连接。

        同一代 :class:`AuthMaterial` 可被 MAIN、SH_L2、SZ_L2 和 REALORDER
        连接按需复用。默认已有材料时直接返回；``force=True`` 或显式传入账号
        凭据时重新鉴权并原子替换当前 generation。
        """
        with self._auth_lock:
            current = self._auth_service.current
            current_matches_legacy = (
                current is not None
                and self._auth is not None
                and dict(current.auth_info) == self._auth
            )
            if (
                not force
                and account is None
                and password is None
                and current_matches_legacy
            ):
                return current

            logger.info("开始 HTTP 三步鉴权 (account=%s)...", account or self.username)
            material = self._refresh_auth_material(account, password)
            self._init_blocks()
            logger.info(
                "HTTP 鉴权成功，passport generation=%d，含 %d 个字段",
                material.generation,
                len(material.passport_fields),
            )
            return material

    def connect(self) -> LoginResult:
        """兼容入口：按需 HTTP 鉴权，然后建立 MAIN 行情连接。"""
        return self.connect_main()

    def connect_main(self, *, refresh_auth: bool = False) -> LoginResult:
        """按需建立 ``ifindhq`` MAIN：STANDARD login → init → ready。

        返回 LoginResult，含成功/失败诊断。失败时 error 字段区分：
          - "http_auth_failed"   HTTP 三步鉴权失败（账号/密码/网络问题）
          - "all_hosts_failed"   所有 8901 IP 都连不上，且刷新 passport 后仍失败
          - "login_rejected"     连上了但 VerifyCode != 0（passport 被拒）
          - "init_failed"        VerifyCode=0，但 MAIN 行情通道初始化失败

        VerifyCode=-1 有两种：A. login 帧内容错误（check 字节/sk/sv，已修复）；
        B. passport 过期或同 IP 短时间重复 login 的会话冲突。MAIN 服务器对过期
        passport 静默返回 -1（无 PromptText）。本方法检测到连续 -1 或全 IP 失败时，
        **自动重新 HTTP 鉴权拿新鲜 Passport64 重试一轮**（和 L2/BOARD 通道一致），
        刷新后通常即恢复。仅当刷新后仍全失败才返回 all_hosts_failed。

        **连接治理（防 -1）**：若距上次成功 connect < 20s 且当前连接仍活着，本方法
        **直接复用现有连接**返回成功，不重新 login——这是 hexin 客户端的策略
        （连接还活着就别重连）。连接已断时正常走登录流程。
        """
        return self._connection_factory.connect_main(
            refresh_auth=refresh_auth
        )

    # ── 连接治理（避免反复 connect 触发 VerifyCode=-1）──

    @property
    def is_connected(self) -> bool:
        """8901 主连接是否仍活着。

        socket 文件描述符仍开**且**未被对端关闭（recv 探测无数据=活着；
        recv 返回 b""=对端关闭）。非阻塞探测，不消耗数据也不阻塞。

        注意：仅检查 8901 主连接，不含 9601 短线精灵连接
        （:attr:`_realorder_sock`，懒连接）。
        """
        with self._sock_lock:
            sock = self._sock
            if sock is None:
                return False
            try:
                # 设非阻塞探测；MSG_PEEK 不消费缓冲区数据
                sock.setblocking(False)
                try:
                    data = sock.recv(1, socket.MSG_PEEK)
                finally:
                    sock.setblocking(True)
                # 有数据=活着且待读；空 b""=对端 FIN
                return data != b""
            except BlockingIOError:
                # 无数据可读=连接仍开着（最常见情况）
                return True
            except OSError:
                return False

    def ensure_connected(self) -> bool:
        """查询前的健康检查：确认 8901 主连接仍可用。

        与 ``self._sock is not None`` 的区别：后者只检查文件描述符是否存在，
        而本方法还会探测 socket 是否已被对端/网络中断关闭。

        本方法**不自动重连**——重连=重新 login=新的 VerifyCode=-1 风险
        （见 docs/handoffs/HANDOFF.md §7）。连接断开时返回 False，由调用方决定是否重连
        （通常应等 ≥20s 冷却后再 connect）。

        Returns:
            True 表示连接可用，可直接查询；False 表示连接已断。

        Raises:
            RuntimeError: 从未登录过（self._sock 为 None 且无 _last_connect_ts）。
        """
        if self._sock is None:
            if self._last_connect_ts == 0.0:
                raise RuntimeError("未登录，请先 connect() / connect_cached()")
            logger.warning("连接已断开，需重新 connect()（注意 ≥20s 冷却避免 -1）")
            return False
        return True

    def _ensure_main_connection(self) -> None:
        """按需建立 MAIN，不要求调用方预先调用 :meth:`connect`。"""
        if self._sock is not None:
            return
        result = self.connect_main()
        if not result.success or self._sock is None:
            raise RuntimeError(
                f"MAIN 连接失败: {result.error or result.detail}"
            )

    def _init_blocks(self) -> None:
        """初始化板块/自选股管理（HTTPS cookie 鉴权）。

        从 self._auth 提取 userid/sessionid/signvalid → docookie2 拿 cookies →
        BlockManager。失败仅 warning，不影响 TCP 登录和行情查询。
        前置条件：self._auth 已通过 full_http_auth 设置。
        """
        if self._auth is None:
            return
        try:
            passport_bytes = self._auth.get("passport_bytes", b"")
            if isinstance(passport_bytes, str):
                passport_bytes = passport_bytes.encode()
            signvalid = ""
            for f in passport_bytes.split(b"|"):
                if f.startswith(b"signvalid="):
                    signvalid = f[len(b"signvalid="):].decode("ascii", errors="replace")
                    break
            from .blocks import BlockAuth, BlockManager
            auth = BlockAuth()
            self._http_cookies = auth.docookie2(
                self._auth.get("userid", ""),
                self._auth.get("sessionid", ""),
                signvalid,
            )
            self._blocks = BlockManager(cookies=self._http_cookies)
            logger.info("板块/自选股功能已就绪")
        except Exception as e:
            logger.warning("板块功能初始化失败（不影响登录）: %s", e)

    def connect_with_qrcode(self, timeout: float = 180.0, png_path: str | None = None,
                            cache_path: str | None = None) -> LoginResult:
        """二维码扫码登录：生成二维码 → 等待手机扫码 → HTTP 鉴权 → 8901。

        扫码成功后用返回的 account/password 走 full_http_auth 拿 passport，
        后续 TCP login 与 connect() 相同。

        Args:
            timeout: 等待扫码确认的最长秒数（二维码默认有效期 ~120s）
            png_path: 若给定，把二维码 PNG 存到该路径（终端 ASCII 扫不了时用图片扫）
            cache_path: 若给定（默认 ~/.ths_qr_credentials.json），扫码成功后把凭证
                        存盘，供 connect_cached() 免扫码复用。传 "" 可禁用缓存。

        error 字段额外值：
          - "qr_timeout"   扫码超时未确认
          - "qr_failed"    二维码生成/轮询失败
        """
        from .qr_login import qr_login_flow, save_credentials, QrLoginResult
        # ---- 第 1 步：二维码扫码拿账号 ----
        try:
            qr: QrLoginResult = qr_login_flow(timeout=timeout, show_qr=True, png_path=png_path)
            logger.info("扫码登录拿到账号: %s", qr.account)
        except TimeoutError as e:
            return LoginResult(success=False, error="qr_timeout", detail=str(e))
        except Exception as e:
            logger.error("二维码登录失败: %s", e)
            return LoginResult(success=False, error="qr_failed", detail=str(e))

        # ---- 第 1.5 步：缓存扫码凭证（供下次免扫码）----
        if cache_path != "":
            try:
                saved = save_credentials(qr, cache_path or None)
                logger.info("扫码凭证已缓存到 %s", saved)
            except Exception as e:
                logger.warning("凭证缓存失败（不影响登录）: %s", e)

        return self._http_auth_and_tcp_login(qr.account, qr.password)

    def connect_cached(self, cache_path: str | None = None,
                       qr_timeout: float = 180.0,
                       png_path: str | None = None) -> LoginResult:
        """带凭证缓存的登录：优先用缓存凭证，过期才回退到扫码。

        手机勾选「30天免登录」后，凭证有效期 30 天，期间无需再扫码。
        缓存路径默认 ~/.ths_qr_credentials.json。

        流程：
          1. 读缓存凭证 → 仍有效 → 直接 HTTP 鉴权 + 8901（秒登录）
          2. 缓存过期/不存在 → 回退到 connect_with_qrcode（扫码 + 重新缓存）

        Args:
            cache_path: 凭证缓存路径，None 用默认路径
            qr_timeout: 回退扫码时的等待超时
            png_path: 回退扫码时的 PNG 备用路径

        自适应策略：不靠时间预判凭证有效性，而是「先试再说」——
          1. 有缓存且未「确定过期」→ 直接用缓存凭证试登录，成功就秒登
          2. 缓存登录失败 / 确定过期 → 清缓存，回退扫码（重新缓存）
        这样无论服务器实际让凭证活多久，都能自动适应，无需关心是否勾选了 30 天。
        """
        from .qr_login import load_credentials, is_credentials_expired

        # ---- 1. 有缓存且未「确定过期」→ 先试一次 ----
        loaded = load_credentials(cache_path)
        if loaded is not None:
            result_cred, saved_at = loaded
            if not is_credentials_expired(result_cred, saved_at):
                logger.info("尝试缓存凭证（account=%s, expire_time=%s）",
                            result_cred.account,
                            result_cred.expire_time or "(未勾选30天)")
                res = self._http_auth_and_tcp_login(
                    result_cred.account, result_cred.password)
                if res.success:
                    return res
                # 缓存凭证鉴权失败（服务器端已失效）→ 清缓存，回退扫码
                logger.warning("缓存凭证登录失败 (%s)，清缓存并回退扫码...", res.error)
                _clear_cache(cache_path)
            else:
                logger.info("缓存凭证已确定过期，需要重新扫码")

        # ---- 2. 回退到扫码 ----
        return self.connect_with_qrcode(
            timeout=qr_timeout, png_path=png_path, cache_path=cache_path)

    @staticmethod
    def _clear_cache(cache_path: str | None = None) -> None:
        """删除凭证缓存文件（凭证已失效时调用）。"""
        from .qr_login import default_cache_path
        path = cache_path or default_cache_path()
        try:
            os.remove(path)
            logger.info("已清除过期凭证缓存: %s", path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("清除缓存失败（不影响登录）: %s", e)

    def connect_with_passport64(self, passport64: str) -> LoginResult:
        """用外部 Passport64 直接登录 8901（绕过 HTTP 鉴权）。

        通常用 ``connect()`` 即可——它会调用 ``build_passport64`` 自动生成
        有行情权限的 Passport64（已复刻 hexin 的字段过滤逻辑，无需抓包）。

        本方法用于特殊场景：已有现成 Passport64（如从 hexin 抓包提取、或
        外部缓存）时，跳过 HTTP 鉴权直接复用。

        Args:
            passport64: hexin login 帧里的完整 Passport64（base64 字符串）

        Returns:
            LoginResult。成功后 self._sock 可用于 list_quotes()。
        """
        login_body = self._auth_service.login_body_for_passport(passport64)
        return self._do_tcp_login_raw(login_body, passport_fields={})

    def _http_auth_and_tcp_login(self, account: str, password: str) -> LoginResult:
        """用 account+password 走 HTTP 三步鉴权 → 8901 TCP login。

        connect_with_qrcode / connect_cached 共用此方法。
        """
        try:
            material = self.authenticate(
                force=True,
                account=account,
                password=password,
            )
            passport_fields = dict(material.passport_fields)
            logger.info("HTTP 鉴权成功（account=%s），passport 含 %d 个字段",
                        account[:6] + "***", len(passport_fields))
        except Exception as e:
            logger.error("HTTP 鉴权失败（account=%s）: %s", account[:6] + "***", e)
            return LoginResult(success=False, error="http_auth_failed", detail=str(e))

        return self._do_tcp_login(passport_fields)

    def _refresh_auth_material(
        self,
        account: str | None = None,
        password: str | None = None,
    ):
        """Refresh one passport generation and mirror the legacy ``_auth``."""
        material = self._auth_service.authenticate(account, password)
        self._auth = material.legacy_auth_info()
        self._account_evidence.record_passport_fields(
            material.passport_fields
        )
        return material

    def _current_passport64(self) -> str:
        """Return service material, falling back to legacy test injection."""
        material = self._auth_service.current
        if (
            material is not None
            and self._auth is not None
            and dict(material.auth_info) == self._auth
        ):
            return material.passport64
        if self._auth is None:
            raise RuntimeError("HTTP authentication material is not available")
        return build_passport64(self._auth)










    # K线周期名 → 周期码（kline/timeline 方法共用）
    _KLINE_PERIOD_CODES = {
        "1min": KLINE_PERIOD_1MIN, "5min": KLINE_PERIOD_5MIN,
        "15min": KLINE_PERIOD_15MIN,
        "30min": KLINE_PERIOD_30MIN, "60min": KLINE_PERIOD_60MIN,
        "day": KLINE_PERIOD_DAY, "week": KLINE_PERIOD_WEEK,
        "month": KLINE_PERIOD_MONTH, "quarter": KLINE_PERIOD_QUARTER,
        "year": KLINE_PERIOD_YEAR,
    }









    def _market_for_code(self, code: str) -> int:
        """股票代码 → 市场码（含指数、北交所，以及 ST/风险警示板 22/34）。

        ST/*ST 股票在 8901 里：沪市走独立风险警示板 17→22（2026-08-13 抓包
        确认 600525/600745 走 CodeList=22(...)）；深市无独立市场码，仍用 33。
        是否 ST 只能靠名称前缀识别，名称来自 fetch_stock_names_full 的当日
        缓存，取不到时退回普通市场码。
        """
        if code.startswith(("1A", "1B")):   # 沪市指数
            return 16
        if code.startswith("39"):            # 深市指数
            return 32
        if code.startswith("899"):           # 北证50 等北交所指数
            return 144
        if code.startswith(("43", "83", "87", "920")):  # 北交所个股
            return 151
        base = 17 if code.startswith("6") else 33
        if is_st_name(self._stock_name(code)):
            return st_market(base)
        return base

    def _stock_name(self, code: str) -> str:
        """股票名称（当日缓存，取不到返回空串）。"""
        cache = getattr(self, "_name_map_cache", None)
        if cache is None:
            try:
                cache = self.fetch_stock_names_full()["names"]
            except Exception:
                cache = {}
            self._name_map_cache = cache
        return cache.get(code, "")





    # ── 全市场快照（hfd1.0 空括号协议）──




    # ── 股票名称（网络 upstockname 协议）──



    # ── 自定义板块/自选股管理（门面方法，委托给 BlockManager）──

    def _ensure_blocks(self):
        if self._blocks is None:
            self.authenticate()
        if self._blocks is None:
            raise RuntimeError("板块功能初始化失败")

    @property
    def blocks(self):
        """直接暴露 BlockManager（高级用法）。未初始化时抛 RuntimeError。"""
        self._ensure_blocks()
        return self._blocks

    def list_groups(self):
        """列出所有自定义板块/分组。"""
        self._ensure_blocks()
        return self._blocks.list_groups()

    def get_group(self, name: str, *, refresh: bool = False):
        """获取指定分组的成分股。refresh=True 强制刷新缓存。"""
        self._ensure_blocks()
        return self._blocks.get_group(name, refresh=refresh)

    def add_group(self, name: str) -> str:
        """新建自定义分组，返回分组 ID。"""
        self._ensure_blocks()
        return self._blocks.add_group(name)

    def delete_group(self, name: str) -> None:
        """删除自定义分组。"""
        self._ensure_blocks()
        return self._blocks.delete_group(name)

    def share_group(self, name: str, valid_time: int = 604800):
        """分享分组（返回分享信息）。valid_time 默认 7 天。"""
        self._ensure_blocks()
        return self._blocks.share_group(name, valid_time)

    def add_stock(self, group: str, symbols):
        """向分组添加股票（symbols 为代码字符串或列表）。"""
        self._ensure_blocks()
        return self._blocks.add_stock(group, symbols)

    def remove_stock(self, group: str, symbols):
        """从分组移除股票。"""
        self._ensure_blocks()
        return self._blocks.remove_stock(group, symbols)

    def get_self_stocks(self):
        """获取「我的自选」成分股。"""
        self._ensure_blocks()
        return self._blocks.get_self_stocks()

    def query_dynamic_plate(self, condition: str, num: int = 3000):
        """动态板块查询（condition 为选股表达式），返回成分股代码列表。"""
        self._ensure_blocks()
        return self._blocks.query_dynamic_plate(condition, num)

    def list_dynamic_plates(self):
        """列出所有动态板块及其成分股（云端快照）。"""
        self._ensure_blocks()
        return self._blocks.list_dynamic_plates()

    # ── 系统板块（行业/概念/地域…，本地 block_hq 缓存，只读，无需登录）──

    @property
    def system_blocks(self):
        """系统板块只读服务（行业/概念/地域等）。

        数据源为本机 hexin 安装目录的 ``BlockUpdate/block_*.ini`` 与
        ``industry.ini``（本地 block_hq 缓存域），不依赖登录、不走 8901。
        目录探测：``$THS_HEXIN_DIR`` → 常见安装路径（如
        ``D:\\同花顺软件\\同花顺``）。未找到时抛
        :class:`thspypc.services.system_blocks.SystemBlocksError`。
        """
        if self._system_blocks is None:
            from .services.system_blocks import SystemBlocksService

            self._system_blocks = SystemBlocksService()
        return self._system_blocks

    def system_block_categories(self):
        """列出系统板块分类（行业/概念/地域/港股/基金…）。"""
        return self.system_blocks.categories()

    def list_system_blocks(self, category: str | None = None):
        """列出系统板块（板块发现）。

        Args:
            category: None=全部分类；否则为分类键/文件 ID/中文名
                （``industry``、``concept``、``2B``、``概念``…）。

        Returns:
            list[SystemBlock]，每项含 ``block_id``（稳定 ID）、``name``、
            ``category``、``category_name``、``source``、``parent_id``。
        """
        return self.system_blocks.boards(category)

    def get_system_block_constituents(self, block_id: str):
        """返回系统板块成分股（稳定 ID → 成分股）。

        Args:
            block_id: ``881121``（半导体）/``C024``（BC电池）等稳定 ID。

        Returns:
            list[BlockStock]，每项含 ``code``、``market``（hexin 数字市场码）、
            ``pattern``（True 表示前缀通配条目，如基金 ``1(36):184*``）。
        """
        return self.system_blocks.constituents(block_id)

    # ── 短线精灵（异动，9601 端口 qurealorder）──


    # ── 心跳（后台线程，维持 8901/9601 长连接）──

    def _start_heartbeat(self) -> None:
        """启动心跳后台线程（connect 成功后自动调用）。

        8901 每 3 秒、9601 每 30 秒（若已连接）。daemon 线程，主进程退出时自动结束。
        enable_heartbeat=False 时不启动（用于对比测试）。
        """
        self._connection_runtime.start_heartbeat()

    def stop_heartbeat(self) -> None:
        """停止心跳线程（disconnect 时自动调用）。"""
        self._connection_runtime.stop_heartbeat()

    # ── 实时分时推送（pageid=5716 多股订阅触发，2026-07-24 抓包破解）──


    def _activate_snapshot_subscription(
        self,
        code: str,
        market: int,
        callback,
    ) -> None:
        """Record a registration and ensure the single push reader is running."""
        self._connection_runtime.activate_snapshot(
            code,
            market,
            callback,
        )







    def _snapshot_loop(self) -> None:
        """后台读取沪深两条 L2 推送连接的 71B 快照帧，更新现价/触发回调。

        用 ``select`` 同时等待 ``self._push_socks`` 里的连接（最多沪深两条），
        可读的就 ``read_frame``。遇到非快照帧（心跳响应、注册响应等）直接丢弃。
        select 超时 1 秒，期间反复检查 ``_snapshot_stop`` 以便及时退出。
        """
        self._connection_runtime.snapshot_loop(
            read_frame,
            is_snapshot_push,
            parse_snapshot_push,
        )

    def _heartbeat_loop(self) -> None:
        """心跳循环：8901 每 3 秒、9601 每 30 秒（10 个 3 秒周期）。

        用 _heartbeat_stop.wait(3) 阻塞，被 set 时立即退出。异常只 warning 不中断。
        """
        self._connection_runtime.heartbeat_loop(
            build_heartbeat_8901,
            build_heartbeat_9601,
        )





    # ── 短线精灵实时推送（9601 subrealorder 订阅 + pushrealorder 接收）──




    def disconnect(self) -> None:
        """关闭所有连接（8901 主连接 + 9601 短线精灵）并停止心跳。

        注意：重复调用 :meth:`connect` 不会触发新的 login——若当前连接仍活着
        且未过冷却期（20s），:meth:`connect` 直接复用现有连接（见其 docstring）。
        只有本方法（或网络中断）真正关闭 socket 后，下次 connect 才会重新 login。

        hexin 客户端从不主动断开（90s 抓包零 FIN），thspypc 遵循同样模式：
        长连接反复查询，避免反复 disconnect/connect 触发 VerifyCode=-1
        （同账号同 IP 短时间重复 login 的会话冲突，见 docs/handoffs/HANDOFF.md §7）。
        """
        self._connection_runtime.disconnect()

    def _close_owned_sockets(self) -> None:
        """Close facade-owned MAIN/REALORDER sockets for runtime shutdown."""
        for attr, lock in (
            ("_sock", self._sock_lock),
            ("_realorder_sock", self._realorder_lock),
            ("_board_sock", self._board_lock),
            ("_board_stats_sock", self._board_stats_lock),
        ):
            with lock:
                sock = getattr(self, attr, None)
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    setattr(self, attr, None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()


# ── 全市场股票代码表本地缓存（有效期一天=自然日）──────────────────────────────
# 仿 qr_login 的缓存模式：JSON 存 home 目录，saved_date 按自然日判断失效。
# stock_list() 拉取 ~7400 条代码一次后写盘，当天重复查询直接读缓存。

# ── IP 测速结果 + 轮换偏移的磁盘持久化（跨进程共享）─────────────────────────
# 反复 connect（如每次新进程 cli_ticker）时，让测速结果和轮换偏移跨进程共享，
# 避免每个进程都 offset=0 取前 7 个快 IP（集中撞同 IP 触发 -1）。

def default_ip_state_path() -> str:
    """IP 测速状态缓存的默认路径（用户 home 目录，跨平台）。"""
    return os.path.join(os.path.expanduser("~"), ".ths_ip_state.json")


# 连接治理按角色分桶的角色键。MAIN / 沪市 L2 / 深市 L2 各自独立，
# 因为 shlv2 与 szlv2 是两套 IP 零重叠的服务器，测速结果和轮换偏移不能混用。
IP_STATE_ROLES = ("main", "sh", "sz")


def save_ip_state(sorted_ips: list[str], rr_offset: int,
                  role: str = "main", path: str | None = None) -> None:
    """把测速排序结果 + 轮换偏移写盘（跨进程共享，按角色分桶）。

    磁盘结构（v2，按角色分桶）::

        {"version": 2, "roles": {"main": {"saved_at", "sorted_ips", "rr_offset"},
                                 "sh": {...}, "sz": {...}}}

    单次调用只更新 ``role`` 对应的那一桶，其它角色的桶原样保留。

    Args:
        sorted_ips: 按延迟升序排列的可达 IP 列表。
        rr_offset: 当前轮换偏移。
        role: 角色键（``main``/``sh``/``sz``）。
        path: 缓存路径，None 用 :func:`default_ip_state_path`。
    """
    path = path or default_ip_state_path()
    existing: dict = {"version": 2, "roles": {}}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict) and raw.get("version") == 2:
                roles = raw.get("roles", {})
                if isinstance(roles, dict):
                    existing["roles"] = roles
        except (json.JSONDecodeError, OSError, TypeError):
            pass
    existing["roles"][role] = {
        "saved_at": int(time.time()),
        "sorted_ips": sorted_ips,
        "rr_offset": rr_offset,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing, f)
    except OSError as e:
        logger.debug("IP 状态写盘失败（不影响运行）: %s", e)


def load_ip_state(path: str | None = None,
                  max_age: float = 300.0) -> dict[str, tuple[list[str], int]] | None:
    """读取磁盘缓存的 IP 测速状态（按角色分桶，未过期的角色才返回）。

    向后兼容：旧 v1 扁平结构 ``{saved_at, sorted_ips, rr_offset}`` 自动迁移
    到 ``main`` 桶，其余角色留空（首次测速时填充）。

    Args:
        path: 缓存路径，None 用 :func:`default_ip_state_path`。
        max_age: 缓存最大有效期（秒），默认 300（5 分钟，与 _PROBE_CACHE_TTL 一致）。

    Returns:
        ``{role: (sorted_ips, rr_offset)}``，仅含未过期的角色；文件不存在/损坏
        返回 None。返回的 dict 可能只含部分角色（其余已过期或从未测速）。
    """
    path = path or default_ip_state_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.debug("IP 状态缓存读取失败（将忽略）: %s", e)
        return None
    now = time.time()
    roles: dict[str, tuple[list[str], int]] = {}

    # v2 分桶结构
    if isinstance(data, dict) and data.get("version") == 2:
        for role, bucket in (data.get("roles") or {}).items():
            if not isinstance(bucket, dict):
                continue
            try:
                if now - bucket["saved_at"] > max_age:
                    continue
                roles[role] = (list(bucket["sorted_ips"]), int(bucket["rr_offset"]))
            except (KeyError, TypeError, ValueError):
                continue
        return roles or None

    # v1 扁平结构（向后兼容）→ 迁移到 main 桶
    try:
        saved_at = data["saved_at"]
        if now - saved_at > max_age:
            return None
        roles["main"] = (list(data["sorted_ips"]), int(data["rr_offset"]))
        return roles
    except (KeyError, TypeError, ValueError) as e:
        logger.debug("IP 状态缓存（v1）读取失败（将忽略）: %s", e)
        return None

