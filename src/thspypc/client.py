"""
同花顺 PC 远航版行情客户端。

登录打通 + 个股列表行情查询 + 自定义板块管理 + 短线精灵（异动）查询。
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

from . import protocol
from .protocol import (
    LIST_QUOTE_DATATYPE_DEFAULT,
    MARKET_HOSTS,
    MARKET_PORT,
    REALORDER_HOST,
    REALORDER_PORT,
    STOCK_LIST_DATATYPE,
    SUBREAL_CHANNELS,
    build_heartbeat_8901,
    build_heartbeat_9601,
    build_init_query,
    build_kline_query,
    build_list_quote_query,
    build_login_body_pc,
    build_passport64,
    build_qurealorder_query,
    build_stock_list_query,
    build_subreal_query,
    build_upstockname_request,
    decode_name_frame,
    encode_frame,
    full_http_auth,
    generate_imei,
    generate_mac64,
    KLINE_PERIOD_5MIN, KLINE_PERIOD_15MIN, KLINE_PERIOD_30MIN,
    KLINE_PERIOD_60MIN, KLINE_PERIOD_DAY, KLINE_PERIOD_WEEK, KLINE_PERIOD_MONTH,
    parse_hd1_response,
    parse_hd3_response,
    parse_kline_hd3_response,
    parse_init_response,
    parse_login_response,
    parse_passport_fields,
    parse_qurealorder_response,
    parse_pushrealorder_response,
    parse_stock_list_response,
    read_frame,
    read_frame_realorder,
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


class THSClient:
    """同花顺 PC 远航版行情客户端。

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

    def __init__(self, username: str, password: str, imei: str | None = None, mac64: str | None = None,
                 enable_heartbeat: bool = True):
        self.username = username
        self.password = password
        self.imei = imei if imei is not None else generate_imei()
        self.mac64 = mac64 if mac64 is not None else generate_mac64()
        self.enable_heartbeat = enable_heartbeat
        self._sock: socket.socket | None = None
        self._auth: dict | None = None
        # 板块/自选股管理（HTTPS，登录后初始化）
        self._blocks = None              # BlockManager 实例
        self._http_cookies: dict | None = None
        # 短线精灵（9601 TCP，懒连接）
        self._realorder_sock: socket.socket | None = None
        self._instance = 700000          # 请求序列号
        # 心跳（后台线程，connect 成功后自动启动）
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop = threading.Event()
        self._sock_lock = threading.Lock()              # 保护 8901 socket send
        self._realorder_lock = threading.Lock()         # 保护 9601 socket send
        self._hb_seq_8901 = 0
        self._hb_seq_9601 = 0
        # 连接治理（避免反复 connect 触发 VerifyCode=-1）
        self._last_connect_ts: float = 0.0   # 上次成功 connect 的时刻
        self._CONNECT_COOLDOWN = 20.0        # 同 IP 会话冲突窗口（秒）
        # 测速缓存 + IP 轮换（减少反复 connect 的 login 次数，降低单点登录会话冲突）
        self._probe_cache: tuple[float, list[str]] | None = None  # (ts, 按延迟排序的IP全表)
        self._PROBE_CACHE_TTL = 300.0        # 测速缓存有效期（秒），5 分钟
        self._login_rr_offset = 0            # login 轮换偏移（每次 connect 后推进）
        # 从磁盘加载跨进程共享的测速状态 + 轮换偏移（避免每个进程都 offset=0）
        _disk = load_ip_state()
        if _disk is not None:
            _ips, self._login_rr_offset = _disk
            self._probe_cache = (time.time(), _ips)
            logger.debug("从磁盘加载 IP 状态：%d 个 IP，offset=%d",
                         len(_ips), self._login_rr_offset)

    def connect(self) -> LoginResult:
        """账号密码登录：HTTP 鉴权 → 构造 PC login 帧 → 连 8901 → 验证。

        返回 LoginResult，含成功/失败诊断。失败时 error 字段区分：
          - "http_auth_failed"   HTTP 三步鉴权失败（账号/密码/网络问题）
          - "all_hosts_failed"   所有 8901 IP 都连不上（网络/防火墙）
          - "login_rejected"     连上了但 VerifyCode != 0（passport 被拒）

        VerifyCode=-1 有两种：A. login 帧内容错误（check 字节/sk/sv，已修复）；
        B. 同 IP 短时间重复 login 的会话冲突（level2 单点登录；**非账号封禁**——
        IP 充分分散时不触发，同花顺客户端始终能登）。本方法用 IP 轮换规避，
        连续 5 个 -1 判定会话冲突提前放弃（error="session_conflict"）。

        **连接治理（防 -1）**：若距上次成功 connect < 20s 且当前连接仍活着，本方法
        **直接复用现有连接**返回成功，不重新 login——这是 hexin 客户端的策略
        （连接还活着就别重连）。连接已断时正常走登录流程。
        """
        # ---- 连接治理：活着且未过冷却期 → 复用，避免重复 login 触发 -1 ----
        if (self._last_connect_ts
                and self.is_connected
                and (time.time() - self._last_connect_ts < self._CONNECT_COOLDOWN)):
            elapsed = time.time() - self._last_connect_ts
            logger.info("connect(): 当前连接仍活着（%.1fs 前），复用避免重复 login 触发 -1",
                        elapsed)
            return LoginResult(
                success=True, verify_code="0",
                server=f"(reused)",
                error="reused_existing_connection",
            )

        # ---- 第 1 步：HTTP 三步鉴权 ----
        try:
            logger.info("开始 HTTP 三步鉴权 (account=%s)...", self.username)
            self._auth = full_http_auth(self.username, self.password, self.imei)
            passport_fields = parse_passport_fields(self._auth["passport_bytes"])
            logger.info("HTTP 鉴权成功，passport 含 %d 个字段", len(passport_fields))
            logger.debug("passport 关键字段: account=%s, userclass=%s, level2=%s",
                         passport_fields.get("account", "?"),
                         passport_fields.get("userclass", "?"),
                         passport_fields.get("level2", "?"))
        except Exception as e:
            logger.error("HTTP 鉴权失败: %s", e)
            return LoginResult(success=False, error="http_auth_failed", detail=str(e))

        # 板块/自选股功能初始化（HTTP 鉴权后、TCP 登录前；失败不影响登录）
        self._init_blocks()

        return self._do_tcp_login(passport_fields)

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
        （见 HANDOFF §7）。连接断开时返回 False，由调用方决定是否重连
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
        login_body = build_login_body_pc(passport64, self.mac64)
        return self._do_tcp_login_raw(login_body, passport_fields={})

    def _http_auth_and_tcp_login(self, account: str, password: str) -> LoginResult:
        """用 account+password 走 HTTP 三步鉴权 → 8901 TCP login。

        connect_with_qrcode / connect_cached 共用此方法。
        """
        try:
            self._auth = full_http_auth(account, password, self.imei)
            passport_fields = parse_passport_fields(self._auth["passport_bytes"])
            logger.info("HTTP 鉴权成功（account=%s），passport 含 %d 个字段",
                        account[:6] + "***", len(passport_fields))
        except Exception as e:
            logger.error("HTTP 鉴权失败（account=%s）: %s", account[:6] + "***", e)
            return LoginResult(success=False, error="http_auth_failed", detail=str(e))

        self._init_blocks()
        return self._do_tcp_login(passport_fields, max_retries=1)

    def _do_tcp_login(self, passport_fields: dict) -> LoginResult:
        """构造 PC login 帧并连 8901（connect / connect_with_qrcode 共用）。

        前置条件：self._auth 已通过 full_http_auth 设置。
        """
        # ---- 构造 PC login 帧 ----
        passport64 = build_passport64(self._auth)
        login_body = build_login_body_pc(passport64, self.mac64)
        logger.debug("PC login 帧构造完成，body %d 字节", len(login_body))
        return self._do_tcp_login_raw(login_body, passport_fields)

    def _do_tcp_login_raw(self, login_body: bytes,
                          passport_fields: dict) -> LoginResult:
        """连 8901 发送已构造的 login 帧（并发连多 IP，用最先成功的）。

        复刻 hexin 客户端的策略：同时连 N 个不同 IP 并发 login，用最先返回
        VerifyCode=0 的连接，其余关闭。这避免了串行逐个尝试时对同一 IP
        重复登录导致 VerifyCode=-1（同账号会话冲突）。

        hexin 抓包确认：每 ~20s 并发连 7 个 IP，全部 VerifyCode=0，从不 -1。

        IP 列表优先用 passport M_hqdns 动态域名解析，回退到硬编码 MARKET_HOSTS。
        """
        # 动态解析 M_hqdns 域名拿 IP，回退到硬编码 MARKET_HOSTS
        hosts = []
        if self._auth:
            hosts = resolve_market_hosts(self._auth.get("passport_bytes", b""))
        if not hosts:
            logger.info("M_hqdns 动态解析无结果，回退到硬编码 MARKET_HOSTS")
            hosts = list(MARKET_HOSTS)

        # 测速选最快的 IP（复刻同花顺「测试 IP」功能）。
        # 并发 TCP 握手测延迟，选最快的 login，避免盲选到慢 IP（曾 46s 超时）。
        # 测速纯 TCP 握手不发 login，不触发 -1。结果缓存 5 分钟复用。
        sorted_ips = self._probe_fastest_hosts(hosts, timeout=1.0)
        if sorted_ips:
            # 从测速排序的全表里轮换取 N 个（不固定前几个）。
            # 每次连接后推进 _login_rr_offset，让反复连接时分散到不同 IP 子集。
            # 并发数取 7（复刻 hexin）：level2 单点登录下并发 login 只有 1 个能赢，
            # 其余 6 个被服务器标 -1（"烧掉"），但 7 个并发提供足够容错（实测 5 个
            # 在跨实例轮换失效时容错不足）。轮换偏移 + 测速结果持久化到磁盘，跨进程共享。
            n_concurrent = min(7, len(sorted_ips))
            offset = self._login_rr_offset % max(1, len(sorted_ips))
            # 环形取 n_concurrent 个（offset 起，绕回）
            batch = (sorted_ips[offset:] + sorted_ips[:offset])[:n_concurrent]
            logger.info("并发连接 %d 个 IP（测速排序+轮换 offset=%d）: %s",
                        len(batch), offset, batch[:3])
        else:
            # 测速全部超时（网络异常），回退到盲取前 7 个
            logger.warning("IP 测速全部超时，回退到盲取前 7 个")
            n_concurrent = min(7, len(hosts))
            batch = hosts[:n_concurrent]

        winner = self._concurrent_login(batch, login_body)
        # 推进轮换偏移：下次 connect 用不同的 IP 子集。写盘持久化（跨进程共享）。
        self._login_rr_offset = (self._login_rr_offset + n_concurrent) % max(1, len(sorted_ips) if sorted_ips else len(hosts))
        if sorted_ips:
            save_ip_state(sorted_ips, self._login_rr_offset)
        if winner:
            host, sock, result = winner
            self._sock = sock
            self._start_heartbeat()
            self._send_init_handshake()
            logger.info("✓ 登录成功 (%s:%d)", host, MARKET_PORT)
            return LoginResult(
                success=True,
                verify_code="0",
                server=f"{host}:{MARKET_PORT}",
                reply_fields=result,
                passport_fields=passport_fields,
            )

        # 并发全部失败，串行试剩余 IP（兼容 IP 列表短的情况）。
        # 加连续 -1 计数：单点登录会话冲突时所有 IP 秒回 -1，试更多 IP 无意义，
        # 串行 fallback：测速排序后的剩余可达 IP（跳过本次 batch），再补原始列表里
        # 测速超时但可能可用的 IP。加连续 -1 计数，避免傻试拖到几十秒。
        fallback_hosts = [ip for ip in (sorted_ips or hosts) if ip not in set(batch)]
        # 补上测速时剔除的超时 IP（万一它们只是测速瞬间不可达）
        seen = set(batch) | set(fallback_hosts)
        for h in hosts:
            if h not in seen:
                fallback_hosts.append(h)

        last_err = ""
        consecutive_minus1 = 0
        MAX_CONSECUTIVE_MINUS1 = 5
        for host in fallback_hosts:
            try:
                logger.info("尝试连接 %s:%d ...", host, MARKET_PORT)
                sock = socket.create_connection((host, MARKET_PORT), timeout=15)
                sock.sendall(encode_frame(login_body) + b"\n")
                resp_body = read_frame(sock)
                result = parse_login_response(resp_body)

                verify_code = result.get("VerifyCode", "?")
                logger.info("%s:%d 响应 VerifyCode=%s", host, MARKET_PORT, verify_code)

                if verify_code == "0":
                    self._sock = sock
                    self._start_heartbeat()
                    self._send_init_handshake()
                    logger.info("✓ 登录成功 (%s:%d)", host, MARKET_PORT)
                    return LoginResult(
                        success=True,
                        verify_code=verify_code,
                        server=f"{host}:{MARKET_PORT}",
                        reply_fields=result,
                        passport_fields=passport_fields,
                    )
                else:
                    sock.close()
                    if verify_code == "-1":
                        consecutive_minus1 += 1
                        logger.warning("%s:%d VerifyCode=-1（连续 %d 次）",
                                       host, MARKET_PORT, consecutive_minus1)
                        # 连续多个 -1 = 同 IP 短时间重复 login 的会话冲突（level2 单点
                        # 登录，对相同 IP 重复 login 触发）。非账号封禁——IP 分散时不触发，
                        # 同花顺客户端始终能登，改用不同 IP 即恢复。
                        if consecutive_minus1 >= MAX_CONSECUTIVE_MINUS1:
                            logger.warning("连续 %d 个 IP 返回 -1，判定为同 IP 重复 login 会话冲突，"
                                           "停止重试（改用不同 IP 即恢复）",
                                           consecutive_minus1)
                            return LoginResult(
                                success=False,
                                verify_code="-1",
                                error="session_conflict",
                                detail=f"连续 {consecutive_minus1} 个 IP VerifyCode=-1，"
                                       "疑似同 IP 短时间重复 login 的会话冲突（level2 单点登录）。"
                                       "改用不同 IP 或等片刻即恢复，非账号封禁",
                            )
                        continue
                    logger.warning("%s:%d 登录被拒 (VerifyCode=%s)", host, MARKET_PORT, verify_code)
                    return LoginResult(
                        success=False,
                        verify_code=verify_code,
                        server=f"{host}:{MARKET_PORT}",
                        reply_fields=result,
                        passport_fields=passport_fields,
                        error="login_rejected",
                    )
            except (socket.timeout, ConnectionError, OSError) as e:
                last_err = f"{host}: {e}"
                logger.warning("连接 %s 失败: %s", host, e)
                continue

        return LoginResult(success=False, error="all_hosts_failed", detail=last_err)

    def _send_init_handshake(self, timeout: float = 2.0) -> None:
        """login 后发 init 请求激活行情通道，读取 init 响应（服务器配置帧）。

        hexin 客户端 login 后紧跟 init 请求（subtype 0x0001），服务器据此
        激活该连接的行情查询通道。不发 init 直接 list_quotes 会超时
        （2026-07-23 抓包确认：hexin 每条连接 LOGIN→INIT→行情查询）。

        init 响应是**服务器配置帧**（~49KB，含 S-OS/S-Version/SName 等元数据），
        不是全量代码表（代码表是 stock_list() 重放序列才触发）。实测稳定返回
        1 帧（多次验证），0.1s 即到达。读完这 1 帧配置即激活行情通道，立即
        可 list_quotes（实测读 1 帧后 list_quotes 0.17s 成功）。

        本方法读第 1 帧配置（短超时等它到达），再用极短 peek（0.2s）确认无
        残留帧后即返回。旧实现用 8s 超时 + 循环 30 帧，每帧后空等一个超时周期，
        白等 ~8s——实际配置帧 1 帧、瞬间到达，无需等待。

        本方法在 login 成功路径上调用（self._sock 已赋值），进入即记录连接就绪
        时刻 ``self._last_connect_ts``（供 connect() 的冷却复用判断）。
        """
        # login 已成功、连接已就绪，记录时刻供下次 connect() 冷却判断
        self._last_connect_ts = time.time()
        try:
            req = build_init_query()
            with self._sock_lock:
                self._sock.sendall(req + b"\n")
                # 读第 1 帧配置（等它到达，最多 timeout 秒）
                self._sock.settimeout(timeout)
                n = 0
                try:
                    read_frame(self._sock)
                    n += 1
                except (socket.timeout, OSError):
                    pass
                except ValueError:
                    try:
                        self._sock.settimeout(1.0)
                        self._sock.recv(8192)
                    except Exception:
                        pass
                # 极短 peek 确认无残留帧（防偶发多帧），0.2s 几乎零成本
                self._sock.settimeout(0.2)
                try:
                    read_frame(self._sock)
                    n += 1
                except (socket.timeout, OSError):
                    pass  # 无残留，正常情况
                except ValueError:
                    pass
                logger.debug("init 握手完成（读 %d 帧配置，行情通道已激活）", n)
        except Exception as e:
            logger.warning("init 握手失败（行情查询可能超时）: %s", e)

    def _probe_fastest_hosts(self, hosts: list[str], timeout: float = 1.0,
                             use_cache: bool = True) -> list[str]:
        """并发 TCP 握手测每个 IP 的延迟，返回**按延迟升序排列的全部可达 IP**。

        复刻同花顺客户端「测试 IP」功能的机制（2026-07-23 抓包确认）：并发对多个
        IP 发 TCP 连接，测 SYN→SYN-ACK 握手往返时间，选最快的 login。同花顺实测
        最快 122.9.115.201=28ms，最慢 74ms，超时的剔除。

        纯 TCP 握手测速——**不发 login**，连上立即关闭，不触发 VerifyCode=-1
        （-1 是 login 帧内容错误或单点登录会话冲突触发的，TCP 连接不触发）。

        **测速缓存**：5 分钟内（``_PROBE_CACHE_TTL``）复用上次测速结果，避免反复
        connect 时重复测速。缓存命中时秒回。缓存只存按延迟排序的全表，调用方用
        ``_login_rr_offset`` 轮换取 batch（见 :meth:`_do_tcp_login_raw`）。

        Args:
            hosts: 待测 IP 列表。
            timeout: 单个 TCP 连接超时（秒）。1s 足够区分（最快 28ms，1s 内必回）。
            use_cache: 是否使用缓存（缓存未命中时测速并写入）。

        Returns:
            按延迟升序排列的可达 IP 列表（全部，不截断）。全部超时返回空列表。
        """
        # 缓存命中检查（避免反复 connect 重复测速）
        if use_cache and self._probe_cache:
            ts, cached = self._probe_cache
            if time.time() - ts < self._PROBE_CACHE_TTL and cached:
                logger.debug("IP 测速缓存命中（%d 个可达 IP）", len(cached))
                return cached
        results: list[tuple[str, float]] = []  # (ip, rtt_seconds)
        lock = threading.Lock()

        def _probe(host):
            t0 = time.time()
            try:
                s = socket.create_connection((host, MARKET_PORT), timeout=timeout)
                rtt = time.time() - t0
                s.close()  # 连上立即关闭，不发任何数据
                with lock:
                    results.append((host, rtt))
            except (socket.timeout, OSError):
                pass  # 超时/拒绝，剔除

        threads = [threading.Thread(target=_probe, args=(h,), daemon=True)
                   for h in hosts]
        t0 = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 0.5)  # 整体最多等 timeout+0.5s

        results.sort(key=lambda x: x[1])
        sorted_ips = [ip for ip, _ in results]  # 全部可达 IP，按延迟升序
        if sorted_ips:
            # 写内存缓存 + 磁盘持久化（跨进程共享，避免每个进程都 offset=0）
            self._probe_cache = (time.time(), sorted_ips)
            save_ip_state(sorted_ips, self._login_rr_offset)
            logger.info("IP 测速完成（%.1fs）：最快 %s=%.0fms，共 %d/%d 个可达",
                        time.time() - t0,
                        sorted_ips[0], results[0][1] * 1000,
                        len(results), len(hosts))
            logger.debug("测速详情: %s",
                         ", ".join(f"{ip}={rtt*1000:.0f}ms" for ip, rtt in results[:7]))
        return sorted_ips

    def _concurrent_login(self, hosts: list[str],
                          login_body: bytes, timeout: float = 12.0):
        """并发连多个 IP 发 login，返回最先 VerifyCode=0 的 (host, sock, result)。

        复刻 hexin 的并发登录策略：同时连 N 个 IP，用最先成功的，其余关闭。
        这避免了串行逐个尝试对同一 IP 重复登录导致 VerifyCode=-1。

        优化：用完成计数器（all_done Event）——所有线程都完成（无论成败）即提前
        退出 wait，不必等满 timeout。当账号处于全局 -1（所有 IP 秒回 -1）时，这能
        省下整段 timeout 的白等（如 14s → 0.1s）。
        """
        results = [None] * len(hosts)  # 每个线程的 (host, sock, result) 或 None
        errors = [None] * len(hosts)
        done = threading.Event()         # 有一个成功
        all_done = threading.Event()     # 所有线程都结束（成败皆可）
        remaining = [len(hosts)]         # 未完成数（用 list 做 mutable 计数）

        def _try_one(idx, host):
            try:
                sock = socket.create_connection((host, MARKET_PORT), timeout=timeout)
                if done.is_set():
                    sock.close(); return
                sock.sendall(encode_frame(login_body) + b"\n")
                sock.settimeout(timeout)
                resp_body = read_frame(sock)
                if done.is_set():
                    sock.close(); return
                result = parse_login_response(resp_body)
                vc = result.get("VerifyCode", "?")
                logger.info("%s:%d 响应 VerifyCode=%s", host, MARKET_PORT, vc)
                if vc == "0":
                    results[idx] = (host, sock, result)
                    done.set()
                else:
                    sock.close()
                    errors[idx] = f"VerifyCode={vc}"
            except Exception as e:
                errors[idx] = str(e)
            finally:
                # 所有线程完成时唤醒 wait（提前退出，不必等满 timeout）
                remaining[0] -= 1
                if remaining[0] <= 0:
                    all_done.set()

        threads = [threading.Thread(target=_try_one, args=(i, h),
                                    daemon=True) for i, h in enumerate(hosts)]
        for t in threads:
            t.start()
        # 等成功（done）或全部完成（all_done），取先到的，最多等 timeout+2
        deadline = time.time() + timeout + 2
        while not done.is_set() and not all_done.is_set():
            if time.time() >= deadline:
                break
            done.wait(timeout=min(0.5, deadline - time.time()))
        # 等所有线程结束（失败的会自己关闭 sock）
        for t in threads:
            t.join(timeout=1)

        # 返回第一个成功的结果
        for r in results:
            if r:
                return r
        # 全部失败，记录错误
        for i, h in enumerate(hosts):
            if errors[i]:
                logger.warning("  %s: %s", h, errors[i])
        return None

    def list_quotes(
        self,
        codes: list[str],
        market: int = 17,
        datatype: list[int] | None = None,
        pageid: int = 1335,
        timeout: float = 15.0,
    ) -> list[dict]:
        """查个股列表行情（复用登录后的 8901 socket）。

        发送 build_list_quote_query 构造的列表行情请求，解析 hd1.0（≤5 股）
        或 hd3.1（≥6 股）响应，返回记录列表。

        前置条件：已 connect() 成功（self._sock 存在）。
        8901 一条 TCP 响应可能含多个 fdfdfdfd 子帧（CodeListSize / MarketTime
        文本帧 + hd 数据帧）。本方法循环 read_frame，跳过非数据帧，取首个含
        ``hd1.0`` / ``hd3.1`` 标记的帧解析。

        Args:
            codes: 股票代码（纯数字，如 ["600056","600057"]）
            market: 市场码（17=沪 33=深）
            datatype: DataType 字段集（默认=精简7列 LIST_QUOTE_DATATYPE_DEFAULT）
            pageid: 页面 id
            timeout: 单次 read_frame 超时（秒）

        Returns:
            记录列表，每条 dict 含 ``code`` 及若干 ``dt<N>`` 字段，例如::

                {"code": "600056", "dt7": 9.36, "dt10": 9.64, "dt6": 9.5,
                 "dt17": 276800.0, "dt66": 0.0, ...}

            字段语义见 README「DataType 字段含义」表。
            竞价金额 = dt17(竞价量) × dt7(开盘价)，成交额 = dt13(成交量) × dt10(现价)，
            均由调用方本地计算。

        Raises:
            RuntimeError: 未登录（self._sock 为空）
        """
        if datatype is None:
            datatype = LIST_QUOTE_DATATYPE_DEFAULT
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        frame = build_list_quote_query(codes, market=market, datatype=datatype,
                                       pageid=pageid)
        self._sock.settimeout(timeout)
        # 每帧后跟 b"\n"（2026-07-17 实时抓包确认：hexin 每个帧 trailing 都是 0a，
        # login/行情/心跳帧无一例外；不加 \n 服务器不响应）。
        # sendall 加锁，避免与心跳线程交错。
        with self._sock_lock:
            if self._sock:
                self._sock.sendall(frame + b"\n")

        # 循环读帧，跳过 CodeListSize/MarketTime 等文本帧，取首个 hd 数据帧。
        # 最多读 8 帧避免无限等待（8901 通常 1-3 帧内出数据）。
        for _ in range(8):
            resp = read_frame(self._sock)
            if b"hd3.1\x00" in resp:
                recs = parse_hd3_response(resp)
                if recs:
                    return recs
                # hd3.1 标记在但解析失败（非 BitRLE 变体）→ 继续读下一帧
                logger.warning("收到 hd3.1 帧但解析为空（可能非 BitRLE 变体），"
                               "原始头 24B: %s", resp[:24].hex(" "))
                continue
            if b"hd1.0" in resp:
                recs = parse_hd1_response(resp)
                if recs:
                    return recs
                logger.warning("收到 hd1.0 帧但解析为空，原始头 24B: %s",
                               resp[:24].hex(" "))
                continue
            # 文本帧（CodeListSize= 等），跳过
            logger.debug("跳过非数据帧: %s",
                         resp[:40].decode("gbk", errors="replace")[:40])
        logger.warning("list_quotes: 8 帧内未找到 hd 数据帧")
        return []

    # K线周期名 → 周期码（kline/timeline 方法共用）
    _KLINE_PERIOD_CODES = {
        "5min": KLINE_PERIOD_5MIN, "15min": KLINE_PERIOD_15MIN,
        "30min": KLINE_PERIOD_30MIN, "60min": KLINE_PERIOD_60MIN,
        "day": KLINE_PERIOD_DAY, "week": KLINE_PERIOD_WEEK,
        "month": KLINE_PERIOD_MONTH,
    }

    def kline(
        self,
        code: str,
        period: str = "day",
        count: int = 2146,
        fuquan: str = "Q",
        market: int = 0,
        timeout: float = 12.0,
        retries: int = 3,
    ) -> list[dict]:
        """查 K线（复用登录后的 8901 长连接，复刻 hexin 单连接连发模式）。

        发送 ``build_kline_query`` 构造的 K线请求，解析 ``parse_kline_hd3_response``
        返回的 hd3.1 变体响应（flag=0x0042/0x0046），返回 OHLCV 记录列表。

        **连接复用**（关键）：抓包确认 hexin 在**同一条 TCP 长连接**上连发日/周/
        月/5分K 请求（不轮换 IP）。本方法复用 ``self._sock``，首次调用触发 connect()，
        后续调用复用同一条连接——这避免了每次重连新建短连接时的会话不稳定
        （周/月K route=0x014e 在新连接上易被 RST，长连接复用则稳定）。

        **重试**：连接断开或读超时时自动 ensure_connected + 重试（最多 ``retries`` 次）。
        每次重试用 IP 轮换取新连接（测速缓存 + 轮换偏移），命中稳定 IP 即成功。

        Args:
            code: 股票代码（纯数字，如 "000089"）
            period: 周期名（"5min"/"15min"/"30min"/"60min"/"day"/"week"/"month"）
            count: 取的根数（服务器按实际数据返回，可能少于 count）
            fuquan: 复权（"Q"=前复权 "H"=后复权 ""=不复权）
            market: 市场码（0=按代码前缀自动推断：6xx=沪17，其余=深33）
            timeout: 单次 read_frame 超时（秒）
            retries: 连接失败时的重试次数（每次重连轮换 IP）

        Returns:
            记录列表，每条 ``{code, time, open, high, low, close, volume,
            amount, bar_index?, dt<N>...}``，按时间正序。日内K（5分等）的
            ``time`` 为 None、原 dt1 值存 ``bar_index``。

        Raises:
            ValueError: period 不在支持列表内。
            RuntimeError: 重试 ``retries`` 次后仍失败。
        """
        if period not in self._KLINE_PERIOD_CODES:
            raise ValueError(f"period 不支持: {period}，可选: {list(self._KLINE_PERIOD_CODES)}")
        period_code = self._KLINE_PERIOD_CODES[period]
        if market == 0:
            market = 17 if code.startswith("6") else 33

        last_err = ""
        for attempt in range(retries + 1):
            # ensure_connected 对从未登录会 raise；这里统一用 is_connected 判断，
            # 连接不在则 connect()（首次登录 + 断线重连都走这里，IP 轮换取新连接）
            if not self.is_connected:
                logger.info("kline: 连接不可用，connect（attempt %d/%d，IP 轮换）",
                            attempt + 1, retries)
                lr = self.connect()
                if not lr.success:
                    last_err = f"connect 失败: {lr.error}"
                    continue
            try:
                return self._kline_query_once(code, market, period_code, count,
                                              fuquan, timeout)
            except (ConnectionError, OSError, TimeoutError) as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning("kline %s %s 失败（attempt %d）: %s",
                               code, period, attempt + 1, last_err)
                # 连接已坏，强制下次重连
                self._drop_connection()
        raise RuntimeError(f"kline {code} {period} 重试 {retries} 次仍失败: {last_err}")

    def _kline_query_once(self, code: str, market: int, period: int, count: int,
                          fuquan: str, timeout: float) -> list[dict]:
        """在当前 8901 连接上发一次 K线请求并解析响应（单次，不重试）。"""
        if self._sock is None:
            raise RuntimeError("未登录")
        frame = build_kline_query(code, market=market, period=period,
                                  fuquan=fuquan, count=count)
        self._sock.settimeout(timeout)
        with self._sock_lock:
            if not self._sock:
                raise ConnectionError("连接已关闭")
            self._sock.sendall(frame + b"\n")
        # 循环读帧，跳过文本/ACK 帧，取首个 hd3.1 K线数据帧
        for _ in range(8):
            resp = read_frame(self._sock)
            if b"hd3.1\x00" in resp:
                recs = parse_kline_hd3_response(resp)
                if recs:
                    return recs
                logger.debug("kline: 收到 hd3.1 但解析为空，继续读")
                continue
            logger.debug("kline: 跳过非数据帧 %dB", len(resp))
        logger.warning("kline: 8 帧内未找到 hd3.1 K线数据帧")
        return []

    def _drop_connection(self) -> None:
        """标记当前 8901 连接为坏（强制下次 ensure_connected 触发重连）。"""
        with self._sock_lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
        self.stop_heartbeat()

    def stock_list_hot(
        self,
        count: int = 29,
        timeout: float = 10.0,
        with_names: bool | str = False,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """获取排序榜单（自动翻页，可拿完整榜单）。

        发送排序代码表查询（同花顺打开 A 股列表、切换排序列时发的请求），
        服务器按 ``sort_by`` 指定的字段排序后返回。本方法自动用 SortBegin 游标
        翻页，直到拿满 ``count`` 条或取完整个榜单。

        ``sort_by`` 是排序键编号（见 :data:`protocol.SORT_BY_VALUES`，均为活网验证）：
        涨幅=199112、涨速=48、换手率=1968584、量比=1771976、主力净流入=592890、
        竞价金额=68758、竞价涨幅=68762。默认按涨幅降序（涨幅榜）。
        换成跌幅榜传 ``sort_by=199112, sort_dir="A"``（升序值 A 为推测，未实测）。

        ⚠ 成交量/成交额**不能**通过本方法拿——它们不走 SortBy 路径，而是客户端
        订阅行情推送（dt13/dt19）后本地排序。详见 HANDOFF_STOCKLIST_PUSH.md。

        翻页机制（2026-07-23 抓包确认）：SortBegin 是游标（首次 0，翻页递增到
        已加载位置），每页 59 条（SortCount 恒 59）。``count`` 是想要的总条数，
        本方法内部循环请求直到拿满。

        Args:
            count: 想要的总条数，默认 29（对齐 hexin 第一页，向后兼容）。
                想要完整榜单（约 5200 条）传一个大数如 5300 即可。
            timeout: 单次请求的超时时间（秒）。
            with_names: 是否填充中文名称（同 stock_list 的 with_names 参数）。
            sort_by: 排序键编号，默认 199112（涨幅）。见
                :data:`protocol.SORT_BY_VALUES`。
            sort_dir: 排序方向，``"D"``=降序（默认）、``"A"``=升序（推测，未实测）。
            max_pages: 翻页安全阀（默认 120，≈5300/59），防止死循环。

        Returns:
            list[dict]，每项 ``{"code": "600519", "name": "贵州茅台"}``。
            按 code 去重（页边界可能重叠）。

        Raises:
            RuntimeError: 未登录。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        # markets 对齐 hexin 抓包真值（stock_list.pcap）：17=沪 22=深A 151=北交所。
        # 注意 33 是深市另一类（非深A 主板/创业板），抓包确认排序查询用的是 22 不是 33。
        PAGE = 59  # hexin 每页恒 59 条（抓包确认）
        stocks: list[dict] = []
        seen_codes: set[str] = set()
        sort_total = 0
        sort_begin = 0
        target = count  # 想要的总条数

        with self._sock_lock:
            sock = self._sock
            for page in range(max_pages):
                req = build_stock_list_query(
                    markets=(17, 22, 151),
                    sort_begin=sort_begin,
                    sort_count=PAGE,
                    datatype=[sort_by],
                    sort_by=sort_by,
                    sort_dir=sort_dir,
                )
                sock.sendall(req + b"\n")
                sock.settimeout(timeout)
                # 循环读帧，跳过 MarketTime 等文本帧，取首个含 SortTotal 的数据帧
                # （同 list_quotes 的多帧模式：服务器可能先推 MarketTime 再推数据）
                resp = None
                for _ in range(8):
                    try:
                        frame = read_frame(sock)
                    except (socket.timeout, OSError) as e:
                        logger.error("stock_list_hot: 读取响应失败: %s", e)
                        return stocks
                    if not frame:
                        continue
                    if b"SortTotal" in frame:
                        resp = frame
                        break
                    # 跳过非数据帧（MarketTime / CodeListSize 等）

                if not resp:
                    logger.warning("stock_list_hot: 第 %d 页无数据帧响应", page + 1)
                    break

                meta = parse_stock_list_response(resp)
                if not sort_total:
                    sort_total = meta.get("sort_total", 0)
                page_stocks = meta.get("stocks", [])
                # 按 code 去重合并（页边界可能重叠）
                new_in_page = 0
                for s in page_stocks:
                    c = s.get("code", "")
                    if c and c not in seen_codes:
                        seen_codes.add(c)
                        stocks.append(s)
                        new_in_page += 1

                data_count = meta.get("sort_data_count", len(page_stocks))
                logger.debug("stock_list_hot: 第 %d 页 SortBegin=%d 拿 %d 条"
                             "（新增 %d），累计 %d/%d",
                             page + 1, sort_begin, data_count, new_in_page,
                             len(stocks), sort_total)

                # 终止条件：已拿够 / 已取完整个榜单 / 本页无数据
                if len(stocks) >= target or len(stocks) >= sort_total \
                        or data_count == 0:
                    break
                # 推进游标：用累计已收条数作为下一页起点（对齐抓包 Begin≈已加载位置）
                sort_begin = len(stocks)

        logger.info("stock_list_hot: 共 %d 页，获取 %d 条（共 %d 条，目标 %d）",
                    page + 1, len(stocks), sort_total, target)

        # 可选名称填充
        if with_names and stocks:
            stockname_dir = with_names if isinstance(with_names, str) else None
            name_map = THSClient.load_hexin_names(stockname_dir)
            if name_map:
                filled = 0
                for s in stocks:
                    nm = name_map.get(s["code"], "")
                    if nm:
                        s["name"] = nm
                        filled += 1
                logger.info("stock_list_hot: 从 hexin 缓存填充 %d/%d 条名称",
                            filled, len(stocks))

        return stocks

    def stock_list(
        self,
        timeout: float = 30.0,
        with_names: bool | str = False,
    ) -> list[dict]:
        """获取全市场股票代码列表（沪深+北交所+新三板+基金，~7400 条）。

        通过重放 hexin 启动序列的关键请求段（subreal×8 + CodeList 1B0987 + init），
        触发服务器下发全量代码表（dc≈7422, unk=0x18, hs=71 的 hd3.1 帧）。
        这是 hexin 启动时加载全量代码表的同一机制（冷启动抓包 stream 44 确认）。

        ⚠ 单独发 init 请求**不会**触发全量下发（服务器只返回配置帧）。
        必须重放完整的 subreal + 特殊 CodeList 订阅序列，服务器才会在登录连接上
        推送 dc≈7422 的全量 hd3.1 帧。本方法用 ``data/stock_list_replay.bin``
        里固化的 4 个请求段（提取自 cold_start.pcap stream 44 帧1619/1965/2308/2481）。

        Args:
            timeout: 收尾读取的总时长（秒）。重放后服务器陆续推送，需等全量帧到达。
            with_names: 是否填充中文名称。
                - False: 不填名称（默认，快）
                - True: 自动从同花顺本地缓存加载名称（需安装同花顺 PC 客户端）
                - str: 指定 stockname 目录路径

        Returns:
            list[dict]，每项 ``{"code": "600000", "name": "浦发银行"}``。
            约 7400 条，按 dt5 代码字段顺序（通常代码升序）。
            with_names=False 时 name 恒为 ""。

        Raises:
            RuntimeError: 未登录。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        # 加载重放段（4 个请求 segment，提取自 cold_start.pcap stream 44）
        replay_path = os.path.join(os.path.dirname(__file__), "data",
                                   "stock_list_replay.bin")
        if not os.path.exists(replay_path):
            logger.error("stock_list: 重放数据文件不存在 %s", replay_path)
            return []
        with open(replay_path, "rb") as f:
            data = f.read()
        n = int.from_bytes(data[:4], "little")
        off = 4
        segments = []
        for _ in range(n):
            ln = int.from_bytes(data[off:off+4], "little")
            off += 4
            segments.append(data[off:off+ln])
            off += ln

        best_stocks: list[dict] = []
        full_dc = 0
        # 重放期间持锁，并临时禁用心跳避免干扰（如果心跳开着）
        with self._sock_lock:
            sock = self._sock
            # 发送 4 个请求段（间隔 0.3s 模拟 hexin 节奏）
            for i, seg in enumerate(segments):
                if sock:
                    sock.sendall(seg)
                time.sleep(0.3)
            # 读响应：短超时轮询，直到 timeout 到或拿到全量帧后再读 3s 确认
            sock.settimeout(2.0)
            t0 = time.time()
            got_full_at = None
            while True:
                if got_full_at and (time.time() - got_full_at > 3):
                    break  # 拿到全量后再读 3s 确认无更大帧
                if not got_full_at and (time.time() - t0 > timeout):
                    break  # 总超时
                try:
                    resp = read_frame(sock)
                    if not resp:
                        continue
                except (socket.timeout, OSError):
                    continue
                except ValueError:
                    # read_frame 偶尔在推送帧中间解析失败（魔数碰撞），跳过
                    try:
                        sock.settimeout(1.0)
                        sock.recv(8192)
                        sock.settimeout(2.0)
                    except Exception:
                        pass
                    continue
                meta = parse_init_response(resp)
                if len(meta["stocks"]) > len(best_stocks):
                    best_stocks = meta["stocks"]
                    # 检查这一帧是否有 dc>5000 的全量帧
                    for f in meta.get("hd31_frames", []):
                        if f["unk"] == 0x18 and f["dc"] > 5000:
                            full_dc = f["dc"]
                            got_full_at = time.time()
                            break

        if best_stocks:
            logger.info("stock_list 获取 %d 条代码（全量帧 dc=%d）",
                        len(best_stocks), full_dc)
        else:
            logger.warning("stock_list: 重放后未收到全量代码表帧 "
                           "（可能服务器实例未响应，重连换 IP 重试）")

        # 可选：从 hexin 本地缓存填充中文名称
        if with_names:
            stockname_dir = with_names if isinstance(with_names, str) else None
            name_map = THSClient.load_hexin_names(stockname_dir)
            if name_map:
                filled = 0
                for s in best_stocks:
                    nm = name_map.get(s["code"], "")
                    if nm:
                        s["name"] = nm
                        filled += 1
                logger.info("stock_list: 从 hexin 缓存填充 %d/%d 条名称",
                            filled, len(best_stocks))

        return best_stocks

    def stock_list_cached(
        self,
        *,
        cache_path: str | None = None,
        refresh: bool = False,
        with_names: bool = True,
        timeout: float = 30.0,
    ) -> list[dict]:
        """获取全市场股票代码表（带本地缓存，有效期一天=自然日）。

        :meth:`stock_list` 的缓存版：当天首次调用走网络拉取（~6s）并写盘，
        之后当天再调用直接读缓存（~瞬时），不再发网络请求。跨自然日自动失效。

        缓存文件 ``~/.ths_stock_codes.json``（见 :func:`default_stock_cache_path`），
        含全量代码 + 名称 + 派生市场码（沪=17/深=33），可直接喂给
        :meth:`list_quotes`。

        Args:
            cache_path: 缓存文件路径，None 用默认路径。
            refresh: True 时强制刷新（忽略缓存，重新走网络拉取并覆盖写盘）。
            with_names: 网络拉取时是否填充名称。默认 True（缓存场景几乎都要名称，
                且只写盘一次）。缓存命中时此参数无效（名称已存盘）。
            timeout: 网络拉取的总超时（秒），传给 :meth:`stock_list`。

        Returns:
            list[dict]，每项 ``{"code", "name", "market"}``，约 7400 条。
            market 为派生值：17=沪市 A 股、33=深市 A 股、None=北交所/新三板/基金
            （list_quotes 当前不支持的市场，仍保留 code+name 供其他用途）。

        Raises:
            RuntimeError: 未登录（缓存未命中需走网络时）。
        """
        path = cache_path or default_stock_cache_path()
        if not refresh:
            loaded = load_stock_codes(path)
            if loaded is not None:
                stocks, saved_date = loaded
                logger.info("stock_list_cached: 命中缓存 (%s, %d 条)",
                            saved_date, len(stocks))
                return stocks
        # 缓存不存在/过期/强制刷新 → 走网络
        logger.info("stock_list_cached: 缓存未命中，走 stock_list() 拉取...")
        stocks = self.stock_list(timeout=timeout, with_names=with_names)
        # 覆盖 market 字段为派生值（stock_list 返回的 market 恒为 0）
        for s in stocks:
            s["market"] = market_from_code(s["code"])
        # 仅在拿到有效结果时写盘，避免失败的拉取被缓存一整天
        if stocks:
            save_stock_codes(stocks, path)
        else:
            logger.warning("stock_list_cached: 拉取为空，不写缓存（可重试）")
        return stocks

    # ── 全市场快照（hfd1.0 空括号协议）──

    def _market_snapshot_on_main_sock(
        self,
        markets: list[int] | None = None,
        timeout: float = 10.0,
    ) -> list[dict]:
        """在主连接 self._sock 上发一次全市场快照请求，解析 hfd1.0 响应。

        ⚠ **不限流的根本前提**：本方法在 :meth:`connect` 建立的长连接上发请求，
        绝不新建/断开连接。反复 connect/disconnect 会触发 VerifyCode=-1（同账号
        同 IP 短时间重复 login 的会话冲突，见 HANDOFF §7），这是此前
        ``market_snapshot`` 必然限流的根因——旧实现循环 ``connect()``/``disconnect()``
        最多 5 次 × 每次并发 7 IP = 短时间 35 次 login 打同一批 IP。

        host 不支持 hfd1.0（返回空/超时）时返回空列表，由调用方
        （:meth:`market_snapshot_with_quotes`）决定是否走 :meth:`list_quotes`
        兜底。本连接不被破坏，后续仍可做其他查询。

        前置条件：已 connect() 成功（self._sock 存在）。

        Args:
            markets: 市场码列表，None 用 :data:`MARKET_SNAPSHOT_MARKETS`。
            timeout: 单次 read_frame 超时（秒）。

        Returns:
            解析后的记录列表（约 1200 条，hfd1.0 数值字段为近似值）。
            host 不支持或超时返回 []。
        """
        if self._sock is None:
            logger.debug("market_snapshot: 未连接，跳过")
            return []

        req = protocol.build_market_snapshot_query(markets=markets)
        try:
            with self._sock_lock:
                if not self._sock:
                    return []
                self._sock.sendall(req + b"\n")
                self._sock.settimeout(timeout)
                # 服务器可能先推文本帧再推 hfd1.0 数据帧，循环找首个含标记的
                # （与 list_quotes 同模式）
                for _ in range(8):
                    try:
                        raw = read_frame(self._sock)
                    except (socket.timeout, OSError):
                        return []
                    except ValueError:
                        # magic 对齐失败（推送帧中间魔数碰撞），跳过这一段继续
                        continue
                    if raw and b"hfd1.0" in raw:
                        from thspypc.parse_hfd1 import parse_hfd1_response
                        try:
                            records = parse_hfd1_response(raw)
                            logger.info("market_snapshot: 主连接 hfd1.0 成功, %d 条",
                                        len(records))
                            return records
                        except Exception as e:
                            logger.debug("market_snapshot: hfd1.0 解析失败: %s", e)
                            return []
        except (socket.timeout, OSError) as e:
            logger.debug("market_snapshot: 主连接读取失败: %s", e)
        return []

    def market_snapshot(
        self,
        markets: list[int] | None = None,
        timeout: float = 10.0,
    ) -> list[dict]:
        """全市场行情快照：一个请求拿沪市全市场 code+name（~0.13s）。

        在 :meth:`connect` 建立的**主连接**上发 hfd1.0 空括号请求
        （``CodeList=16();17();...``），服务器一次性返回整个市场的股票代码和
        名称。相比 :meth:`list_quotes` 逐批查询（~250 请求），本方法只需 1 个请求，
        速度提升 2~3 个数量级。

        ⚠️ **数值字段（price/change_pct 等）当前为近似值**，通过 THS float 扫描
        推断，准确度有限。对于准确行情请用 :meth:`list_quotes`（或
        :meth:`market_snapshot_with_quotes` 的混合方案）。

        ⚠️ 当前连接的服务器 host **可能不支持 hfd1.0**（集群中仅部分 host 支持）。
        不支持时本方法返回空列表——但**不重连**（重连会触发 VerifyCode=-1，
        见 HANDOFF §7）。需要稳定拿沪市行情时优先用
        :meth:`market_snapshot_with_quotes`。

        Args:
            markets: 市场码列表，None 用 :data:`MARKET_SNAPSHOT_MARKETS`
                （16-22/144-151 沪市全）。
            timeout: 单次 read_frame 超时（秒）。

        Returns:
            list[dict]，每项 ``{"code", "name", "price", "change_pct", ...}``，
            约 1200+ 条（当前锚点覆盖率）。host 不支持或超时返回 []。

        Raises:
            RuntimeError: 未登录（self._sock 为空）。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")
        return self._market_snapshot_on_main_sock(markets=markets, timeout=timeout)

    def market_snapshot_with_quotes(
        self,
        timeout: float = 60.0,
        batch_size: int = 30,
    ) -> list[dict]:
        """全市场行情快照：沪深全市场 code+name+准确行情。

        纯双数据源方案（**不依赖 hfd1.0**，彻底避免反复 connect 限流）：

        | 数据源 | 覆盖 | 速度 |
        |--------|------|------|
        | :meth:`stock_list_cached` | 沪深全市场 code+name | ~瞬时(缓存) / ~6s(首次) |
        | :meth:`list_quotes` | 全市场准确行情（批量回填） | ~10-30s |

        旧实现额外调用 hfd1.0 空括号快照拿沪市 code+name，但 hfd1.0 路径
        反复 connect/disconnect 触发 VerifyCode=-1（限流根因，见 HANDOFF §7），
        且名称覆盖（1209 锚点）不如 hexin 本地缓存（~8000 条）全，故移除。
        code+name 现完全由 ``stock_list_cached(with_names=True)`` 提供。

        Args:
            timeout: list_quotes 单批超时（秒）。
            batch_size: 每批 list_quotes 数量。

        Returns:
            list[dict]，每项 ``{"code", "name", "price", "change_pct", ...}``。
            code 和 name 来自 stock_list 缓存（hexin 本地名称），数值来自
            list_quotes（盘中准确值，需在交易时段调用）。

        Raises:
            RuntimeError: 未登录。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        # 1. stock_list 缓存取全量 code+name（含沪深，名称来自 hexin 本地缓存）
        stock_codes = self.stock_list_cached(with_names=True)
        all_by_code: dict[str, dict] = {}
        for s in stock_codes:
            code = s["code"]
            all_by_code[code] = {"code": code, "name": s.get("name", "")}

        # 2. list_quotes 批量回填行情（在主连接上，安全）
        # DataType 字段集（2026-07-23 实测确认含义，见 tests/diag_field_mapping.py）：
        #   dt5=代码 dt6=昨收 dt7=今开 dt8=最高 dt9=最低 dt10=最新价
        #   dt13=成交股数(÷100=手) dt19=成交额(元) dt48=涨速 dt66=涨幅(盘中有效)
        # ⚠ 必须含 dt6（昨收），否则涨跌幅无法本地计算（实测缺 dt6 时返回 None）。
        # ⚠ 字段名必须用 r.get("dt10") 等原始键——list_quotes 返回 dt<N> 原始键，
        #   不是 "price"/"change_pct" 等具名键（旧代码用具名键导致全部 None）。
        datatype = [5, 6, 7, 8, 9, 10, 13, 18, 19, 48, 49]
        codes_all = list(all_by_code.keys())
        quote_count = 0

        for i in range(0, len(codes_all), batch_size):
            batch = codes_all[i:i + batch_size]
            try:
                mkt = market_from_code(batch[0]) if batch else 17
                recs = self.list_quotes(batch, market=mkt,
                                        datatype=datatype,
                                        timeout=min(timeout, 15))
                for r in recs:
                    code = r.get("code", "")
                    if code and code in all_by_code:
                        # 用 list_quotes 实际返回的 dt<N> 原始键回填
                        all_by_code[code].update({
                            "price": r.get("dt10"),
                            "prev_close": r.get("dt6"),
                            "open": r.get("dt7"),
                            "high": r.get("dt8"),
                            "low": r.get("dt9"),
                            "amount": r.get("dt19"),   # 成交额(元)，服务器直接返回
                            "volume": r.get("dt13"),   # 成交股数(÷100=手)
                        })
                        quote_count += 1
            except Exception as e:
                logger.debug("market_snapshot batch %s 失败: %s", batch[:3], e)

        result = list(all_by_code.values())
        logger.info("market_snapshot_with_quotes: %d 条, 回填 %d 条行情",
                    len(result), quote_count)
        return result

    # ── 股票名称（网络 upstockname 协议）──

    def fetch_stock_names(
        self,
        market: str = "URS",
        stock_name_ver: str = ";;",
        timeout: float = 10.0,
    ) -> dict:
        """通过 upstockname 协议从服务器获取股票名称（探索性能力）。

        ⚠ **默认名称源是** :meth:`load_hexin_names`（同花顺本地缓存，瞬时、稳定、
        覆盖沪深北 A 股）。本方法仅作探索性补充——且对主用途（A 股名称）无增益：
        thspypc 拿到的增量帧恰好是未解的 ``name_16_16`` 块状段。

        发送 ``method=upstockname`` 请求，解析响应中的 ``[name_<MARKET>]`` 段。
        纯文本段（外汇/期货/北交所/外盘等）直接解出；块状自定义编码段
        （沪深 A 股 ``name_16_16``）当前跳过（编码未逆向，简单模型已穷举证伪，见
        :func:`thspypc.protocol.decode_name_frame` 与 HANDOFF §6a/§6b）。

        服务器按账号追踪名称版本，thspypc 账号通常只能拿到**增量**（~12 条），
        全量需 hexin 客户端冷启动触发。本方法适合补充 :meth:`load_hexin_names`
        覆盖不到的市场（外盘/期货）。

        Args:
            market: 市场通道码（``URS``/``UNX``/``UCX``/``UNS``/``UHI`` …）。
            stock_name_ver: 本地版本号，``;;`` 请求全量（实际仍可能只回增量）。
            timeout: 读响应总时长（秒）。

        Returns:
            :func:`decode_name_frame` 的结果 dict::

                {
                  "names": {code: name, ...},
                  "by_segment": {...},
                  "skipped": [...],   # 块状编码、未解的段名
                  "segments": [(seg_name, data_len, kind), ...],
                }

        Raises:
            RuntimeError: 未登录。
        """
        if self._sock is None:
            raise RuntimeError("未登录，请先 connect() / connect_cached()")

        req = build_upstockname_request(market, stock_name_ver)
        names_result: dict = {
            "names": {}, "by_segment": {}, "skipped": [], "segments": [],
        }
        with self._sock_lock:
            sock = self._sock
            if not sock:
                return names_result
            sock.sendall(req)
            sock.settimeout(2.0)
            t0 = time.time()
            # 名称帧通常 1~2 帧就到；读到含 [name_ 的帧后继续读 2s 收尾
            got_name = False
            while True:
                if got_name and (time.time() - t0 > 4):
                    break
                if not got_name and (time.time() - t0 > timeout):
                    break
                try:
                    resp = read_frame(sock)
                    if not resp:
                        continue
                except (socket.timeout, OSError):
                    continue
                except ValueError:
                    try:
                        sock.settimeout(1.0)
                        sock.recv(8192)
                        sock.settimeout(2.0)
                    except Exception:
                        pass
                    continue
                # 名称帧特征：含 [name_ 或 MarketCode 或 upnametype
                if b"[name_" in resp or b"upnametype" in resp or b"MarketCode" in resp:
                    got_name = True
                    r = decode_name_frame(resp)
                    names_result["names"].update(r["names"])
                    names_result["by_segment"].update(r["by_segment"])
                    names_result["skipped"].extend(r["skipped"])
                    names_result["segments"].extend(r["segments"])

        logger.info("fetch_stock_names(market=%s): 解出 %d 条名称，跳过 %d 个块状段",
                    market, len(names_result["names"]), len(names_result["skipped"]))
        return names_result

    # ── 股票名称加载 ──

    @staticmethod
    def load_hexin_names(
        stockname_dir: str | None = None,
    ) -> dict[str, str]:
        """从同花顺本地缓存加载股票代码→名称映射（**默认名称源**）。

        这是获取 A 股名称的推荐方式——瞬时、稳定、零网络依赖，覆盖沪深北交易所。
        相比网络协议 :meth:`fetch_stock_names`（块状段未解、只能拿增量），本方法
        是主用途的首选。

        读取 ``<hexin_dir>/stockname/stockname_*_0.txt`` 文件，
        解析 ``CODE=NAME|ALIAS@FLAG`` 格式。仅保留 6 位数字代码。

        Args:
            stockname_dir: stockname 目录路径。为 None 时自动探测常见安装位置：
                ``C:/同花顺软件/同花顺/stockname/``。

        Returns:
            dict[str, str]，键为 6 位数字代码（如 "600000"），值为中文名称（如 "浦发银行"）。
            约 8000+ 条（覆盖沪深北交易所）。
        """
        if stockname_dir is None:
            # 自动探测常见安装路径
            candidates = [
                r"C:\同花顺软件\同花顺\stockname",
                r"D:\同花顺软件\同花顺\stockname",
                os.path.expandvars(r"%LOCALAPPDATA%\同花顺\stockname"),
                os.path.expandvars(r"%APPDATA%\同花顺\stockname"),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    stockname_dir = c
                    break
        if not stockname_dir or not os.path.isdir(stockname_dir):
            logger.warning("load_hexin_names: stockname 目录不存在，返回空映射。"
                           "请安装同花顺 PC 客户端或手动指定 --stockname-dir")
            return {}

        names: dict[str, str] = {}
        for fname in sorted(os.listdir(stockname_dir)):
            # 只读 _0.txt 基础文件（_1.txt 是增量，.base 是备份）
            if not (fname.endswith("_0.txt") and fname.startswith("stockname_")):
                continue
            fpath = os.path.join(stockname_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            try:
                text = raw.decode("gbk", errors="replace")
            except UnicodeDecodeError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("ConfigVer"):
                    continue
                if "=" not in line:
                    continue
                code, _, rest = line.partition("=")
                # 只取 6 位纯数字代码（A 股/北交所/新三板）
                if not (code.isdigit() and len(code) == 6):
                    continue
                name = rest.split("|")[0].split("@")[0].strip()
                if name:
                    names[code] = name

        logger.info("load_hexin_names: 从 %s 加载 %d 条名称",
                    stockname_dir, len(names))
        return names

    # ── 自定义板块/自选股管理（门面方法，委托给 BlockManager）──

    def _ensure_blocks(self):
        if self._blocks is None:
            raise RuntimeError("板块功能未初始化，请先 connect()")

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

    # ── 短线精灵（异动，9601 端口 qurealorder）──

    def _connect_realorder_server(self) -> None:
        """懒连接 9601 短线精灵服务（passport64 登录）。

        用 PC 版 login 帧（build_login_body_pc）登录，VerifyCode=0 则存 socket。
        前置条件：self._auth 已设置。
        """
        if self._realorder_sock or self._auth is None:
            return
        try:
            passport64 = build_passport64(self._auth)
            login_body = build_login_body_pc(passport64, self.mac64)
            sock = socket.create_connection((REALORDER_HOST, REALORDER_PORT), timeout=15)
            sock.sendall(encode_frame(login_body) + b"\n")
            resp = read_frame(sock)
            result = parse_login_response(resp)
            if result.get("VerifyCode") == "0":
                self._realorder_sock = sock
                logger.info("9601 短线精灵服务连接成功 (%s:%d)", REALORDER_HOST, REALORDER_PORT)
            else:
                sock.close()
                logger.warning("9601 登录失败: VerifyCode=%s", result.get("VerifyCode"))
        except Exception as e:
            logger.warning("9601 短线精灵服务连接失败: %s", e)

    # ── 心跳（后台线程，维持 8901/9601 长连接）──

    def _start_heartbeat(self) -> None:
        """启动心跳后台线程（connect 成功后自动调用）。

        8901 每 3 秒、9601 每 30 秒（若已连接）。daemon 线程，主进程退出时自动结束。
        enable_heartbeat=False 时不启动（用于对比测试）。
        """
        if not self.enable_heartbeat:
            return
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return  # 已在运行
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="ths-heartbeat", daemon=True)
        self._heartbeat_thread.start()
        logger.debug("心跳线程已启动")

    def stop_heartbeat(self) -> None:
        """停止心跳线程（disconnect 时自动调用）。"""
        self._heartbeat_stop.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)
        self._heartbeat_thread = None

    def _heartbeat_loop(self) -> None:
        """心跳循环：8901 每 3 秒、9601 每 30 秒（10 个 3 秒周期）。

        用 _heartbeat_stop.wait(3) 阻塞，被 set 时立即退出。异常只 warning 不中断。
        """
        tick = 0
        while not self._heartbeat_stop.is_set():
            # 等 3 秒（或被 stop 唤醒立即退出）
            if self._heartbeat_stop.wait(3.0):
                break
            tick += 1
            # 8901 心跳（每 3 秒）
            if self._sock:
                try:
                    self._hb_seq_8901 += 1
                    with self._sock_lock:
                        if self._sock:
                            self._sock.sendall(build_heartbeat_8901(self._hb_seq_8901) + b"\n")
                except OSError as e:
                    logger.debug("8901 心跳发送失败（不影响查询）: %s", e)
            # 9601 心跳（每 30 秒 = 每 10 个 tick）
            if tick % 10 == 0 and self._realorder_sock:
                try:
                    self._hb_seq_9601 += 1
                    with self._realorder_lock:
                        if self._realorder_sock:
                            self._realorder_sock.sendall(
                                build_heartbeat_9601(self._hb_seq_9601) + b"\n")
                except OSError as e:
                    logger.debug("9601 心跳发送失败（不影响查询）: %s", e)

    def _realorder_query(self, body: bytes) -> bytes:
        """在 9601 连接上发查询，返回原始响应。"""
        if not self._realorder_sock:
            self._connect_realorder_server()
        if not self._realorder_sock:
            raise RuntimeError("9601 短线精灵服务未连接")
        with self._realorder_lock:
            self._realorder_sock.sendall(encode_frame(body) + b"\n")
            self._realorder_sock.settimeout(15)
            return read_frame_realorder(self._realorder_sock)

    def dxjl_page(self, market: int, endtime_us: int) -> list[dict]:
        """获取短线精灵单页数据（9601，method=qurealorder）。

        Args:
            market: 市场代码，32=深 16=沪。
            endtime_us: 微秒时间戳游标（取此时间之前的记录）。

        Returns:
            list[dict]，每项含 时间(微秒戳)/市场/代码/异动类型/异动编码/金额/涨跌幅。
        """
        try:
            self._instance += 1
            body = build_qurealorder_query(self._instance, market, endtime_us)
            resp = self._realorder_query(body)
            return parse_qurealorder_response(resp, str(market))
        except Exception as e:
            logger.error("dxjl_page 查询失败: %s", e)
            return []

    def dxjl_latest(self, markets: tuple = (32, 16)) -> list[dict]:
        """获取短线精灵最新一页（沪深）。

        Args:
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序（最新在前）。非交易时段可能为空。
        """
        now_us = int(time.time() * 1_000_000)
        all_recs = []
        for mk in markets:
            all_recs.extend(self.dxjl_page(mk, now_us))
        all_recs.sort(key=lambda r: r["时间"], reverse=True)
        return all_recs

    def dxjl_history(self, pages: int = 5, markets: tuple = (32, 16)) -> list[dict]:
        """翻页获取短线精灵历史数据（endtime 游标分页）。

        翻页机制：第 N+1 页的 endtime = 第 N 页最早记录的时间戳。

        Args:
            pages: 翻页数。
            markets: 市场元组，默认 (32, 16) = 深沪。

        Returns:
            list[dict]，按时间倒序。
        """
        now_us = int(time.time() * 1_000_000)
        all_recs = []
        cursor = now_us
        for _ in range(pages):
            page_recs = []
            for mk in markets:
                page_recs.extend(self.dxjl_page(mk, cursor))
            if not page_recs:
                break
            page_recs.sort(key=lambda r: r["时间"])
            all_recs.extend(page_recs)
            cursor = page_recs[0]["时间"]
        all_recs.sort(key=lambda r: r["时间"], reverse=True)
        return all_recs

    # ── 短线精灵实时推送（9601 subrealorder 订阅 + pushrealorder 接收）──

    def subscribe_realtime(self, markets: list[int] | None = None) -> None:
        """在 9601 上订阅异动推送（method=subrealorder）。

        订阅后服务器在盘中主动推送 pushrealorder 帧（实测约 1500 条异动/分钟）。
        用 receive_pushes() 接收推送数据。

        抓包确认（2026-07-17 hexin stream 9）：在 9601 发 subrealorder，
        market=16/32/151/48，服务器 90s 内推 1125 个 pushrealorder 帧。

        Args:
            markets: 市场代码列表，默认 [16,32,151,48]（沪/深/北交所/板块）。
        """
        from .protocol import SUBREALORDER_MARKETS, build_subrealorder_query
        if markets is None:
            markets = SUBREALORDER_MARKETS
        if not self._realorder_sock:
            self._connect_realorder_server()
        if not self._realorder_sock:
            raise RuntimeError("9601 短线精灵服务未连接")
        for mk in markets:
            self._instance += 1
            body = build_subrealorder_query(self._instance, mk)
            with self._realorder_lock:
                if self._realorder_sock:
                    self._realorder_sock.sendall(encode_frame(body) + b"\n")
        logger.info("已订阅 %d 个市场的异动推送: %s", len(markets), markets)

    def receive_pushes(self, timeout: float = 10.0,
                       callback=None) -> list[dict]:
        """接收 9601 实时推送（阻塞循环，直到 timeout）。

        需先 subscribe_realtime() 订阅。盘中会持续收到 pushrealorder 帧，
        每帧含 1~8 条异动记录（代码 + 原始字节）。

        推送从 9601 短线精灵连接接收。注意：9601 用 read_frame_realorder
        （len-1 编码，不同于 8901 的 read_frame）。

        Args:
            timeout: 接收时长（秒）。到时间后返回。
            callback: 若给定，每收到一条记录回调 ``callback(record_dict)``（实时处理）。
                      若为 None，收集所有记录到列表返回（批量模式）。

        Returns:
            list[dict]，每项 ``{代码, 市场, raw_bytes}``。callback 模式下返回空列表。
            非交易时段返回空列表（无推送）。
        """
        if not self._realorder_sock:
            raise RuntimeError("9601 未连接，请先 subscribe_realtime()")
        all_recs = []
        import time as _time
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            remaining = deadline - _time.time()
            if remaining <= 0:
                break
            self._realorder_sock.settimeout(min(remaining, 5.0))
            try:
                resp = read_frame_realorder(self._realorder_sock)
            except (socket.timeout, OSError):
                break
            # 只处理 pushrealorder 帧（跳过心跳响应/其他帧）
            if b"pushrealorder" not in resp:
                continue
            recs = parse_pushrealorder_response(resp)
            if callback:
                for r in recs:
                    callback(r)
            else:
                all_recs.extend(recs)
        return all_recs

    def receive_pushes_locked(self, timeout: float = 5.0,
                              callback=None, full_frame_callback=None) -> int:
        """带锁接收 9601 推送，可安全穿插历史查询（与 receive_pushes 的区别）。

        receive_pushes 直接读 socket 不持锁，若同时另一线程调 dxjl_page
        （持 _realorder_lock 读同一 socket）或心跳线程写 socket，会产生
        帧错位/数据竞争。本方法全程持 _realorder_lock，每收到一帧后**短暂
        释放再重获锁**，给心跳线程写入的机会（心跳 30s 周期，不会饿死）。

        配合 dxjl_history 在调用方交替使用（见 tests/collect_push_samples.py）：
        推送 N 秒（本方法）→ 释放锁后 dxjl_history 翻页 → 再推送 → …
        两者串行，不并发读同一 socket。

        Args:
            timeout: 本次接收时长（秒）。建议 ≤ 5s，避免长时间独占锁。
            callback: 每条解析记录回调 ``callback(rec_dict)``。
            full_frame_callback: 每个完整推送帧回调 ``cb(frame_bytes)``，
                用于离线逆向（保留 hq1.0 字段表头）。

        Returns:
            本次收到的推送帧数（不含心跳/其他帧）。
        """
        if not self._realorder_sock:
            raise RuntimeError("9601 未连接，请先 subscribe_realtime()")
        frame_count = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            got_frame = False
            # 持锁读单帧；读完释放锁给心跳/dxjl_history 机会
            with self._realorder_lock:
                if not self._realorder_sock:
                    break
                self._realorder_sock.settimeout(min(remaining, 2.0))
                try:
                    resp = read_frame_realorder(self._realorder_sock)
                    got_frame = True
                except (socket.timeout, OSError):
                    resp = None
            if not got_frame or resp is None:
                continue
            if b"pushrealorder" not in resp:
                continue
            frame_count += 1
            if full_frame_callback:
                full_frame_callback(resp)
            recs = parse_pushrealorder_response(resp)
            if callback:
                for r in recs:
                    callback(r)
        return frame_count

    def disconnect(self) -> None:
        """关闭所有连接（8901 主连接 + 9601 短线精灵）并停止心跳。

        注意：重复调用 :meth:`connect` 不会触发新的 login——若当前连接仍活着
        且未过冷却期（20s），:meth:`connect` 直接复用现有连接（见其 docstring）。
        只有本方法（或网络中断）真正关闭 socket 后，下次 connect 才会重新 login。

        hexin 客户端从不主动断开（90s 抓包零 FIN），thspypc 遵循同样模式：
        长连接反复查询，避免反复 disconnect/connect 触发 VerifyCode=-1
        （同账号同 IP 短时间重复 login 的会话冲突，见 HANDOFF §7）。
        """
        self.stop_heartbeat()
        for attr, lock in (("_sock", self._sock_lock),
                           ("_realorder_sock", self._realorder_lock)):
            with lock:
                sock = getattr(self, attr, None)
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    setattr(self, attr, None)
        logger.info("连接已关闭")

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


def save_ip_state(sorted_ips: list[str], rr_offset: int,
                  path: str | None = None) -> None:
    """把测速排序结果 + 轮换偏移写盘（跨进程共享）。

    Args:
        sorted_ips: 按延迟升序排列的可达 IP 列表。
        rr_offset: 当前轮换偏移。
        path: 缓存路径，None 用 :func:`default_ip_state_path`。
    """
    path = path or default_ip_state_path()
    data = {
        "saved_at": int(time.time()),
        "sorted_ips": sorted_ips,
        "rr_offset": rr_offset,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError as e:
        logger.debug("IP 状态写盘失败（不影响运行）: %s", e)


def load_ip_state(path: str | None = None,
                  max_age: float = 300.0) -> tuple[list[str], int] | None:
    """读取磁盘缓存的 IP 测速状态（未过期返回，否则 None）。

    Args:
        path: 缓存路径，None 用 :func:`default_ip_state_path`。
        max_age: 缓存最大有效期（秒），默认 300（5 分钟，与 _PROBE_CACHE_TTL 一致）。

    Returns:
        ``(sorted_ips, rr_offset)``，文件不存在/过期/损坏返回 None。
    """
    path = path or default_ip_state_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        saved_at = data["saved_at"]
        if time.time() - saved_at > max_age:
            return None
        return data["sorted_ips"], data["rr_offset"]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        logger.debug("IP 状态缓存读取失败（将忽略）: %s", e)
        return None


def default_stock_cache_path() -> str:
    """股票代码表缓存的默认路径（用户 home 目录，跨平台）。"""
    return os.path.join(os.path.expanduser("~"), ".ths_stock_codes.json")


def market_from_code(code: str) -> int | None:
    """按股票代码前缀派生 ``list_quotes`` 的市场码。

    ``stock_list()`` 返回的 market 字段恒为 0（dt5 首字节在解码中丢失，
    见 ``protocol._dt5_market``），无法直接用。本函数按 A 股代码前缀规则
    派生 ``list_quotes`` 能认的市场码（17=沪 33=深，见
    ``build_list_quote_query`` docstring）。

    Args:
        code: 6 位数字股票代码（如 "600000"、"000001"、"300750"）。

    Returns:
        17（沪市 A 股/科创板）、33（深市 A 股/创业板），或 None（北交所/
        新三板/基金等 list_quotes 当前不支持的市场）。
    """
    if len(code) < 3:
        return None
    p = code[:3]
    # 沪市 A 股（600/601/603/605）+ 科创板（688）
    if p in ("600", "601", "603", "605") or p == "688":
        return 17
    # 深市 A 股（000/001/002/003）+ 创业板（300/301）
    if p in ("000", "001", "002", "003", "300", "301"):
        return 33
    # 北交所（8xxxxx/920xxx）、新三板（830-839）、基金（430/400）等：list_quotes 不支持
    return None


def save_stock_codes(stocks: list[dict], path: str | None = None) -> str:
    """把全量股票代码表写盘缓存（覆盖写）。

    每条记录保留 ``code/name/market``，并写入 ``saved_date``（自然日，用于失效判断）
    和 ``saved_at``（Unix 时间戳，调试用）。

    Args:
        stocks: ``stock_list()`` 的返回值，每项含 ``code``（其余字段如 name/market
            有则保留，market 会用 :func:`market_from_code` 重新派生覆盖）。
        path: 缓存路径，None 用 :func:`default_stock_cache_path`。

    Returns:
        实际写入的文件路径。
    """
    path = path or default_stock_cache_path()
    # 规范化：确保每条有 name/market 字段，market 用派生值覆盖
    records = []
    for s in stocks:
        code = s.get("code", "")
        if not code:
            continue
        records.append({
            "code": code,
            "name": s.get("name", ""),
            "market": market_from_code(code),
        })
    data = {
        "saved_date": datetime.date.today().isoformat(),
        "saved_at": int(time.time()),
        "count": len(records),
        "stocks": records,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("股票代码表已缓存: %s (%d 条)", path, len(records))
    except OSError as e:
        logger.warning("股票代码表写盘失败（不影响本次返回）: %s", e)
    return path


def load_stock_codes(
    path: str | None = None,
) -> tuple[list[dict], str] | None:
    """读取缓存的股票代码表（已过期或损坏时返回 None）。

    Args:
        path: 缓存路径，None 用 :func:`default_stock_cache_path`。

    Returns:
        ``(stocks, saved_date)``：stocks 为 ``[{code, name, market}, ...]``，
        saved_date 为缓存写入的自然日（如 "2026-07-22"）。
        文件不存在、已过期（跨自然日）或格式错误时返回 None。
    """
    path = path or default_stock_cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        saved_date = data["saved_date"]
        stocks = data["stocks"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("股票代码表缓存读取失败（将忽略）: %s", e)
        return None
    # 按自然日判断：saved_date 与今天不同即过期
    today = datetime.date.today().isoformat()
    if saved_date != today:
        logger.info("股票代码表缓存已过期 (saved_date=%s, today=%s)",
                    saved_date, today)
        return None
    return stocks, saved_date


def is_stock_cache_expired(path: str | None = None,
                           now: datetime.date | None = None) -> bool:
    """判断股票代码表缓存是否已过期（按自然日）。

    与 :func:`load_stock_codes` 的内置判断一致：缓存写入的自然日与查询日不同
    即视为过期。文件不存在或损坏也返回 True。

    Args:
        path: 缓存路径，None 用默认路径。
        now: 指定查询日（调试用），None 用 datetime.date.today()。

    Returns:
        True 表示缓存已过期/不存在/损坏（需重新拉取）。
    """
    loaded = load_stock_codes(path)
    if loaded is None:
        return True
    _, saved_date = loaded
    today = (now or datetime.date.today()).isoformat()
    return saved_date != today
