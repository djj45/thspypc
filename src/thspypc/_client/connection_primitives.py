"""Low-level socket login and connection primitives.

This mixin is intentionally independent from ``thspypc.client``. The
public facade supplies state and compatibility hooks; the wire-level
implementation lives here so lower layers never import the facade.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any

from ..features.auth_protocol import LoginIdentity
from ..models import Capability, Support
from ..protocol import (
    MARKET_PORT,
    REALORDER_HOST,
    REALORDER_PORT,
    STATSCALC_HOST,
    STATSCALC_PORT,
    build_init_query,
    encode_frame,
    parse_init_response,
)
from ..transport import ConnectionRole
from .._transport.tracing import maybe_wrap_board_socket

logger = logging.getLogger(__name__)


class ConnectionPrimitives:
    """Reusable MAIN/L2/REALORDER login and socket primitives."""

    def _do_tcp_login(self, passport_fields: dict) -> Any:
        """构造 PC login 帧并连 8901（connect / connect_with_qrcode 共用）。

        前置条件：self._auth 已通过 full_http_auth 设置。
        """
        # ---- 构造 PC login 帧 ----
        passport64 = self._current_passport64()
        login_body = self._auth_service.login_body_for_passport(passport64)
        logger.debug("PC login 帧构造完成，body %d 字节", len(login_body))
        return self._do_tcp_login_raw(login_body, passport_fields)

    def _do_tcp_login_raw(self, login_body: bytes,
                          passport_fields: dict) -> Any:
        """连 8901 发送已构造的 login 帧（并发连多 IP，用最先成功的）。

        复刻 hexin 客户端的策略：同时连 N 个不同 IP 并发 login，用最先返回
        VerifyCode=0 的连接，其余关闭。这避免了串行逐个尝试时对同一 IP
        重复登录导致 VerifyCode=-1（同账号会话冲突）。

        hexin 抓包确认：每 ~20s 并发连 7 个 IP，全部 VerifyCode=0，从不 -1。

        IP 列表优先用 passport M_hqdns 动态域名解析，回退到硬编码 MARKET_HOSTS。

        全部 IP 失败时，重新 HTTP 鉴权拿新鲜 Passport64 重试一轮（和 L2/BOARD
        通道一致）。MAIN 服务器对过期 passport 静默返回 -1（无 PromptText），
        旧逻辑判为 session_conflict 直接放弃；实际刷新 passport 后即可恢复。
        """
        def _try_round(body: bytes):
            """一轮登录尝试（并发 + 串行 fallback）。

            返回 None = 全部 IP 失败（可刷新 passport 再试）；
            返回 LoginResult = 有明确结论（成功 / login_rejected / init_failed）。
            """
            # 动态解析 M_hqdns 域名拿 IP，回退到硬编码 MARKET_HOSTS
            hosts = []
            if self._auth:
                hosts = self._resolve_market_hosts(
                    self._auth.get("passport_bytes", b"")
                )
            if not hosts:
                logger.info("M_hqdns 动态解析无结果，回退到硬编码 MARKET_HOSTS")
                hosts = list(self._market_host_candidates())

            # 测速选最快的 IP（复刻同花顺「测试 IP」功能）。
            # 并发 TCP 握手测延迟，选最快的 login，避免盲选到慢 IP（曾 46s 超时）。
            # 测速纯 TCP 握手不发 login，不触发 -1。结果缓存 5 分钟复用。
            # main.123ths.com 优先（支持北交所 151，2026-08-14 抓包确认），
            # 组内按延迟序；ifindhq 等回退域名的 IP 排后，避免测速快的 ifindhq
            # 抢走 main 连接（ifindhq 排序榜无北交所）。
            priority_hosts = set()
            try:
                _, _, main_ips = socket.gethostbyname_ex("main.123ths.com")
                priority_hosts = set(main_ips)
            except OSError:
                pass
            sorted_ips = self._probe_fastest_hosts(
                hosts, timeout=1.0, role="main",
                priority_hosts=priority_hosts or None,
            )
            if sorted_ips:
                # ★ K线坏 IP 黑名单过滤：部分 IP（如 116.63.x.x）不支持大 K线查询，
                # 只返回部分数据或 timeout（实测 §14j）。重连时跳过这些 IP，优先选
                # 未失败过的。若全部在黑名单（罕见），退而用全表（不让黑名单卡死）。
                good_ips = [ip for ip in sorted_ips if ip not in self._bad_kline_ips]
                pool = good_ips if good_ips else sorted_ips
                # 优先组（main.123ths.com，支持北交所）恒优先：组内轮换取
                # 满 n_concurrent 个；不足时才用回退组（ifindhq）补齐。
                # 轮换偏移只在组内推进，避免偏移把 main 全部跳过。
                priority_pool = [
                    ip for ip in pool if ip in (priority_hosts or set())
                ]
                fallback_pool = [ip for ip in pool if ip not in (priority_hosts or set())]
                n_concurrent = min(7, len(pool))
                if priority_pool:
                    offset = self._login_rr_offset.get("main", 0) % len(priority_pool)
                    batch = (priority_pool[offset:] + priority_pool[:offset])[:n_concurrent]
                    if len(batch) < n_concurrent:
                        batch = batch + fallback_pool[: n_concurrent - len(batch)]
                else:
                    offset = self._login_rr_offset.get("main", 0) % max(1, len(pool))
                    batch = (pool[offset:] + pool[:offset])[:n_concurrent]
                skip_note = f"（跳过 {len(self._bad_kline_ips)} 个坏IP）" if self._bad_kline_ips else ""
                logger.info("并发连接 %d 个 IP（优先组%d+回退%d, 轮换 offset=%d）%s: %s",
                            len(batch), len(priority_pool), len(fallback_pool),
                            self._login_rr_offset.get("main", 0), skip_note, batch[:3])
            else:
                # 测速全部超时（网络异常），回退到盲取前 7 个
                logger.warning("IP 测速全部超时，回退到盲取前 7 个")
                n_concurrent = min(7, len(hosts))
                batch = hosts[:n_concurrent]

            winner = self._concurrent_login(batch, body)
            # 推进轮换偏移：下次 connect 用不同的 IP 子集。写盘持久化（跨进程共享）。
            self._login_rr_offset["main"] = (self._login_rr_offset.get("main", 0) + n_concurrent) % max(1, len(sorted_ips) if sorted_ips else len(hosts))
            if sorted_ips:
                self._persist_ip_state(sorted_ips, self._login_rr_offset["main"], role="main")
            if winner:
                host, sock, result = winner
                # VerifyCode=0 后若 init 失败，不得在同一次 connect 中继续串行
                # login 其他服务器。短时间跨节点重复登录会触发会话保护；本次直接
                # 返回 init_failed，下次独立 connect 再按持久化 offset 换一批节点。
                return self._finalize_main_login(
                    host,
                    sock,
                    result,
                    passport_fields,
                )

            concurrent_errors = [
                err for err in getattr(self, "_last_concurrent_login_errors", [])
                if err
            ]
            if (
                len(batch) >= 5
                and concurrent_errors
                and all(err == "连接已关闭" for err in concurrent_errors)
            ):
                # 所有并发 IP 都直接关闭 login 连接，通常是账号会话被服务端
                # 临时限制，而不是某个 IP 不可达。继续串行打剩余 IP 只会
                # 加重限制；直接结束本轮，交给外层刷新/等待重试。
                logger.warning(
                    "并发批次 %d 个 IP 全部返回连接关闭，跳过串行 fallback",
                    len(batch),
                )
                return None

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
                    sock.sendall(encode_frame(body) + b"\n")
                    resp_body = self._connection_read_frame(sock)
                    result = self._parse_connection_login_response(resp_body)

                    verify_code = result.get("VerifyCode", "?")
                    logger.info("%s:%d 响应 VerifyCode=%s", host, MARKET_PORT, verify_code)

                    if verify_code == "0":
                        # 与并发 winner 相同：认证成功后 init 失败即结束本次 connect，
                        # 不在同一会话窗口继续尝试其他服务器。
                        return self._finalize_main_login(
                            host,
                            sock,
                            result,
                            passport_fields,
                        )
                    else:
                        sock.close()
                        if verify_code == "-1":
                            consecutive_minus1 += 1
                            logger.warning("%s:%d VerifyCode=-1（连续 %d 次）",
                                           host, MARKET_PORT, consecutive_minus1)
                            # 连续多个 -1 = passport 过期或同 IP 短时间重复 login
                            # 会话冲突。返回 None 让外层刷新 passport 再试一轮
                            # （和 L2/BOARD 通道一致）。旧逻辑直接判 session_conflict
                            # 返回失败，但实际刷新 passport 后通常即可恢复。
                            if consecutive_minus1 >= MAX_CONSECUTIVE_MINUS1:
                                logger.warning("连续 %d 个 IP 返回 -1，停止本轮（可能 passport 过期）",
                                               consecutive_minus1)
                                return None
                            continue
                        # VerifyCode 非 0 非 -1 = 明确拒绝（账号/权限问题），
                        # 刷新 passport 无益，直接返回。
                        logger.warning("%s:%d 登录被拒 (VerifyCode=%s)", host, MARKET_PORT, verify_code)
                        return self._login_result_type(
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

            # 全部 IP 都试完了仍无结论（全 -1 或全超时）→ 返回 None 让外层刷新重试
            logger.warning("MAIN 本轮全部 %d 个 IP 失败（last_err=%s）",
                           len(fallback_hosts), last_err or "(无)")
            return None

        # 第一轮
        result = _try_round(login_body)
        if result is not None:
            return result

        first_errors = [
            err for err in getattr(self, "_last_concurrent_login_errors", [])
            if err
        ]
        if first_errors and all(err == "连接已关闭" for err in first_errors):
            # 所有 IP 都是“连接已关闭”而不是 -1/超时：通常是服务端临时限制
            # 新会话。此时刷新 passport 再立刻打一轮没有意义，还会加重限制；
            # 直接失败，让上层冷却后重试。
            logger.warning("MAIN 所有 IP 均直接关闭连接，等待上层冷却后重试")
            return self._login_result_type(
                success=False,
                error="all_hosts_failed",
                detail="服务端关闭了所有 login 连接（可能临时限制新会话），请稍后重试",
            )

        # 全失败：重新 HTTP 鉴权拿新鲜 Passport64 重试一轮（和 L2/BOARD 通道一致）。
        # MAIN 服务器对过期 passport 静默返回 -1（无 PromptText），刷新后通常即恢复。
        logger.warning("MAIN 全部 IP 失败，2 秒后重新 HTTP 鉴权拿新鲜 Passport64 重试...")
        time.sleep(2)
        try:
            fresh = self._refresh_auth_material()
            fresh_body = self._auth_service.login_body_for_passport(fresh.passport64)
            logger.info("MAIN 已拿到新鲜 Passport64，重试一轮")
            result = _try_round(fresh_body)
            if result is not None:
                return result
        except Exception as e:
            logger.error("MAIN 重新鉴权失败: %s", e)

        # 刷新后仍全失败
        return self._login_result_type(
            success=False,
            error="all_hosts_failed",
            detail="passport 刷新后仍全部 IP 失败（账号可能被临时限制，等片刻重试）",
        )

    def _finalize_main_login(
        self,
        host: str,
        sock: socket.socket,
        reply_fields: dict,
        passport_fields: dict,
    ) -> Any:
        """Initialize and expose a verified ordinary-login socket as MAIN."""
        # 旧连接的心跳线程可能仍存活；先停掉，避免替换 _sock 后抢在 init
        # 之前向新连接发心跳。init 成功后再重新启动。
        self.stop_heartbeat()
        previous = self._sock
        if previous is not None and previous is not sock:
            try:
                previous.close()
            except OSError:
                pass
        self._sock = sock
        self._connected_ip = host
        try:
            self._send_init_handshake()
        except (OSError, ValueError) as exc:
            try:
                sock.close()
            except OSError:
                pass
            if self._sock is sock:
                self._sock = None
            self._connected_ip = None
            self._last_connect_ts = 0.0
            logger.warning(
                "%s:%d 登录验证通过，但 MAIN init 失败: %s",
                host,
                MARKET_PORT,
                exc,
            )
            return self._login_result_type(
                success=False,
                verify_code="0",
                server=f"{host}:{MARKET_PORT}",
                reply_fields=reply_fields,
                passport_fields=passport_fields,
                error="init_failed",
                detail=str(exc),
            )

        self._last_connect_ts = time.time()
        self._account_evidence.record_main_ready(passport_fields)
        self._start_heartbeat()
        logger.info("✓ 登录成功 (%s:%d)", host, MARKET_PORT)
        return self._login_result_type(
            success=True,
            verify_code="0",
            server=f"{host}:{MARKET_PORT}",
            reply_fields=reply_fields,
            passport_fields=passport_fields,
        )

    def _send_init_handshake(self, timeout: float = 2.0) -> None:
        """login 后发 init 请求激活行情通道，读取 init 响应（服务器配置帧）。

        hexin 客户端 login 后紧跟 init 请求（subtype 0x0001），服务器据此
        激活该连接的行情查询通道。不发 init 直接查 K线会超时
        （list_quotes 走 hd1.0/hd3.1 不强依赖 init，但 K线 hd1.0/hd3.1
        flag=0x0042/0x0046
        要求 init 激活通道才响应——实测 MAIN login 跳过 init 后 kline 全超时，
        list_quotes 仍正常，故 init 缺失会被 list_quotes 的成功掩盖）。

        init 响应是**服务器配置帧**（~49KB，含 S-OS/S-Version/SName 等元数据），
        不是全量代码表（代码表由 stock_list() 的独立单请求触发）。实测稳定返回
        1 帧（多次验证），0.1s 即到达。读完这 1 帧配置即激活行情通道。
        """
        req = build_init_query()
        with self._sock_lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError("MAIN 连接已关闭，无法发送 init")
            sock.sendall(req + b"\n")
            # 第一帧是激活成功的必要证据；超时、FIN 或非法帧均不能把 MAIN
            # 标记为 ready。后续短读仅用于排空 ACK/通知帧。
            sock.settimeout(timeout)
            try:
                first_frame = self._connection_read_frame(sock)
            except socket.timeout as exc:
                raise TimeoutError("等待 MAIN init 响应超时") from exc
            except ConnectionError:
                raise
            except OSError as exc:
                raise ConnectionError(f"读取 MAIN init 响应失败: {exc}") from exc
            except ValueError as exc:
                raise ValueError(f"MAIN init 响应帧无效: {exc}") from exc

            frames = [first_frame]
            sock.settimeout(0.3)
            for _ in range(8):
                try:
                    frames.append(self._connection_read_frame(sock))
                except socket.timeout:
                    break
                except ConnectionError:
                    raise
                except OSError as exc:
                    raise ConnectionError(
                        f"排空 MAIN init 响应时连接异常: {exc}"
                    ) from exc
                except ValueError as exc:
                    raise ValueError(
                        f"排空 MAIN init 响应时遇到非法帧: {exc}"
                    ) from exc

            if not any(
                parse_init_response(frame).get("server_info")
                for frame in frames
            ):
                raise ValueError("MAIN init 响应未包含服务器配置")
            logger.debug(
                "init 握手完成（读 %d 帧，行情通道已激活，缓冲区已排空）",
                len(frames),
            )

    def _initialize_independent_main_socket(
        self,
        sock: socket.socket,
        *,
        timeout: float = 2.0,
    ) -> None:
        """Activate an ordinary 8901 socket without touching ``self._sock``."""
        sock.sendall(build_init_query() + b"\n")
        sock.settimeout(timeout)
        try:
            first_frame = self._connection_read_frame(sock)
        except socket.timeout as exc:
            raise TimeoutError("waiting for KLINE_FAST init timed out") from exc

        frames = [first_frame]
        sock.settimeout(0.3)
        for _ in range(8):
            try:
                frames.append(self._connection_read_frame(sock))
            except socket.timeout:
                break
        if not any(
            parse_init_response(frame).get("server_info")
            for frame in frames
        ):
            raise ValueError(
                "KLINE_FAST init response did not contain server config"
            )

    def _open_independent_main_connection(self, material=None) -> socket.socket:
        """Open a role-owned iFinD socket with a fresh one-use Passport.

        Candidate hosts race concurrently.  Once a host returns
        ``VerifyCode=0`` the Passport is consumed, so this method never tries
        serial logins with the same credential.

        ``material`` 可传调用方已取得的一代 AuthMaterial（并行预热使用）；
        默认 None 时方法内部重新 HTTP 鉴权。
        """
        if material is None:
            material = self.authenticate(force=True)
        hosts = self._resolve_market_hosts(material.passport_bytes)
        if not hosts:
            hosts = list(self._market_host_candidates())
        sorted_ips = self._probe_fastest_hosts(
            hosts,
            timeout=1.0,
            role="kline",
        )
        pool = [ip for ip in sorted_ips if ip not in self._bad_kline_ips]
        if not pool:
            pool = sorted_ips or hosts
        count = min(7, len(pool))
        offset = self._login_rr_offset.get("kline", 0) % max(1, len(pool))
        batch = (pool[offset:] + pool[:offset])[:count]
        self._login_rr_offset["kline"] = (
            offset + count
        ) % max(1, len(pool))
        login_body = self._auth_service.login_body_for_passport(
            material.passport64
        )
        winner = self._concurrent_login(batch, login_body)
        if winner is None:
            raise ConnectionError(
                "KLINE_FAST concurrent login failed; fresh auth required"
            )
        host, sock, _reply = winner
        try:
            self._initialize_independent_main_socket(sock)
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise
        logger.info("KLINE_FAST connected (%s:%d)", host, MARKET_PORT)
        return sock

    def _probe_fastest_hosts(self, hosts: list[str], timeout: float = 1.0,
                             use_cache: bool = True,
                             role: str = "main",
                             priority_hosts: set[str] | None = None) -> list[str]:
        """并发 TCP 握手测每个 IP 的延迟，返回**按延迟升序排列的全部可达 IP**。

        复刻同花顺客户端「测试 IP」功能的机制（2026-07-23 抓包确认）：并发对多个
        IP 发 TCP 连接，测 SYN→SYN-ACK 握手往返时间，选最快的 login。同花顺实测
        最快 122.9.115.201=28ms，最慢 74ms，超时的剔除。

        纯 TCP 握手测速——**不发 login**，连上立即关闭，不触发 VerifyCode=-1
        （-1 是 login 帧内容错误或单点登录会话冲突触发的，TCP 连接不触发）。

        **测速缓存**：5 分钟内（``_PROBE_CACHE_TTL``）复用上次测速结果，避免反复
        connect 时重复测速。缓存命中时秒回。缓存只存按延迟排序的全表，调用方用
        ``_login_rr_offset`` 轮换取 batch（见 :meth:`_do_tcp_login_raw`）。

        **按角色分桶**：``role`` 为 ``main``/``sh``/``sz``，各自独立缓存与持久化
        ——shlv2 与 szlv2 是两套 IP 零重叠的服务器，测速结果不能混用。

        Args:
            hosts: 待测 IP 列表。
            timeout: 单个 TCP 连接超时（秒）。1s 足够区分（最快 28ms，1s 内必回）。
            use_cache: 是否使用缓存（缓存未命中时测速并写入）。
            role: 连接角色键（``main``/``sh``/``sz``），用于隔离缓存与持久化。

        Returns:
            按延迟升序排列的可达 IP 列表（全部，不截断）。全部超时返回空列表。
        """
        # 缓存命中检查（避免反复 connect 重复测速）
        cached_entry = self._probe_cache.get(role) if use_cache else None
        if cached_entry is not None:
            ts, cached = cached_entry
            cache_matches_hosts = set(cached).issubset(set(hosts))
            if (
                time.time() - ts < self._PROBE_CACHE_TTL
                and cached
                and cache_matches_hosts
            ):
                logger.debug("IP 测速缓存[%s]命中（%d 个可达 IP）", role, len(cached))
                if priority_hosts:
                    in_priority = [ip for ip in cached if ip in priority_hosts]
                    rest = [ip for ip in cached if ip not in priority_hosts]
                    return in_priority + rest
                return cached
            if cached and not cache_matches_hosts:
                logger.debug("IP 测速缓存[%s]与当前 DNS 候选不一致，重新测速", role)
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
        if priority_hosts:
            # 域名优先级分组：优先组（如 main.123ths.com，支持北交所）的 IP
            # 恒排前，组内按延迟升序；非优先组（ifindhq 回退）排后，避免
            # 测速快但无北交所 151 的 ifindhq 抢走 main 连接。
            in_priority = [ip for ip, _ in results if ip in priority_hosts]
            rest = [ip for ip, _ in results if ip not in priority_hosts]
            sorted_ips = in_priority + rest
        else:
            sorted_ips = [ip for ip, _ in results]  # 全部可达 IP，按延迟升序
        if sorted_ips:
            # 写内存缓存 + 磁盘持久化（跨进程共享，避免每个进程都 offset=0）
            self._probe_cache[role] = (time.time(), sorted_ips)
            self._persist_ip_state(
                sorted_ips, self._login_rr_offset.get(role, 0), role=role,
            )
            logger.info("IP 测速[%s]完成（%.1fs）：最快 %s=%.0fms，共 %d/%d 个可达",
                        role, time.time() - t0,
                        sorted_ips[0], results[0][1] * 1000,
                        len(results), len(hosts))
            logger.debug("测速[%s]详情: %s", role,
                         ", ".join(f"{ip}={rtt*1000:.0f}ms" for ip, rtt in results[:7]))
        return sorted_ips


    def _rotated_l2_batch(self, sorted_ips: list[str], key: str) -> list[str]:
        """按角色轮换偏移重排 L2 候选 IP，返回从 offset 起绕回的全表。

        与 MAIN 的 batch 取子集不同，L2 是串行逐个尝试（每个 IP 要 login+init），
        所以这里返回**完整轮换后的列表**（调用方按序遍历），而非只取前 N 个。
        偏移按 ``sh``/``sz`` 独立分桶推进（IP 零重叠，不能混用）。
        """
        if not sorted_ips:
            return []
        offset = self._login_rr_offset.get(key, 0) % len(sorted_ips)
        return (sorted_ips[offset:] + sorted_ips[:offset])

    def _advance_l2_offset(self, key: str, tried: int, total: int,
                           *, force_advance: bool = False) -> None:
        """推进 L2 轮换偏移并持久化（跨进程共享，避免集中撞同一 IP 触发 -1）。

        当遍历完整个 IP 表（``tried == total``）时，``(offset + total) % total``
        会回到原点——这正是「全失败重连反复打同一批 IP」触发 -1 的根因。此时
        ``force_advance`` 至少推进 1 位，保证下次连接从不同的起点开始。
        """
        if total <= 0:
            return
        step = max(1, tried)
        new_offset = (self._login_rr_offset.get(key, 0) + step) % total
        if force_advance and new_offset == self._login_rr_offset.get(key, 0) % total:
            new_offset = (new_offset + 1) % total
        self._login_rr_offset[key] = new_offset
        # 持久化当前测速缓存里该角色的全表 + 新偏移（测速缓存可能尚未填充，
        # 此时只推进内存偏移，下次测速成功后会一并写盘）。
        cached = self._probe_cache.get(key)
        if cached is not None:
            self._persist_ip_state(cached[1], new_offset, role=key)

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
                resp_body = self._connection_read_frame(sock)
                if done.is_set():
                    sock.close(); return
                result = self._parse_connection_login_response(resp_body)
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
        # 全部失败，记录错误，并供调用方决定是否跳过串行 fallback。
        self._last_concurrent_login_errors = list(errors)
        for i, h in enumerate(hosts):
            if errors[i]:
                logger.warning("  %s: %s", h, errors[i])
        return None

    def _drop_connection(self) -> None:
        """标记当前 8901 连接为坏（强制下次 ensure_connected 触发重连）。"""
        with self._sock_lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
            if self._service_connections is not None:
                self._service_connections.close(ConnectionRole.MAIN)
        self.stop_heartbeat()

    def _connect_realorder_server(self) -> None:
        """懒连接 9601 短线精灵服务（passport64 登录）。

        用 PC 版 login 帧（build_login_body_pc）登录，VerifyCode=0 则存 socket。
        缺少 Passport64 时只执行 HTTP 鉴权，不建立 MAIN。
        """
        if self._realorder_sock:
            return
        try:
            if self._auth is None:
                self.authenticate()
            passport64 = self._current_passport64()
            login_body = self._auth_service.login_body_for_passport(
                passport64,
                LoginIdentity.STANDARD,
            )
            sock = socket.create_connection((REALORDER_HOST, REALORDER_PORT), timeout=15)
            sock.sendall(encode_frame(login_body) + b"\n")
            resp = self._connection_read_frame(sock)
            result = self._parse_connection_login_response(resp)
            if result.get("VerifyCode") == "0":
                self._realorder_sock = sock
                self._account_evidence.record_feature(
                    Capability.REALORDER,
                    Support.YES,
                )
                logger.info("9601 短线精灵服务连接成功 (%s:%d)", REALORDER_HOST, REALORDER_PORT)
            else:
                sock.close()
                logger.warning("9601 登录失败: VerifyCode=%s", result.get("VerifyCode"))
        except Exception as e:
            logger.warning("9601 短线精灵服务连接失败: %s", e)

    def _connect_board_stats_server(self) -> None:
        """懒连接板块统计（statscalc）独立 9601 节点（passport64 登录）。

        与 REALORDER 同为 9601 PC login，但走**独立统计节点**
        （``STATSCALC_HOST``，抓包确认 ``8.132.233.77``，不在 DNS/passport，
        是客户端缓存发现的）。``SERVER_MATRIX.md`` 明确警告不能把该节点作为
        REALORDER 备选——两节点承载不同 method（statscalc vs qurealorder）。

        失败时优雅降级（记 warning，不抛异常）；服务层捕获后返回空列表。
        """
        if self._board_stats_sock:
            return
        try:
            if self._auth is None:
                self.authenticate()
            passport64 = self._current_passport64()
            login_body = self._auth_service.login_body_for_passport(
                passport64,
                LoginIdentity.STANDARD,
            )
            sock = socket.create_connection(
                (STATSCALC_HOST, STATSCALC_PORT), timeout=15
            )
            sock.sendall(encode_frame(login_body) + b"\n")
            resp = self._connection_read_frame(sock)
            result = self._parse_connection_login_response(resp)
            if result.get("VerifyCode") == "0":
                self._board_stats_sock = sock
                logger.info(
                    "9601 板块统计服务连接成功 (%s:%d)",
                    STATSCALC_HOST,
                    STATSCALC_PORT,
                )
            else:
                sock.close()
                logger.warning(
                    "9601 板块统计登录失败: VerifyCode=%s",
                    result.get("VerifyCode"),
                )
        except Exception as e:
            logger.warning("9601 板块统计服务连接失败: %s", e)

    def _preheat_other_market(self, current_key: str) -> None:
        """后台异步预热另一市的 L2 连接（复刻 hexin 启动即双连行为）。

        hexin 启动时同时连 sz+sh 两条 L2 服务器，所以切任何票都秒加载。thspypc
        原来是惰性的——遇到某市票才建该市连接，首次切另一市要等 init（4-5s）。
        本方法在首次建好某市连接后，后台异步建另一市，用户无感。

        预热线程存入 _preheat_threads，主流程用到该市时可 join 等待（避免重复建）。
        """
        other = "sh" if current_key == "sz" else "sz"
        with self._push_lock:
            if other in self._push_socks or other in self._preheat_threads:
                return  # 已有连接或正在预热
        other_market = 17 if other == "sh" else 33

        def _do_preheat():
            try:
                # 预热线程持有自己这一代不可变材料，不能在建连时再读取可能被
                # 其他线程覆盖的全局 current。
                material = self.authenticate(force=True)
                sock = self._open_manual_push_connection(
                    other_market,
                    material=material,
                )
                if sock is not None:
                    with self._push_lock:
                        if other not in self._push_socks:  # 防竞争（主线程可能已建）
                            self._push_socks[other] = sock
                            self._push_initialized.add(other)
                            logger.info("预热[%s] 连接已就绪（后台）", other)
                        else:
                            sock.close()  # 主线程抢先建了，关掉重复的
            except Exception as e:
                logger.debug("预热[%s] 失败（不影响主流程）: %s", other, e)

        t = threading.Thread(target=_do_preheat, name=f"ths-preheat-{other}",
                             daemon=True)
        with self._push_lock:
            self._preheat_threads[other] = t
        t.start()

    def _open_manual_push_connection(self, market: int, skip_init: bool = False,
                                      use_main_ip: bool = False,
                                      material=None):
        """打开一条独立的沪市或深市 L2 8901 连接。

        复用当前 HTTP AuthMaterial 的 Passport64/Mac64；不要求 MAIN 已连接。
        并行预热时调用方传入 ``material``（独立一代 Passport64），保证每条新
        socket 只使用自己的通行证，不与其它并发建连共享（一个 Passport64 在
        首次成功登录后即被消费）。兼容方法名沿用 ``manual``。生产 login 帧
        使用 ``LoginIdentity.L2``（无 UserName/Password 的 7 字段壳，
        2026-08-10 hexin 抓包字节级确认）；Level2 权限来自 passport 和业务证据。
        登录后默认发 init 激活行情通道（``skip_init=False``）。

        ★ **按沪深选 L2 服务器**（2026-07-24 实测突破）：shlv2/szlv2 是两套独立
        服务器（IP 0 重叠）。必须按 market 选对应域名解析出的 IP，且 init 的
        MarketCode 匹配该市场，否则 init 只回 210B、4214 注册 CodeListSize=0::

            沪市（17/16/144）→ shlv2 IP + init(MarketCode="16;144;")
            深市（33/32）    → szlv2 IP + init(MarketCode="32;")

        docs/handoffs/HANDOFF.md 的旧结论"init(16) 被拒、改 32 正常"
        是误判——当时连的
        是 szlv2 的深市 IP，发沪市 init(16) 当然被拒。真相是 IP 与 MarketCode
        必须配套，而非 16 vs 32 谁对谁错。

        IP 组里逐个尝试：连接失败或 init 响应过小（<5000B，说明连错了市或该
        IP 不健康）则换下一个，直到找到能正常激活的 IP。

        Args:
            market: 17/33（snapshot 市场码）或 16/144/32（init 市场码）。
                    用 :func:`pick_l2_market` 归约为 sh/sz 选服。
            skip_init: 跳过 init 握手（调试用）。默认 False。
            use_main_ip: 强制用主连接的 IP（调试用）。默认 False。``_replay_exact.py``
                    的成功路径连的是 ``client._connected_ip``（主连接同 IP），
                    而非 szlv2/shlv2 解析的 IP。设 True 复刻该路径，用于隔离
                    "IP 来源"变量——若 True 能成、False 不能成，说明推送注册
                    需要主连接先在该 IP 建立过普通会话（会话预热）。
            material: 可选 AuthMaterial。并行建连时传各自独立的新一代鉴权材料，
                    避免并发线程都读到全局最新 Passport64 而共享同一通行证。
                    默认 None=沿用历史行为（使用当前全局材料）。

        Returns:
            成功激活的 socket，或 None（全组 IP 都失败）。
        """
        import socket as _socket
        from thspypc.protocol import resolve_l2_hosts_grouped, pick_l2_market

        if self._auth is None and material is None:
            self.authenticate()

        if material is None:
            # 历史路径：直接使用当前全局材料（AuthService 优先，兼容旧 _auth 注入）。
            passport64 = self._current_passport64()
            auth_bytes = self._auth.get("passport_bytes", b"")
        else:
            # 并行路径：调用方持有独立一代 AuthMaterial，全程只看它。
            passport64 = material.passport64
            auth_bytes = material.passport_bytes

        def _try_round(passport64, auth_bytes, allow_refresh):
            """用给定 passport64 尝试所有候选 IP；全失败时可选重新鉴权重试一轮。"""
            if use_main_ip:
                if not self._connected_ip:
                    logger.error("L2: use_main_ip 但无主连接 IP")
                    return None
                hosts = [self._connected_ip]
                logger.info("L2[%s] use_main_ip=True → 强制连主连接 IP %s",
                            key, self._connected_ip)
            else:
                grouped = resolve_l2_hosts_grouped(auth_bytes)
                candidates = list(grouped.get(key, []))
                if not candidates:
                    logger.error("L2: 无 %s 组 L2 IP（账号可能无 L2 权限）", key)
                    return None
                # 测速排序 + 轮换偏移：与 MAIN 同一套治理逻辑，避免反复建 L2 连接
                # 时总从同一个最快的 IP 开始打，触发同 IP 重复 login 的 -1 会话冲突。
                # SH/SZ 各自独立分桶（IP 零重叠）。测速纯 TCP 握手不发 login。
                probed = self._probe_fastest_hosts(candidates, timeout=1.0, role=key)
                if probed:
                    hosts = self._rotated_l2_batch(probed, key)
                else:
                    # 测速全超时（网络异常），回退到原始候选 + 轮换偏移
                    hosts = self._rotated_l2_batch(candidates, key)
                if self._connected_ip and self._connected_ip in hosts:
                    hosts.remove(self._connected_ip)
                    hosts.insert(0, self._connected_ip)

            logger.info("L2[%s] 推送连接: 候选 %d IP %s，init MarketCode=%s%s",
                        key, len(hosts), hosts[:3], init_market_code,
                        "（skip_init）" if skip_init else "")
            stale = False
            tried = 0
            for host in hosts:
                tried += 1
                result = self._try_open_manual_sock(host, passport64, key,
                                                     init_market_code, skip_init)
                if result is not None and result != "stale_passport":
                    # 成功：推进轮换偏移到已尝试的位置，下次从更靠后的 IP 开始。
                    self._advance_l2_offset(key, tried, len(hosts))
                    return result
                if result == "stale_passport":
                    # 服务端用“通行证有被修改的痕迹”拒绝当前登录。活网已观察到
                    # 新鲜、独占的 Passport 也可能非必现地收到该通用文案，因此
                    # 这里只把它解释为“当前票据/节点会话不可继续”，不声称本地
                    # 确实修改了票据。剩余 IP 不再复用该票，立即重新鉴权。
                    stale = True
                    logger.info("L2[%s] 票据/会话被拒（%s），跳过剩余 IP 直接重新鉴权",
                                key, host)
                    break
                logger.info("L2[%s] IP %s 不可用，换下一个", key, host)
            # 全部尝试过：推进偏移，下次 connect 换一批起点。遍历完整个表时
            # (offset+total)%total 会回到原点，用 force_advance 至少挪 1 位，
            # 否则反复全失败重连会一直打同一批 IP 触发 -1 会话冲突。
            self._advance_l2_offset(key, tried, len(hosts), force_advance=True)
            # ★ 票据失效或全失败：L2 登录对 Passport64 新鲜度敏感——同一票据
            # 被多次使用后服务器会拒（PromptText="通行证有被修改的痕迹"）。主连接
            # 已建立不受影响，但新的 L2 登录会被拒。检测到 stale 或全失败时，
            # 重新 full_http_auth 拿新鲜票据再试一轮。
            if stale or allow_refresh:
                if stale:
                    logger.warning("L2[%s] 登录票据/节点会话被服务端拒绝，"
                                   "重新 HTTP 鉴权拿新鲜 Passport64...",
                                   key)
                else:
                    logger.warning("L2[%s] 全失败，重新 HTTP 鉴权拿新鲜 Passport64 重试...",
                                   key)
                try:
                    fresh = self.authenticate(force=True)
                    logger.info("L2[%s] 已拿到新鲜 Passport64，重试一轮", key)
                    return _try_round(
                        fresh.passport64,
                        fresh.passport_bytes,
                        allow_refresh=False,
                    )
                except Exception as e:
                    logger.error("L2[%s] 重新鉴权失败: %s", key, e)
            logger.error("L2[%s] 全部候选 IP 都失败", key)
            return None

        key = pick_l2_market(market)
        init_market_code = "16;144;" if key == "sh" else "32;"
        return _try_round(passport64, auth_bytes, allow_refresh=True)

    def _try_open_manual_sock(self, host, passport64, key, init_market_code, skip_init=False):
        """对单个 L2 IP 执行连接 → 标准行情登录壳 → init。

        init 响应 <5000B 视为该 IP 不健康（连错市/未激活），返回 None 让调用方换 IP。
        ``skip_init=True`` 时跳过 init（复刻 ``_replay_exact.py`` 的成功路径）。
        """
        import socket as _socket
        try:
            sock = _socket.create_connection((host, MARKET_PORT), timeout=15)
        except OSError as e:
            logger.warning("L2[%s] 连接失败 %s: %s", key, host, e)
            return None
        login_body = self._auth_service.login_body_for_passport(
            passport64,
            LoginIdentity.L2,
        )
        try:
            sock.sendall(encode_frame(login_body) + b"\n")
            sock.settimeout(8.0)
            resp = self._connection_read_frame(sock)
            vc = ""
            prompt = ""
            for line in resp.decode("gbk", "replace").replace("\r\n", "\n").split("\n"):
                if line.startswith("VerifyCode="):
                    vc = line.split("=", 1)[1]
                elif line.startswith("PromptText="):
                    prompt = line.split("=", 1)[1]
            if vc != "0":
                logger.error("L2[%s] %s 登录失败 VerifyCode=%s PromptText=%s",
                             key, host, vc, prompt or "(无)")
                sock.close()
                if self._is_explicit_l2_permission_rejection(prompt):
                    self._account_evidence.record_l2_entitlement(
                        Support.NO
                    )
                    self._account_evidence.record_manual_login(Support.NO)
                # 票据失效（"通行证被修改痕迹"等）→ 返回特殊标记，让调用方
                # 立即重新鉴权，不再浪费剩余 IP（旧逻辑要试完全部 9 个才重试）
                if "通行证" in prompt or "身份" in prompt:
                    return "stale_passport"
                return None
            logger.info("L2[%s] %s 登录成功", key, host)
            self._account_evidence.record_manual_login(Support.YES)
        except (OSError, ValueError) as e:
            logger.error("L2[%s] %s 登录异常: %s", key, host, e)
            sock.close()
            return None
        if skip_init:
            logger.info("L2[%s] %s 跳过 init（skip_init）", key, host)
            return sock
        # ★ 发 init 激活行情通道。MarketCode 必须匹配该 IP 所属市场
        # （shlv2→16;144 沪市，szlv2→32 深市），否则只回 210B 小帧。
        try:
            init_frame = build_init_query(market_code=init_market_code)
            sock.sendall(init_frame + b"\n")
            n_frames = 0
            n_bytes = 0
            # 先用较长 timeout 等第一帧（配置帧 23-49KB，可能分多段到达），
            # 拿到大帧后用短 timeout 快速排空残留，避免白等。
            sock.settimeout(5.0)
            try:
                b = self._connection_read_frame(sock)
                n_frames += 1
                n_bytes += len(b)
            except (socket.timeout, OSError, ValueError):
                pass
            # 排空后续帧（配置帧后可能跟 ACK/推送帧），短 timeout 快速结束
            for _ in range(10):
                sock.settimeout(0.5)
                try:
                    b = self._connection_read_frame(sock)
                    n_frames += 1
                    n_bytes += len(b)
                except (socket.timeout, OSError, ValueError):
                    break
            logger.info("L2[%s] %s init 完成（MarketCode=%s，%d帧/%dB）",
                        key, host, init_market_code, n_frames, n_bytes)
            if n_bytes < 5000:
                logger.warning("L2[%s] %s init 响应过小（%dB），该 IP 未激活行情通道",
                               key, host, n_bytes)
                sock.close()
                return None
            self._account_evidence.record_l2_init(Support.YES)
        except OSError as e:
            logger.warning("L2[%s] %s init 异常: %s", key, host, e)
            sock.close()
            return None
        return sock

    @staticmethod
    def _is_explicit_l2_permission_rejection(prompt: str) -> bool:
        normalized = prompt.lower().replace(" ", "")
        return any(
            marker in normalized
            for marker in (
                "无level2权限",
                "没有level2权限",
                "无l2权限",
                "没有l2权限",
            )
        )

    # ── 板块专用通道（fu4 8901）──

    def _open_board_channel(
        self,
        timeout: float = 20.0,
        *,
        constituent_side: str | None = None,
    ):
        """打开板块专用通道：BOARD login → 完整引导序列。

        ★ 2026-08-01 抓包铁证：**板块指数**行情/分时/竞价走 **fu4** 市场组
        （``fu4.123ths.com:8901``，MarketCode=96;128;88;216;48;），在 MAIN
        连接上重放相同引导帧服务器只回 CodeListSize=0。login 壳按账号 profile
        分支（Level2 无用户名 / 普通 __manual，见
        :func:`thspypc.features.auth_protocol.build_login_body` 的
        ``LoginIdentity.BOARD``）。

        **成分股独立连接不走 fu4**：普通账号连 ``main.123ths.com``（thsuser，
        MarketCode=16;32;144;）、L2 沪连 ``shlv2.123ths.com``（thsuser，
        MarketCode=16;144;）、L2 深连 ``szlv2.123ths.com``（__manual，
        MarketCode=32;）——与抓包登录回执后端、MKT_INIT 市场集一一对应。
        连到 fu4（globalthsindex 网关）时服务器对全部 subreal 注册回
        ``errorcode=-1``，业务查询只回空 Sort 响应。

        核心引导（字节级复刻 2026-08-01 双账号抓包）：MarketCode init →
        subreal 注册 → pageid 注册；L2 成分股不发 qureal-init。原始 TCP
        流确认每个完整 FD 帧（包括 login、引导和查询）后均带 ``0x0a`` 分隔符。

        Returns:
            已引导的 socket（未收编，调用方负责持有/关闭）。

        Raises:
            OSError: 全候选 IP 登录失败或引导失败。
        """
        from ..features.auth_protocol import build_login_body
        from ..protocol import resolve_fu4_hosts

        if self._auth is None:
            self.authenticate()

        def _try_round(material, allow_refresh: bool, use_local_stocklink: bool = False):
            """用给定票据登录 fu4 + 引导；失败时可换票据和 IP 批次重试一次。

            ``use_local_stocklink=False`` 时优先用 ConfigVer=0 自行请求全量
            版本表；只有该路径引导失败后，才回退本机 StockLink.ini 表。
            """
            profile = material.profile
            passport64 = material.passport64
            level2 = profile.supports_manual_identity
            if constituent_side == "sz" and not level2:
                raise OSError("普通账号没有独立的深市板块成分连接")
            if constituent_side == "sh":
                identity = LoginIdentity.STANDARD
                role_key = "board_constituent_sh"
            elif constituent_side == "sz":
                identity = LoginIdentity.MANUAL
                role_key = "board_constituent_sz"
            else:
                identity = LoginIdentity.BOARD
                role_key = "board"
            if constituent_side is not None:
                # 成分股独立连接必须走股票行情网关（main/shlv2/szlv2），
                # 不能复用板块指数网关 fu4。
                from ..protocol import (
                    MARKET_HOSTS,
                    resolve_l2_hosts_grouped,
                    resolve_market_hosts,
                )

                if not level2:
                    hosts = resolve_market_hosts(material.passport_bytes)
                    group_name = "main"
                else:
                    grouped = resolve_l2_hosts_grouped(
                        material.passport_bytes
                    )
                    hosts = grouped.get(
                        "sh" if constituent_side == "sh" else "sz",
                        [],
                    )
                    group_name = (
                        "shlv2" if constituent_side == "sh" else "szlv2"
                    )
                if not hosts:
                    logger.warning(
                        "成分股通道：passport 无 %s 域名，回退 MARKET_HOSTS",
                        group_name,
                    )
                    hosts = list(MARKET_HOSTS)
            else:
                hosts = resolve_fu4_hosts(material.passport_bytes)
                if not hosts:
                    logger.warning(
                        "板块通道：passport 无 fu4 域名，回退 MARKET_HOSTS"
                    )
                    from ..protocol import MARKET_HOSTS
                    hosts = list(MARKET_HOSTS)
            probed = self._probe_fastest_hosts(
                hosts, timeout=1.0, role=role_key
            )
            candidates = probed or hosts
            offset = self._login_rr_offset.get(role_key, 0) % max(1, len(candidates))
            ordered = candidates[offset:] + candidates[:offset]
            logger.info(
                "板块通道：从 fu4 IP offset=%d 单连接登录（共 %d 个候选）",
                offset,
                len(ordered),
            )

            # 板块业务身份必须与真实客户端一致。STANDARD/MANUAL 即使 login
            # VerifyCode=0，也不代表服务器会激活 fu4 板块路由，不能作为降级壳。
            login_body = build_login_body(
                passport64,
                self.mac64,
                identity=identity,
                profile=profile,
            )
            # 每个逻辑角色只顺序登录一个 fu4 节点。指数 BOARD、标准身份的
            # 成分沪侧和 manual 身份的成分深侧是三个不同角色，不能并发登录
            # 同一角色的多个 IP 再关闭“输家”。
            winner = None
            tried = 0
            for host in ordered:
                tried += 1
                try:
                    sock = socket.create_connection(
                        (host, MARKET_PORT), timeout=min(timeout, 15.0)
                    )
                except (socket.timeout, ConnectionError, OSError):
                    continue
                sock = maybe_wrap_board_socket(
                    sock,
                    role=role_key,
                    host=host,
                    level2=level2,
                )
                try:
                    try:
                        sock.sendall(encode_frame(login_body) + b"\n")
                        sock.settimeout(min(timeout, 8.0))
                        resp_body = self._connection_read_frame(sock)
                        result = self._parse_connection_login_response(
                            resp_body
                        )
                        verify_code = result.get("VerifyCode")
                        logger.info(
                            "板块通道：%s:%d VerifyCode=%s",
                            host,
                            MARKET_PORT,
                            verify_code,
                        )
                        if verify_code == "0":
                            trace = getattr(sock, "trace", None)
                            if trace is not None:
                                trace.mark_login_ok(verify_code)
                            winner = (host, sock, result)
                            break
                        sock.close()
                    except (socket.timeout, OSError, ValueError):
                        try:
                            sock.close()
                        except OSError:
                            pass
                except (socket.timeout, ConnectionError, OSError):
                    continue

            # board 也必须像 MAIN/L2 一样把轮换偏移写盘。此前这里只改内存，
            # verify 每开一个新进程都会重新打同一批最快 fu4 IP。
            self._advance_l2_offset(
                role_key,
                tried,
                len(candidates),
                force_advance=winner is None,
            )
            if winner is None:
                if allow_refresh:
                    logger.warning(
                        "板块通道：全部 fu4 IP 登录失败，重新 HTTP 鉴权拿新鲜票据重试"
                    )
                    fresh = self._refresh_auth_material()
                    return _try_round(
                        fresh,
                        allow_refresh=False,
                        use_local_stocklink=use_local_stocklink,
                    )
                raise OSError("板块通道：全部 fu4 IP 登录失败")

            host, sock, _result = winner
            try:
                n_replies = self._send_board_bootstrap(
                    sock,
                    level2,
                    timeout=timeout,
                    constituent_side=constituent_side,
                    use_local_stocklink=use_local_stocklink,
                )
            except (OSError, ValueError) as exc:
                try:
                    sock.close()
                except OSError:
                    pass
                if allow_refresh:
                    # 自请求版本表被服务器拒绝/FIN 时，再退回本机表试一次。
                    logger.warning(
                        "板块通道：%s 自请求版本表引导失败（%s），"
                        "刷新票据并回退本机 StockLink.ini 重试",
                        host, exc,
                    )
                    fresh = self._refresh_auth_material()
                    return _try_round(
                        fresh,
                        allow_refresh=False,
                        use_local_stocklink=True,
                    )
                raise OSError(
                    f"板块通道引导失败（{host}）: {exc}"
                ) from exc
            if n_replies == 0:
                if allow_refresh:
                    # 引导零响应 = 当前连接未激活；下一轮优先用本机版本表。
                    logger.warning(
                        "板块通道：%s 自请求版本表引导零响应，"
                        "刷新票据并回退本机 StockLink.ini 重试",
                        host,
                    )
                    try:
                        sock.close()
                    except OSError:
                        pass
                    fresh = self._refresh_auth_material()
                    return _try_round(
                        fresh,
                        allow_refresh=False,
                        use_local_stocklink=True,
                    )
                raise OSError(
                    f"板块通道引导失败（{host}）：无响应"
                )
            if n_replies and constituent_side is not None:
                # 成分股连接的成功引导本身就是 L2 市场通道证据：MKT_INIT
                # 在 shlv2/szlv2 网关完成 = l2_market_init；深市 manual 身份
                # 登录成功 = manual_login。回填后能力门禁不再依赖该账号是否
                # 已开过 L2 推送连接。
                if level2:
                    self._account_evidence.record_l2_init(Support.YES)
                if constituent_side == "sz":
                    self._account_evidence.record_manual_login(Support.YES)
            logger.info(
                "✓ 板块通道就绪（%s:%d, level2=%s, role=%s）",
                host,
                MARKET_PORT,
                level2,
                role_key,
            )
            return sock

        material = self._auth_service.require_current()
        return _try_round(material, allow_refresh=True)

    def _send_board_bootstrap(
        self,
        sock,
        level2: bool,
        *,
        timeout: float = 12.0,
        constituent_side: str | None = None,
        use_local_stocklink: bool = False,
    ) -> int:
        """按真实客户端的阶段和等待发送板块引导；返回读取的响应帧数。"""
        from ..features.system_blocks_protocol import (
            build_board_bootstrap_stages,
            build_board_constituent_bootstrap_stages,
            load_local_board_stocklink_ver,
        )

        if use_local_stocklink:
            stocklink_ver = load_local_board_stocklink_ver()
            if stocklink_ver is None:
                logger.warning(
                    "板块通道：未找到完整的本机 StockLink.ini 版本表，"
                    "回退 ConfigVer=0"
                )
            else:
                logger.info("板块通道：回退使用本机 StockLink.ini 的逐市场版本表")
        else:
            stocklink_ver = None
            logger.info("板块通道：优先使用 ConfigVer=0 自行请求全量版本表")
        if constituent_side is None:
            stages = build_board_bootstrap_stages(
                level2,
                stocklink_ver=stocklink_ver,
            )
        else:
            stages = build_board_constituent_bootstrap_stages(
                level2,
                constituent_side,
                stocklink_ver=stocklink_ver,
            )

        # 抓包中 login reply 到第一阶段固定间隔约 0.45s。这个等待让 fu4 完成
        # 会话角色绑定；旧实现立即突发全部帧，恰好对应零响应/FIN 表型。
        time.sleep(0.45)
        for index, frames in enumerate(stages):
            # pcap 原始 TCP 流中每个 FD 帧后都有 0x0a。早期分析脚本按 MAGIC
            # split 后丢掉了帧间字节，曾误判为“无换行”；缺少这个分隔符时
            # fu4 会在第一阶段后直接 FIN。
            payload = b"".join(
                encode_frame(frame) + b"\n" for frame in frames
            )
            logger.debug(
                "板块通道：发送引导阶段 %d/%d：%d 帧 / %dB",
                index + 1,
                len(stages),
                len(frames),
                len(payload),
            )
            try:
                sock.sendall(payload)
            except OSError as exc:
                raise OSError(
                    f"阶段 {index + 1}/{len(stages)} 发送失败: {exc}"
                ) from exc
            if index == 0:
                # L2 抓包约 0.26s；普通账号需等待 subreal 回执，约 0.59s。
                time.sleep(0.55 if not level2 else 0.26)
            elif index == 1:
                # 给 init/qureal-init 留出产生 rettype=ini 的时间，再做二次注册。
                time.sleep(0.20 if not level2 else 0.06)

        # 排空：init 配置帧 / rettype=ini / 分类表 / StockNameVer 响应。
        # 等服务器完成 init；后续业务查询不应再吞初始化残留帧。
        deadline = time.time() + timeout
        n = 0
        sock.settimeout(0.8)
        while time.time() < deadline and n < 40:
            try:
                self._connection_read_frame(sock)
                n += 1
            except socket.timeout:
                break
            except (OSError, ValueError):
                break
        logger.debug("板块通道：引导响应排空 %d 帧", n)
        return n
