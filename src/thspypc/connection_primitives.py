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

from .features.auth_protocol import LoginIdentity
from .models import Capability, Support
from .protocol import (
    MARKET_PORT,
    REALORDER_HOST,
    REALORDER_PORT,
    build_init_query,
    encode_frame,
    parse_init_response,
)
from .transport import ConnectionRole

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
        sorted_ips = self._probe_fastest_hosts(hosts, timeout=1.0)
        if sorted_ips:
            # ★ K线坏 IP 黑名单过滤：部分 IP（如 116.63.x.x）不支持大 K线查询，
            # 只返回部分数据或 timeout（实测 §14j）。重连时跳过这些 IP，优先选
            # 未失败过的。若全部在黑名单（罕见），退而用全表（不让黑名单卡死）。
            good_ips = [ip for ip in sorted_ips if ip not in self._bad_kline_ips]
            pool = good_ips if good_ips else sorted_ips
            n_concurrent = min(7, len(pool))
            offset = self._login_rr_offset % max(1, len(pool))
            # 环形取 n_concurrent 个（offset 起，绕回）
            batch = (pool[offset:] + pool[:offset])[:n_concurrent]
            skip_note = f"（跳过 {len(self._bad_kline_ips)} 个坏IP）" if self._bad_kline_ips else ""
            logger.info("并发连接 %d 个 IP（测速排序+轮换 offset=%d）%s: %s",
                        len(batch), offset, skip_note, batch[:3])
        else:
            # 测速全部超时（网络异常），回退到盲取前 7 个
            logger.warning("IP 测速全部超时，回退到盲取前 7 个")
            n_concurrent = min(7, len(hosts))
            batch = hosts[:n_concurrent]

        winner = self._concurrent_login(batch, login_body)
        # 推进轮换偏移：下次 connect 用不同的 IP 子集。写盘持久化（跨进程共享）。
        self._login_rr_offset = (self._login_rr_offset + n_concurrent) % max(1, len(sorted_ips) if sorted_ips else len(hosts))
        if sorted_ips:
            self._persist_ip_state(sorted_ips, self._login_rr_offset)
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
                        # 连续多个 -1 = 同 IP 短时间重复 login 的会话冲突（level2 单点
                        # 登录，对相同 IP 重复 login 触发）。非账号封禁——IP 分散时不触发，
                        # 同花顺客户端始终能登，改用不同 IP 即恢复。
                        if consecutive_minus1 >= MAX_CONSECUTIVE_MINUS1:
                            logger.warning("连续 %d 个 IP 返回 -1，判定为同 IP 重复 login 会话冲突，"
                                           "停止重试（改用不同 IP 即恢复）",
                                           consecutive_minus1)
                            return self._login_result_type(
                                success=False,
                                verify_code="-1",
                                error="session_conflict",
                                detail=f"连续 {consecutive_minus1} 个 IP VerifyCode=-1，"
                                       "疑似同 IP 短时间重复 login 的会话冲突（level2 单点登录）。"
                                       "改用不同 IP 或等片刻即恢复，非账号封禁",
                            )
                        continue
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

        return self._login_result_type(success=False, error="all_hosts_failed", detail=last_err)

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
        （list_quotes 走 hd1.0/hd3.1 不强依赖 init，但 K线 hd3.1 flag=0x0042/0x0046
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
            cache_matches_hosts = set(cached).issubset(set(hosts))
            if (
                time.time() - ts < self._PROBE_CACHE_TTL
                and cached
                and cache_matches_hosts
            ):
                logger.debug("IP 测速缓存命中（%d 个可达 IP）", len(cached))
                return cached
            if cached and not cache_matches_hosts:
                logger.debug("IP 测速缓存与当前 DNS 候选不一致，重新测速")
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
            self._persist_ip_state(sorted_ips, self._login_rr_offset)
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
        # 全部失败，记录错误
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

    def _preheat_other_market(self, current_key: str) -> None:
        """后台异步预热另一市的 __manual 连接（复刻 hexin 启动即双连行为）。

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
                sock = self._open_manual_push_connection(other_market)
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
                                      use_main_ip: bool = False):
        """用 __manual 身份开一条独立 8901 连接（推送通道专用，按沪深分服）。

        复用当前 HTTP AuthMaterial 的 Passport64/Mac64；不要求 MAIN 已连接。
        login 帧使用 UserName=__manual。
        登录后默认发 init 激活行情通道（``skip_init=False``）。

        ★ **按沪深选 L2 服务器**（2026-07-24 实测突破）：shlv2/szlv2 是两套独立
        服务器（IP 0 重叠）。必须按 market 选对应域名解析出的 IP，且 init 的
        MarketCode 匹配该市场，否则 init 只回 210B、4214 注册 CodeListSize=0::

            沪市（17/16/144）→ shlv2 IP + init(MarketCode="16;144;")
            深市（33/32）    → szlv2 IP + init(MarketCode="32;")

        HANDOFF 旧结论"__manual 发 init(16) 被拒、改 32 正常"是误判——当时连的
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

        Returns:
            成功激活的 socket，或 None（全组 IP 都失败）。
        """
        import socket as _socket
        from thspypc.protocol import resolve_l2_hosts_grouped, pick_l2_market

        if self._auth is None:
            self.authenticate()

        def _try_round(passport64, allow_refresh):
            """用给定 passport64 尝试所有候选 IP；全失败时可选重新鉴权重试一轮。"""
            if use_main_ip:
                if not self._connected_ip:
                    logger.error("__manual: use_main_ip 但无主连接 IP")
                    return None
                hosts = [self._connected_ip]
                logger.info("__manual[%s] use_main_ip=True → 强制连主连接 IP %s",
                            key, self._connected_ip)
            else:
                grouped = resolve_l2_hosts_grouped(self._auth.get("passport_bytes", b""))
                hosts = list(grouped.get(key, []))
                if self._connected_ip and self._connected_ip in hosts:
                    hosts.remove(self._connected_ip)
                    hosts.insert(0, self._connected_ip)
                if not hosts:
                    logger.error("__manual: 无 %s 组 L2 IP（账号可能无 L2 权限）", key)
                    return None

            logger.info("__manual[%s] 推送连接: 候选 %d IP %s，init MarketCode=%s%s",
                        key, len(hosts), hosts[:3], init_market_code,
                        "（skip_init）" if skip_init else "")
            stale = False
            for host in hosts:
                result = self._try_open_manual_sock(host, passport64, key,
                                                     init_market_code, skip_init)
                if result is not None and result != "stale_passport":
                    return result
                if result == "stale_passport":
                    # 票据失效，剩余 IP 必然也失败，立即跳出重新鉴权
                    stale = True
                    logger.info("__manual[%s] 票据失效（%s），跳过剩余 IP 直接重新鉴权",
                                key, host)
                    break
                logger.info("__manual[%s] IP %s 不可用，换下一个", key, host)
            # ★ 票据失效或全失败：__manual 登录对 Passport64 新鲜度敏感——同一票据
            # 被多次使用后服务器会拒（PromptText="通行证有被修改的痕迹"）。主连接
            # 已建立不受影响，但新 __manual 登录会被拒。检测到 stale 或全失败时，
            # 重新 full_http_auth 拿新鲜票据再试一轮。
            if stale or allow_refresh:
                if stale:
                    logger.warning("__manual[%s] 票据失效，重新 HTTP 鉴权拿新鲜 Passport64...",
                                   key)
                else:
                    logger.warning("__manual[%s] 全失败，重新 HTTP 鉴权拿新鲜 Passport64 重试...",
                                   key)
                try:
                    fresh = self._refresh_auth_material().passport64
                    logger.info("__manual[%s] 已拿到新鲜 Passport64，重试一轮", key)
                    return _try_round(fresh, allow_refresh=False)
                except Exception as e:
                    logger.error("__manual[%s] 重新鉴权失败: %s", key, e)
            logger.error("__manual[%s] 全部候选 IP 都失败", key)
            return None

        passport64 = self._current_passport64()
        key = pick_l2_market(market)
        init_market_code = "16;144;" if key == "sh" else "32;"
        return _try_round(passport64, allow_refresh=True)

    def _try_open_manual_sock(self, host, passport64, key, init_market_code, skip_init=False):
        """对单个 IP 执行 __manual 连接 → 登录 → init，成功返回 socket。

        init 响应 <5000B 视为该 IP 不健康（连错市/未激活），返回 None 让调用方换 IP。
        ``skip_init=True`` 时跳过 init（复刻 ``_replay_exact.py`` 的成功路径）。
        """
        import socket as _socket
        try:
            sock = _socket.create_connection((host, MARKET_PORT), timeout=15)
        except OSError as e:
            logger.warning("__manual[%s] 连接失败 %s: %s", key, host, e)
            return None
        login_body = self._auth_service.login_body_for_passport(
            passport64,
            LoginIdentity.MANUAL,
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
                logger.error("__manual[%s] %s 登录失败 VerifyCode=%s PromptText=%s",
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
            logger.info("__manual[%s] %s 登录成功", key, host)
            self._account_evidence.record_manual_login(Support.YES)
        except (OSError, ValueError) as e:
            logger.error("__manual[%s] %s 登录异常: %s", key, host, e)
            sock.close()
            return None
        if skip_init:
            logger.info("__manual[%s] %s 跳过 init（skip_init）", key, host)
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
            logger.info("__manual[%s] %s init 完成（MarketCode=%s，%d帧/%dB）",
                        key, host, init_market_code, n_frames, n_bytes)
            if n_bytes < 5000:
                logger.warning("__manual[%s] %s init 响应过小（%dB），该 IP 未激活行情通道",
                               key, host, n_bytes)
                sock.close()
                return None
            self._account_evidence.record_l2_init(Support.YES)
        except OSError as e:
            logger.warning("__manual[%s] %s init 异常: %s", key, host, e)
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
