"""K-line workflows over the MAIN / L2 market connection."""
from __future__ import annotations

import socket
import threading
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import CapabilityUnavailableError, ProtocolError, SupersededError
from ..features.account_profile import AccountEvidenceRecorder
from ..features.kline_protocol import (
    build_kline_l2_query,
    build_kline_query,
    parse_kline_hd1_response,
    parse_kline_hd3_response,
)
from ..models import AccountKind, Capability, Support
from .quote import _repair_short_record


FrameReader = Callable[[SocketLike], bytes]

# 大 K 线响应在少数服务器上可能拆成多个独立 hd3.1 业务帧。只有首帧未达到
# 请求窗口大小时才需要短暂尾读；正常完整响应不应为兼容分片固定等待数秒。
KLINE_FRAGMENT_TAIL_TIMEOUT = 0.02


def _kline_l2_role(market: int) -> ConnectionRole:
    """Level2 K线连接角色（与 timeline/depth 的 L2 角色一致）。

    北交所（151）也走沪 L2（shlv2）：2026-08-15 抓包确认 Level2 客户端在
    shlv2 上用 pageid=1334 查询 920083 的日K。
    """
    if market in (16, 17, 144, 151):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"K线暂不支持市场码: {market}")


class KlineService:
    """Execute one K-line request while holding the connection request lock.

    普通账号走 MAIN + pageid=9355；Level2 账号走 L2 连接 + pageid=1334
    （2026-08-05 抓包对齐，见 ``build_kline_l2_query``）。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 16,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._evidence = evidence
        self._kline_gate = 0
        self._kline_gate_lock = threading.Lock()

    def kline(
        self,
        code: str,
        *,
        market: int,
        period: int,
        count: int = 2146,
        anchor: int = 0,
        fuquan: str = "Q",
        timeout: float = 12.0,
        channel: str = "auto",
        latest: bool = False,
    ) -> list[dict]:
        """Return all K-line data frames belonging to one request."""
        if channel not in ("auto", "level2", "ifindhq_fast"):
            raise ValueError(
                "K-line channel must be auto, level2, or ifindhq_fast"
            )
        profile = self._connections.profile
        use_l2 = (
            profile.kind is AccountKind.LEVEL2
            if channel == "auto"
            else channel == "level2"
        )
        if use_l2 and profile.kind is not AccountKind.LEVEL2:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "kline:level2",
            )
        if use_l2:
            request = build_kline_l2_query(
                code,
                market=market,
                period=period,
                fuquan=fuquan,
                count=count,
                anchor=anchor,
            )
            connection = self._connections.acquire(
                _kline_l2_role(market),
                capability=Capability.L2_TIMELINE,
            )
        else:
            request = build_kline_query(
                code,
                market=market,
                period=period,
                fuquan=fuquan,
                count=count,
                anchor=anchor,
            )
            role = (
                ConnectionRole.KLINE_FAST
                if channel == "ifindhq_fast"
                else ConnectionRole.MAIN
            )
            connection = self._connections.acquire(
                role,
                capability=Capability.BASIC_QUOTE,
            )
        records: list[dict] = []
        saw_kline_frame = False

        def drain(sock) -> None:
            nonlocal records, saw_kline_frame
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    if records:
                        break
                    raise
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("connection closed") from exc
                    if records:
                        break
                    continue

                # 新股首日的单根 K 线走 hd1.0，实测也会出现通用行情同型的
                # “帧体少末记录 1B、该字节紧随帧后到达”现象。K 线字段表后
                # 固定多一个 22B 股票壳，复用 quote 的补尾逻辑时显式计入。
                response = _repair_short_record(
                    sock,
                    response,
                    record_prefix_size=22,
                )

                if b"hd3.1\x00" in response:
                    saw_kline_frame = True
                    parsed = parse_kline_hd3_response(response)
                elif b"hd1.0\x00" in response:
                    saw_kline_frame = True
                    parsed = parse_kline_hd1_response(response)
                else:
                    parsed = None

                if parsed is not None:
                    if parsed:
                        records.extend(parsed)
                        # DateTime={period}(-count-anchor) 返回窗口包含终点，正常
                        # 是 count+1 根。达到完整窗口即可立即返回；新股等历史不足
                        # 的合法短响应则保留一个很短的尾读窗口，以兼容服务器把
                        # 大响应拆成多个 hd3.1 业务帧的旧行为。
                        if len(records) >= count + 1:
                            break
                        sock.settimeout(KLINE_FRAGMENT_TAIL_TIMEOUT)
                    continue
                if records:
                    break

        if channel == "ifindhq_fast" or latest:
            # Web 快速切股会让旧请求在共享 socket 后排队。领递增 gate，
            # 排到 socket 时若已被更新的请求取代则直接淘汰。公共
            # Python API 默认 latest=False，仍保留“每个调用都返回”的语义。
            with self._kline_gate_lock:
                self._kline_gate += 1
                gate = self._kline_gate
            try:
                with connection.request_latest(
                    request,
                    gate=gate,
                    timeout=timeout,
                ) as sock:
                    drain(sock)
            except SupersededError:
                return []
        else:
            with connection.request(request, timeout=timeout) as sock:
                drain(sock)

        if records:
            if self._evidence is not None:
                if use_l2:
                    self._evidence.record_feature(
                        Capability.L2_TIMELINE,
                        Support.YES,
                    )
                else:
                    self._evidence.record_main_ready()
            return records
        if saw_kline_frame:
            raise ProtocolError("received K-line frame but parsing failed")
        return []


__all__ = ["KLINE_FRAGMENT_TAIL_TIMEOUT", "KlineService"]
