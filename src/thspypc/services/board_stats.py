"""Capability-gated workflows for the 9601 board statistics channel.

编排两类板块统计计算（2026-08-05 抓包确认的 9601 纯文本协议）：

- **statscalc**：批量板块指数聚合计算（区间涨跌幅/涨速、涨跌停统计），返回
  hd1.0 表。走**独立统计节点**（``ConnectionRole.BOARD_STATS``，``8.132.233.77``）。
- **calcext**：单股/单板块扩展计算（如流通市值），返回 JSON。走 REALORDER
  节点（``ConnectionRole.REALORDER``，与 ``qurealorder`` 共享 9601 socket）。

两者共享同一帧封装（``\\x09`` + GBK key=value 文本 + ``\\x00``），但走不同
节点，因此用不同连接角色，互不干扰。
"""
from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import encode_frame
from ..errors import ChannelUnavailableError
from ..features.board_stats_protocol import (
    DATATYPE_INTERVAL_STAT,
    DATATYPE_MARKETCAP,
    DATATYPE_UPDOWNLIMIT,
    build_calcext_query,
    build_statscalc_query,
    parse_calcext_response,
    parse_statscalc_response,
    read_frame_board_stats,
)
from ..models import Capability


logger = logging.getLogger(__name__)


FrameReader = Callable[[SocketLike], bytes]
InstanceFactory = Callable[[], int]


class BoardStatsService:
    """Serialize statscalc/calcext requests on their respective 9601 channels.

    statscalc 与 calcext 走不同节点（见模块文档），因此分别通过
    ``ConnectionRole.BOARD_STATS`` 和 ``ConnectionRole.REALORDER`` 取通道。
    两通道各有独立的请求锁（``_board_stats_lock`` / ``_realorder_lock``），
    串行化整个请求生命周期（9601 无请求 id，必须串行 send + read）。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        next_instance: InstanceFactory,
        *,
        frame_reader: FrameReader = read_frame_board_stats,
        max_frames: int = 8,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connections = connections
        self._next_instance = next_instance
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._clock = clock

    # ── statscalc：批量板块统计（独立统计节点）──

    def statscalc_interval(
        self,
        codes,
        *,
        market: int = 48,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块区间涨跌幅/涨速聚合统计（dataclass=intervalcalc, datatype=330342）。

        Args:
            codes: 板块指数代码列表（如 ``["881121", "885897"]``）。
            market: 板块市场（默认 48）。
            timeout: 单次请求超时（秒）。

        Returns:
            list[dict]，每条含 ``code``（前导零补齐，如 ``"0881121"``）/
            ``date``（形如 20160127）/``value``（涨跌幅%，浮点）。统计节点不可达
            或超时时返回空列表并记 warning（不抛异常，便于上层降级到 board_quotes）。
        """
        body = build_statscalc_query(
            self._next_instance(),
            codes,
            market=market,
            datatype=DATATYPE_INTERVAL_STAT,
            dataclass="intervalcalc",
        )
        return self._query_statscalc(body, timeout=timeout)

    def statscalc_updownlimit(
        self,
        codes,
        *,
        market: int = 48,
        timeout: float = 15.0,
    ) -> list[dict]:
        """板块涨跌停统计（dataclass=updownlimit, datatype=330326,330328）。

        Args/Returns 同 :meth:`statscalc_interval`，``value`` 为涨跌停家数统计。
        """
        body = build_statscalc_query(
            self._next_instance(),
            codes,
            market=market,
            datatype=DATATYPE_UPDOWNLIMIT,
            dataclass="updownlimit",
        )
        return self._query_statscalc(body, timeout=timeout)

    def _query_statscalc(
        self,
        body: bytes,
        *,
        timeout: float,
    ) -> list[dict]:
        """在 BOARD_STATS 通道上发送 statscalc 请求并解析 hd1.0 响应。

        服务器可能先回一个 metadata 帧（无 hd1.0，只有 ``\\x00\\x00\\0...``），
        再回数据帧；因此最多读 ``max_frames`` 帧直到拿到含 ``hd1.0`` 的数据帧。
        """
        try:
            connection = self._connections.acquire(
                ConnectionRole.BOARD_STATS,
                capability=Capability.BASIC_QUOTE,
            )
        except (OSError, ChannelUnavailableError) as exc:
            logger.warning("statscalc 通道建连失败，返回空（可降级 board_quotes）: %s", exc)
            return []
        try:
            with connection.request(
                encode_frame(body),
                timeout=timeout,
            ) as sock:
                deadline = self._clock() + timeout
                for _ in range(self._max_frames):
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    response = self._read_frame(sock)
                    if b"hd1.0" in response:
                        return parse_statscalc_response(response)
        except socket.timeout:
            logger.warning("statscalc 请求超时（%ss），返回空", timeout)
            return []
        except OSError as exc:
            logger.warning("statscalc 查询网络错误: %s", exc)
            return []
        return []

    # ── calcext：单股/单板块扩展计算（REALORDER 节点）──

    def calcext(
        self,
        code: str,
        market: int,
        *,
        datatype: str = DATATYPE_MARKETCAP,
        timeout: float = 15.0,
    ) -> list[dict]:
        """单股/单板块扩展计算（rettype=json）。

        Args:
            code: 单个证券代码（如 ``"600030"`` / ``"881121"``）。
            market: 代码所属市场（17=沪 / 33=深 / 48=板块）。
            datatype: 计算字段编号，默认 ``199359``（流通市值）。
            timeout: 单次请求超时（秒）。

        Returns:
            list[dict]，每条含 ``market``/``code``/``value``（数值，类型取决于
            datatype）。REALORDER 通道不可达时返回空列表。
        """
        body = build_calcext_query(
            self._next_instance(),
            code,
            market,
            datatype=datatype,
        )
        try:
            connection = self._connections.acquire(
                ConnectionRole.REALORDER,
                capability=Capability.REALORDER,
            )
        except (OSError, ChannelUnavailableError) as exc:
            logger.warning("calcext 通道建连失败，返回空: %s", exc)
            return []
        try:
            with connection.request(
                encode_frame(body),
                timeout=timeout,
            ) as sock:
                deadline = self._clock() + timeout
                for _ in range(self._max_frames):
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    response = self._read_frame(sock)
                    if b"rettype=json" in response and b"status_code" in response:
                        return parse_calcext_response(response)
        except socket.timeout:
            logger.warning("calcext 请求超时（%ss），返回空", timeout)
            return []
        except OSError as exc:
            logger.warning("calcext 查询网络错误: %s", exc)
            return []
        return []


__all__ = ["BoardStatsService"]
