"""超级盘口 / 逐笔成交回放工作流（period=7169，Level2 市场连接专用）。"""
from __future__ import annotations

import logging
import socket
import struct
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..features.superorder_protocol import (
    BUY_CANCEL_PERIOD,
    CANCEL_DETAIL_FIELD_COUNT,
    CANCEL_DETAIL_FLAG,
    CANCEL_DETAIL_RECORD_SIZE,
    ORDER_QUEUE_BUY_PERIOD,
    ORDER_QUEUE_HIST_PAGEID,
    ORDER_QUEUE_PAGEID,
    ORDER_QUEUE_SELL_PERIOD,
    ORDER_DETAIL_PERIOD,
    ORDER_DETAIL_FIELD_COUNT,
    ORDER_DETAIL_FLAG,
    ORDER_DETAIL_RECORD_SIZE,
    SELL_CANCEL_PERIOD,
    SNAPSHOT_REPLAY_HIST_PAGEID,
    SNAPSHOT_REPLAY_INDEX_PAGEID,
    SNAPSHOT_REPLAY_PAGEID,
    build_order_detail_query,
    build_order_queue_query,
    build_snapshot_replay_query,
    build_superorder_query,
    parse_order_detail_response,
    parse_order_queue_response,
    parse_snapshot_replay_response,
    parse_superorder_response,
)
from ..models import AccountKind, Capability, Support
from .subscription import L2SubscriptionCoordinator

logger = logging.getLogger(__name__)
FrameReader = Callable[[SocketLike], bytes]


def _repair_order_detail_tail(sock, body: bytes, *, period: int) -> bytes:
    """补读 7175/7170/7171 明文表落在 declared frame 外的末字节。"""
    if body.startswith(b"\x0a"):
        return body
    marker = body.find(b"hd1.0\x00")
    if marker < 0 or marker + 16 > len(body):
        return body
    row_count, flag, row_size, field_count = struct.unpack_from(
        "<IHHH", body, marker + 6
    )
    expected_layout = (
        (ORDER_DETAIL_FLAG, ORDER_DETAIL_RECORD_SIZE, ORDER_DETAIL_FIELD_COUNT)
        if period == ORDER_DETAIL_PERIOD
        else (CANCEL_DETAIL_FLAG, CANCEL_DETAIL_RECORD_SIZE, CANCEL_DETAIL_FIELD_COUNT)
    )
    if (flag, row_size, field_count) != expected_layout:
        return body
    field_end = marker + 16 + field_count * 4
    search_end = min(field_end + 120, len(body) - 7)
    code_pos = None
    for candidate in range(field_end, search_end + 1):
        if body[candidate] not in (0x11, 0x21):
            continue
        code = body[candidate + 1 : candidate + 7]
        if len(code) == 6 and code.isalnum():
            code_pos = candidate
            break
    if code_pos is None:
        return body
    expected_end = code_pos + 18 + row_count * row_size
    if expected_end != len(body) + 1:
        return body
    try:
        sock.settimeout(1.0)
        tail = sock.recv(1)
    except OSError:
        return body
    return body + tail if tail else body


def _superorder_l2_role(market: int) -> ConnectionRole:
    """7169 走对应市场的 Level2 连接（沪 shlv2 / 深 szlv2）。"""
    if market in (16, 17, 144):
        return ConnectionRole.SH_L2
    if market in (32, 33):
        return ConnectionRole.SZ_L2
    raise ValueError(f"7169 逐笔回放暂不支持市场码: {market}")


class SuperorderService:
    """在持有 L2 连接请求锁的前提下执行一次 7169 逐笔成交回放请求。

    仅 Level2 账号可用（普通账号无 L2 通道）。走市场专用 L2 连接，先 4214 注册
    （与十档盘口 depth_ten 同一套注册机制），再发 7169 区间请求。

    响应模式（2026-08-05 抓包确认）：**一个区间请求 → 一个响应帧**。服务端按请求的
    DateTime 区间一次性返回该段全部逐笔（单帧可达 2.5MB / 15 万条，TCP 拆包由
    read_frame 自动重组）。``max_frames`` 是兜底（防异常分页），正常只读 1 帧。
    """

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 32,
        subscriptions: L2SubscriptionCoordinator | None = None,
        evidence: AccountEvidenceRecorder | None = None,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._subscriptions = subscriptions
        self._evidence = evidence

    def superorder(
        self,
        code: str,
        *,
        market: int,
        start_ts: int,
        end_ts: int,
        pageid: int = 4214,
        timeout: float = 12.0,
    ) -> list[dict]:
        """请求并解析 7169 逐笔成交回放，返回逐笔记录列表。

        Args:
            code: 股票代码。
            market: 市场码（17=沪, 33=深）。
            start_ts/end_ts: 回放区间的 unix 时间戳（秒）。
            pageid: 4214（逐笔面板）或 4260（超级盘口）。
            timeout: 单次 read_frame 超时（秒）。
        """
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "superorder",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "superorder",
                profile.kind,
                "账号类型未知，不能推断 L2 逐笔通道",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        # 先 4214 注册（与十档盘口同一套机制；7169 复用 4214 通道）
        # 指数 77 通道不需要 4214 注册（2026-08-07 盘后抓包确认），
        # 且 build_snapshot_subscribe 只接受纯数字代码（1A0001/1B0680 会抛错）。
        if self._subscriptions is not None and pageid != SNAPSHOT_REPLAY_INDEX_PAGEID:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )

        request = build_superorder_query(
            code,
            market=market,
            start_ts=start_ts,
            end_ts=end_ts,
            pageid=pageid,
        )
        records: list[dict] = []
        saw_frame = False

        with connection.request(request, timeout=timeout) as sock:
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
                            raise ConnectionError("连接已关闭") from exc
                    if records:
                        break
                    continue

                # 7169 帧：normalize 前以 0x0a 开头，normalize 后含 hd1.0
                if response.startswith(b"\x0a") or b"hd1.0" in response:
                    parsed = parse_superorder_response(response)
                    if parsed:
                        records.extend(parsed)
                        sock.settimeout(2.0)
                        saw_frame = True
                        continue
                    if b"hd1.0" in response:
                        saw_frame = True
                if records:
                    break

        if records:
            if self._evidence is not None:
                self._evidence.record_feature(
                    Capability.L2_TIMELINE,
                    Support.YES,
                )
            return records
        if saw_frame:
            raise ProtocolError("收到 7169 逐笔帧但无法解析")
        return []

    def snapshot_replay(
        self,
        code: str,
        *,
        market: int,
        start_ts: int = 0,
        end_ts: int = 0,
        pageid: int = SNAPSHOT_REPLAY_PAGEID,
        timeout: float = 30.0,
    ) -> list[dict]:
        """请求并解析 4096 盘口快照回放（超级盘口分时曲线）。

        返回区间内每 ~3 秒一个完整盘口快照（全天 ~4927 点），每条含十档买卖价量。
        - 盘中 4260@4096(0-0)：flag=0x00FE hs=216 fc=54
        - 盘后/历史 4417@4096(<start>-<end>)：flag=0x009E hs=120 fc=30
          （2026-08-07 盘后抓包确认，``SNAPSHOT_REPLAY_HIST_PAGEID``）

        Args:
            code: 股票代码（如 ``"000938"``）。
            market: 市场码（17=沪, 33=深）。
            start_ts/end_ts: 区间 unix 秒；0-0 = 当日全天，绝对区间 = 历史日期，
                负值 = 相对窗口。
            pageid: 4260（盘中，默认）或 4417（盘后/历史）。
            timeout: 单次 read_frame 超时（秒）。全天数据 ~500KB，需较长超时。
        """
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "snapshot_replay",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "snapshot_replay",
                profile.kind,
                "账号类型未知，不能推断 L2 通道",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        # 指数 77 通道不需要 4214 注册（2026-08-07 盘后抓包确认），
        # 且 build_snapshot_subscribe 只接受纯数字代码（1A0001/1B0680 会抛错）。
        if self._subscriptions is not None and pageid != SNAPSHOT_REPLAY_INDEX_PAGEID:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )

        request = build_snapshot_replay_query(
            code,
            market=market,
            pageid=pageid,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        records: list[dict] = []
        saw_frame = False

        with connection.request(request, timeout=timeout) as sock:
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
                            raise ConnectionError("连接已关闭") from exc
                    if records:
                        break
                    continue

                if response.startswith(b"\x0a") or b"hd1.0" in response:
                    parsed = parse_snapshot_replay_response(response)
                    if parsed and start_ts > 0 and end_ts > 0:
                        # 指数响应一个帧常含多张表（今日 + 请求历史日），
                        # 按请求区间过滤出目标日期的记录。
                        parsed = [
                            r
                            for r in parsed
                            if start_ts <= r.get("ts", 0) <= end_ts
                        ]
                    if parsed:
                        records.extend(parsed)
                        sock.settimeout(2.0)
                        saw_frame = True
                        continue
                    if b"hd1.0" in response:
                        saw_frame = True
                if records:
                    break

        if records:
            if self._evidence is not None:
                self._evidence.record_feature(
                    Capability.L2_TIMELINE,
                    Support.YES,
                )
            return records
        if saw_frame:
            raise ProtocolError("收到 4096 盘口快照帧但无法解析")
        return []

    def order_details(
        self,
        code: str,
        *,
        market: int,
        start_ts: int = -29,
        end_ts: int = 0,
        timeout: float = 30.0,
    ) -> dict:
        """Return full submitted-order, buy-cancel and sell-cancel details.

        The three 4214 feeds are queried on the same market Level2 connection.
        Cancellation rows are linked back to their original 7175 order through
        ``dt37 == dt1`` whenever that order is present in the requested range.
        """
        orders = self._order_detail_one(
            code,
            market=market,
            period=ORDER_DETAIL_PERIOD,
            start_ts=start_ts,
            end_ts=end_ts,
            timeout=timeout,
        )
        buy_cancels = self._order_detail_one(
            code,
            market=market,
            period=BUY_CANCEL_PERIOD,
            start_ts=start_ts,
            end_ts=end_ts,
            timeout=timeout,
        )
        sell_cancels = self._order_detail_one(
            code,
            market=market,
            period=SELL_CANCEL_PERIOD,
            start_ts=start_ts,
            end_ts=end_ts,
            timeout=timeout,
        )

        by_id = {row["order_id"]: row for row in orders}
        for cancel in buy_cancels + sell_cancels:
            original = by_id.get(cancel["order_id"])
            cancel["linked_order"] = original is not None
            if original is not None:
                cancel["original_kind_raw"] = original["kind_raw"]
                cancel["link_exact"] = (
                    original["placed_ts"] == cancel["placed_ts"]
                    and original["price_raw"] == cancel["price_raw"]
                    and original["volume"] == cancel["volume"]
                )

        events = orders + buy_cancels + sell_cancels
        events.sort(
            key=lambda row: (
                row.get("ts", 0),
                0 if row.get("event") == "order" else 1,
                row.get("order_id", 0),
            )
        )
        return {
            "code": code,
            "market": market,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "orders": orders,
            "buy_cancels": buy_cancels,
            "sell_cancels": sell_cancels,
            "events": events,
        }

    def _order_detail_one(
        self,
        code: str,
        *,
        market: int,
        period: int,
        start_ts: int,
        end_ts: int,
        timeout: float,
    ) -> list[dict]:
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "order_details",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "order_details",
                profile.kind,
                "账号类型未知，不能推断 Level2 挂单/撤单明细权限",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        if self._subscriptions is not None:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )
        request = build_order_detail_query(
            code,
            market=market,
            period=period,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        with connection.request(request, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    break
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("连接已关闭") from exc
                    continue
                response = _repair_order_detail_tail(
                    sock,
                    response,
                    period=period,
                )
                parsed = parse_order_detail_response(response, period=period)
                if parsed:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_TIMELINE,
                            Support.YES,
                        )
                    return parsed
                if b"CodeListSize=" in response:
                    return []
        return []

    def order_queue(
        self,
        code: str,
        *,
        side: str,
        market: int,
        context_start_ts: int = 0,
        context_end_ts: int = 0,
        timeout: float = 12.0,
    ) -> dict:
        """请求买一/卖一委托队列（7173/7174，Level2 专属）。

        传入历史上下文区间时，先在同一 ConnectionManager 管理的市场 L2 连接上
        请求 4417@4096，再发队列请求。目前服务端只确认最近一个交易日可用。
        """
        if context_start_ts or context_end_ts:
            self.snapshot_replay(
                code,
                market=market,
                start_ts=context_start_ts,
                end_ts=context_end_ts,
                pageid=SNAPSHOT_REPLAY_HIST_PAGEID,
                timeout=max(timeout, 30.0),
            )
            pageid = ORDER_QUEUE_HIST_PAGEID
        else:
            pageid = ORDER_QUEUE_PAGEID
        return self._order_queue_one(
            code,
            side=side,
            market=market,
            pageid=pageid,
            timeout=timeout,
        )

    def order_queues(
        self,
        code: str,
        *,
        market: int,
        context_start_ts: int = 0,
        context_end_ts: int = 0,
        timeout: float = 12.0,
    ) -> dict[str, dict]:
        """一次建立上下文并依次返回买一、卖一委托队列。"""
        if context_start_ts or context_end_ts:
            snapshots = self.snapshot_replay(
                code,
                market=market,
                start_ts=context_start_ts,
                end_ts=context_end_ts,
                pageid=SNAPSHOT_REPLAY_HIST_PAGEID,
                timeout=max(timeout, 30.0),
            )
            pageid = ORDER_QUEUE_HIST_PAGEID
        else:
            snapshots = []
            pageid = ORDER_QUEUE_PAGEID

        result = {
            side: self._order_queue_one(
                code,
                side=side,
                market=market,
                pageid=pageid,
                timeout=timeout,
            )
            for side in ("buy", "sell")
        }
        if snapshots:
            latest = snapshots[-1]
            # 4096 的买一/卖一总量分别是 dt25/dt31；用于补齐界面顶栏数据。
            for side, dt_key in (("buy", "dt25"), ("sell", "dt31")):
                raw_total = latest.get(dt_key)
                if raw_total is None:
                    continue
                total_shares = int(round(float(raw_total)))
                queue = result[side]
                queue["total_shares"] = total_shares
                queue["total_hands"] = (total_shares + 50) // 100
                count = queue.get("total_order_count", 0)
                if count:
                    queue["average_hands"] = total_shares / 100.0 / count
        return result

    def _order_queue_one(
        self,
        code: str,
        *,
        side: str,
        market: int,
        pageid: int,
        timeout: float,
    ) -> dict:
        if side not in ("buy", "sell"):
            raise ValueError("side 必须是 'buy' 或 'sell'")
        profile = self._connections.profile
        if profile.kind is AccountKind.STANDARD:
            raise CapabilityUnavailableError(
                Capability.L2_TIMELINE,
                "order_queue",
            )
        if profile.kind is AccountKind.UNKNOWN:
            raise UnsupportedAccountFeatureError(
                "order_queue",
                profile.kind,
                "账号类型未知，不能推断 Level2 委托队列权限",
            )

        role = _superorder_l2_role(market)
        connection = self._connections.acquire(
            role,
            capability=Capability.L2_TIMELINE,
        )
        if self._subscriptions is not None:
            self._subscriptions.ensure_registered(
                connection,
                code,
                market=market,
                timeout=min(timeout, 5.0),
            )
        request = build_order_queue_query(
            code,
            market=market,
            side=side,
            pageid=pageid,
        )
        with connection.request(request, timeout=timeout) as sock:
            for _ in range(self._max_frames):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    break
                except ValueError:
                    recv = getattr(sock, "recv", None)
                    if recv is not None:
                        try:
                            recv(8192)
                        except OSError as exc:
                            raise ConnectionError("连接已关闭") from exc
                    continue
                parsed = parse_order_queue_response(response, side=side)
                if parsed is not None:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_TIMELINE,
                            Support.YES,
                        )
                    parsed["pageid"] = pageid
                    parsed["empty"] = False
                    return parsed
                if b"CodeListSize=" in response:
                    if self._evidence is not None:
                        self._evidence.record_feature(
                            Capability.L2_TIMELINE,
                            Support.YES,
                        )
                    return {
                        "code": code,
                        "side": side,
                        "period": (
                            ORDER_QUEUE_BUY_PERIOD
                            if side == "buy"
                            else ORDER_QUEUE_SELL_PERIOD
                        ),
                        "pageid": pageid,
                        "empty": True,
                        "entries": [],
                        "visible_count": 0,
                        "visible_major_order_count": 0,
                        "visible_major_shares": 0,
                        "visible_major_hands": 0.0,
                    }
        return {
            "code": code,
            "side": side,
            "period": (
                ORDER_QUEUE_BUY_PERIOD
                if side == "buy"
                else ORDER_QUEUE_SELL_PERIOD
            ),
            "pageid": pageid,
            "empty": True,
            "entries": [],
            "visible_count": 0,
            "visible_major_order_count": 0,
            "visible_major_shares": 0,
            "visible_major_hands": 0.0,
        }


__all__ = ["SuperorderService"]
