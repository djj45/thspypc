"""Stock-list workflows over the MAIN market connection."""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from collections.abc import Callable

from .._transport import ConnectionManager, ConnectionRole, SocketLike
from ..codecs.framing import read_frame
from ..errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from ..features.account_profile import AccountEvidenceRecorder
from ..features.stock_list_protocol import (
    DDE_LEVEL2_MARKETS,
    DDE_STANDARD_MARKETS,
    FULL_STOCK_LIST_MARKETS,
    FULL_STOCK_LIST_ST_MARKETS,
    FULL_STOCK_LIST_SZ_MARKETS,
    build_dde_query,
    build_full_stock_list_query,
    build_stock_list_query,
    parse_dde_response,
    parse_init_response,
    parse_stock_list_response,
    strip_to_identity,
    RANKED_VALUE_FIELDS,
)
from ..models import AccountKind, Capability, Support


FrameReader = Callable[[SocketLike], bytes]
Clock = Callable[[], float]
Sleep = Callable[[float], None]

logger = logging.getLogger(__name__)


class StockListService:
    """Fetch server-ranked stock-list pages using only MAIN."""

    def __init__(
        self,
        connections: ConnectionManager,
        *,
        frame_reader: FrameReader = read_frame,
        max_frames: int = 8,
        max_full_frames: int = 1024,
        evidence: AccountEvidenceRecorder | None = None,
        replay_segments: tuple[bytes, ...] | None = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._connections = connections
        self._read_frame = frame_reader
        self._max_frames = max_frames
        self._max_full_frames = max_full_frames
        self._evidence = evidence
        self._replay_segments = replay_segments
        self._clock = clock
        self._sleep = sleep
        self._dde_sequence = 0x6000
        self._dde_sequence_lock = threading.Lock()

    def _next_dde_sequence(self) -> int:
        with self._dde_sequence_lock:
            self._dde_sequence = (self._dde_sequence + 1) & 0xFFFF
            if self._dde_sequence == 0:
                self._dde_sequence = 1
            return self._dde_sequence

    def _get_request_segments(
        self,
        markets: tuple[int, ...] = FULL_STOCK_LIST_MARKETS,
    ) -> tuple[bytes, ...]:
        if self._replay_segments is not None:
            return self._replay_segments
        return (build_full_stock_list_query(markets=markets),)

    def ranked(
        self,
        *,
        count: int = 29,
        timeout: float = 10.0,
        sort_by: int = 199112,
        sort_dir: str = "D",
        max_pages: int = 120,
        with_values: bool = False,
    ) -> list[dict]:
        """Fetch and de-duplicate ranked pages up to ``count`` records.

        ``with_values=False``(默认)只返回 ``code/name/market``,与历史行为一致。
        ``with_values=True`` 保留响应里的全部 ``dt<N>`` 字段(排序值、行情字段),
        供调用方拿到封单额(dt<响应字段>)、涨幅等数值,不必再走 list_quotes 回填。
        """
        if count <= 0 or max_pages <= 0:
            return []

        direction = sort_dir.upper()
        if direction not in {"A", "D"}:
            raise ValueError("sort_dir must be 'A' or 'D'")

        # 账号分流（2026-08-14 客户端抓包确认，captures_live/rank_sort_20260814_1545*.pcap）：
        # - Level2：拆两条 L2 连接（沪 17();22();151(); + 深 33();），pageid=1341，
        #   SortCount 放大；MAIN 单请求不返回北交所 151 且 10~20% 区间缺条目。
        # - 普通：MAIN 单请求 17();22();33();151(); pageid=1334，SortBegin 翻页。
        if self._connections.profile.kind is AccountKind.LEVEL2:
            stocks = self._ranked_l2(
                count=count,
                timeout=timeout,
                sort_by=sort_by,
                sort_dir=direction,
                max_pages=max_pages,
                with_values=with_values,
            )
        else:
            stocks = self._ranked_main(
                count=count,
                timeout=timeout,
                sort_by=sort_by,
                sort_dir=direction,
                max_pages=max_pages,
                with_values=with_values,
            )
        if with_values:
            self._normalize_ranked_values(stocks, sort_by)
        return stocks

    def _ranked_l2(
        self,
        *,
        count: int,
        timeout: float,
        sort_by: int,
        sort_dir: str,
        max_pages: int,
        with_values: bool,
    ) -> list[dict]:
        """Level2 拆沪深两条 L2 连接取排序榜，本地合并后按排序值重排。

        请求参数对齐 2026-08-14 客户端抓包：pageid=1341、SortCount 从 20
        起逐步放大（20→160→…→全市场总数），沪 CodeList=17();22();151();
        深 CodeList=33();。SortBegin 恒 0——服务器按 SortCount 一次给满。
        """
        response_field = RANKED_VALUE_FIELDS.get(sort_by, f"dt{sort_by & 0xFF}")
        # 只对百分比类排序键归一化（涨幅/涨速/换手/量比/竞价涨幅）；
        # 金额类（竞价额 dt150/封单额 dt44/主力 dt250）是原始元不缩放。
        pct_sort_keys = {199112, 48, 1968584, 1771976, 68762}
        normalize_value = sort_by in pct_sort_keys

        def fetch_all(role: ConnectionRole, markets: tuple[int, ...]) -> list[dict]:
            connection = self._connections.acquire(
                role, capability=Capability.L2_MARKET_ACCESS
            )
            all_rows: list[dict] = []
            seen: set[str] = set()
            sort_count = min(20, max(count, 20))
            for _ in range(max_pages):
                request = build_stock_list_query(
                    markets=markets,
                    sort_begin=0,
                    sort_count=sort_count,
                    datatype=[sort_by],
                    sort_by=sort_by,
                    sort_dir=sort_dir,
                    pageid=1341,
                )
                response = None
                try:
                    with connection.request(request, timeout=timeout) as sock:
                        for _ in range(max(self._max_frames, 32)):
                            candidate = self._read_frame(sock)
                            if b"SortTotal" in candidate:
                                response = candidate
                                break
                except (socket.timeout, OSError):
                    break
                if response is None:
                    break
                metadata = parse_stock_list_response(response)
                page_stocks = metadata["stocks"]
                data_count = metadata["sort_data_count"]
                if data_count > 0 and not page_stocks:
                    raise ProtocolError(
                        "received stock-list data metadata but parsing failed"
                    )
                for stock in page_stocks:
                    code = stock.get("code", "")
                    if code and code not in seen:
                        seen.add(code)
                        # 就地归一化排序字段：L2 响应同榜混用除法（直接小数）
                        # 与乘法（x1e8）两种编码，排序/展示前统一真值。
                        if normalize_value:
                            stock[response_field] = _normalize_rank_value(
                                stock.get(response_field)
                            )
                        all_rows.append(stock)
                sort_total = metadata["sort_total"]
                if (
                    len(all_rows) >= count
                    or data_count == 0
                    or (sort_total > 0 and len(all_rows) >= sort_total)
                ):
                    break
                sort_count = max(
                    sort_count * 4,
                    min(len(all_rows) + 59, sort_total or 6000),
                )
            return all_rows

        sh_rows = fetch_all(ConnectionRole.SH_L2, (17, 22, 151))
        if self._evidence is not None and sh_rows:
            self._evidence.record_l2_init(Support.YES)
        sz_rows = fetch_all(ConnectionRole.SZ_L2, (33,))

        rows = _merge_ranked_rows(
            sh_rows + sz_rows,
            sort_dir=sort_dir,
            value_field=response_field,
        )
        if with_values:
            return rows[:count]
        return strip_to_identity(rows[:count])

    def _ranked_main(
        self,
        *,
        count: int,
        timeout: float,
        sort_by: int,
        sort_dir: str,
        max_pages: int,
        with_values: bool,
    ) -> list[dict]:
        """普通账号：MAIN 单请求 17/22/33/151 + pageid=1334，SortBegin 翻页。"""
        connection = self._connections.acquire(
            ConnectionRole.MAIN,
            capability=Capability.BASIC_QUOTE,
        )
        stocks: list[dict] = []
        seen_codes: set[str] = set()
        sort_total = 0
        sort_begin = 0

        for _page in range(max_pages):
            request = build_stock_list_query(
                markets=(17, 22, 33, 151),
                sort_begin=sort_begin,
                sort_count=59,
                datatype=[sort_by],
                sort_by=sort_by,
                sort_dir=sort_dir,
                pageid=1334,
            )
            response = None
            try:
                with connection.request(
                    request,
                    timeout=timeout,
                ) as sock:
                    for _ in range(self._max_frames):
                        candidate = self._read_frame(sock)
                        if b"SortTotal" in candidate:
                            response = candidate
                            break
            except (socket.timeout, OSError):
                return stocks

            if response is None:
                break
            metadata = parse_stock_list_response(response)
            if not sort_total:
                sort_total = metadata["sort_total"]
            page_stocks = metadata["stocks"]
            data_count = metadata["sort_data_count"]
            if data_count > 0 and not page_stocks:
                raise ProtocolError(
                    "received stock-list data metadata but parsing failed"
                )

            for stock in page_stocks:
                code = stock.get("code", "")
                if code and code not in seen_codes:
                    seen_codes.add(code)
                    stocks.append(stock)

            if self._evidence is not None and page_stocks:
                self._evidence.record_main_ready()
            if (
                len(stocks) >= count
                or data_count == 0
                or (sort_total > 0 and len(stocks) >= sort_total)
            ):
                break
            sort_begin = len(stocks)

        return stocks if with_values else strip_to_identity(stocks)

    def _normalize_ranked_values(
        self,
        stocks: list[dict],
        sort_by: int,
    ) -> None:
        """统一排序值缩放：真值 = mantissa/10000（2026-08-14 抓包确认）。

        排序响应里同一字段混用两种 THS float 编码：
        - 除法编码（bit31=1，如 0xc000431c → 1.718）：解码后直接是真值；
        - 乘法编码（bit31=0，如 0x40001536 → 54300000）：解码值 ×1e8，
          需 ÷1e8 还原（54300000/1e8 = 0.543）。
        按量级判断：|dec| >= 1e6 视为乘法编码（×1e8），否则直接使用。

        只归一化**百分比类**排序字段（涨幅 dt200/涨速 dt48/换手 dt200/
        量比 dt200/竞价涨幅 dt154）；金额类（竞价额 dt150/封单额 dt44/
        主力 dt250）是原始元，不缩放。
        """
        # sort_by → 是否百分比类（与 web/src/types.ts SORT_BY 对齐）。
        pct_sort_keys = {199112, 48, 1968584, 1771976, 68762}
        if sort_by not in pct_sort_keys:
            return
        field = RANKED_VALUE_FIELDS.get(sort_by)
        if field is None:
            return
        for stock in stocks:
            stock[field] = _normalize_rank_value(stock.get(field))

    def dde_ranked(
        self,
        *,
        count: int = 58,
        timeout: float = 10.0,
        sort_by: int = 592888,
        sort_dir: str = "D",
        max_pages: int = 120,
    ) -> list[dict]:
        """Fetch the pageid=10723 DDE table for standard or Level2 accounts."""
        if count <= 0 or max_pages <= 0:
            return []
        direction = sort_dir.upper()
        if direction not in {"A", "D"}:
            raise ValueError("sort_dir must be 'A' or 'D'")

        if self._connections.profile.kind is AccountKind.LEVEL2:
            page_count = max(58, count)
            pages = [
                self._dde_page(
                    role=role,
                    markets=markets,
                    count=page_count,
                    begin=0,
                    sort_by=sort_by,
                    sort_dir=direction,
                    timeout=timeout,
                    level2=True,
                    capability=Capability.L2_MARKET_ACCESS,
                )
                for role, markets in (
                    (ConnectionRole.SH_L2, DDE_LEVEL2_MARKETS[0]),
                    (ConnectionRole.SZ_L2, DDE_LEVEL2_MARKETS[1]),
                )
            ]
            rows = _merge_dde_rows(
                [row for page in pages for row in page["rows"]],
                sort_dir=direction,
            )
            if self._evidence is not None and rows:
                self._evidence.record_l2_init(Support.YES)
            return rows[:count]

        rows: list[dict] = []
        seen_codes: set[str] = set()
        begin = 0
        total = 0
        for _page in range(max_pages):
            page = self._dde_page(
                role=ConnectionRole.MAIN,
                markets=DDE_STANDARD_MARKETS,
                count=58,
                begin=begin,
                sort_by=sort_by,
                sort_dir=direction,
                timeout=timeout,
                level2=False,
                capability=Capability.BASIC_QUOTE,
            )
            if not total:
                total = page["sort_total"]
            for row in page["rows"]:
                code = row["code"]
                if code not in seen_codes:
                    seen_codes.add(code)
                    rows.append(row)
            data_count = page["sort_data_count"]
            if len(rows) >= count or data_count == 0:
                break
            if total and begin + data_count >= total:
                break
            begin += data_count

        if self._evidence is not None and rows:
            self._evidence.record_main_ready()
        return rows[:count]

    def _dde_page(
        self,
        *,
        role: ConnectionRole,
        markets: tuple[int, ...],
        count: int,
        begin: int,
        sort_by: int,
        sort_dir: str,
        timeout: float,
        level2: bool,
        capability: Capability,
    ) -> dict:
        connection = self._connections.acquire(role, capability=capability)
        sequence = self._next_dde_sequence()
        request = build_dde_query(
            markets=markets,
            sort_by=sort_by,
            sort_dir=sort_dir,
            sort_begin=begin,
            sort_count=count,
            level2=level2,
            seq=sequence,
        )
        saw_data = False
        with connection.request(request, timeout=timeout) as sock:
            # Fresh L2 connections can still have a burst of initialization
            # responses queued ahead of this request.  Sequence matching keeps
            # them safe to skip, while the larger bound prevents a valid DDE
            # response from being abandoned after the legacy eight-frame cap.
            for _ in range(max(self._max_frames, 64)):
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    break
                if (
                    len(response) < 7
                    or struct.unpack_from("<H", response, 5)[0] != sequence
                ):
                    continue
                if b"SortTotal" not in response:
                    continue
                page = parse_dde_response(response, sort_by=sort_by)
                if page["sort_data_count"] == 0:
                    return page
                saw_data = True
                if page["rows"] and page["has_value_field"]:
                    if level2 and sort_by == 592888:
                        for row in page["rows"]:
                            value = row.get("value")
                            if value is not None:
                                row["value"] = value / 100_000_000
                    return page
        if saw_data:
            raise ProtocolError("received DDE ranking data but parsing failed")
        raise ProtocolError("DDE ranking response timed out")

    def full_list(
        self,
        *,
        timeout: float = 30.0,
        replay_delay: float = 0.3,
        settle_timeout: float = 3.0,
    ) -> list[dict]:
        """Request all configured markets and merge every code table.

        Level2 账号的深市代码表不在 MAIN：MAIN 全量表只覆盖沪系市场
        （16/17/19/20/144-151；2026-08-14 实测 26356 行、无 00/30x 代码）。
        深市表需在 SZ_L2（szlv2）上用同一 DataType=[5],[55] 查询再取一次
        （市场码 32/33；实测单帧 3274 行，覆盖全部深市 A 股），合并返回。
        重放模式（replay_segments）保持 MAIN 单路，不复用抓包字节打 SZ。
        """
        stocks = self._full_list_on(
            ConnectionRole.MAIN,
            FULL_STOCK_LIST_MARKETS,
            capability=Capability.BASIC_QUOTE,
            timeout=timeout,
            replay_delay=replay_delay,
            settle_timeout=settle_timeout,
            full_frame_min_dc=5000,
        )
        if self._replay_segments is None:
            try:
                st_stocks = self._full_list_on(
                    ConnectionRole.MAIN,
                    FULL_STOCK_LIST_ST_MARKETS,
                    capability=Capability.BASIC_QUOTE,
                    timeout=timeout,
                    replay_delay=replay_delay,
                    settle_timeout=settle_timeout,
                    full_frame_min_dc=0,
                )
            except (
                CapabilityUnavailableError,
                UnsupportedAccountFeatureError,
                ChannelUnavailableError,
                ProtocolError,
            ) as exc:
                logger.warning(
                    "full_list: 沪市风险警示板(22)代码表不可用: %s",
                    exc,
                )
            else:
                if st_stocks:
                    merged = {stock["code"]: stock for stock in stocks}
                    for stock in st_stocks:
                        merged.setdefault(stock["code"], stock)
                    stocks = list(merged.values())
        if (
            self._replay_segments is None
            and self._connections.profile.kind is AccountKind.LEVEL2
        ):
            try:
                sz_stocks = self._full_list_on(
                    ConnectionRole.SZ_L2,
                    FULL_STOCK_LIST_SZ_MARKETS,
                    capability=Capability.L2_MARKET_ACCESS,
                    timeout=timeout,
                    replay_delay=replay_delay,
                    settle_timeout=settle_timeout,
                    full_frame_min_dc=0,
                )
            except (
                CapabilityUnavailableError,
                UnsupportedAccountFeatureError,
                ChannelUnavailableError,
                ProtocolError,
            ) as exc:
                # 深市表拿不到时退回沪系-only（旧行为），不拖垮整个股票表。
                logger.warning(
                    "full_list: SZ_L2 深市代码表不可用，仅返回沪系: %s",
                    exc,
                )
            else:
                if sz_stocks:
                    if self._evidence is not None:
                        self._evidence.record_l2_init(Support.YES)
                    merged = {stock["code"]: stock for stock in stocks}
                    for stock in sz_stocks:
                        merged.setdefault(stock["code"], stock)
                    stocks = list(merged.values())
        if self._evidence is not None and stocks:
            self._evidence.record_main_ready()
        return stocks

    def _full_list_on(
        self,
        role: ConnectionRole,
        markets: tuple[int, ...],
        *,
        capability: Capability,
        timeout: float,
        replay_delay: float,
        settle_timeout: float,
        full_frame_min_dc: int,
    ) -> list[dict]:
        """Collect one market family's full code table on one connection."""
        connection = self._connections.acquire(role, capability=capability)
        generated_request = self._replay_segments is None
        try:
            segments = self._get_request_segments(markets)
        except (OSError, ValueError) as exc:
            raise ProtocolError(
                f"stock-list request sequence is invalid: {exc}"
            ) from exc
        if not segments:
            raise ProtocolError("stock-list request sequence is empty")

        by_code: dict[str, dict] = {}
        started_at = self._clock()
        full_table_at: float | None = None
        request_timeout = min(2.0, max(timeout, 0.1))
        with connection.request(
            segments[0],
            timeout=request_timeout,
            trailing_newline=generated_request,
        ) as sock:
            for index, segment in enumerate(segments[1:]):
                if index == 0:
                    self._sleep(replay_delay)
                sock.sendall(segment)
                self._sleep(replay_delay)

            for _ in range(self._max_full_frames):
                now = self._clock()
                if (
                    full_table_at is not None
                    and now - full_table_at >= settle_timeout
                ):
                    break
                if (
                    full_table_at is None
                    and now - started_at >= timeout
                ):
                    break
                try:
                    response = self._read_frame(sock)
                except socket.timeout:
                    continue
                except OSError:
                    break
                except ValueError:
                    continue
                if not response:
                    continue

                metadata = parse_init_response(response)
                stocks = metadata["stocks"]
                full_frames = [
                    frame
                    for frame in metadata["hd31_frames"]
                    if frame["unk"] == 0x18 and frame["dc"] > full_frame_min_dc
                ]
                if full_frames and not stocks:
                    raise ProtocolError(
                        "received full stock table but parsing failed"
                    )
                for stock in stocks:
                    code = stock.get("code", "")
                    if code:
                        by_code.setdefault(code, stock)
                if full_frames:
                    full_table_at = self._clock()

        return list(by_code.values())


def _normalize_rank_value(value) -> float | None:
    """统一排序值真值 = mantissa/10000（2026-08-14 抓包/活网确认）。

    排序响应同字段混用三种编码，解码值量级可区分：
    - 除法 THS float（bit31=1，如 0xc000431c → 1.718）：直接是真值；
    - 乘法 THS float（bit31=0，如 0x40001536 → 54300000）：×1e8，÷1e8；
    - 裸 mantissa（如 L2 涨速榜 dt48=17180）：×10000，÷10000。
    阈值：|v| >= 1e7 → ÷1e8；1e3 <= |v| < 1e7 → ÷1e4；否则原样。
    A 股涨跌幅/涨速均 < 1000%，不会误伤真值本身。
    """
    if not isinstance(value, (int, float)):
        return value
    if value == 0.0:
        return value
    magnitude = abs(value)
    if magnitude >= 1e7:
        return value / 1e8
    if magnitude >= 1e3:
        return value / 1e4
    return value


def _merge_dde_rows(rows: list[dict], *, sort_dir: str) -> list[dict]:
    """Globally merge the independently sorted SH and SZ Level2 pages."""
    unique: dict[str, dict] = {}
    for row in rows:
        unique.setdefault(row["code"], row)

    def key(row: dict) -> tuple:
        value = row.get("value")
        if value is None:
            return (1, 0.0, row["code"])
        numeric = float(value)
        return (
            0,
            -numeric if sort_dir == "D" else numeric,
            row["code"],
        )

    return sorted(unique.values(), key=key)



def _merge_ranked_rows(
    rows: list[dict],
    *,
    sort_dir: str,
    value_field: str,
) -> list[dict]:
    """Globally merge the independently sorted SH and SZ ranked pages.

    沪（17/22/151）与深（33）两榜各自按排序值有序；本地按 value_field
    做全局归并（数值缺失的记录排末尾）。sort_dir D=降序、A=升序。
    """
    unique: dict[str, dict] = {}
    for row in rows:
        unique.setdefault(row.get("code", ""), row)

    def key(row: dict) -> tuple:
        value = row.get(value_field)
        if value is None:
            return (1, 0.0, row.get("code", ""))
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return (1, 0.0, row.get("code", ""))
        return (
            0,
            -numeric if sort_dir == "D" else numeric,
            row.get("code", ""),
        )

    return sorted(unique.values(), key=key)


__all__ = ["StockListService"]
