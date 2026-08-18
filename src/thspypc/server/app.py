"""FastAPI REST 接口（单用户、请求-响应；实时推送待盘中核对后另加 WebSocket）。"""
from __future__ import annotations

from collections.abc import Callable
import concurrent.futures
from contextlib import asynccontextmanager
import contextvars
from dataclasses import asdict, is_dataclass
import threading
import time

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from ..errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from .runtime import ThsRuntime
from .._transport.timing import (
    RequestTiming,
    reset_request_timing,
    set_request_timing,
)


def _market_for_code(code: str) -> int:
    """按代码前缀推断市场码（与 client.THSClient._market_for_code 保持一致）。

    支持：6xx=沪17、1A/1B=沪指16、39x=深指32、899=北证指数144、
    43/83/87/920=北交所个股151，其余=深33。
    """
    if code.startswith("6"):
        return 17
    if code.startswith(("1A", "1B")):
        return 16
    if code.startswith("39"):
        return 32
    if code.startswith("899"):
        return 144
    if code.startswith(("43", "83", "87", "920")):
        return 151
    return 33


def _split_codes(codes: str) -> list[str]:
    result = [code.strip() for code in codes.split(",") if code.strip()]
    if not result:
        raise HTTPException(400, "codes 不能为空（逗号分隔，如 600519,000938）")
    return result


def _to_dict(value):
    """把 dataclass（SystemBlock/StockGroup 等）转成 JSON 字典。"""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    return value


def _jsonable(value):
    """递归剥掉 hd 解析遗留的 ``_raw`` bytes 字段（如 ``dt39_raw``）。

    部分 service（如 ``hot_boards``）的解析路径会把原始未解码字节塞进 dict
    的 ``<field>_raw`` 键，这些是调试产物、前端无需，且含 non-UTF-8 字节会
    让 pydantic 序列化失败（500）。这里递归移除所有 bytes/bytearray 值。
    """
    if isinstance(value, dict):
        return {
            k: _jsonable(v)
            for k, v in value.items()
            if not isinstance(v, (bytes, bytearray))
        }
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def create_app(runtime: ThsRuntime | None = None) -> FastAPI:
    runtime = runtime or ThsRuntime()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        runtime.start_preheat()
        yield

    app = FastAPI(
        title="thspypc Web API",
        version="0.1.0",
        description="同花顺 PC 协议的单用户 REST 接口（前端 JS 消费）。",
        lifespan=lifespan,
    )
    # 开发期放开跨域，方便本地前端（React/Vue dev server）调试
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.runtime = runtime

    @app.middleware("http")
    async def server_timing(request: Request, call_next):
        timing = RequestTiming()
        token = set_request_timing(timing)
        started = time.perf_counter()
        try:
            response = await call_next(request)
            response.headers["Server-Timing"] = timing.header(
                (time.perf_counter() - started) * 1000
            )
            return response
        finally:
            reset_request_timing(token)

    def _call(operation: Callable[[object], object]) -> object:
        try:
            return runtime.call(operation)
        except CapabilityUnavailableError as exc:
            raise HTTPException(403, str(exc))
        except (UnsupportedAccountFeatureError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        except (ChannelUnavailableError, ProtocolError, RuntimeError, OSError) as exc:
            raise HTTPException(502, str(exc))

    # 短 TTL 响应缓存：同一只票快速来回切换/刷新时，不再重复打 8901 socket。
    # 仅缓存成功结果；失败不缓存。缓存为进程内、单用户（runtime 唯一）。
    _cache_lock = threading.Lock()
    _response_cache: dict[tuple, tuple[float, object]] = {}
    _cache_max_entries = 64

    def _cached(
        key: tuple,
        ttl: float,
        operation: Callable[[object], object],
    ) -> object:
        now = time.monotonic()
        with _cache_lock:
            entry = _response_cache.get(key)
            if entry is not None and now - entry[0] < ttl:
                return entry[1]
        result = _call(operation)
        with _cache_lock:
            if len(_response_cache) >= _cache_max_entries:
                oldest = min(
                    _response_cache,
                    key=lambda item: _response_cache[item][0],
                )
                _response_cache.pop(oldest, None)
            _response_cache[key] = (time.monotonic(), result)
        return result

    # ── 连接 / 状态 ──
    @app.get("/api/status")
    def status() -> dict:
        return runtime.status()

    @app.post("/api/connect")
    def connect() -> dict:
        return runtime.connect()

    # ── 个股行情 ──
    @app.get("/api/quote")
    def quote(codes: str = Query(..., description="逗号分隔的股票代码")) -> list[dict]:
        code_list = _split_codes(codes)

        def operation(client) -> list[dict]:
            groups: dict[int, list[str]] = {}
            for code in code_list:
                groups.setdefault(client._market_for_code(code), []).append(code)
            merged: list[dict] = []
            for market, batch in groups.items():
                merged.extend(client.list_quotes(batch, market=market))
            return merged

        return _call(operation)

    @app.get("/api/quotes_ext")
    def quotes_ext(codes: str = Query(..., description="逗号分隔的股票代码")) -> list[dict]:
        """统一列表字段（涨幅/竞价涨幅/竞价金额/成交额/4分钟涨速，批量）。"""
        code_list = _split_codes(codes)
        return _call(lambda client: client.stock_quote_fields(code_list))

    @app.get("/api/depth/{code}")
    def depth(code: str, levels: int = 5, market: int = 0) -> dict:
        if levels not in (5, 10):
            raise HTTPException(400, "levels 只能是 5 或 10")
        return _call(
            lambda client: client.depth_quote(
                code,
                market=market,
                ten_levels=levels == 10,
            )
        )

    @app.get("/api/kline/{code}")
    def kline(
        code: str,
        period: str = "day",
        count: int = 2146,
        anchor: int = 0,
        fuquan: str = "Q",
        market: int = 0,
        channel: str = "auto",
    ) -> list[dict]:
        intraday_period = period in {
            "1min", "5min", "15min", "30min", "60min",
            "1", "5", "15", "30", "60",
        }
        ttl = 2.0 if intraday_period else 15.0
        return _cached(
            ("kline", code, period, count, anchor, fuquan, market, channel),
            ttl,
            lambda client: client.kline(
                code,
                period=period,
                count=count,
                anchor=anchor,
                fuquan=fuquan,
                market=market,
                channel=channel,
            ),
        )

    @app.get("/api/timeline/{code}")
    def timeline(code: str, market: int = 0) -> list[dict]:
        return _call(lambda client: client.timeline(code, market=market))

    @app.get("/api/history_timeline/{code}")
    def history_timeline(
        code: str,
        date: str = Query(..., description="YYYY-MM-DD"),
        market: int = 0,
    ) -> list[dict]:
        return _call(
            lambda client: client.history_timeline(code, date=date, market=market)
        )

    @app.get("/api/auction/{code}")
    def auction(code: str, trade_date: str | None = None, market: int = 0) -> list[dict]:
        return _jsonable(
            _call(
                lambda client: client.auction(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            )
        )

    @app.get("/api/closing_auction/{code}")
    def closing_auction(
        code: str,
        trade_date: str | None = None,
        market: int = 0,
    ) -> list[dict]:
        return _jsonable(
            _call(
                lambda client: client.closing_auction(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            )
        )

    @app.get("/api/intraday/{code}")
    def intraday(code: str, trade_date: str | None = None, market: int = 0) -> list[dict]:
        return _jsonable(
            _cached(
                ("intraday", code, trade_date, market),
                2.0,
                lambda client: client.intraday(
                    code,
                    market=market,
                    trade_date=trade_date,
                ),
            )
        )

    @app.get("/api/intraday_auctions/{code}")
    def intraday_auctions(
        code: str,
        trade_date: str | None = None,
        market: int = 0,
    ) -> list[dict]:
        """Return opening/closing auctions that supplement the fast timeline."""
        return _jsonable(
            _call(
                lambda client: client.intraday_auctions(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
            )
        )

    @app.get("/api/market_view_fast/{code}")
    def market_view_fast(
        code: str,
        levels: int = 5,
        market: int = 0,
    ) -> dict:
        """Return first-paint quote and depth without querying intraday data."""
        if levels not in (5, 10):
            raise HTTPException(400, "levels 只能是 5 或 10")

        def operation(client) -> dict:
            resolved_market = market or client._market_for_code(code)
            if levels == 5 and hasattr(client, "market_view_pipeline"):
                quote_row, depth_row = client.market_view_pipeline(
                    code,
                    market=resolved_market,
                )
            else:
                rows = client.list_quotes([code], market=resolved_market)
                quote_row = next(
                    (row for row in rows if str(row.get("code", "")) == code),
                    rows[0] if rows else None,
                )
                depth_row = client.depth_quote(
                    code,
                    market=market,
                    ten_levels=levels == 10,
                )

            return {
                "code": code,
                "quote": quote_row,
                "depth": depth_row,
            }

        return _jsonable(
            _cached(
                ("market_view_fast", code, levels, market),
                1.0,
                operation,
            )
        )

    @app.get("/api/market_view/{code}")
    def market_view(
        code: str,
        period: str = "day",
        count: int = 320,
        anchor: int = 0,
        fuquan: str = "Q",
        levels: int = 5,
        market: int = 0,
        trade_date: str | None = None,
    ) -> dict:
        """Return all data needed by the single-stock screen in one HTTP response.

        MAIN owns quote/depth while the selected market L2 connection owns
        intraday/kline.  Each lane remains sequential (one socket, one reader),
        but the two independent sockets run concurrently.
        """
        if levels not in (5, 10):
            raise HTTPException(400, "levels 只能是 5 或 10")

        def operation(client) -> dict:
            resolved_market = market or client._market_for_code(code)

            def main_lane() -> tuple[dict | None, dict]:
                rows = client.list_quotes([code], market=resolved_market)
                quote_row = next(
                    (row for row in rows if str(row.get("code", "")) == code),
                    rows[0] if rows else None,
                )
                depth_row = client.depth_quote(
                    code,
                    market=market,
                    ten_levels=levels == 10,
                )
                return quote_row, depth_row

            def market_lane() -> tuple[list[dict], list[dict]]:
                intraday_rows = client.intraday(
                    code,
                    market=market,
                    trade_date=trade_date,
                )
                kline_rows = client.kline(
                    code,
                    period=period,
                    count=count,
                    anchor=anchor,
                    fuquan=fuquan,
                    market=market,
                )
                return intraday_rows, kline_rows

            # ContextVars are not automatically copied into ThreadPoolExecutor
            # workers.  Separate copies preserve request-local Server-Timing for
            # both lanes without attempting to enter one Context concurrently.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                main_future = executor.submit(contextvars.copy_context().run, main_lane)
                market_future = executor.submit(
                    contextvars.copy_context().run,
                    market_lane,
                )
                quote_row, depth_row = main_future.result()
                intraday_rows, kline_rows = market_future.result()

            return {
                "code": code,
                "period": period,
                "fuquan": fuquan,
                "quote": quote_row,
                "intraday": intraday_rows,
                "kline": kline_rows,
                "depth": depth_row,
            }

        return _jsonable(_call(operation))

    # ── 全市场 ──
    @app.get("/api/stocks")
    def stocks(with_names: bool = False) -> list[dict]:
        return _call(lambda client: client.stock_list(with_names=with_names))

    @app.get("/api/hot")
    def hot(
        count: int = 29,
        sort_by: int = 199112,
        sort_dir: str = "D",
    ) -> list[dict]:
        return _call(
            lambda client: client.stock_list_hot(
                count=count,
                sort_by=sort_by,
                sort_dir=sort_dir,
            )
        )

    @app.get("/api/market_snapshot")
    def market_snapshot() -> list[dict]:
        return _call(lambda client: client.market_snapshot())

    # ── 板块 ──
    @app.get("/api/boards")
    def boards(category: str | None = None) -> list[dict]:
        result = _call(lambda client: client.list_system_blocks(category=category))
        return [_to_dict(item) for item in result]

    @app.get("/api/board/{code}/constituents")
    def board_constituents(code: str, timeout: float = 45.0) -> list[dict]:
        return _call(
            lambda client: client.board_constituents([code], timeout=timeout)
        )

    @app.get("/api/board/{code}/quotes")
    def board_quotes(code: str, timeout: float = 40.0) -> list[dict]:
        return _call(
            lambda client: client.board_quotes([code], timeout=timeout)
        )

    @app.get("/api/board/{code}/timeline")
    def board_timeline(code: str, date: str | None = None) -> list[dict]:
        return _call(lambda client: client.board_timeline(code, date=date))

    @app.get("/api/board/{code}/auction")
    def board_auction(code: str, date: str | None = None) -> list[dict]:
        return _call(lambda client: client.board_auction(code, date=date))

    # ── 自定义板块 / 自选股 ──
    @app.get("/api/groups")
    def groups() -> list[dict]:
        return [_to_dict(item) for item in _call(lambda client: client.list_groups())]

    # ── 短线精灵（历史，无推送）──
    @app.get("/api/dxjl")
    def dxjl(pages: int = 5, endtime: int | None = None) -> list[dict]:
        """短线精灵历史。endtime=微秒游标（已加载最早一条的时间），不传则从
        当前时刻向前翻；前端上拉翻历史时传游标增量拉取。"""
        return _call(
            lambda client: client.dxjl_history(pages=pages, endtime_us=endtime)
        )

    # ── 前端补充接口（板块分类/热点板块/排序榜/自选/动态板块/最新短线精灵）──
    # app.py 原 8/3 版本未暴露这些最近新增的 client 能力，这里统一补齐薄路由。

    @app.get("/api/board_categories")
    def board_categories() -> list[dict]:
        """板块分类树（行业/概念/地域/同花顺一二级），本地 ini，无需登录。"""
        return _call(lambda client: client.system_block_categories())

    @app.get("/api/hot_boards")
    def hot_boards() -> list[dict]:
        """热点板块全量行情（pageid=12480），codes=None 一次拿全 513 个板块的
        chg_pct/speed_1m/speed_4m/main_inflow/limit_up/up_count/down_count，前端本地排序分页。"""
        return _jsonable(_call(lambda client: client.hot_boards()))

    @app.get("/api/dynamic_plates")
    def dynamic_plates() -> list[dict]:
        """动态板块列表（条件选股，云端快照），含问财语句 question。"""
        return _call(lambda client: client.list_dynamic_plates())

    @app.get("/api/dynamic_plate_refresh")
    def dynamic_plate_refresh(
        name: str = Query(..., description="动态板块名"),
    ) -> dict:
        """按问财语句实时重查动态板块成分股（非云端快照）。"""
        try:
            return _call(lambda client: client.refresh_dynamic_plate(name))
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/groups/{name}")
    def group_detail(name: str, refresh: bool = False) -> dict:
        """单个自定义板块的成分股。"""
        return _to_dict(_call(lambda client: client.get_group(name, refresh=refresh)))

    @app.get("/api/self_stocks")
    def self_stocks() -> dict:
        """自选股（默认自选股分组）。"""
        return _to_dict(_call(lambda client: client.get_self_stocks()))

    @app.get("/api/stocks2")
    def stocks2(refresh: bool = False) -> list[dict]:
        """全市场股票代码表（带磁盘缓存，自然日有效），含 code/name/market。"""
        return _call(
            lambda client: client.stock_list_cached(refresh=refresh, with_names=True)
        )

    @app.get("/api/stock_list_ranked")
    def stock_list_ranked(
        sort_by: int = 199112,
        count: int = 59,
        sort_dir: str = "D",
        with_values: bool = False,
        with_names: bool = False,
    ) -> list[dict]:
        """股票排序榜（自动翻页，59/页）。with_values=True 时返回 dt<N> 数值字段。
        已验证 sort_by：涨幅199112(dt200)/涨速48/换手1968584/量比1771976/
        主力592890/竞价金额68758(dt150)/竞价涨幅68762/封单额265260(dt44)。"""
        return _call(
            lambda client: client.stock_list_hot(
                count=count,
                sort_by=sort_by,
                sort_dir=sort_dir,
                with_values=with_values,
                with_names=with_names,
            )
        )

    @app.get("/api/dde_rank")
    def dde_rank(
        sort_by: int = 592888,
        count: int = 58,
        sort_dir: str = "D",
        with_names: bool = False,
    ) -> list[dict]:
        """DDE 主力资金排行（pageid=10723），每行带 value 数值。"""
        return _call(
            lambda client: client.dde_rank(
                count=count,
                sort_by=sort_by,
                sort_dir=sort_dir,
                with_names=with_names,
            )
        )

    @app.get("/api/dxjl/latest")
    def dxjl_latest() -> list[dict]:
        """短线精灵最新一页（结构化字段），适合前端定时轮询。"""
        return _call(lambda client: client.dxjl_latest())

    return app


__all__ = ["create_app"]
