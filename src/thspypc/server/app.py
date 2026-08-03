"""FastAPI REST 接口（单用户、请求-响应；实时推送待盘中核对后另加 WebSocket）。"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, is_dataclass

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from ..errors import (
    CapabilityUnavailableError,
    ChannelUnavailableError,
    ProtocolError,
    UnsupportedAccountFeatureError,
)
from .runtime import ThsRuntime


def _market_for_code(code: str) -> int:
    """按代码前缀推断市场：6xx/68x=沪 17，其余=深 33（与客户端一致）。"""
    return 17 if code.startswith("6") else 33


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


def create_app(runtime: ThsRuntime | None = None) -> FastAPI:
    runtime = runtime or ThsRuntime()
    app = FastAPI(
        title="thspypc Web API",
        version="0.1.0",
        description="同花顺 PC 协议的单用户 REST 接口（前端 JS 消费）。",
    )
    # 开发期放开跨域，方便本地前端（React/Vue dev server）调试
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.runtime = runtime

    def _call(operation: Callable[[object], object]) -> object:
        try:
            return runtime.call(operation)
        except CapabilityUnavailableError as exc:
            raise HTTPException(403, str(exc))
        except (UnsupportedAccountFeatureError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        except (ChannelUnavailableError, ProtocolError, RuntimeError, OSError) as exc:
            raise HTTPException(502, str(exc))

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
                groups.setdefault(_market_for_code(code), []).append(code)
            merged: list[dict] = []
            for market, batch in groups.items():
                merged.extend(client.list_quotes(batch, market=market))
            return merged

        return _call(operation)

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
        market: int = 0,
    ) -> list[dict]:
        return _call(
            lambda client: client.kline(
                code,
                period=period,
                count=count,
                anchor=anchor,
                market=market,
            )
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
        return _call(
            lambda client: client.auction(
                code,
                market=market,
                trade_date=trade_date,
            )
        )

    @app.get("/api/closing_auction/{code}")
    def closing_auction(
        code: str,
        trade_date: str | None = None,
        market: int = 0,
    ) -> list[dict]:
        return _call(
            lambda client: client.closing_auction(
                code,
                market=market,
                trade_date=trade_date,
            )
        )

    @app.get("/api/intraday/{code}")
    def intraday(code: str, trade_date: str | None = None, market: int = 0) -> list[dict]:
        return _call(
            lambda client: client.intraday(
                code,
                market=market,
                trade_date=trade_date,
            )
        )

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
    def dxjl(pages: int = 5) -> list[dict]:
        return _call(lambda client: client.dxjl_history(pages=pages))

    return app


__all__ = ["create_app"]
