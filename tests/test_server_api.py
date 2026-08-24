"""Web API 服务层离线契约（FastAPI 路由 + 错误映射，不联网）。"""

import concurrent.futures
from datetime import datetime
import threading
import time

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from thspypc.errors import (  # noqa: E402
    CapabilityUnavailableError,
    ProtocolError,
)
from thspypc.models import Capability  # noqa: E402
from thspypc.server.app import create_app  # noqa: E402
from thspypc.server.runtime import ThsRuntime  # noqa: E402


class _Result:
    def __init__(self, success=True, server="fake:8901", error=""):
        self.success = success
        self.server = server
        self.error = error


class FakeClient:
    def __init__(self):
        self.is_connected = False
        self.calls = []
        self.stream_callback = None

    def connect(self):
        self.calls.append(("connect",))
        self.is_connected = True
        return _Result()

    def _market_for_code(self, code):
        # 与 THSClient._market_for_code 的基础映射一致（测试桩无名称缓存，不做 ST 覆盖）
        if code.startswith(("1A", "1B")):
            return 16
        if code.startswith("39"):
            return 32
        if code.startswith("899"):
            return 144
        if code.startswith(("43", "83", "87", "920")):
            return 151
        return 17 if code.startswith("6") else 33

    def list_quotes(self, codes, market=17):
        self.calls.append(("list_quotes", codes, market))
        return [{"code": code, "market": market} for code in codes]

    def depth_quote(self, code, market=0, ten_levels=False):
        self.calls.append(("depth_quote", code, market, ten_levels))
        return {"code": code, "buy": [], "sell": []}

    def kline(
        self,
        code,
        period="day",
        count=2146,
        anchor=0,
        fuquan="Q",
        market=0,
        channel="auto",
        timeout=12.0,
        retries=3,
        latest=False,
    ):
        self.calls.append(
            ("kline", code, period, count, anchor, fuquan, market, channel)
        )
        return [{"code": code, "time": None}]

    def timeline(self, code, market=0):
        self.calls.append(("timeline", code, market))
        return [{"code": code}]

    def history_timeline(self, code, date, market=0):
        self.calls.append(("history_timeline", code, date, market))
        return [{"code": code, "date": date}]

    def auction(self, code, market=0, trade_date=None):
        self.calls.append(("auction", code, market, trade_date))
        return []

    def closing_auction(self, code, market=0, trade_date=None):
        self.calls.append(("closing_auction", code, market, trade_date))
        return []

    def intraday(
        self,
        code,
        market=0,
        trade_date=None,
        timeout=12.0,
        retries=3,
    ):
        self.calls.append(("intraday", code, market, trade_date))
        return []

    def intraday_auctions(self, code, market=0, trade_date=None):
        self.calls.append(("intraday_auctions", code, market, trade_date))
        return [{"phase": "opening_auction", "dt10": 12.2}]

    def superorder(
        self,
        code,
        start,
        end,
        market=0,
        pageid=4214,
        timeout=25.0,
    ):
        self.calls.append(
            ("superorder", code, start, end, market, pageid, timeout)
        )
        return [
            {
                "code": code,
                "seq": 7508,
                "dt1": int(start.timestamp()),
                "dt56_raw": b"private-wire-bytes",
            }
        ]

    def order_details(
        self,
        code,
        start,
        end,
        market=0,
        timeout=25.0,
    ):
        self.calls.append(
            ("order_details", code, start, end, market, timeout)
        )
        return {
            "code": code,
            "orders": [],
            "sell_cancels": [{"order_id": 11_761_615}],
        }

    def order_queues(self, code, market=0, trade_date=None, timeout=25.0):
        self.calls.append(
            ("order_queues", code, market, trade_date, timeout)
        )
        return {
            "buy": {"side": "buy", "entries": [1200, 800]},
            "sell": {"side": "sell", "entries": [500]},
        }

    def snapshot_replay(
        self,
        code,
        market=0,
        start=None,
        end=None,
        timeout=30.0,
    ):
        self.calls.append(
            ("snapshot_replay", code, market, start, end, timeout)
        )
        return [
            {
                "time": "09:30:00",
                "ts": 1_776_646_200,
                "price": 34.86,
                "dt13": 1000,
                "dt24": 34.85,
                "dt25": 4900,
                "dt30": 34.86,
                "dt31": 100,
            },
            {
                "time": "09:30:03",
                "ts": 1_776_646_203,
                "price": 34.87,
                "dt13": 1200,
                "dt24": 34.86,
                "dt25": 5100,
                "dt30": 34.87,
                "dt31": 200,
            },
        ]

    def market_events_subscribe(self, code, market=0, callback=None):
        self.calls.append(("market_events_subscribe", code, market))
        self.stream_callback = callback
        return True

    def market_events_prepare(self, code, market=0):
        self.calls.append(("market_events_prepare", code, market))
        return market or self._market_for_code(code)

    def market_events_unsubscribe(self, code):
        self.calls.append(("market_events_unsubscribe", code))
        self.stream_callback = None
        return True

    def stock_list(self, with_names=False):
        self.calls.append(("stock_list", with_names))
        return [{"code": "600000"}]

    def stock_list_hot(self, count=29, sort_by=199112, sort_dir="D"):
        self.calls.append(("stock_list_hot", count, sort_by, sort_dir))
        return [{"code": "600519"}]

    def market_snapshot(self):
        self.calls.append(("market_snapshot",))
        return [{"code": "1A0001"}]

    def list_system_blocks(self, category=None):
        self.calls.append(("list_system_blocks", category))
        return [{"block_id": "881121"}]

    def board_constituents(self, codes, timeout=45.0):
        self.calls.append(("board_constituents", codes))
        return [{"code": "688981"}]

    def board_quotes(self, codes, timeout=40.0):
        self.calls.append(("board_quotes", codes))
        return [{"code": codes[0]}]

    def board_timeline(self, code, date=None):
        self.calls.append(("board_timeline", code, date))
        return []

    def board_auction(self, code, date=None):
        self.calls.append(("board_auction", code, date))
        return []

    def list_groups(self):
        self.calls.append(("list_groups",))
        return [{"name": "自选"}]

    def dxjl_history(self, pages=5):
        self.calls.append(("dxjl_history", pages))
        return []


@pytest.fixture()
def env_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        'THS_USERNAME="u"\nTHS_PASSWORD="p"\nTHS_IMEI="i"\n',
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def client_and_app(env_file):
    fake = FakeClient()
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    app = create_app(runtime)
    return fake, TestClient(app)


def test_status_and_connect(client_and_app):
    fake, client = client_and_app

    status = client.get("/api/status").json()
    assert status["connected"] is False
    assert status["heartbeat"] == {
        "enabled": False,
        "mode": "unavailable",
        "lanes": {},
    }

    resp = client.post("/api/connect").json()
    assert resp["success"] is True
    assert fake.calls[0] == ("connect",)


def test_quote_splits_markets(client_and_app):
    fake, client = client_and_app
    resp = client.get("/api/quote", params={"codes": "600519,000938"}).json()

    assert [r["code"] for r in resp] == ["600519", "000938"]
    assert ("list_quotes", ["600519"], 17) in fake.calls
    assert ("list_quotes", ["000938"], 33) in fake.calls


def test_api_reports_request_local_server_timing(client_and_app):
    _, client = client_and_app

    response = client.get("/api/quote", params={"codes": "600519"})

    timing = response.headers["server-timing"]
    assert "total;dur=" in timing
    assert "lifecycle_wait;dur=" in timing
    assert "app;dur=" in timing


def test_depth_ten_levels(client_and_app):
    fake, client = client_and_app
    client.get("/api/depth/600519", params={"levels": 10}).json()
    assert ("depth_quote", "600519", 0, True) in fake.calls

    fake.calls.clear()
    client.get("/api/depth/000938").json()
    assert ("depth_quote", "000938", 0, False) in fake.calls


def test_kline_anchor_passthrough(client_and_app):
    fake, client = client_and_app
    client.get(
        "/api/kline/000938",
        params={"period": "day", "count": 1938, "anchor": 20180727},
    ).json()
    assert (
        "kline", "000938", "day", 1938, 20180727, "Q", 0, "auto"
    ) in fake.calls


def test_kline_empty_result_is_not_cached(env_file):
    class EmptyThenDataClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.kline_calls = 0

        def kline(self, code, **kwargs):
            self.kline_calls += 1
            if self.kline_calls == 1:
                return []
            return [{"code": code, "time": "2026-08-19"}]

    fake = EmptyThenDataClient()
    fake.is_connected = True
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    runtime._connected_once = True
    client = TestClient(create_app(runtime))

    assert client.get("/api/kline/688836").json() == []
    expected = [{"code": "688836", "time": "2026-08-19"}]
    assert client.get("/api/kline/688836").json() == expected
    assert client.get("/api/kline/688836").json() == expected
    assert fake.kline_calls == 2


def test_interactive_routes_bound_protocol_work_below_browser_timeout(env_file):
    seen = {}

    class BoundedFakeClient(FakeClient):
        def kline(self, code, **kwargs):
            seen["kline"] = (
                kwargs["timeout"],
                kwargs["retries"],
                kwargs["latest"],
            )
            return []

        def intraday(self, code, **kwargs):
            seen["intraday"] = (kwargs["timeout"], kwargs["retries"])
            return []

        def market_view_pipeline(self, code, **kwargs):
            seen["market_view_fast"] = kwargs["timeout"]
            return ({"code": code}, {"code": code, "buy": [], "sell": []})

    fake = BoundedFakeClient()
    fake.is_connected = True
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    runtime._connected_once = True
    client = TestClient(create_app(runtime))

    assert client.get("/api/kline/000938").status_code == 200
    assert client.get("/api/intraday/000938").status_code == 200
    assert client.get("/api/market_view_fast/000938").status_code == 200
    assert seen == {
        "kline": (2.0, 0, True),
        "intraday": (2.0, 0),
        "market_view_fast": 2.0,
    }


def test_market_view_returns_four_datasets_and_forwards_options(client_and_app):
    fake, client = client_and_app
    response = client.get(
        "/api/market_view/000938",
        params={"period": "week", "count": 320, "fuquan": "H", "levels": 10},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == "000938"
    assert body["period"] == "week"
    assert body["fuquan"] == "H"
    assert body["quote"] == {"code": "000938", "market": 33}
    assert body["intraday"] == []
    assert body["kline"] == [{"code": "000938", "time": None}]
    assert body["depth"] == {"code": "000938", "buy": [], "sell": []}
    assert ("list_quotes", ["000938"], 33) in fake.calls
    assert ("intraday", "000938", 0, None) in fake.calls
    assert (
        "kline", "000938", "week", 320, 0, "H", 0, "auto"
    ) in fake.calls
    assert ("depth_quote", "000938", 0, True) in fake.calls


def test_market_view_fast_returns_first_paint_datasets(
    client_and_app,
):
    fake, client = client_and_app

    body = client.get("/api/market_view_fast/000938").json()

    assert body == {
        "code": "000938",
        "quote": {"code": "000938", "market": 33},
        "depth": {"code": "000938", "buy": [], "sell": []},
    }
    assert ("list_quotes", ["000938"], 33) in fake.calls
    assert not any(call[0] == "timeline" for call in fake.calls)
    assert ("depth_quote", "000938", 0, False) in fake.calls


def test_market_view_fast_prefers_bounded_pipeline(env_file):
    class PipelineFakeClient(FakeClient):
        def market_view_pipeline(self, code, market=0, timeout=12.0):
            self.calls.append(("market_view_pipeline", code, market))
            return (
                {"code": code, "market": market, "pipeline": True},
                {"code": code, "buy": [], "sell": [], "pipeline": True},
            )

    fake = PipelineFakeClient()
    fake.is_connected = True
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    runtime._connected_once = True
    client = TestClient(create_app(runtime))
    body = client.get("/api/market_view_fast/000938").json()

    assert body["quote"]["pipeline"] is True
    assert body["depth"]["pipeline"] is True
    assert ("market_view_pipeline", "000938", 33) in fake.calls
    assert not any(call[0] == "list_quotes" for call in fake.calls)
    assert not any(call[0] == "depth_quote" for call in fake.calls)


def test_market_view_fast_never_queries_timeline(client_and_app):
    fake, client = client_and_app

    body = client.get("/api/market_view_fast/000938").json()

    assert "intraday" not in body
    assert not any(call[0] == "timeline" for call in fake.calls)


def test_intraday_auctions_endpoint(client_and_app):
    fake, client = client_and_app

    body = client.get("/api/intraday_auctions/600519").json()

    assert body == [{"phase": "opening_auction", "dt10": 12.2}]
    assert ("intraday_auctions", "600519", 0, None) in fake.calls


def test_superorder_reuses_runtime_client_and_forwards_interval(client_and_app):
    fake, client = client_and_app
    start = datetime(2026, 8, 20, 13, 19, 14)
    end = datetime(2026, 8, 20, 13, 19, 37)

    response = client.get(
        "/api/superorder/603334",
        params={
            "start": start.isoformat(),
            "end": end.isoformat(),
            "market": 17,
            "pageid": 4214,
        },
    )

    assert response.status_code == 200
    assert response.json() == [
        {"code": "603334", "seq": 7508, "dt1": int(start.timestamp())}
    ]
    assert (
        "superorder",
        "603334",
        start,
        end,
        17,
        4214,
        25.0,
    ) in fake.calls


def test_superorder_rejects_invalid_interval_without_client_call(client_and_app):
    fake, client = client_and_app

    response = client.get(
        "/api/superorder/603334",
        params={
            "start": "2026-08-20T13:20:00",
            "end": "2026-08-20T13:19:00",
        },
    )

    assert response.status_code == 400
    assert not any(call[0] == "superorder" for call in fake.calls)


def test_order_details_reuses_runtime_client_and_forwards_interval(client_and_app):
    fake, client = client_and_app
    start = datetime(2026, 8, 20, 13, 17, 0)
    end = datetime(2026, 8, 20, 13, 20, 0)

    response = client.get(
        "/api/order-details/603334",
        params={
            "start": start.isoformat(),
            "end": end.isoformat(),
            "market": 17,
        },
    )

    assert response.status_code == 200
    assert response.json()["sell_cancels"] == [{"order_id": 11_761_615}]
    assert (
        "order_details",
        "603334",
        start,
        end,
        17,
        25.0,
    ) in fake.calls


def test_order_details_rejects_invalid_interval_without_client_call(
    client_and_app,
):
    fake, client = client_and_app

    response = client.get(
        "/api/order-details/603334",
        params={
            "start": "2026-08-20T13:20:00",
            "end": "2026-08-20T13:19:00",
        },
    )

    assert response.status_code == 400
    assert not any(call[0] == "order_details" for call in fake.calls)


def test_order_queues_reuses_runtime_client(client_and_app):
    fake, client = client_and_app

    response = client.get(
        "/api/order-queues/603334",
        params={"trade_date": "2026-08-20", "market": 17},
    )

    assert response.status_code == 200
    assert response.json()["buy"]["entries"] == [1200, 800]
    assert (
        "order_queues", "603334", 17, "2026-08-20", 25.0
    ) in fake.calls


def test_superorder_replay_index_and_snapshot_share_cache(client_and_app):
    fake, client = client_and_app

    replay = client.get(
        "/api/superorder-replay/603334",
        params={"trade_date": "2026-08-20", "market": 17},
    )
    snapshot = client.get(
        "/api/superorder-replay/603334/snapshot",
        params={
            "trade_date": "2026-08-20",
            "market": 17,
            "ts": 1_776_646_202,
        },
    )

    assert replay.status_code == 200
    assert replay.json()["count"] == 2
    assert replay.json()["index"][0]["buy1_price"] == 34.85
    assert snapshot.status_code == 200
    assert snapshot.json()["snapshot"]["price"] == 34.87
    assert snapshot.json()["snapshot"]["bids"][0] == {
        "level": 1,
        "price": 34.86,
        "volume": 5100,
    }
    assert sum(call[0] == "snapshot_replay" for call in fake.calls) == 1


def test_current_superorder_replay_rechecks_transient_empty(client_and_app):
    fake, client = client_and_app
    responses = iter(
        [
            [],
            [{"time": "13:01:00", "ts": 1_787_293_260, "price": 34.86}],
        ]
    )

    def replay(*args, **kwargs):
        fake.calls.append(("snapshot_replay", *args))
        return next(responses)

    fake.snapshot_replay = replay

    first = client.get("/api/superorder-replay/603334", params={"market": 17})
    second = client.get("/api/superorder-replay/603334", params={"market": 17})

    assert first.status_code == 200
    assert first.json()["count"] == 1
    assert second.status_code == 200
    assert second.json()["count"] == 1
    assert sum(call[0] == "snapshot_replay" for call in fake.calls) == 2


def test_current_superorder_replay_only_returns_empty_after_recheck(client_and_app):
    fake, client = client_and_app
    responses = iter(
        [
            [],
            [],
            [{"time": "13:01:00", "ts": 1_787_293_260, "price": 34.86}],
        ]
    )

    def replay(*args, **kwargs):
        fake.calls.append(("snapshot_replay", *args))
        return next(responses)

    fake.snapshot_replay = replay

    first = client.get("/api/superorder-replay/603334", params={"market": 17})
    second = client.get("/api/superorder-replay/603334", params={"market": 17})

    assert first.status_code == 200
    assert first.json()["count"] == 0
    assert second.status_code == 200
    assert second.json()["count"] == 1
    assert sum(call[0] == "snapshot_replay" for call in fake.calls) == 3


def test_superorder_window_serially_aggregates_truth(client_and_app):
    fake, client = client_and_app
    start = datetime(2026, 8, 20, 13, 19, 0)
    end = datetime(2026, 8, 20, 13, 20, 0)

    response = client.get(
        "/api/superorder-window/603334",
        params={"start": start.isoformat(), "end": end.isoformat(), "market": 17},
    )

    assert response.status_code == 200
    assert response.json()["trades"][0]["seq"] == 7508
    assert response.json()["details"]["sell_cancels"][0]["order_id"] == 11_761_615
    names = [call[0] for call in fake.calls]
    assert names.index("superorder") < names.index("order_details")


def test_stock_stream_fans_out_shared_client_events(client_and_app):
    fake, client = client_and_app
    client.app.state.runtime._stream_release_delay = 0.0

    with client.websocket_connect(
        "/api/stock-stream/603334?market=17"
    ) as websocket:
        assert websocket.receive_json() == {
            "event": "status",
            "code": "603334",
            "state": "subscribed",
        }
        assert fake.stream_callback is not None
        fake.stream_callback(
            {
                "event": "trade",
                "code": "603334",
                "price": 34.86,
                "volume": 100,
                "time": datetime(2026, 8, 21, 13, 8, 59),
            }
        )
        event = websocket.receive_json()
        assert event["event"] == "trade"
        assert event["time"] == "2026-08-21T13:08:59"

    assert ("market_events_subscribe", "603334", 17) in fake.calls
    deadline = time.monotonic() + 1.0
    while (
        ("market_events_unsubscribe", "603334") not in fake.calls
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert ("market_events_unsubscribe", "603334") in fake.calls


def test_stock_ready_registers_code_before_page_fanout(client_and_app):
    fake, client = client_and_app

    response = client.get("/api/stock-ready/000938")

    assert response.status_code == 200
    assert response.json() == {
        "code": "000938",
        "market": 33,
        "ready": True,
    }
    assert ("market_events_prepare", "000938", 0) in fake.calls


def test_stock_stream_reconnect_grace_reuses_client_subscription(env_file):
    fake = FakeClient()
    fake.is_connected = True
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    runtime._connected_once = True
    runtime._stream_release_delay = 0.05

    first = runtime.subscribe_stock_stream("603334", market=17)
    runtime.unsubscribe_stock_stream("603334", first)
    second = runtime.subscribe_stock_stream("603334", market=17)
    time.sleep(0.08)

    assert sum(call[0] == "market_events_subscribe" for call in fake.calls) == 1
    assert not any(call[0] == "market_events_unsubscribe" for call in fake.calls)

    runtime.unsubscribe_stock_stream("603334", second)
    time.sleep(0.08)
    assert sum(call[0] == "market_events_unsubscribe" for call in fake.calls) == 1


def test_market_view_runs_main_and_market_lanes_concurrently(env_file):
    class LaneFakeClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.lane_barrier = threading.Barrier(2)

        def list_quotes(self, codes, market=17):
            self.lane_barrier.wait(timeout=1.0)
            return super().list_quotes(codes, market)

        def intraday(self, code, market=0, trade_date=None):
            self.lane_barrier.wait(timeout=1.0)
            return super().intraday(code, market, trade_date)

    fake = LaneFakeClient()
    fake.is_connected = True
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    runtime._connected_once = True
    client = TestClient(create_app(runtime))

    assert client.get("/api/market_view/600519").status_code == 200


def test_history_timeline_date(client_and_app):
    fake, client = client_and_app
    resp = client.get(
        "/api/history_timeline/000938",
        params={"date": "2026-07-23"},
    ).json()
    assert resp == [{"code": "000938", "date": "2026-07-23"}]
    assert ("history_timeline", "000938", "2026-07-23", 0) in fake.calls


def test_error_mapping(client_and_app, monkeypatch):
    fake, client = client_and_app

    def boom_kline(*args, **kwargs):
        raise CapabilityUnavailableError(Capability.L2_TIMELINE, "kline")

    monkeypatch.setattr(fake, "kline", boom_kline)
    assert client.get("/api/kline/000938").status_code == 403

    def boom_quote(*args, **kwargs):
        raise ProtocolError("broken")

    monkeypatch.setattr(fake, "list_quotes", boom_quote)
    assert client.get("/api/quote", params={"codes": "000938"}).status_code == 502


def test_empty_codes_rejected(client_and_app):
    _, client = client_and_app
    assert client.get("/api/quote", params={"codes": " , "}).status_code == 400


def test_runtime_serializes_cold_connect_but_not_business_calls(env_file):
    """首次登录只能发生一次，连接就绪后的不同角色业务允许并行。"""

    class ConcurrentFakeClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.connect_count = 0
            self.connect_entered = threading.Event()
            self.allow_connect = threading.Event()

        def connect(self):
            self.connect_count += 1
            self.connect_entered.set()
            assert self.allow_connect.wait(timeout=1.0)
            self.is_connected = True
            return _Result()

    fake = ConcurrentFakeClient()
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    both_operations_entered = threading.Event()
    operation_count = 0
    operation_lock = threading.Lock()

    def operation(_client):
        nonlocal operation_count
        with operation_lock:
            operation_count += 1
            if operation_count == 2:
                both_operations_entered.set()
        assert both_operations_entered.wait(timeout=1.0)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(runtime.call, operation) for _ in range(2)]
        assert fake.connect_entered.wait(timeout=1.0)
        fake.allow_connect.set()
        assert [future.result(timeout=2.0) for future in futures] == [True, True]

    assert fake.connect_count == 1


def test_runtime_background_preheat_runs_once_and_reports_markets(env_file):
    class PreheatFakeClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.preheat_count = 0

        @property
        def observed_account_profile(self):
            class Profile:
                class Kind:
                    value = "level2"

                kind = Kind()

            return Profile()

        def preheat_l2_connections(self):
            self.preheat_count += 1
            return {
                "sh": {"ready": True, "initialized": True},
                "sz": {"ready": True, "initialized": True},
            }

    fake = PreheatFakeClient()
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)

    assert runtime.start_preheat()
    assert not runtime.start_preheat()
    deadline = time.monotonic() + 2.0
    while runtime.status()["preheat"]["state"] == "running":
        assert time.monotonic() < deadline
        time.sleep(0.01)

    status = runtime.status()
    assert status["preheat"]["state"] == "ready"
    assert status["preheat"]["markets"]["sh"]["ready"]
    assert status["preheat"]["markets"]["sz"]["ready"]
    assert fake.preheat_count == 1


def test_preheat_retry_stops_when_foreground_login_succeeds(
    env_file,
    monkeypatch,
):
    """The 30s preheat backoff must not outlive a successful foreground login."""

    class FirstLoginFailsClient(FakeClient):
        def __init__(self):
            super().__init__()
            self.connect_count = 0

        def connect(self):
            self.connect_count += 1
            return _Result(success=False, error="all_hosts_failed")

    fake = FirstLoginFailsClient()
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)
    runtime._client = fake
    sleeps = []

    def foreground_connects(delay):
        sleeps.append(delay)
        runtime._connected_once = True

    monkeypatch.setattr("thspypc.server.runtime.time.sleep", foreground_connects)

    result = runtime._connect_with_retry(fake)

    assert result.success is True
    assert result.error == "already_connected"
    assert fake.connect_count == 1
    assert sleeps == [0.25]


def test_runtime_reconnects_after_transport_failure_marks_main_dead(env_file):
    fake = FakeClient()
    runtime = ThsRuntime(env_path=env_file, client_factory=lambda u, p, i: fake)

    def disconnect(_client):
        fake.is_connected = False
        raise OSError("connection closed")

    with pytest.raises(OSError, match="connection closed"):
        runtime.call(disconnect)

    assert runtime.call(lambda _client: "ok") == "ok"
    assert fake.calls == [("connect",), ("connect",)]
