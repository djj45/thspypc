"""Web API 服务层离线契约（FastAPI 路由 + 错误映射，不联网）。"""

import concurrent.futures
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

    def connect(self):
        self.calls.append(("connect",))
        self.is_connected = True
        return _Result()

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

    def intraday(self, code, market=0, trade_date=None):
        self.calls.append(("intraday", code, market, trade_date))
        return []

    def intraday_auctions(self, code, market=0, trade_date=None):
        self.calls.append(("intraday_auctions", code, market, trade_date))
        return [{"phase": "opening_auction", "dt10": 12.2}]

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
