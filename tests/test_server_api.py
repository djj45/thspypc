"""Web API 服务层离线契约（FastAPI 路由 + 错误映射，不联网）。"""

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

    def kline(self, code, period="day", count=2146, anchor=0, market=0):
        self.calls.append(("kline", code, period, count, anchor, market))
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
    assert ("kline", "000938", "day", 1938, 20180727, 0) in fake.calls


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
