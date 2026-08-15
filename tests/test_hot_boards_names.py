"""hot_boards 应从当日名称组缓存补全板块名称（94 页面响应无名称列）。"""

import pytest

from thspypc.client import THSClient


@pytest.fixture
def client():
    return THSClient("offline-user", "offline-password", enable_heartbeat=False)


def test_hot_boards_fills_missing_names(monkeypatch, client):
    monkeypatch.setattr(
        client,
        "_run_default_service",
        lambda capabilities, operation: [
            {"code": "885927", "chg_pct": 0.1},
            {"code": "881101", "name": "已有名称", "chg_pct": -0.2},
            {"code": "999999", "chg_pct": 0.3},
        ],
    )
    monkeypatch.setattr(
        client,
        "fetch_stock_names_full",
        lambda **kwargs: {
            "names": {"885927": "CRO概念", "881101": "种植业与林业"}
        },
    )

    rows = client.hot_boards()

    assert rows[0]["name"] == "CRO概念"
    assert rows[1]["name"] == "已有名称"
    assert "name" not in rows[2]
