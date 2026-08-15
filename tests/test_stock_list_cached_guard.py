"""stock_list_cached 名称覆盖率守卫：空名称不得污染当日磁盘缓存。"""

import os

import pytest

from thspypc._client.stock_cache import load_stock_codes, save_stock_codes
from thspypc.client import THSClient


@pytest.fixture
def client():
    return THSClient("offline-user", "offline-password", enable_heartbeat=False)


def test_sparse_names_are_not_cached(tmp_path, monkeypatch, client):
    path = str(tmp_path / "codes.json")
    monkeypatch.setattr(
        client,
        "stock_list",
        lambda **kwargs: [
            {"code": "600000", "name": ""},
            {"code": "000001", "name": ""},
        ],
    )
    monkeypatch.setattr(
        client,
        "fetch_stock_names_full",
        lambda **kwargs: {"names": {}},
    )

    stocks = client.stock_list_cached(cache_path=path, with_names=True)

    assert [stock["name"] for stock in stocks] == ["", ""]
    assert not os.path.exists(path), "名称稀疏时不得写盘，避免污染整天缓存"


def test_sparse_disk_cache_self_heals_when_names_ready(
    tmp_path,
    monkeypatch,
    client,
):
    path = str(tmp_path / "codes.json")
    save_stock_codes(
        [
            {"code": "600000", "name": ""},
            {"code": "000001", "name": ""},
        ],
        path,
    )
    monkeypatch.setattr(
        client,
        "fetch_stock_names_full",
        lambda **kwargs: {
            "names": {"600000": "浦发银行", "000001": "平安银行"}
        },
    )

    stocks = client.stock_list_cached(cache_path=path, with_names=True)

    assert [stock["name"] for stock in stocks] == ["浦发银行", "平安银行"]
    healed = load_stock_codes(path)[0]
    assert [stock["name"] for stock in healed] == ["浦发银行", "平安银行"]
