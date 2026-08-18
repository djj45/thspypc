"""统一列表字段派生（derive_list_quote_fields）的离线契约。"""

from thspypc.features.quote_protocol import (
    STOCK_QUOTE_FIELDS_DATATYPE,
    derive_list_quote_fields,
)


def test_datatype_covers_required_raw_fields():
    # 派生列只依赖这 6 个 dt 字段（dt5 是代码列本身）
    assert set(STOCK_QUOTE_FIELDS_DATATYPE) >= {5, 6, 7, 10, 17, 19, 48}


def test_derive_fields_computes_pct_and_auction():
    record = {
        "code": "600000",
        "dt6": 10.0,   # 昨收
        "dt7": 10.5,   # 今开（竞价撮合价）
        "dt10": 11.0,  # 最新
        "dt17": 2_000_000.0,  # 竞价量（股）
        "dt19": 123_456_789.0,
        "dt48": -0.55,
    }
    row = derive_list_quote_fields(record)
    assert row["code"] == "600000"
    assert row["chg_pct"] == 10.0          # (11-10)/10
    assert row["auction_chg_pct"] == 5.0   # (10.5-10)/10
    assert row["auction_amount"] == 21_000_000.0  # 竞价量 × 今开
    assert row["amount"] == 123_456_789.0
    assert row["speed_4m"] == -0.55


def test_derive_fields_suspended_stock_yields_none():
    # 停牌：昨收 0 / 字段缺失，派生列必须为 None 而不是除零
    row = derive_list_quote_fields({"code": "000001", "dt6": 0.0, "dt10": 0.0})
    assert row["chg_pct"] is None
    assert row["auction_chg_pct"] is None
    assert row["auction_amount"] is None
    assert row["amount"] is None
    assert row["speed_4m"] is None
