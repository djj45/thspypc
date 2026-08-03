"""Level2 十档盘口：请求构造 + 抓包样本解析回归（2026-08-03）。"""

import hashlib
from pathlib import Path

import pytest

from thspypc.features import quote_protocol

FIXTURES = Path(__file__).parent / "fixtures" / "depth10"


def test_ten_levels_request_extends_five_levels():
    five = quote_protocol.build_depth_quote_query("000001", market=33)
    ten = quote_protocol.build_depth_quote_query(
        "000001",
        market=33,
        ten_levels=True,
    )

    # 默认五档请求字节必须保持不变（既有线上契约）
    assert len(five) == 272
    assert hashlib.sha256(five).hexdigest() == (
        "5b58c503eca5c386d8ccb7e87f69bbb119aa0c6e975cf39ab48061935e3f758f"
    )
    # 十档请求在五档 DataType 基础上追加 dt102-121
    text = ten[23:].decode("gbk", errors="replace")
    for dt in range(102, 122):
        assert f"{dt}," in text
    assert len(ten) > len(five)
    # 十档 DataType 顺序对齐 07-28 抓包：24-35 → 102-121 → 122-125 → 150-157
    assert quote_protocol.DEPTH_QUOTE_DATATYPE_10 == (
        quote_protocol.DEPTH_QUOTE_DATATYPE[:14]
        + list(range(102, 122))
        + quote_protocol.DEPTH_QUOTE_DATATYPE[14:]
    )


def test_depth_ten_builder_matches_capture():
    """十档请求（pageid=4214 单子帧）与 07-28 L2 抓包请求帧逐字节一致。"""
    built = quote_protocol.build_depth_ten_query(
        "000938",
        market=33,
        seq=0x00CB,
    )
    captured = (FIXTURES / "req_000938_4214_ten.bin").read_bytes()
    assert built[12:] == captured


def test_parse_l2_channel_response_real_values():
    """07-28 盘后 L2 通道（szlv2，pageid=4214）响应：十档为真实挂单而非哨兵。"""
    result = quote_protocol.parse_depth_quote_response(
        (FIXTURES / "resp_000938_4214_ten.bin").read_bytes()
    )

    assert result["code"] == "000938"
    buy = result["buy"]
    sell = result["sell"]
    assert len(buy) == 10 and len(sell) == 10
    assert buy[0]["price"] == 41.47 and buy[-1]["price"] == 41.38
    assert sell[0]["price"] == 41.48 and sell[-1]["price"] == 41.57


@pytest.mark.parametrize(
    ("fixture", "code", "buy_first_last", "sell_first_last"),
    [
        ("000938_ten_levels.bin", "000938", (41.47, 41.38), (41.48, 41.57)),
        ("000001_ten_levels.bin", "000001", (11.19, 11.10), (11.20, 11.29)),
    ],
)
def test_parse_ten_levels_from_capture(
    fixture,
    code,
    buy_first_last,
    sell_first_last,
):
    result = quote_protocol.parse_depth_quote_response(
        (FIXTURES / fixture).read_bytes()
    )

    assert result["code"] == code
    buy = result["buy"]
    sell = result["sell"]
    numerals = "一二三四五六七八九十"
    assert [b["level"] for b in buy] == [f"买{numerals[i - 1]}" for i in range(1, 11)]
    assert [s["level"] for s in sell] == [f"卖{numerals[i - 1]}" for i in range(1, 11)]
    assert (buy[0]["price"], buy[-1]["price"]) == buy_first_last
    assert (sell[0]["price"], sell[-1]["price"]) == sell_first_last
    # 十档价格阶梯必须连续（相邻档差价一致）
    buy_diffs = {
        round(buy[i + 1]["price"] - buy[i]["price"], 3) for i in range(9)
    }
    sell_diffs = {
        round(sell[i + 1]["price"] - sell[i]["price"], 3) for i in range(9)
    }
    assert len(buy_diffs) == 1
    assert len(sell_diffs) == 1
    assert "dt102" in result["fields"]
    assert "dt121" in result["fields"]


def test_parse_live_600519_ten_levels_sentinel_tail():
    """活网 600519（盘后）：服务端记录区比 hs 少 1 字节、末字段为
    0xFFFFFFFF 哨兵截尾，解析应补齐哨兵并输出买卖各 10 档。"""
    result = quote_protocol.parse_depth_quote_response(
        (FIXTURES / "600519_ten_levels_live.bin").read_bytes()
    )

    assert result["code"] == "600519"
    assert len(result["buy"]) == 10
    assert len(result["sell"]) == 10
    assert "dt121" in result["fields"]
    # 盘后深层档位为空：六~十档为 0.0；一~五档保留收盘最后盘口
    assert result["sell"][0]["price"] == 1358.98
    assert result["buy"][0]["price"] == 1358.11
    assert result["sell"][-1]["qty"] == 0.0
