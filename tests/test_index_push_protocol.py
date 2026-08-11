"""看盘界面指数实时推送解析的离线契约测试。

用 2026-08-05 盘中抓包提取的真实帧验证 ``parse_index_push``：
- 深市 399001（``captures_live/kanpan_push_20260805_132347.pcap``）
- 沪市 1A0001 / 1B0680 / 北证 899050（``captures_live/index_push_20260805_140642.pcapng``）

字段偏移表见 ``features/index_push_protocol.py`` 模块文档。
字段定义：dt6=昨收 dt7=开盘 dt10=最新 dt19=成交额 dt66=涨跌幅。
"""

import struct

import thspypc.protocol as protocol
from thspypc.features import index_push_protocol


# ── 真实帧（盘中抓包逐字节提取）──

# 399001 深证成指（深市帧：代码@22，价格区@48，dt19@76）
REAL_399001_HEX = (
    "097bd00f7f7c00a006534b11ed8a8083818080808120"
    "333939303031c9eed6a4b3c9d6b80000000000000000"
    "000000000fe1d3b02334d0b019f7d8b02334d0b0b8e7d"
    "8b0ffffffff44e408339f3d4246e840bf0300000000ac"
    "6f8c3166626531740b0000cc0700003503000084be28"
    "2447242e26b70000000dfbffff01000000ffffffffb0"
    "598c00ffffffff310900a09eaba962c6fd446282b071"
    "31630a29253e000000000000000000000091f09935df"
    "1d9037e9d1cfb03f39e6b0c68bcd31e2c1ef30590b3c"
    "25e98cc524bd6b51412e5828417616df2365c32324fb"
    "b908415a6d15419154a5228bc89d222ca1a9355d8842"
    "35f2e32122f140522274c299344d5eec341c16f72424"
    "c40b25cf5ef9404529f4400b9d0925b6f34225d5a7ed"
    "403836024113d2ef400a3feb406a050000d9050000ac"
    "763943b3cb5642900000b07d"
)

# 1A0001 上证指数（沪市帧：代码@33，价格区@39，dt19@63）
REAL_1A0001_HEX = (
    "097bd00f7f7c009006534b25f5b48083818080808102"
    "947dffbffeffffffff3f1031413030303114d505a048"
    "d205a058ed05a048d205a0e7e805a05233df325be5ff"
    "45007d69030000000066646431adda69312f090000b1"
    "0400005004000020"
    "53ca238575002678000000adf0ffff0100000030fca5"
    "00410c00a0c23a106434459b632f75773165d92d2637"
    "000000020000000000000086b45b345b1ab8363f6639"
    "b0eda33db05623cd3134a4063167ded6247d5f1b2511"
    "9a4041b9d41c41a46b13248ee2ba2319c7ff40f14af6"
    "405e4f6e226d6baf2232b3b2354b947135a90b362230"
    "d61222fcf3aa3422b2c5345cf4752447860125bc78fc"
    "40fc1f0641f9712a255e28bb243ddcfa4061fd094184"
    "a8eb371907d540a5040000630400005bbcfd423fce53"
    "426d0000b8c4857d"
)

# 899050 北证50（紧凑帧：代码@29，字段相对代码偏移 +6/+10/+14/+30/+34）
REAL_899050_HEX = (
    "097bd00f7f7c019006534b25f3b48183818080808100"
    "c841c38f3c0890383939303530280311b0d65573147a"
    "72ff304d010000030100003d000000df710a0105dcd0"
    "00b4000000c04e0500d53ed14446dec4420c984b11e3"
    "a6d910f10000b855207d"
)

# 2026-08-11 09:15 集合竞价真实帧。竞价帧中的参考价近乎静态，不能当成
# pageid=6240 Auction.newprice；完整字段结论见 HANDOFF_INDEX_AUCTION_PUSH_20260811。
REAL_AUCTION_1A0001_HEX = (
    "097bd00f7f7c00900653696f97b48083818080808101fc7df717fee7ffffff3f10314130303031730d06a0000000000000000000000000510d06a00000000000000000000000000000000000000000310900008e0000008f000000f0b7c6131dfaed1200000000d00c00a069c02464a6f8b0636b4040036b404003000000000000000000000000f7b67e22b13526216b4040036b404003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000b8ab6a"
)

REAL_AUCTION_399001_HEX = (
    "097bd00f7f7c00a00653696fc1b480838180808081028007f717fee7ffffff3f20333939303031c9eed6a4b3c9d6b8000000000000000000000000a175dab00000000000000000000000000000000000000000760b00003804000008040000ca7a2113764b1a1100000000830900a0a4b7b56234294e62bdf70321bdf703210000000000000000000000000000000000000000bdf70321bdf70321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e7c"
)

REAL_AUCTION_899050_HEX = (
    "097bd00f7f7c01900653696f99b48183818080808100e047c30f3d0890383939"
    "303530b1b1d6a4353000ffffffffffffffffffffffffff3b2211b03b2211b000"
    "000000000000004e010000390000003a00000046021f00bc341c00edffffffcb"
    "a27a226d020d34333ece429867bc0161289d0100000000f384"
)


def test_parse_sz_index_399001():
    """深市 399001 深证成指：代码/名称/dt6/dt7/dt10/高/低/成交额。

    真实帧（2026-08-05 13:23 抓包）：prevclose=13885.711(off48), price=14215.096(off64)。
    """
    body = bytes.fromhex(REAL_399001_HEX)
    result = index_push_protocol.parse_index_push(body)
    assert result is not None
    assert result["code"] == "399001"
    assert result["name"] == "深证成指"
    # dt6 昨收（off=48，固定）
    assert result["prevclose"] == 13885.711
    # dt7 开盘（off=52，固定）
    assert result["open"] == 13644.835
    # dt10 最新价（off=64，盘中变化）
    assert result["price"] == 14215.096
    # 成交额（off=76）——深市全天
    assert result["amount"] == 1050044470000.0


def test_parse_sh_index_1a0001():
    """沪市 1A0001 上证指数：代码@33/dt6@39/dt10@55/dt19@63。

    真实帧（2026-08-05 14:06 抓包）：prevclose=3822.28, price=3873.03,
    成交额=10066亿（上证全天~1万亿）。
    """
    body = bytes.fromhex(REAL_1A0001_HEX)
    result = index_push_protocol.parse_index_push(body)
    assert result is not None
    assert result["code"] == "1A0001"
    assert result["name"] == "上证指数"
    # dt6 昨收（off=39）
    assert result["prevclose"] == 3822.28
    # dt7 开盘（off=43）
    assert result["open"] == 3815.12
    # dt10 最新（off=55）
    assert result["price"] == 3873.03
    # 高/低
    assert result["high"] == 3884.4
    assert result["low"] == 3815.12
    # dt19 成交额（off=63）——上证全天~1万亿
    assert result["amount"] == 1006564750000.0


def test_change_pct_sz():
    """深市涨跌幅：(dt10 - dt6) / dt6 * 100。"""
    body = bytes.fromhex(REAL_399001_HEX)
    result = index_push_protocol.parse_index_push(body)
    # (14215.096 - 13885.711) / 13885.711 * 100 ≈ 2.37
    assert abs(result["change_pct"] - 2.37) < 0.01


def test_change_pct_sh():
    """沪市涨跌幅：(3873.03 - 3822.28) / 3822.28 * 100 ≈ 1.33。"""
    body = bytes.fromhex(REAL_1A0001_HEX)
    result = index_push_protocol.parse_index_push(body)
    assert abs(result["change_pct"] - 1.33) < 0.01


def test_parse_bj_index_899050():
    """北证50 紧凑帧：代码@29，字段相对代码偏移 +6(dt10)/+10(dt13)/+14(dt19)。

    真实帧（2026-08-05 14:06 抓包）：dt10=1114.920, dt19=16740986000(167亿)。
    与分时响应交叉验证逐字节吻合。北证50 紧凑帧无 dt6/dt7/高/低（需分时响应）。
    """
    body = bytes.fromhex(REAL_899050_HEX)
    assert len(body) == 98
    result = index_push_protocol.parse_index_push(body)
    assert result is not None
    assert result["code"] == "899050"
    assert result["name"] == "北证50"
    # dt10 最新点位（code+6 = body 35）
    assert result["price"] == 1114.92
    # dt19 累计额（code+14 = body 43）——北证50 成交额
    assert result["amount"] == 16740986000.0
    # dt13 累计量（code+10 = body 39）
    assert result["volume"] == 746674780.0


def test_parse_sh_index_auction_does_not_mislabel_reference_as_price():
    body = bytes.fromhex(REAL_AUCTION_1A0001_HEX)
    assert len(body) == 277

    result = index_push_protocol.parse_index_push(body)

    assert result == {
        "code": "1A0001",
        "name": "上证指数",
        "phase": "auction",
        "reference_price": 3966.59,
        "secondary_reference_price": 3966.25,
    }
    assert "price" not in result


def test_parse_sz_index_auction_uses_code_at_33_not_continuous_market_flag():
    body = bytes.fromhex(REAL_AUCTION_399001_HEX)
    assert len(body) == 281

    result = index_push_protocol.parse_index_push(body)

    assert result == {
        "code": "399001",
        "name": "深证成指",
        "phase": "auction",
        "reference_price": 14316.961,
    }
    assert "price" not in result


def test_parse_bj_index_auction_121b_uses_shifted_reference_price():
    body = bytes.fromhex(REAL_AUCTION_899050_HEX)
    assert len(body) == 121

    result = index_push_protocol.parse_index_push(body)

    assert result == {
        "code": "899050",
        "name": "北证50",
        "phase": "auction",
        "reference_price": 1122.875,
    }


def test_is_index_push_and_reject():
    """is_index_push 识别 magic；非指数帧/短帧返回 None。"""
    body = bytes.fromhex(REAL_399001_HEX)
    assert index_push_protocol.is_index_push(body)
    # 非 magic 帧
    assert not index_push_protocol.is_index_push(b"\x09\x00\x16" + b"\x00" * 50)
    # 太短
    assert index_push_protocol.parse_index_push(b"\x09\x7b\xd0\x0f" + b"\x00" * 50) is None
    # 标志不匹配（非深市/沪市）
    other = bytearray(body)
    other[14:22] = b"\x82\x83\x81\x80\x80\x80\x81\x04"
    assert index_push_protocol.parse_index_push(bytes(other)) is None


def test_sh_code_format():
    """沪市代码格式：数字+字母+数字（1A0001/1B0680），不是纯字母开头。"""
    body = bytes.fromhex(REAL_1A0001_HEX)
    result = index_push_protocol.parse_index_push(body)
    assert result["code"] == "1A0001"  # 数字开头
    # 修改为 1B0680 验证
    other = bytearray(body)
    other[33:39] = b"1B0680"
    result2 = index_push_protocol.parse_index_push(bytes(other))
    assert result2 is not None
    assert result2["code"] == "1B0680"
    assert result2["name"] == "科创50"


def test_protocol_reexport():
    """protocol.py 聚合器导出新函数。"""
    assert hasattr(protocol, "parse_index_push")
    assert hasattr(protocol, "is_index_push")
    assert hasattr(protocol, "INDEX_PUSH_MAGIC")


def test_module_exports():
    """__all__ 覆盖所有公开符号。"""
    for name in (
        "INDEX_PUSH_MAGIC",
        "SH_INDEX_FLAG_PREFIX",
        "SZ_INDEX_FLAG",
        "is_index_push",
        "parse_index_push",
    ):
        assert name in index_push_protocol.__all__
        assert hasattr(index_push_protocol, name)
