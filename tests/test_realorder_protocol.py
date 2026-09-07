"""Offline contracts for the extracted 9601 real-order protocol."""

import hashlib
import struct

import thspypc
import thspypc.protocol as protocol
from thspypc.features import realorder_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _field(field_id: int, width: int) -> bytes:
    return struct.pack("<IBBH", field_id, 0, 0, width)


def _ths_divided(mantissa: int, exponent: int = 2) -> bytes:
    encoded = 0x80000000 | (exponent << 28) | mantissa
    return struct.pack("<I", encoded)


def test_realorder_builder_wire_contracts():
    query = realorder_protocol.build_qurealorder_query(
        700001,
        32,
        1_753_680_000_000_000,
    )
    subscription = realorder_protocol.build_subrealorder_query(700002, 16)
    heartbeat = realorder_protocol.build_heartbeat_9601(0x123456)

    # 2026-08-05 抓包对齐：字段顺序改为 maxcount/endtime/datatype/market/accept_ziptype/rettype，
    # 新增 accept_ziptype=snappy（真实客户端 46/46 帧全带）。
    assert len(query) == 234
    assert _sha256(query) == (
        "a9cc3de5d9bacaeb4ec539258ae96ae372434664be8ece98887aa4593e289884"
    )
    assert len(subscription) == 92
    assert _sha256(subscription) == (
        "8105157608b06bbb2a2c9712fce866e75295493d92273fdba3686e0ce8e9f293"
    )
    assert heartbeat == (
        b"\xfd\xfd\xfd\xfd00000005\x09\x12\x34\x56\x07"
    )


def test_datatype_category_contracts():
    assert realorder_protocol.build_category_id(0xD6) == 1074269398
    assert realorder_protocol.build_category_id(0x66) == 133990
    assert realorder_protocol.build_datatype(
        [0xD6, 0xD7],
        volume_min=10000,
        amount_min=5_000_000,
    ) == (
        "1074269398{19[10000~-]|17[5000000~-]},"
        "1074269399{19[10000~-]|17[5000000~-]},"
    )
    standard = realorder_protocol.STANDARD_REALORDER_CATEGORY_IDS
    level2_only = realorder_protocol.LEVEL2_ONLY_REALORDER_CATEGORY_IDS
    all_categories = realorder_protocol.ALL_REALORDER_CATEGORY_IDS

    assert len(standard) == 23
    assert len(level2_only) == 30
    assert len(all_categories) == 53
    assert set(standard).isdisjoint(level2_only)
    assert set(standard) | set(level2_only) == set(all_categories)
    assert realorder_protocol.build_datatype("standard") == (
        ",".join(map(str, standard)) + ","
    )
    assert realorder_protocol.build_datatype("all") == (
        ",".join(map(str, all_categories)) + ","
    )


def test_standard_only_anomaly_names_fall_back_to_byte_map():
    assert realorder_protocol.ANOMALY_BYTE_MAP[0xD3] == "区间放量平"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0xD4] == "单笔冲涨"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0xD5] == "单笔冲跌"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0xAB] == "笼子触涨停"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0xAC] == "笼子触跌停"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0x99] == "涨幅突破"
    assert realorder_protocol.ANOMALY_BYTE_MAP[0x9A] == "跌幅突破"


def test_qurealorder_parser_contract():
    fields = [
        _field(199, 8),
        _field(5, 17),
        _field(61, 4),
        _field(64, 4),
        _field(17, 4),
        _field(18, 4),
    ]
    header_length = 24 + len(fields) * 8
    record = (
        struct.pack("<Q", 1_753_680_000_000_000)
        + b"\x00" + b"000938" + b"\x00" * 10
        + b"\xd6\x00\x00\x00"
        + b"\xff\x32\x32\x00"
        + struct.pack("<I", 5_000_000)
        + _ths_divided(325)
    )
    payload = (
        b"hq1.0\x00\x00\x00"
        + struct.pack("<IIII", header_length, 1, len(fields) - 1, len(record))
        + b"".join(fields)
        + record
    )

    assert realorder_protocol.parse_qurealorder_response(payload, "32") == [
        {
            "时间": 1_753_680_000_000_000,
            "市场": "32",
            "代码": "000938",
            "异动类型": "大笔买入",
            "异动编码": 0xD6,
            "金额": 5_000_000.0,
            "涨跌幅": 3.25,
        }
    ]


def test_push_parser_contract():
    body = (
        b"\x09method=pushrealorder\nmarket=32\n\x00hq1.0\x00\x00\x00"
        + b"!000938"
        + b"\xd6\x0c\x08\x40"
        + b"\xff\x32\x32\x00"
        + b"\x00\x00"
        + struct.pack("<I", 5_000_000)
        + _ths_divided(325)
    )

    records = realorder_protocol.parse_pushrealorder_response(body)

    assert len(records) == 1
    assert records[0]["代码"] == "000938"
    assert records[0]["市场"] == "32"
    assert records[0]["异动类型"] == "大笔买入"
    assert records[0]["异动编码"] == 0xD6


def test_push_parser_prefers_each_record_market_marker():
    def push_record(marker: int, code: str) -> bytes:
        return (
            bytes((marker,))
            + code.encode("ascii")
            + b"\xd6\x0c\x08\x40"
            + b"\xff\x32\x32\x00"
            + b"\x00\x00"
            + struct.pack("<I", 5_000_000)
            + _ths_divided(325)
        )

    body = (
        b"\x09method=pushrealorder\nmarket=16\n\x00hq1.0\x00\x00\x00"
        + push_record(0x21, "000938")
        + push_record(0x11, "600519")
    )

    records = realorder_protocol.parse_pushrealorder_response(body)

    assert [(row["代码"], row["市场"]) for row in records] == [
        ("000938", "32"),
        ("600519", "16"),
    ]


def test_realorder_frame_reader_uses_len_minus_one_contract():
    body = b"realorder"
    wire = b"noise" + b"\xfd\xfd\xfd\xfd00000008" + body

    class SocketBytes:
        def __init__(self, data):
            self.data = bytearray(data)

        def recv(self, size):
            result = bytes(self.data[:size])
            del self.data[:size]
            return result

    assert (
        realorder_protocol.read_frame_realorder(SocketBytes(wire))
        == body
    )


# 2026-09-07 dxjl_compare_20260907.pcap 真实推送帧（snappy 压缩），
# 含 5 条 14:11:09 深市异动（含 300145 南方泵业 特大挂卖）。
_SNAPPY_PUSH_FRAME = bytes.fromhex(
    "096d6574686f643d707573687265616c6f726465720a696e737469643d323134"
    "373438333634370a6d61726b65743d33320a726574747970653d687166696c65"
    "0a7a6970747970653d736e617070790a00ea000000b902306871312e30000000"
    "58000000050d04042d0009011020080700c7011d10000800051001140811003d"
    "0510080400400d080413700118080400110d0800120d08385999f27bde5a0600"
    "213030313330390125090150bf0a090000e60000d0f417a05870c5932b0100a0"
    "5a112d143330303134350929010108670b02052d3010b9b2a1c6b5d3908e0000"
    "a85b112d143030323839330127090150a40a0200ff323200809698a000ea32a6"
    "390000a85c112d1033303030331d2d006c0d5a3020a107a0c88475a6ed0000a8"
    "5d112d10303031333305e10901046a0b095a2c30ffd7a22a47ce91ed0300a0"
)


def test_decode_realorder_frame_unwraps_snappy_and_is_idempotent():
    decoded = realorder_protocol.decode_realorder_frame(_SNAPPY_PUSH_FRAME)
    assert decoded.startswith(b"\x09method=pushrealorder")
    assert b"hq1.0" in decoded
    # 已解压帧（载荷直接以 hq1.0 开头）二次解包必须原样返回
    assert realorder_protocol.decode_realorder_frame(decoded) == decoded


def test_decode_realorder_frame_leaves_plain_frames_untouched():
    plain = b"\x09method=pushrealorder\nmarket=32\n\x00hq1.0\x00"
    assert realorder_protocol.decode_realorder_frame(plain) == plain
    # 声明 snappy 但载荷非法时应原样返回（不抛异常）
    broken = b"ziptype=snappy\n\x00\x01\x02\x03\x04garbage"
    assert realorder_protocol.decode_realorder_frame(broken) == broken


def test_parse_pushrealorder_frame_golden_snappy_table():
    records = realorder_protocol.parse_pushrealorder_frame(_SNAPPY_PUSH_FRAME)
    by_code = {row["代码"]: row for row in records}
    assert len(records) == 5
    nanfang = by_code["300145"]
    # 2026-09-07 14:11:09（含亚秒微秒尾巴）；南方泵业 特大挂卖 1387463 元
    assert nanfang["时间"] // 1_000_000 == 1_788_761_469
    assert nanfang["市场"] == "32"
    assert nanfang["异动类型"] == "特大挂卖"
    assert nanfang["金额"] == 1387463.0
    assert nanfang["涨跌幅"] == -1.42
    # 逐条校验字段完整性（回归：压缩字节曾让正则解析整帧丢失/幻造记录）
    assert [(r["代码"], r["异动类型"]) for r in records] == [
        ("001309", "特大被动卖"),
        ("300145", "特大挂卖"),
        ("002893", "远价位垫单"),
        ("300033", "撤特大买"),
        ("001330", "未知0x6a"),
    ]


def test_parse_pushrealorder_frame_falls_back_to_regex_for_legacy_body():
    # 旧格式（未压缩裸记录）帧体：含 hq1.0 字样但不是表格，
    # 必须回退正则路径而不是误判为表格返回空
    legacy = (
        b"\x09method=pushrealorder\nmarket=32\n\x00hq1.0\x00\x00\x00"
        + b"!000938"
        + b"\xd6\x0c\x08\x40"
        + b"\xff\x32\x32\x00"
        + b"\x00\x00"
        + struct.pack("<I", 5_000_000)
        + _ths_divided(325)
    )
    records = realorder_protocol.parse_pushrealorder_frame(legacy)
    assert len(records) == 1
    assert records[0]["代码"] == "000938"
    assert records[0]["异动类型"] == "大笔买入"


def test_hq10_table_market_marker_overrides_frame_market():
    fields = [
        _field(199, 8),
        _field(5, 17),
        _field(61, 4),
        _field(64, 4),
        _field(17, 4),
        _field(18, 4),
    ]
    header_length = 24 + len(fields) * 8

    def record(marker: int, code: str) -> bytes:
        return (
            struct.pack("<Q", 1_753_680_000_000_000)
            + bytes((marker,)) + code.encode("ascii") + b"\x00" * 10
            + b"\xd6\x00\x00\x00"
            + b"\xff\x32\x32\x00"
            + struct.pack("<I", 5_000_000)
            + _ths_divided(325)
        )

    payload = (
        b"hq1.0\x00\x00\x00"
        + struct.pack(
            "<IIII", header_length, 2, len(fields) - 1, len(record(0x21, "0" * 6))
        )
        + b"".join(fields)
        + record(0x21, "000938")
        + record(0x11, "600519")
    )
    body = (
        b"\x09method=pushrealorder\nmarket=48\nziptype=snappy\n\x00"
        + payload
    )
    records = realorder_protocol.parse_pushrealorder_frame(body)
    # 帧头 market=48（板块通道），但记录级 0x21/0x11 标记覆写为深/沪
    assert [(row["代码"], row["市场"]) for row in records] == [
        ("000938", "32"),
        ("600519", "16"),
    ]


def test_protocol_reexports_realorder_contracts():
    for name in realorder_protocol.__all__:
        assert getattr(protocol, name) is getattr(realorder_protocol, name)


def test_package_reexports_historical_realorder_contracts():
    names = (
        "ALL_REALORDER_CATEGORY_IDS",
        "ANOMALY_GROUP_PREFIX",
        "ANOMALY_MAP_DXJL",
        "DXJL_DATATYPE",
        "LEVEL2_ONLY_REALORDER_CATEGORY_IDS",
        "REALORDER_HOST",
        "REALORDER_PORT",
        "SUBREALORDER_MARKETS",
        "STANDARD_REALORDER_CATEGORY_IDS",
        "build_category_id",
        "build_datatype",
        "build_heartbeat_9601",
        "build_qurealorder_query",
        "build_subrealorder_query",
        "parse_pushrealorder_response",
        "parse_qurealorder_response",
        "read_frame_realorder",
    )
    for name in names:
        assert name in thspypc.__all__
        assert getattr(thspypc, name) is getattr(realorder_protocol, name)
