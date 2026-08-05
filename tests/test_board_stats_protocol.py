"""Offline contracts for the 9601 board statistics protocol (statscalc/calcext).

请求构造的 sha256 字节契约对齐 2026-08-05 抓包
（``captures_live/kanpan_unknown_pnopid_r3030_20260805_001601.bin`` statscalc、
``kanpan_unknown_pnopid_r3033_20260805_003538.bin`` calcext）。响应解析用自包含
合成帧（不依赖外部 .bin），结构逐字节复刻抓包。
"""

import hashlib
import struct

import thspypc
import thspypc.protocol as protocol
from thspypc.features import board_stats_protocol


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_statscalc_builder_wire_contract():
    """statscalc 请求体字段顺序逐字节对齐抓包（instid/method/market/codelist/
    datatype/dataclass/interval/rightstype/period/datetime/rettype + \\x00）。"""
    query = board_stats_protocol.build_statscalc_query(
        154009600,
        [
            "881121", "881172", "881270", "885897", "886009",
            "886033", "886042", "886048", "886054", "886084",
            "886111",
        ],
    )
    assert len(query) == 250
    assert _sha256(query) == (
        "c8e178790c636560371a2f3dafcbb05340f51416515f834287a847b253776c0a"
    )
    # 帧封装：\x09 起始，\x00 结束，无二进制子帧头
    assert query[0:1] == b"\x09"
    assert query[-1:] == b"\x00"
    # 字段顺序核对
    text = query[1:-1].decode("gbk")
    assert text.startswith("instid=154009600\nmethod=statscalc\nmarket=48,\n")
    assert "rettype=hdfile" in text
    assert "dataclass=intervalcalc" in text


def test_statscalc_updownlimit_builder():
    """涨跌停统计：datatype=330326,330328 dataclass=updownlimit。"""
    query = board_stats_protocol.build_statscalc_query(
        700002,
        ["881121", "885897"],
        datatype="330326,330328",
        dataclass="updownlimit",
    )
    assert len(query) == 190
    assert _sha256(query) == (
        "2bf94ffffbf4ea579d974a816f08ac5e44c903b4c4c6382f0e60ed65c9916574"
    )
    text = query[1:-1].decode("gbk")
    assert "datatype=330326,330328," in text
    assert "dataclass=updownlimit" in text


def test_calcext_builder_wire_contract():
    """calcext 请求体对齐抓包（instid/method/codelist/datatype/rightstype/rettype
    + \\x00；无 market=/dataclass 等 statscalc 专属字段）。"""
    query = board_stats_protocol.build_calcext_query(69730304, "600030", 17)
    assert len(query) == 103
    assert _sha256(query) == (
        "ff7a778deaf730eacdad826329bf5b2f75bb8b75fe28507a1471d53c419d19cb"
    )
    text = query[1:-1].decode("gbk")
    assert text.startswith("instid=69730304\nmethod=calcext\ncodelist=17(600030,);\n")
    assert text.endswith("rettype=json")
    assert "market=" not in text  # calcext 无 market 字段
    assert "dataclass" not in text


def test_calcext_board_index():
    """calcext 查板块指数（market=48）。"""
    query = board_stats_protocol.build_calcext_query(700001, "881121", 48)
    assert len(query) == 101
    assert _sha256(query) == (
        "8aed0f7c0ae97769fe31f744c2e8df16df9e555c14ba8e2a05e69f105696dda4"
    )


def _build_statscalc_response(record_count=1, code="0881121", date=20160127, value=-3.12):
    """构造一个自包含 statscalc 数据响应（结构逐字节复刻抓包）。"""
    header_text = (
        f"\tinstid=700001\nmethod=statscalc\nmarket=48,\nperiod=0\n"
        f"rettype=hdfile\nidname=330342:20160127至今\n"
    )
    header = header_text.encode("gbk") + b"\x00"
    field_meta = bytes(26)  # 26 字节字段元数据（记录区由计算长度切分）
    records = b""
    for i in range(record_count):
        code_bytes = code.encode("ascii").ljust(8, b"\x00")
        records += code_bytes + b"\x00" * 8 + struct.pack("<I", date) + struct.pack("<f", value)
    header_region = struct.pack("<H", record_count) + field_meta
    payload_body = b"hd1.0\x00" + header_region + records
    payload = struct.pack("<I", len(payload_body)) + payload_body
    return header + payload


def _build_calcext_response(market=17, code="600017", value=8488804730.88):
    """构造一个自包含 calcext JSON 响应（紧凑 JSON，对齐抓包）。"""
    json_text = (
        '{"status_code":0,"status_msg":null,'
        f'"data":[{{"3":{market},"4":"{code}","199359":{value}}}]}}'
    )
    header = b"\tinstid=700002\nmethod=calcext\nrettype=json\n\x00"
    return header + struct.pack("<I", len(json_text)) + json_text.encode("ascii")


def test_parse_statscalc_response():
    """statscalc hd1.0 响应解析：code(前导零)/date/value。"""
    response = _build_statscalc_response(record_count=1)
    records = board_stats_protocol.parse_statscalc_response(response)
    assert records == [{"code": "0881121", "date": 20160127, "value": -3.12}]


def test_parse_statscalc_response_multi_records():
    """多条记录：record_count 由响应头 LE16 决定，record_len 由 payload 计算。"""
    response = _build_statscalc_response(record_count=3)
    records = board_stats_protocol.parse_statscalc_response(response)
    assert len(records) == 3
    assert all(r["code"] == "0881121" for r in records)
    assert all(r["date"] == 20160127 for r in records)


def test_parse_statscalc_metadata_frame_returns_empty():
    """metadata 帧（无 hd1.0，只有 \\x00\\x00...）返回空列表。"""
    empty = (
        b"\tinstid=700001\nmethod=statscalc\nmarket=48,\nperiod=0\n"
        b"rettype=hdfile\nidname=330342:20160127"
        + "至今".encode("gbk") + b"\n\x00\x00\x00\x00\x00"
    )
    assert board_stats_protocol.parse_statscalc_response(empty) == []


def test_parse_calcext_response():
    """calcext JSON 响应解析：market/code/value。"""
    response = _build_calcext_response()
    records = board_stats_protocol.parse_calcext_response(response)
    assert records == [
        {"market": 17, "code": "600017", "value": 8488804730.88}
    ]


def test_parse_calcext_response_board_index():
    """calcext 查板块指数（market=48）。"""
    response = _build_calcext_response(market=48, code="881121", value=12345.6)
    records = board_stats_protocol.parse_calcext_response(response)
    assert records == [{"market": 48, "code": "881121", "value": 12345.6}]


def test_parse_calcext_empty_data():
    """data 为空数组时返回空列表。"""
    json_text = '{"status_code":0,"status_msg":null,"data":[]}'
    response = (
        b"\tinstid=700002\nmethod=calcext\nrettype=json\n\x00"
        + struct.pack("<I", len(json_text)) + json_text.encode("ascii")
    )
    assert board_stats_protocol.parse_calcext_response(response) == []


def test_protocol_reexport():
    """protocol.py 聚合器导出新函数（向后兼容导入面）。"""
    assert hasattr(protocol, "build_statscalc_query")
    assert hasattr(protocol, "build_calcext_query")
    assert hasattr(protocol, "parse_statscalc_response")
    assert hasattr(protocol, "parse_calcext_response")
    assert hasattr(protocol, "STATSCALC_HOST")
    assert hasattr(protocol, "STATSCALC_PORT")
    assert protocol.STATSCALC_HOST == "8.132.233.77"
    assert protocol.STATSCALC_PORT == 9601


def test_module_exports():
    """__all__ 覆盖所有公开符号。"""
    for name in (
        "build_statscalc_query",
        "build_calcext_query",
        "parse_statscalc_response",
        "parse_calcext_response",
        "read_frame_board_stats",
        "STATSCALC_HOST",
        "STATSCALC_PORT",
        "DATATYPE_INTERVAL_STAT",
        "DATATYPE_UPDOWNLIMIT",
        "DATATYPE_MARKETCAP",
    ):
        assert name in board_stats_protocol.__all__, name
        assert hasattr(board_stats_protocol, name), name


def test_statscalc_host_env_override(monkeypatch):
    """THSPYPC_STATSCALC_HOST 环境变量覆盖默认统计节点 IP。"""
    # 默认值
    import importlib

    monkeypatch.setenv("THSPYPC_STATSCALC_HOST", "1.2.3.4")
    importlib.reload(board_stats_protocol)
    assert board_stats_protocol.STATSCALC_HOST == "1.2.3.4"
    # 恢复默认（清环境变量后 reload）
    monkeypatch.delenv("THSPYPC_STATSCALC_HOST", raising=False)
    importlib.reload(board_stats_protocol)
    assert board_stats_protocol.STATSCALC_HOST == "8.132.233.77"
