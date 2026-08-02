"""板块指数全量行情：请求构造 + 三表合并解析（2026-08-02 抓包回归）。

样本来源：``captures_live/system_blocks_20260802_002725.pcap``（普通账号），
UI 对照值由用户 2026-08-02 客户端核对：

- 885998：涨幅 +4.24%、1分钟涨速 -0.04%、4分钟涨速 -0.05%、主力 +27.78亿
- 886068：涨幅 +8.10%、1分钟涨速 -0.04%、4分钟涨速 -0.04%、主力 +44.48亿
- 886112（新板块）：涨幅 +2.07%、1分钟涨速 -0.06%、4分钟涨速/主力显示“-”
"""

from pathlib import Path

import pytest

from thspypc._transport import ConnectionManager, ConnectionRole
from thspypc.features.system_blocks_protocol import (
    build_board_full_list_query,
    build_board_list_query,
    load_board_full_codes,
    parse_board_full_quote_response,
)
from thspypc.models import AccountKind, AccountProfile, Capability, Support
from thspypc.services.system_blocks import BoardService

FIXTURES = Path(__file__).parent / "fixtures" / "board"


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _manager(kind, sock):
    capabilities = {Capability.BASIC_QUOTE: Support.YES}
    profile = AccountProfile(kind=kind, capabilities=capabilities)
    return ConnectionManager(profile, lambda _spec: sock)


def _codes():
    return list(load_board_full_codes())


def _by_code(records):
    return {r["code"]: r for r in records}


def test_full_codes_universe():
    codes = _codes()
    assert len(codes) == 513
    assert len(set(codes)) == 513
    assert codes[0] == "881101"
    assert codes[-1] == "886112"
    assert "527527" not in codes


def test_build_full_request_normal_matches_capture():
    built = build_board_full_list_query(_codes(), level2=False)
    captured = (FIXTURES / "full_req_392.bin").read_bytes()
    assert built[12:] == captured  # 去掉 FDF 封帧头后逐字节一致
    text = built[23:].decode("gbk", errors="replace")
    assert "DataType=527527," in text
    assert "DateTime=8192(-2-0)" in text
    assert "pageid=392" in text


def test_build_full_request_l2_matches_capture():
    built = build_board_full_list_query(_codes(), level2=True)
    captured = (FIXTURES / "full_req_5716.bin").read_bytes()
    assert built[12:] == captured
    text = built[23:].decode("gbk", errors="replace")
    assert "pageid=5716" in text


def test_build_list_request_normal_matches_capture():
    """板块列表查询（前缀=可见页 52 码，查询=完整 universe）逐字节对齐抓包。

    2026-08-02 起服务端对旧路由（0x0039/0x0139）静默不回复；本样本为
    ``system_blocks_20260802_002725.pcap`` 流 3 的真实客户端请求（route
    0x006C/0x016C、seq=0x01C4、无 history flag、LackTime 全 0）。
    """
    codes = _codes()
    built = build_board_list_query(
        codes[:52], level2=False, universe_codes=codes
    )
    captured = (FIXTURES / "list_req_392.bin").read_bytes()
    assert built[12:] == captured
    text = built[23:].decode("gbk", errors="replace")
    assert "DataType=48,592890,10,6,66," in text
    assert "LackTime=0,0,0,0,0,0,0,0" in text


def test_parse_full_quote_base_and_main_inflow():
    """0x20 帧（含 0x1c/11B 主力金额表）解析。"""
    records = parse_board_full_quote_response(
        (FIXTURES / "full_resp_0x20.bin").read_bytes()
    )
    by_code = _by_code(records)
    assert len(by_code) == 513
    assert by_code["885998"]["chg_pct"] == pytest.approx(4.2427, abs=0.01)
    assert by_code["885998"]["speed_4m"] == pytest.approx(-0.045, abs=0.002)
    assert by_code["885998"]["main_inflow"] == pytest.approx(
        2_777_553_000, rel=1e-6
    )
    assert by_code["886068"]["chg_pct"] == pytest.approx(8.1041, abs=0.01)
    assert by_code["886068"]["speed_4m"] == pytest.approx(-0.040, abs=0.002)
    assert by_code["886068"]["main_inflow"] == pytest.approx(
        4_448_409_400, rel=1e-6
    )
    # 新板块 886112：涨幅由 dt10/dt6 计算；4分钟涨速/主力金额为哨兵 -> None
    new = by_code["886112"]
    assert new["chg_pct"] == pytest.approx(2.0658, abs=0.01)
    assert new["speed_4m"] is None
    assert new["main_inflow"] is None


def test_parse_full_quote_speed_1m():
    """0x22 帧（每板块 3 行，1分钟涨速取 bar 最大行）解析。"""
    records = parse_board_full_quote_response(
        (FIXTURES / "full_resp_22.bin").read_bytes()
    )
    by_code = _by_code(records)
    assert len(by_code) == 513
    assert by_code["885998"]["speed_1m"] == pytest.approx(-0.0407, abs=0.001)
    assert by_code["886068"]["speed_1m"] == pytest.approx(-0.0396, abs=0.001)
    assert by_code["886112"]["speed_1m"] == pytest.approx(-0.0622, abs=0.001)


def test_merge_across_frames():
    merged = {}
    for name in ("full_resp_0x20.bin", "full_resp_22.bin"):
        for rec in parse_board_full_quote_response(
            (FIXTURES / name).read_bytes()
        ):
            target = merged.setdefault(rec["code"], {})
            for key, value in rec.items():
                if key not in target or target[key] is None:
                    target[key] = value
    assert len(merged) == 513
    r = merged["885998"]
    assert r["chg_pct"] == pytest.approx(4.2427, abs=0.01)
    assert r["speed_4m"] == pytest.approx(-0.045, abs=0.002)
    assert r["speed_1m"] == pytest.approx(-0.0407, abs=0.001)
    assert r["main_inflow"] == pytest.approx(2_777_553_000, rel=1e-6)
    new = merged["886112"]
    assert new["chg_pct"] == pytest.approx(2.0658, abs=0.01)
    assert new["speed_4m"] is None
    assert new["main_inflow"] is None
    assert new["speed_1m"] == pytest.approx(-0.0622, abs=0.001)


def test_service_accumulates_frames_until_complete():
    """服务层双请求 + 跨帧累积：列表订阅帧 + 0x22 帧后三类字段收齐即返回。"""
    sock = FakeSocket()
    frames = [
        (FIXTURES / "full_resp_0x20.bin").read_bytes(),
        (FIXTURES / "full_resp_22.bin").read_bytes(),
    ]
    service = BoardService(
        _manager(AccountKind.STANDARD, sock),
        frame_reader=lambda _sock: frames.pop(0) if frames else b"",
        max_frames=10,
    )
    codes = _codes()
    list_request = build_board_list_query(codes, level2=False)
    full_request = build_board_full_list_query(codes, level2=False)
    records = service._request_full_quotes(
        (list_request, full_request), codes, timeout=5.0
    )

    by_code = _by_code(records)
    assert len(by_code) == 513
    r = by_code["885998"]
    assert r["chg_pct"] == pytest.approx(4.2427, abs=0.01)
    assert r["speed_1m"] == pytest.approx(-0.0407, abs=0.001)
    assert r["main_inflow"] == pytest.approx(2_777_553_000, rel=1e-6)
    new = by_code["886112"]
    assert new["speed_4m"] is None
    assert new["main_inflow"] is None
    assert new["speed_1m"] == pytest.approx(-0.0622, abs=0.001)
    assert len(sock.sent) == 2
    assert list_request in sock.sent[0]
    assert full_request in sock.sent[1]


def test_service_explicit_codes_parses_compact_table_and_filters():
    """显式 codes 的 board_quotes：服务端 08-02 起回 0x20 紧凑表而非 0x130。

    请求与真实客户端同形（前缀=请求码，查询=完整 universe），返回仅保留
    请求的 codes（紧凑表无名称列）。
    """
    sock = FakeSocket()
    response = (FIXTURES / "full_resp_0x20.bin").read_bytes()
    service = BoardService(
        _manager(AccountKind.STANDARD, sock),
        frame_reader=lambda _sock: response,
        max_frames=2,
    )

    records = service.board_quotes(["885998", "886112"], timeout=5.0)

    assert [r.get("code") for r in records] == ["885998", "886112"]
    assert records[0]["dt10"] > 0
    assert records[1]["dt10"] > 0
    sent = b"".join(sock.sent)
    assert b"CodeList=48(885998,886112,);\r\npageid=392\r\n" in sent
    assert b"DataType=527527" not in sent
