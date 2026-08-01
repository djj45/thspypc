"""板块专用通道（fu4 8901）离线回归：login 壳、引导 builders、fu4 解析。"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.features.auth_protocol import (  # noqa: E402
    PC_LEVEL2_LOGIN_PROFILE,
    PC_STANDARD_LOGIN_PROFILE,
    LoginIdentity,
    build_login_body,
)
from thspypc.features.system_blocks_protocol import (  # noqa: E402
    BOARD_CLASSIFY_MARKETS_L2,
    BOARD_CLASSIFY_MARKETS_NORMAL,
    BOARD_MARKET_CODES_L2,
    BOARD_MARKET_CODES_NORMAL,
    PAGEID_BOARD_HISTORY,
    PAGEID_BOARD_LIST,
    PAGEID_BOARD_LIST_L2,
    PAGEID_BOARD_TL,
    build_board_classification_query,
    build_board_market_init,
    build_board_pageid_register,
    build_board_qureal_init,
    build_board_stockname_query,
    build_board_subreal_registration,
)

CAP_MAC64 = "GHRdIuxqLKg7diotlao7dioNtao7diodpQ=="
CAP_PASSPORT64 = "vgYGgAAFzDqigorqU62cDKnbV104BTU6JCFc3BNIs1mSneWw"


def _l2_login() -> bytes:
    return build_login_body(
        CAP_PASSPORT64,
        CAP_MAC64,
        identity=LoginIdentity.BOARD,
        profile=PC_LEVEL2_LOGIN_PROFILE,
    )


def _normal_login() -> bytes:
    return build_login_body(
        CAP_PASSPORT64,
        CAP_MAC64,
        identity=LoginIdentity.BOARD,
        profile=PC_STANDARD_LOGIN_PROFILE,
    )


def test_board_login_l2_no_username_matches_capture():
    """L2 板块 login：无 UserName/Password，suffix=计算 check+09（抓包 aa 09）。"""
    body = _l2_login()
    assert body[:15] == b"\x09\x41\x09\x00" + b"zh_CN.GBK" + b"\xaa\x09"
    text = body.decode("gbk", "replace")
    assert text.startswith("\tA\t\x00zh_CN.GBK�\tAsk=login")
    assert "UserName=" not in text
    assert "Password=" not in text
    assert "VerifyType=1" in text
    assert "Mac64=" in text
    assert "Passport64=" in text
    assert body.endswith(CAP_PASSPORT64.encode())


def test_board_login_normal_manual_matches_capture():
    """普通账号板块 login：__manual + \\r\\n\\n 分隔，suffix=5e 07（抓包字节）。"""
    body = _normal_login()
    assert body[:15] == b"\x09\x41\x09\x00" + b"zh_CN.GBK" + b"\x5e\x07"
    text = body.decode("gbk", "replace")
    assert "UserName=__manual\r\n\nPassword=__manual\r\n\n" in text
    assert "VerifyType=1" in text


def test_board_subreal_registration_matches_capture_l2():
    """L2 subreal 帧（pageid=5716，URS 首帧）与抓包 101B 逐字节一致。"""
    frames = build_board_subreal_registration(level2=True)
    assert len(frames) == 5
    first = frames[0]
    assert len(first) == 101
    text = first.decode("gbk")
    assert text == (
        "\tinstid=2147483647\nmethod=subreal\nmarket=URS\nperiod=0\n"
        "action=change\nclass=URSI\ncodelist= \npageid=5716"
    )
    assert frames[4].decode("gbk").endswith("market=UME\nperiod=0\n"
                                            "action=change\nclass=UMEF\n"
                                            "codelist= \npageid=5716")


def test_board_subreal_registration_normal_has_seven_channels():
    """普通账号 subreal 注册 7 通道（含 UNS/UHI），pageid=392。"""
    frames = build_board_subreal_registration(level2=False)
    assert len(frames) == 7
    assert all("pageid=392" in f.decode("gbk") for f in frames)
    assert "market=UNS" in frames[5].decode("gbk")
    assert "market=UHI" in frames[6].decode("gbk")


def test_board_pageid_register_shape():
    """pageid 注册帧：3 个子帧、sub=0x0002、文本 \\r\\npageid=N\\r\\n。"""
    frame = build_board_pageid_register(level2=True)
    text = frame.decode("gbk", "replace")
    assert text.count("pageid=5716") == 3
    assert "\r\npageid=5716\r\n" in text
    # 长度字段 = len("\r\npageid=5716\r\n") = 15（0x0f）
    assert frame[19:23] == b"\x0f\x00\x00\x00"
    frame_n = build_board_pageid_register(level2=False)
    assert b"pageid=392" in frame_n


def test_board_market_init_header_and_text():
    """MKT_INIT：subtype 0x0001、MarketCode/MarketDate/pageid、长度 len+1。"""
    frame = build_board_market_init(level2=True)
    assert frame[:1] == b"\x09"
    assert frame[1:5] == b"\x00\x16\x00\x00"
    assert frame[7:11] == b"\x12\x00\x01\x00"
    text = frame[23:].decode("gbk", "replace")
    assert text.startswith("C-Language=2052\r\nC-Version=E029.60.20.0031\r\n")
    assert "C-UACS=20120716#208#" in text
    assert f"MarketCode={BOARD_MARKET_CODES_L2}" in text
    assert "MarketDate=96(1552184517);128(-590752822);" in text
    assert "StockLinkVer=^bConfigInfo^B^r^n" in text
    assert text.endswith("\r\npageid=5716\r")
    assert int.from_bytes(frame[19:23], "little") == len(frame) - 23 + 1
    normal = build_board_market_init(level2=False)
    ntext = normal[23:].decode("gbk", "replace")
    assert f"MarketCode={BOARD_MARKET_CODES_NORMAL}" in ntext
    assert ntext.endswith("\r\npageid=392\r")


def test_board_qureal_init_instids_match_capture():
    """qureal-init：L2 从 0xE0000/0xF0000，普通从 0x290000/0x2A0000 递增。"""
    l2 = build_board_qureal_init(level2=True)
    assert len(l2) == 10
    assert l2[0].decode("gbk").startswith("\tinstid=917504\nmarket=URS\n")
    assert l2[1].decode("gbk").startswith("\tinstid=983040\nmethod=qustocklink\n")
    assert l2[9].decode("gbk").startswith("\tinstid=1507328\nmethod=qustocklink\n")
    normal = build_board_qureal_init(level2=False)
    assert normal[0].decode("gbk").startswith("\tinstid=2686976\nmarket=URS\n")
    assert normal[1].decode("gbk").startswith("\tinstid=2752512\nmethod=qustocklink\n")
    for fb in l2:
        assert b"StockLinkVer=^bConfigInfo^B^r^n" in fb or b"stocklinkver=^b" in fb


def test_board_classification_query_matches_capture_bytes():
    """[5],[55] 分类表查询与抓包帧逐字节一致（L2 16 市场 / 普通 4 市场）。"""
    frame = build_board_classification_query(level2=True)
    text = frame.decode("gbk", "replace")
    assert text.startswith("\t\x00\x16\x00\x00\x01\x00\x12\x00\t\x00\x00\x01\x00")
    assert "DataType=[5],[55]\r\n" in text
    for market in BOARD_CLASSIFY_MARKETS_L2:
        assert f"{market}();" in text
    assert text.endswith("\r\nDateTime=0\r\npageid=5716\r")
    assert int.from_bytes(frame[19:23], "little") == len(frame[23:]) + 1
    normal = build_board_classification_query(level2=False)
    ntext = normal.decode("gbk", "replace")
    for market in BOARD_CLASSIFY_MARKETS_NORMAL:
        assert f"{market}();" in ntext
    assert ntext.endswith("\r\npageid=392\r")


def test_board_stockname_query_shapes():
    """StockNameVer：L2 双子帧 subtype 0x001C；普通 upstockname（无尾随换行）。"""
    l2 = build_board_stockname_query(level2=True)
    text = l2.decode("gbk", "replace")
    assert "\r\npageid=5716\r\n" in text
    assert f"MarketCode={BOARD_MARKET_CODES_L2}" in text
    assert "StockNameVer=;;" in text
    assert text.endswith("\r\npageid=5716\r")
    normal = build_board_stockname_query(level2=False)
    ntext = normal.decode("gbk", "replace")
    assert ntext == (
        "\tinstid=65536\nmethod=upstockname\nmarket=URS\nStockNameVer=;;\n"
        "prototype=kvproto\npageid=392"
    )


def test_resolve_fu4_hosts_parses_m_hqdns(monkeypatch):
    """fu4 域名从 M_hqdns 解析（与 MAIN/shlv2 分组隔离）。"""
    from thspypc.protocol import resolve_fu4_hosts

    passport = (
        b"userclass=30002|level2=16;32;48|"
        b"M_hqdns=main.123ths.com:8901:16;144;:,"
        b"shlv2.123ths.com:8901:16;144;:,"
        b"fu4.123ths.com:8901:96;128;88;URS;UCT;UNX;UCX;UME;216;48;:,"
        b"ifindhq.123ths.com:8901:232;120;104;56;:"
    )

    def fake_resolve(domain):
        if domain == "fu4.123ths.com":
            return ("fu4.123ths.com", [], ["106.15.249.238", "122.9.78.232"])
        if domain == "main.123ths.com":
            return ("main.123ths.com", [], ["8.134.116.126"])
        raise OSError(domain)

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_resolve)
    ips = resolve_fu4_hosts(passport)
    assert ips == ["106.15.249.238", "122.9.78.232"]


def test_resolve_fu4_hosts_empty_without_domain(monkeypatch):
    from thspypc.protocol import resolve_fu4_hosts

    monkeypatch.setattr(
        socket,
        "gethostbyname_ex",
        lambda domain: ("main.123ths.com", [], ["8.134.116.126"]),
    )
    assert resolve_fu4_hosts(b"M_hqdns=main.123ths.com:8901:16;144;:") == []


def test_board_pageids_by_account():
    """板块查询 pageid 家族：L2=5716/6000/6002，普通=392/4180/4181。"""
    from thspypc.features.system_blocks_protocol import (
        PAGEID_BOARD_HISTORY_L2,
        PAGEID_BOARD_TL_L2,
    )

    assert PAGEID_BOARD_LIST_L2 == 5716
    assert PAGEID_BOARD_TL_L2 == 6000
    assert PAGEID_BOARD_HISTORY_L2 == 6002
    assert PAGEID_BOARD_LIST == 392
    assert PAGEID_BOARD_TL == 4180
    assert PAGEID_BOARD_HISTORY == 4181
