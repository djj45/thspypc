"""北交所超级盘口逐笔窗口协议测试（金样本取自 2026-09-08 L2 账号抓包）。"""

from __future__ import annotations

import pytest

from thspypc.features.superorder_protocol import (
    build_bse_tick_window_query,
    parse_bse_tick_response,
)

# 920118 早盘竞价窗（09:15-09:25）响应：flag=0x003a，7 行逐笔。
GOLDEN_TICK_920118 = bytes.fromhex(
    "fdfdfdfd3030303030303965090016ff0f140112000900fc0100010000081c84000000"
    "000000006864332e3100070000003a0014000500013000040a700004317000041b700"
    "004217000041600010097393230313138000000000000000000070046000000000000"
    "8c090f0135f8f451cf793f2af8e801071cfe803fe00ff8140180efef083a803f804f1"
    "ff007fc0168f003fe1b7ec040c0ef0f047cf0247e7f5beba7216f4b831b04c006"
)


def test_parse_bse_tick_golden():
    rows = parse_bse_tick_response(GOLDEN_TICK_920118[12:])

    assert len(rows) == 7
    assert all(r["code"] == "920118" for r in rows)
    first = rows[0]
    assert first["ts"] == 1788830105
    assert first["price"] == pytest.approx(22.19)
    assert first["volume"] == 100
    assert first["dt27"] == 0
    assert first["dt33"] == 900
    # dt49 累计、volume 差分
    assert rows[1]["dt49"] == 205
    assert rows[1]["volume"] == 105
    assert rows[6]["ts"] == 1788830684


def test_build_bse_tick_window_request_shape():
    frame = build_bse_tick_window_query(
        "920118", start_ts=1788830100, end_ts=1788830700, seq=0x0300
    )
    body = frame[12:]
    assert body[:1] == b"\x09"
    assert b"DateTime=7176(1788830100-1788830700)" in body
    assert b"pageid=10443" in body
    assert body[11:13] == b"\xfc\x01"  # route 0x01fc
    assert body[15:17] == b"\x40\x00"  # flag14=0x0040


# ---------------------------------------------------------------------------
# 6144 历史竞价窗（分时页历史日期 09:15-09:25，pageid=10444/route=0x0100）
# 金样本取自 2026-09-08 日期标定抓包（bse_920083_20260908_161904.pcapng）。
# ---------------------------------------------------------------------------

from pathlib import Path

# 官方 6144 请求（920118，09-04 竞价窗，seq=0x016d）。
OFFICIAL_REQ_6144_0904_BODY = bytes.fromhex(
    "09001600006d011200090000010000000000187d000000436f64654c6973743d31353128"
    "3932303131382c293b0d0a44617461547970653d31302c32372c33332c34392c0d0a4461"
    "746554696d653d3631343428313738383438343530302d31373838343835313030290d0a"
    "4c61636b54696d653d302c302c302c302c302c302c302c300d0a7061676569643d313034"
    "34340d0a"
)


def test_build_bse_auction_window_query_matches_official_frame():
    frame = build_bse_tick_window_query(
        "920118",
        start_ts=1788484500,
        end_ts=1788485100,
        tag=6144,
        pageid=10444,
        seq=0x016D,
        route=0x0100,
        flag14=0x0000,
        byte16=0x00,
        byte17=0x18,
    )
    assert frame[12:] == OFFICIAL_REQ_6144_0904_BODY


def test_build_bse_tick_window_request_header_bytes():
    # 7176 变体：[14:18] = 40 00 08 1c（两次抓包一致）。
    frame = build_bse_tick_window_query(
        "920118", start_ts=1788830100, end_ts=1788830700, seq=0x0106
    )
    body = frame[12:]
    assert body[11:13] == b"\xfc\x01"  # route 0x01fc
    assert body[15:17] == b"\x40\x00"  # flag14=0x0040
    assert body[17:19] == b"\x08\x1c"  # byte16=0x08 byte17=0x1c


def test_parse_bse_auction_golden_covers_dc_high_bits():
    # 09-04 竞价响应：dc=0x0600001c（高 16 位 0x0600 修饰位），28 笔。
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "history_timeline"
        / "bse_920118_20260904_6144.bin"
    ).read_bytes()
    rows = parse_bse_tick_response(fixture)

    assert len(rows) == 28
    assert all(r["code"] == "920118" for r in rows)
    first = rows[0]
    assert first["ts"] == 1788484502  # 09-04 09:15:02
    assert first["price"] == pytest.approx(21.19)
    last = rows[-1]
    assert last["ts"] == 1788485099  # 09-04 09:24:59
    assert last["price"] == pytest.approx(21.6)
