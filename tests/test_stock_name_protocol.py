"""Wire and corpus contracts for the partial stock-name decoder."""

import hashlib
from pathlib import Path

import pytest

import thspypc.protocol as protocol
from thspypc.features import stock_name_protocol
from thspypc.features.stock_name_protocol import (
    build_stock_name_ver_frame,
    build_upstockname_request,
    decode_name_frame,
)


@pytest.mark.parametrize(
    ("kwargs", "expected_sha"),
    [
        (
            {},
            "58d2726acf585f365c81f7d6bc030a4a725f49b8646f054796308270f11fbef9",
        ),
        (
            {
                "market": "UNX",
                "stock_name_ver": "20260728;1;",
                "pageid": 392,
                "instid": 7,
            },
            "e0aa06146829c9326ce0f11a22c9314fa814c3e01247270dc68bff07781e7eda",
        ),
    ],
)
def test_upstockname_builder_wire_contract(kwargs, expected_sha):
    request = build_upstockname_request(**kwargs)

    assert hashlib.sha256(request).hexdigest() == expected_sha


def test_text_and_nul_terminated_segment_names_are_decoded():
    body = (
        b"[name_96_96]\r\n"
        + "AUDUSD=澳元/美元|AUDUSD@0\r\n".encode("gbk")
        + b"[name_64_64\x00]\x00"
        + "850001=同花顺商品|alias@1\n".encode("gbk")
    )

    result = decode_name_frame(body)

    assert result["names"] == {
        "AUDUSD": "澳元/美元",
        "850001": "同花顺商品",
    }
    assert result["skipped"] == []
    assert [item[0] for item in result["segments"]] == [
        "96_96",
        "64_64",
    ]


def test_history_lines_are_skipped_and_current_name_wins():
    # 同一代码在响应里同时有 ``code=现名|别名@f`` 与历史行
    # ``code=旧名@h1|旧名2@h2|...``；历史行必须跳过，否则历史名会覆盖现名
    # （600664 被 "S哈药" 覆盖、000001 被 "深发展A" 覆盖）。
    body = (
        b"[name_16_16]\r\n"
        + b"ConfigVer=20260807_1\r\n"
        + "600664=哈药股份|哈药股份@f\r\n".encode("gbk")
        + "600664=S哈药@h1|哈药集团@h2|哈医药@h3\r\n".encode("gbk")
        + "000001=平安银行|平安银行@f\r\n".encode("gbk")
        + "000001=深发展A@h1|S深发展A@h2\r\n".encode("gbk")
        + "600519=贵州茅台|贵州茅台@f\r\n".encode("gbk")
    )

    result = decode_name_frame(body)

    assert result["names"] == {
        "600664": "哈药股份",
        "000001": "平安银行",
        "600519": "贵州茅台",
    }
    assert result["skipped"] == []


def test_captured_normal_name_response_prefers_current_over_history():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "upstockname_full_normal_215908.bin"
    )
    if not path.exists():
        pytest.skip("optional captured normal name response is unavailable")

    # fd fd fd fd + 8 位 ASCII hex 长度 + body（body 以 0x0a 开头）
    result = decode_name_frame(path.read_bytes()[12:])

    assert result["names"]["600664"] == "哈药股份"
    assert result["names"]["600403"] == "大有能源"
    assert result["names"]["000001"] == "平安银行"


def test_block_encoded_segment_is_reported_not_guessed():
    body = b"[name_16_16]\x00\xffbroken\x00payload"

    result = decode_name_frame(body)

    assert result["names"] == {}
    assert result["by_segment"] == {}
    assert result["skipped"] == ["16_16"]
    assert result["segments"] == [("16_16", 15, "block")]


def test_st_name_detection_and_market_mapping():
    from thspypc.features.stock_name_protocol import is_st_name, st_market

    # ST/*ST/SST/S*ST 前缀识别
    assert is_st_name("ST长园") is True
    assert is_st_name("*ST闻泰") is True
    assert is_st_name("S*ST生化") is True
    assert is_st_name("SST中华") is True
    assert is_st_name("贵州茅台") is False
    assert is_st_name("平安银行") is False
    assert is_st_name("") is False
    assert is_st_name(None) is False

    # 风险警示股市场码映射：仅沪 17→22，深市无独立市场码（33 不变）
    assert st_market(17) == 22
    assert st_market(33) == 33
    assert st_market(16) == 16
    assert st_market(151) == 151


def test_captured_text_stream_preserves_known_result():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "upstockname_stream37_server.bin"
    )
    if not path.exists():
        pytest.skip("optional captured stock-name text stream is unavailable")

    result = decode_name_frame(path.read_bytes())

    assert len(result["names"]) == 3510
    assert len(result["segments"]) == 22
    assert result["skipped"] == []
    assert "AUDUSD" in result["names"]
    assert result["segments"][0] == ("96_96", 21, "text")
    assert result["segments"][-1] == ("48_49", 47011, "text")


def test_captured_a_share_compressed_stream_decodes_names():
    cipher = (
        Path(__file__).parents[1]
        / "captures_live"
        / "name_dump_20260808_105709"
        / "name16_cipher_mem.bin"
    )
    if not cipher.exists():
        pytest.skip("optional captured A-share compressed stream is unavailable")

    data = cipher.read_bytes()
    frame_header = bytes.fromhex(
        "0016ff0fda49121c013681d991a3260b0f0000"
    )
    body = (
        b"\x0a"
        + (0x00174828).to_bytes(4, "big")
        + frame_header
        + b"MarketCode=16\x00\r\n"
        + data
    )

    result = decode_name_frame(body)

    assert result["names"]["600000"].encode("gbk") == bytes.fromhex("c6d6b7a2d2f8d0d0")
    assert result["names"]["1A0001"].encode("gbk") == bytes.fromhex("c9cfd6a4d6b8cafd")
    # 历史段（第三个 [name_16_16]，块状）现在被显式跳过，不再把历史名当当前名解析。
    assert result["skipped"] == ["16_16"]
    assert len(result["names"]) > 20000


def test_stock_name_groups_metadata():
    from thspypc.features.stock_name_bootstrap import (
        LEVEL2_BOOTSTRAP_FRAMES,
        STOCK_NAME_GROUPS,
        build_group_frames,
        stock_name_group,
    )

    assert build_group_frames("level2_16") == LEVEL2_BOOTSTRAP_FRAMES
    meta = stock_name_group("fu4_96")
    assert meta["domain"] == "fu4.123ths.com"
    assert "48" in meta["markets"]
    assert len(build_group_frames("fu4_96")) == 153
    assert len(build_group_frames("standard_32")) == 102
    assert "level2_32" in STOCK_NAME_GROUPS["level2"]
    assert "standard_32" in STOCK_NAME_GROUPS["standard"]
    assert stock_name_group("standard_32")["domain"] == "main.123ths.com"


def test_stock_name_cache_roundtrip_and_version_value(tmp_path):
    from thspypc.features.stock_name_cache import (
        build_version_value,
        extract_config_vers,
        load_name_cache,
        save_name_cache,
    )

    names = {"600000": "????", "000001": "????"}
    config_vers = {"16_16": "20260807_1", "16_19": "20260807_2"}
    path = tmp_path / "stockname_test_0.txt"
    save_name_cache(names, config_vers, path)

    loaded = load_name_cache(path)
    assert loaded is not None
    loaded_vers, loaded_names = loaded
    assert loaded_vers == config_vers
    assert loaded_names["600000"] == "????"
    assert loaded_names["000001"] == "????"

    value = build_version_value(config_vers, "16;144;208;")
    assert value.count("^bname_16_16^B") == 3
    assert "^r^nConfigVer^e20260807_1^r^n" in value

    frame = b"[name_16_16]\r\nConfigVer=20260807_1\r\n600000=test\r\n"
    assert extract_config_vers(frame) == {"16_16": "20260807_1"}


def test_name_cache_is_fresh(tmp_path):
    from thspypc.features.stock_name_cache import (
        name_cache_is_fresh,
        save_name_cache,
    )

    path = tmp_path / "stockname_test_0.txt"
    save_name_cache({"600000": "浦发银行"}, {"16_16": "20260807_1"}, path)

    assert name_cache_is_fresh(path) is True
    assert name_cache_is_fresh(tmp_path / "missing.txt") is False


def test_stock_name_bootstrap_templates_match_captures(tmp_path):
    import json

    from thspypc.features.stock_name_bootstrap import (
        LEVEL2_BOOTSTRAP_FRAMES,
        LEVEL2_VERSIONED_BOOTSTRAP_FRAMES,
        STANDARD_BOOTSTRAP_FRAMES,
        STOCK_NAME_DOMAINS,
    )

    assert len(LEVEL2_BOOTSTRAP_FRAMES) == 48
    assert len(LEVEL2_VERSIONED_BOOTSTRAP_FRAMES) == 44
    assert len(STANDARD_BOOTSTRAP_FRAMES) == 102
    assert STOCK_NAME_DOMAINS["level2"] == "shlv2.123ths.com"
    assert STOCK_NAME_DOMAINS["standard"] == "main.123ths.com"

    trigger = LEVEL2_BOOTSTRAP_FRAMES[-1]
    assert trigger[:23].hex().startswith("0900160000000012001c")
    assert b"MarketCode=16" in trigger
    assert b"StockNameVer=;;" in trigger

    standard_trigger = STANDARD_BOOTSTRAP_FRAMES[-1]
    assert b"MarketCode=32" in standard_trigger
    assert b"StockNameVer=;;" in standard_trigger

    # Optional byte-for-byte regression against captured templates.
    pairs = [
        ("LEVEL2_BOOTSTRAP_FRAMES", "bootstrap_214435_frames.json", LEVEL2_BOOTSTRAP_FRAMES),
        ("LEVEL2_VERSIONED_BOOTSTRAP_FRAMES", "bootstrap_oldver_222248_frames.json", LEVEL2_VERSIONED_BOOTSTRAP_FRAMES),
        ("STANDARD_BOOTSTRAP_FRAMES", "bootstrap_normal_215908_frames.json", STANDARD_BOOTSTRAP_FRAMES),
    ]
    for name, fname, frames in pairs:
        path = Path(__file__).parents[1] / "captures_live" / fname
        if not path.exists():
            continue
        captured = [
            bytes.fromhex(item)
            for item in json.loads(path.read_text(encoding="utf-8"))
        ]
        assert frames == tuple(captured), name



def test_stock_name_ver_frame_matches_deleted_cache_capture():
    sample = (
        Path(__file__).parents[1]
        / "captures_live"
        / "stockname_ver_deleted_214435.bin"
    )
    if not sample.exists():
        pytest.skip("optional deleted-cache StockNameVer capture is unavailable")

    frame = build_stock_name_ver_frame(
        markets="16;144;208;",
        stock_name_ver=";;",
        pageid=5716,
    )

    assert frame == sample.read_bytes()


def test_captured_a_share_block_stream_stays_explicitly_skipped():
    path = (
        Path(__file__).parents[1]
        / "captures_live"
        / "upstockname_stream35_server.bin"
    )
    if not path.exists():
        pytest.skip("optional captured stock-name block stream is unavailable")

    result = decode_name_frame(path.read_bytes())

    assert result["names"] == {}
    assert result["skipped"] == ["16_16"]
    assert result["segments"] == [("16_16", 942899, "block")]


def test_protocol_facade_reexports_single_name_implementation():
    assert (
        protocol.build_upstockname_request
        is stock_name_protocol.build_upstockname_request
    )
    assert protocol.decode_name_frame is stock_name_protocol.decode_name_frame
