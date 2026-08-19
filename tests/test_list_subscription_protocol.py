from __future__ import annotations

import struct

from thspypc.features.list_subscription_protocol import (
    LIST_MODE_DELTA,
    LIST_MODE_GROUP_3,
    LIST_MODE_QUERY,
    RANKING_LIST_COMMAND,
    RANKING_LIST_DATATYPE,
    RANKING_LIST_PAGEID,
    LIST_SUBTYPE_MANAGE,
    LIST_SUBTYPE_QUERY,
    build_list_subscription_clear,
    build_list_subscription_codes,
    build_list_subscription_delta,
    build_list_subscription_query,
    parse_list_subscription_response,
)


def test_clear_builder_matches_captured_cmd56_body():
    captured_body = bytes.fromhex(
        "090016000000001200020056040000000000000f000000"
        "0d0a7061676569643d313333340d"
    )

    built = build_list_subscription_clear(0x56)

    assert built[12:] == captured_body


def test_delta_builder_bundles_manage_and_query_children():
    built = build_list_subscription_delta(
        0x56,
        add={151: ["920001"]},
        remove={17: ["600000"]},
        query_datatype=[592890, 592888],
        wire_seq=0x125E,
    )
    body = built[12:]

    assert body[0] == 0x09
    first = body[1:23]
    assert first[6:10] == LIST_SUBTYPE_MANAGE
    assert first[10] == 0x56
    assert struct.unpack_from("<I", first, 11)[0] == LIST_MODE_DELTA
    first_size = struct.unpack_from("<I", first, 18)[0]
    first_payload = body[23 : 23 + first_size]
    assert first_payload == (
        b"AddCode=151(920001,);\r\n"
        b"DelCode=17(600000,);\r\n"
        b"pageid=1334\r\n"
    )

    second_start = 23 + first_size
    second = body[second_start : second_start + 22]
    assert second[6:10] == LIST_SUBTYPE_QUERY
    assert second[10] == 0x56
    assert struct.unpack_from("<H", second, 4)[0] == 0x125E
    assert struct.unpack_from("<I", second, 11)[0] == LIST_MODE_QUERY
    second_size = struct.unpack_from("<I", second, 18)[0]
    second_payload = body[second_start + 22 :]
    assert len(second_payload) == second_size - 1
    assert b"DataType=592890,592888,\r\n" in second_payload
    assert second_payload.endswith(b"pageid=1334\r")


def test_standalone_query_uses_wire_seq_and_final_lf_convention():
    built = build_list_subscription_query(
        0x56,
        {151: ["920001", "920002"]},
        [7, 49],
        wire_seq=0x1260,
    )
    body = built[12:]
    header = body[1:23]

    assert struct.unpack_from("<H", header, 4)[0] == 0x1260
    assert header[6:10] == LIST_SUBTYPE_QUERY
    assert header[10] == 0x56
    assert struct.unpack_from("<I", header, 11)[0] == LIST_MODE_QUERY
    assert len(body[23:]) + 1 == struct.unpack_from("<I", header, 18)[0]


def test_parse_captured_delta_ack():
    captured_body = bytes.fromhex(
        "0900160000000012000200560500000000000011000000"
        "11000000436f64654c69737453697a653d33300d0a"
    )

    responses = parse_list_subscription_response(captured_body)

    assert len(responses) == 1
    assert responses[0].command == 0x56
    assert responses[0].mode_raw == LIST_MODE_DELTA
    assert responses[0].subtype == LIST_SUBTYPE_MANAGE
    assert responses[0].code_list_size == 30
    assert responses[0].payload == b"CodeListSize=30\r\n"
    assert responses[0].truncated == 0


def test_parser_skips_server_text_length_even_when_not_declared_size():
    metadata = b"MarketTime=144(58310);\r\n"
    binary = b"hd3.1\x00payload"
    payload = metadata + binary
    header = bytearray(22)
    header[0:4] = b"\x00\x16\x00\x00"
    struct.pack_into("<H", header, 4, 0x125E)
    header[6:10] = LIST_SUBTYPE_QUERY
    header[10] = 0x56
    struct.pack_into("<I", header, 11, 0x10010101)
    struct.pack_into("<I", header, 18, len(payload))
    body = b"\x09" + bytes(header) + struct.pack("<I", len(metadata)) + payload

    responses = parse_list_subscription_response(body)

    assert len(responses) == 1
    assert responses[0].payload == payload
    assert responses[0].wire_seq == 0x125E


def test_codes_builder_preserves_captured_group_mode_without_semantic_guess():
    built = build_list_subscription_codes(
        0x56,
        {33: ["000001", "000002"]},
        mode=LIST_MODE_GROUP_3,
    )
    header = built[13:35]

    assert struct.unpack_from("<I", header, 11)[0] == LIST_MODE_GROUP_3
    assert b"CodeList=33(000001,000002,);" in built


def test_ranking_query_matches_captured_page982_field_shape():
    built = build_list_subscription_query(
        RANKING_LIST_COMMAND,
        {33: ["000020", "000059"]},
        RANKING_LIST_DATATYPE,
        wire_seq=0x12E1,
        pageid=RANKING_LIST_PAGEID,
        datetime="8192(-2-0)",
        lack_time="0,3,0,0,0,0,0,0",
    )

    assert b"DataType=7,14,49,13,127,48," in built
    assert b"DateTime=8192(-2-0)\r\n" in built
    assert b"LackTime=0,3,0,0,0,0,0,0\r\n" in built
    assert b"pageid=982\r" in built
