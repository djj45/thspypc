"""Bounded L2 response integrity, independent of archive services."""
import struct

import pytest

from thspypc.features import superorder_protocol as protocol


TRADE_FIELDS = tuple(
    (datatype, 0x70 if datatype in (10, 13, 18) else 0x30, 4)
    for datatype in (1, 56, 10, 13, 12, 74, 75, 18)
)


def table(fields, flag, row_size, rows, *, code="000001", count=None):
    header = b"hd1.0\x00" + struct.pack(
        "<IHHH", len(rows) if count is None else count, flag, row_size, len(fields)
    )
    descriptors = b"".join(bytes((dt, fmt, 0, width)) for dt, fmt, width in fields)
    shell = b"\x16\x00\x01\x00\x21" + code.encode("ascii") + bytes(11)
    return header + descriptors + shell + b"".join(rows)


def compressed_literals(body):
    stream = bytearray(body[:4] + b"\x00")
    for index, offset in enumerate(range(4, len(body), 2)):
        if index % 8 == 7:
            stream.append(0)
        stream.extend(body[offset:offset + 2])
    return b"\x0a" + struct.pack(">I", len(body)) + bytes(stream)


def trades(*, code="000001", count=3):
    rows = [
        struct.pack("<8I", 4000 + index, 1788487200 + index, 0x9000076C,
                    100 * (index + 1), 5, 2000 + index, 3000, 1000 + index)
        for index in range(count)
    ]
    return table(TRADE_FIELDS, 0x46, 32, rows, code=code)


def orders(*, code="000001", count=2, kind_raw=513, volume=400):
    rows = [
        struct.pack("<5I", 16318240 + index, 1788487260 + index,
                    3221344672, volume, kind_raw)
        for index in range(count)
    ]
    return table(protocol._ORDER_DETAIL_FIELDS, 0x3A, 20, rows, code=code)


@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("count", [1, 2, 3])
def test_trade_row_starts_with_its_own_trade_number(compressed, count):
    body = trades(count=count)
    if compressed:
        body = compressed_literals(body)
    result = protocol._market_response_evidence(body, period=7169)
    assert result["recognized"] and result["complete"]
    assert result["declared_count"] == result["parsed_count"] == count
    assert [row["trade_no"] for row in result["rows"]] == list(range(4000, 4000 + count))
    assert [row["seq"] for row in result["rows"]] == list(range(1000, 1000 + count))
    assert [row["dt1"] for row in result["rows"]] == list(range(1788487200, 1788487200 + count))
    assert result["rows"][-1]["volume"] == count * 100


@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("period,make_body,parser", [
    (7169, trades, protocol.parse_superorder_response),
    (7175, orders, lambda body: protocol.parse_order_detail_response(body, period=7175)),
])
def test_short_response_keeps_only_real_complete_rows(compressed, period, make_body, parser):
    complete = make_body(count=3)
    if compressed:
        complete = compressed_literals(complete)
    short = complete[:-1]
    result = protocol._market_response_evidence(short, period=period)
    assert result["recognized"] and not result["complete"] and result["truncated"]
    assert result["declared_count"] == 3 and result["parsed_count"] == 2
    assert len(parser(short)) == 2
    if compressed:
        assert "compressed_source_exhausted" in result["errors"]
    assert protocol._market_response_evidence(complete, period=period)["complete"]


@pytest.mark.parametrize("compressed", [False, True])
def test_full_length_unknown_order_side_is_incomplete(compressed):
    body = orders(count=1, kind_raw=4150502656, volume=131584)
    if compressed:
        body = compressed_literals(body)
    result = protocol._market_response_evidence(body, period=7175, code="000001")
    assert result["recognized"] and not result["complete"] and not result["truncated"]
    assert result["declared_count"] == result["parsed_count"] == 1
    assert result["errors"] == ["unknown_order_side:000001"]
    assert result["rows"][0]["side"] is None
    assert result["rows"][0]["volume"] == 131584
    assert result["rows"][0]["kind_raw"] == 4150502656


@pytest.mark.parametrize("kind_raw,side", [(513, "buy"), (514, "sell"), (67109378, "sell")])
def test_order_side_validation_preserves_high_flags_and_large_volume(kind_raw, side):
    result = protocol._market_response_evidence(
        orders(kind_raw=kind_raw, volume=164300), period=7175,
    )
    assert result["complete"] and result["errors"] == []
    assert result["rows"][0]["side"] == side
    assert result["rows"][0]["volume"] == 164300
    assert result["rows"][0]["kind_flags"] == kind_raw & ~0xFF


@pytest.mark.parametrize("first", [True, False])
@pytest.mark.parametrize("period,make_body", [(7169, trades), (7175, orders)])
def test_code_filter_does_not_hide_another_table_short_tail(first, period, make_body):
    selected = make_body(code="000001")
    short = make_body(code="600519")[:-1]
    body = selected + short if first else short + selected
    result = protocol._market_response_evidence(body, period=period, code="000001")
    assert result["recognized"] and not result["complete"]
    assert result["table_codes"] == ["000001", "600519"]
    assert all(row["code"] == "000001" for row in result["rows"])
    assert result["parsed_count"] == result["declared_count"] - 1
    assert any(error.startswith("row_count_mismatch:600519:") for error in result["errors"])


def test_code_filter_does_not_hide_another_table_unknown_side():
    body = orders() + orders(code="600519", kind_raw=0)
    result = protocol._market_response_evidence(body, period=7175, code="000001")
    assert result["recognized"] and not result["complete"]
    assert result["errors"] == ["unknown_order_side:600519"]


@pytest.mark.parametrize("period,make_body", [(7169, trades), (7175, orders)])
def test_zero_row_tables_are_recognized_and_complete(period, make_body):
    result = protocol._market_response_evidence(make_body(count=0), period=period, code="000001")
    assert result["recognized"] and result["complete"]
    assert result["rows"] == []
    assert result["declared_count"] == result["parsed_count"] == 0


def test_wrong_code_or_unrelated_layout_is_not_a_response():
    for body in (b"CodeListSize=1", orders(code="600519"), trades()):
        result = protocol._market_response_evidence(body, period=7175, code="000001")
        assert not result["recognized"] and not result["complete"]
        assert result["rows"] == []


@pytest.mark.parametrize("period", [7170, 7171])
def test_cancel_row_stock_code_must_match_its_table(period):
    row = struct.pack("<I", 1234) + b"\x21" + b"600519" + struct.pack(
        "<5I", 1788487200, 1788487205, 0x9000076C, 100, 9876,
    )
    body = table(protocol._CANCEL_DETAIL_FIELDS, 0x42, 31, [row])
    result = protocol._market_response_evidence(body, period=period)
    assert result["recognized"] and not result["complete"]
    assert result["errors"] == ["row_code_mismatch:000001"]


def test_trade_field_widths_must_cover_the_entire_row():
    body = bytearray(trades())
    body[16 + 3] = 3
    result = protocol._market_response_evidence(bytes(body), period=7169)
    assert result["recognized"] and not result["complete"]
    assert "field_width_mismatch:000001" in result["errors"]


@pytest.mark.parametrize("descriptor_offset,value", [(0, 99), (1, 0x30), (3, 3)])
@pytest.mark.parametrize("malformed_first", [False, True])
def test_malformed_trade_signature_cannot_hide_in_a_complete_frame(
    descriptor_offset, value, malformed_first,
):
    complete = trades(count=1)
    malformed = bytearray(complete)
    malformed[16 + 3 * 4 + descriptor_offset] = value
    malformed = bytes(malformed)
    body = malformed + complete if malformed_first else complete + malformed
    result = protocol._market_response_evidence(body, period=7169, code="000001")
    assert result["recognized"] and not result["complete"]
    assert result["declared_count"] == 2 and result["parsed_count"] == 1
    assert "field_signature_mismatch:000001" in result["errors"]
    assert protocol.parse_superorder_response(malformed) == []
    assert protocol.parse_superorder_response(body) == result["rows"]


def test_index_table_with_trade_layout_remains_unrelated():
    fields = tuple(
        (datatype, 0x30 if datatype == 1 else 0x70, 4)
        for datatype in (1, 10, 13, 19, 49, 18, 123, 125)
    )
    row = struct.pack("<8I", 1788487200, 0x9000076C, *([100] * 6))
    index = table(fields, 0x46, 32, [row], code="399001")
    unrelated = protocol._market_response_evidence(index, period=7169)
    assert not unrelated["recognized"] and not unrelated["complete"]
    assert unrelated["errors"] == []
    result = protocol._market_response_evidence(trades(count=1) + index, period=7169)
    assert result["complete"] and result["errors"] == []
    assert result["declared_count"] == result["parsed_count"] == 1
    assert protocol.parse_superorder_response(index) == []


@pytest.mark.parametrize("period,make_body", [(7169, trades), (7175, orders)])
@pytest.mark.parametrize("missing", [1, 11])
def test_empty_table_requires_its_entire_stock_shell(period, make_body, missing):
    short = make_body(count=0)[:-missing]
    result = protocol._market_response_evidence(short, period=period)
    assert result["recognized"] and not result["complete"]
    assert result["errors"] == ["incomplete_stock_shell:000001"]
    assert result["declared_count"] == result["parsed_count"] == 0


def test_unsupported_period_fails_explicitly():
    with pytest.raises(ValueError, match="unsupported market detail period"):
        protocol._market_response_evidence(b"", period=4096)
