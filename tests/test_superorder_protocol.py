"""超级盘口 / 逐笔成交回放（period=7169）协议离线契约测试。

覆盖：请求构造哈希、合成帧解析、深沪 captures_live 回归、protocol reexport。
合成帧的字段表 / shell / 记录字节取自真实深市 000938 样本（2026-08-05）。
"""
from __future__ import annotations

import hashlib
import struct
from datetime import datetime
from pathlib import Path

import pytest

from thspypc.features import superorder_protocol
import thspypc.protocol as protocol

CAPTURES = Path(__file__).resolve().parents[1] / "captures_live"
FIXTURES = Path(__file__).parent / "fixtures" / "superorder"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


# ── 真实深市 000938 样本字节（2026-08-05，用于构造合成帧）──
# 字段表 8 项：dt1(0x30) dt56(0x30) dt10(0x70) dt13(0x70) dt12(0x30) dt74(0x30) dt75(0x30) dt18(0x70)
_REAL_FIELD_TABLE = bytes.fromhex(
    "01300004383000040a7000040d7000040c3000044a3000044b30000412700004"
)
# shell（深市 0x21 + "000938" + 头部填充，26 字节）
_REAL_SHELL = bytes.fromhex("1600010021303030393338000200000000000000975db4503502")
# 前 3 条记录（13:18:51，价 37.75，量 100/7400/1000，方向 5/5/5）
_REAL_RECORDS = bytes.fromhex(
    "bbc7726a9cc205c06400000005000000b350350265453502af9807009b513502"
    "bbc7726a9cc205c0e81c0000050000009a51350265453502b09807001a523502"
    "bbc7726a9cc205c0e8030000050000001952350265453502b1980700de523502"
)


def _build_synthetic_frame(record_count: int, market_byte: int = 0x21,
                           code: str = "000938") -> bytes:
    """构造一个可被 parse_superorder_response 解析的 hd1.0 合成帧。

    用真实字段表 + shell + 前 N 条记录（N<=3）拼装。market_byte 控制沪深：
    0x21=深, 0x11=沪。
    """
    n = min(record_count, 3)
    header = b"hd1.0\x00" + struct.pack("<IHHH", n, 0x0046, 32, 8)
    # 替换 shell 里的市场标记字节和代码
    shell = bytearray(_REAL_SHELL)
    shell[4] = market_byte
    shell[5:11] = code.encode("ascii")
    records = _REAL_RECORDS[: n * 32]
    return bytes(header) + _REAL_FIELD_TABLE + bytes(shell) + records


# ────────────────── 请求构造 ──────────────────

def test_build_superorder_query_structure():
    """请求帧结构：fdfdfdfd + 8 位 ASCII 长度 + body（含 pageid/DateTime/DataType）。"""
    frame = superorder_protocol.build_superorder_query(
        "000938", market=33, start_ts=1785907131, end_ts=1785913200,
    )
    assert frame.startswith(b"\xfd\xfd\xfd\xfd")
    # 8 位 ASCII hex 长度头（encode_frame 格式）
    len_hex = frame[4:12].decode("ascii")
    assert int(len_hex, 16) == len(frame) - 12
    # body 含关键字段
    body = frame[12:].decode("gbk", errors="replace")
    assert "CodeList=33(000938,);" in body
    assert "DataType=10,12,13," in body
    assert "DateTime=7169(1785907131-1785913200)" in body
    assert "pageid=4214" in body


def test_build_superorder_query_matches_capture():
    """★ 请求帧与真实抓包逐字节一致（2026-08-05 深市 000938，pageid=4214）。

    这是服务端能否正确响应的关键：header route/seq/长度字段、三层嵌套结构、
    text 编码必须和真实客户端完全一致，否则服务端会拒绝或返回错误。
    fixture ``req_000938_4214_p7169.bin`` 是真实请求的 body（去 12B 帧头）。
    """
    built = superorder_protocol.build_superorder_query(
        "000938", market=33, start_ts=-27, end_ts=0, pageid=4214, seq=0,
    )
    captured = (FIXTURES / "req_000938_4214_p7169.bin").read_bytes()
    # built[12:] 去掉 fdfdfdfd + 8 位 ASCII 长度头，对齐 captured body
    assert built[12:] == captured


def test_build_superorder_query_deterministic():
    """同参数两次构造逐字节一致（确定性）。"""
    a = superorder_protocol.build_superorder_query(
        "603118", market=17, start_ts=100, end_ts=200, pageid=4260,
    )
    b = superorder_protocol.build_superorder_query(
        "603118", market=17, start_ts=100, end_ts=200, pageid=4260,
    )
    assert a == b


def test_build_superorder_query_pageid_super():
    """超级盘口入口 pageid=4260 可切换。"""
    frame = superorder_protocol.build_superorder_query(
        "000938", market=33, start_ts=0, end_ts=0, pageid=4260,
    )
    assert b"pageid=4260" in frame


# ────────────────── 合成帧解析 ──────────────────

def test_parse_synthetic_frame_deep_market():
    """深市合成帧：8 字段全部正确解出。"""
    body = _build_synthetic_frame(3, market_byte=0x21, code="000938")
    records = superorder_protocol.parse_superorder_response(body)

    assert len(records) == 3
    for r in records:
        assert r["code"] == "000938"
        # 价 37.75（ths_float），方向 5（主动卖），序号递增
        assert abs(r["price"] - 37.75) < 0.01
        assert r["direction"] == 5
    # 时间戳 = 13:18:51（深市样本起点）
    assert records[0]["dt1"] == 1785907131
    # 逐笔序号递增：497839 → 497840 → 497841
    assert records[0]["seq"] == 497839
    assert records[1]["seq"] == 497840
    assert records[2]["seq"] == 497841
    # 成交量：100 / 7400 / 1000
    assert records[0]["volume"] == 100
    assert records[1]["volume"] == 7400
    assert records[2]["volume"] == 1000
    # time 字段是 datetime
    assert isinstance(records[0]["time"], datetime)


def test_parse_synthetic_frame_shanghai_market():
    """沪市合成帧：市场标记 0x11，代码 603118，同样可解。"""
    body = _build_synthetic_frame(2, market_byte=0x11, code="603118")
    records = superorder_protocol.parse_superorder_response(body)

    assert len(records) == 2
    assert all(r["code"] == "603118" for r in records)
    # 沪市代码不影响价/量解析（记录字节相同）
    assert abs(records[0]["price"] - 37.75) < 0.01


def test_parse_rejects_wrong_flag():
    """非 0x0046 flag 的 hd1.0 帧不解析（避免误吞 timeline/kline 帧）。"""
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 3, 0x0042, 32, 8)  # flag=0x0042 非 7169
        + _REAL_FIELD_TABLE + _REAL_SHELL + _REAL_RECORDS[:96]
    )
    assert superorder_protocol.parse_superorder_response(body) == []


def test_parse_rejects_non_hd_frame():
    """不含 hd1.0 标记的帧返回空。"""
    assert superorder_protocol.parse_superorder_response(b"\x00" * 200) == []


def test_parse_truncated_record_filtered():
    """记录区尾部混入非法时间戳时，仅保留合法记录（截断帧兜底）。

    定位阶段验证前 4 条 ts 合法（连续 4 条），因此构造 5 条记录的帧（前 3 条真实
    + 复制前 2 条补足 5 条），把坏 ts 放在第 5 条（index=4）：定位验证前 4 条通过，
    记录循环读到第 5 条时 ts 非法即停止。
    """
    # 构造 5 条记录：真实 3 条 + 复制前 2 条（ts 单调需递增，复制会破坏单调，
    # 改用直接拼 5 份第 0 条的 ts 递增序列）
    rec0 = _REAL_RECORDS[0:32]
    rec1 = _REAL_RECORDS[32:64]
    rec2 = _REAL_RECORDS[64:96]
    # 构造 rec3/rec4：基于 rec2，ts 各 +3 保持单调近距
    rec2_ts = struct.unpack_from("<I", rec2, 0)[0]
    rec3 = bytearray(rec2)
    struct.pack_into("<I", rec3, 0, rec2_ts + 3)
    rec4 = bytearray(rec2)
    struct.pack_into("<I", rec4, 0, rec2_ts + 6)
    five_records = rec0 + rec1 + rec2 + bytes(rec3) + bytes(rec4)

    header = b"hd1.0\x00" + struct.pack("<IHHH", 5, 0x0046, 32, 8)
    body = bytes(header) + _REAL_FIELD_TABLE + _REAL_SHELL + five_records
    rec_off = len(header) + len(_REAL_FIELD_TABLE) + len(_REAL_SHELL)

    # 第 5 条记录（index=4）的 ts 改成非法
    body_bad = bytearray(body)
    struct.pack_into("<I", body_bad, rec_off + 4 * 32, 0xFFFFFFFF)
    records = superorder_protocol.parse_superorder_response(bytes(body_bad))
    # 前 4 条合法（定位验证通过 + 循环读到第 5 条非法停止）
    assert len(records) == 4
    assert records[0]["seq"] == 497839


# ────────────────── captures_live 回归（skip guard）──────────────────

def _load_resp_frames(path: Path) -> list[bytes]:
    """读 _resp_streamN.bin，按 MAGIC 拆帧去 8 字节头。"""
    data = path.read_bytes()
    magic = b"\xfd\xfd\xfd\xfd"
    return [p[8:] for p in data.split(magic) if len(p) >= 8]


def test_deep_market_000938_capture():
    """深市 000938 全天 7169 回归：解析正确（seq 去重后连续度 >99%）。

    抓包样本里用户反复滚动浏览同一区间，76 个 7169 请求区间高度重叠 → stream
    含大量重复响应。parser 单帧正确，但跨帧累加会重复。因此用 **seq 去重**验证
    解析器正确性：去重后 seq 应几乎连续（>99%），证明每一笔都被解对了。
    """
    cap = CAPTURES / "superorder_20260805_195859_resp_stream1.bin"
    if not cap.exists():
        pytest.skip("本机无深市 000938 超级盘口语料")
    frames = _load_resp_frames(cap)
    all_records = []
    for f in frames:
        if len(f) < 200 or not (f.startswith(b"\x0a") or b"hd1.0" in f):
            continue
        recs = superorder_protocol.parse_superorder_response(f)
        if recs and recs[0].get("code") == "000938":
            all_records.extend(recs)
    assert len(all_records) > 100000  # 含重复，宽松下限

    # ★ 核心验证：按 seq 去重后应几乎连续（证明逐笔无遗漏/无错解）
    by_seq = {r["seq"]: r for r in all_records}
    seqs = sorted(by_seq)
    span = seqs[-1] - seqs[0] + 1
    continuity = len(by_seq) / span
    assert continuity > 0.99, f"seq 去重后连续度 {continuity:.3f} < 0.99"

    # 价区间合理（紫光股份 8-5 当日 36.94-37.75）
    uniq = list(by_seq.values())
    prices = [r["price"] for r in uniq]
    assert all(36.0 <= p <= 38.5 for p in prices), "去重后所有价格应在 36-38.5"
    # 方向 {1,5} 占绝大多数
    good = sum(1 for r in uniq if r["direction"] in (1, 5))
    assert good / len(uniq) > 0.99


def test_shanghai_market_603118_capture():
    """沪市 603118 7169 回归：价格/方向/时间均合理。

    沪市 seq 跨请求区间不连续（不同时间段返回不同基数的序号空间，值可达千万级），
    因此不像深市那样用 seq 跨段连续度验证。改用价格合理性 + 方向 {1,5} 占比。
    """
    cap = CAPTURES / "superorder_20260805_234035_resp_stream0.bin"
    if not cap.exists():
        pytest.skip("本机无沪市 603118 超级盘口语料")
    frames = _load_resp_frames(cap)
    all_records = []
    for f in frames:
        if len(f) < 200 or not (f.startswith(b"\x0a") or b"hd1.0" in f):
            continue
        recs = superorder_protocol.parse_superorder_response(f)
        if recs and recs[0].get("code") == "603118":
            all_records.extend(recs)
    assert len(all_records) > 10000

    # 通合科技 8-5 当日 ~13-15 元
    prices = [r["price"] for r in all_records if 5 < r["price"] < 50]
    assert len(prices) / len(all_records) > 0.99, "99%+ 价格应合理"
    assert 13.0 < min(prices) < 15.5
    assert max(prices) < 16.0
    # 方向 {1,5} 占比 >99%（盘后段少量其它值容忍）
    good = sum(1 for r in all_records if r["direction"] in (1, 5))
    assert good / len(all_records) > 0.99
    # 时间均在交易时段 9:15-15:30
    import datetime as _dt
    for r in all_records:
        if r["time"] is not None:
            h = r["time"].hour
            assert 9 <= h <= 15, f"时间 {r['time']} 不在交易时段"


# ────────────────── protocol reexport ──────────────────

def test_protocol_reexports_superorder():
    assert protocol.build_superorder_query is superorder_protocol.build_superorder_query
    assert protocol.parse_superorder_response is superorder_protocol.parse_superorder_response
    assert protocol.SUPERORDER_PERIOD == 7169


# ────────────────── 7173/7174 委托队列 ──────────────────

def _build_order_queue_frame(
    *,
    side: str,
    code: str,
    market_marker: int,
    values: list[int],
    total_order_count: int,
    meta_value: int,
) -> bytes:
    field_table = bytes((56, 0x30, 0, 4))
    shell = bytearray(42)
    shell[0] = market_marker
    shell[1:7] = code.encode("ascii")
    struct.pack_into("<I", shell, 18, 1786112984)
    struct.pack_into("<I", shell, 22, 0x9000076C)  # 190.0
    struct.pack_into("<I", shell, 26, meta_value)
    shell[32] = 50
    shell[33] = 16
    struct.pack_into("<H", shell, 34, total_order_count)
    struct.pack_into("<H", shell, 38, 0x0101)
    rows = b"".join(struct.pack("<I", value) for value in values)
    return (
        b"hd1.0\x00"
        + struct.pack("<IHHH", len(values) + 6, 0x002A, 4, 1)
        + field_table
        + b"\x00\x00\x00\x00"
        + bytes(shell)
        + rows
    )


@pytest.mark.parametrize(
    ("side", "period"),
    [("buy", 7173), ("sell", 7174)],
)
def test_build_order_queue_query_structure(side, period):
    frame = superorder_protocol.build_order_queue_query(
        "688693",
        market=17,
        side=side,
        pageid=4417,
        seq=0,
        inner_seq=0x09A0,
    )
    assert int(frame[4:12], 16) == len(frame) - 12
    assert len(frame[12:]) == 178
    assert frame[12] == 0x09
    assert frame[23:25] == b"\xfc\x02"
    assert b"CodeList=17(688693,);" in frame
    assert b"DataType=10," in frame
    assert f"DateTime={period}(-1-0)".encode() in frame
    assert b"pageid=4417" in frame


def test_parse_buy_order_queue_and_major_marks():
    values = [
        1100,
        0x08000000 | 9900,
        400,
        0x08000000 | 99800,
        500,
        0x08000000 | 8393,
        0x08000000 | 5000,
    ]
    body = _build_order_queue_frame(
        side="buy",
        code="688693",
        market_marker=0x11,
        values=values,
        total_order_count=700,
        meta_value=1_152_067,
    )
    result = superorder_protocol.parse_order_queue_response(body, side="buy")
    assert result is not None
    assert result["code"] == "688693"
    assert result["period"] == 7173
    assert result["price"] == 190.0
    assert result["total_order_count"] == 700
    assert result["visible_count"] == 7
    assert result["truncated"] is True
    assert [entry["hands"] for entry in result["entries"]] == [
        11, 99, 4, 998, 5, 84, 50,
    ]
    assert result["visible_major_order_count"] == 4
    assert result["visible_major_shares"] == 123_093
    assert result["visible_major_hands"] == 1230.93


def test_parse_sell_order_queue_and_empty_ack():
    values = [824_200, 500, 4_100, 0x08000000 | 314_700]
    body = _build_order_queue_frame(
        side="sell",
        code="000779",
        market_marker=0x21,
        values=values,
        total_order_count=7756,
        meta_value=16_322_619,
    )
    result = superorder_protocol.parse_order_queue_response(body, side="sell")
    assert result is not None
    assert result["period"] == 7174
    assert result["meta_value"] == 16_322_619
    assert [entry["hands"] for entry in result["entries"]] == [8242, 5, 41, 3147]
    assert result["visible_major_order_count"] == 1
    assert superorder_protocol.parse_order_queue_response(
        b"CodeListSize=1",
        side="buy",
    ) is None


def test_parse_single_visible_order_queue_entry():
    body = _build_order_queue_frame(
        side="buy",
        code="688693",
        market_marker=0x11,
        values=[1234],
        total_order_count=1,
        meta_value=0,
    )
    result = superorder_protocol.parse_order_queue_response(body, side="buy")
    assert result is not None
    assert result["visible_count"] == 1
    assert result["entries"][0]["shares"] == 1234


def test_protocol_reexports_order_queue():
    assert protocol.build_order_queue_query is superorder_protocol.build_order_queue_query
    assert protocol.parse_order_queue_response is superorder_protocol.parse_order_queue_response
    assert protocol.ORDER_QUEUE_BUY_PERIOD == 7173
    assert protocol.ORDER_QUEUE_SELL_PERIOD == 7174


# ─────────────────────────── 7175/7170/7171 挂撤全量明细 ───────────────────────────

def _build_order_detail_frame(period: int) -> bytes:
    shell = bytearray(22)
    shell[0:4] = b"\x16\x00\x01\x00"
    shell[4] = 0x21
    shell[5:11] = b"002428"
    if period == 7175:
        fields = bytes.fromhex(
            "01300004383000040a7000040d7000040c300004"
        )
        rows = b"".join((
            struct.pack("<IIIII", 1001, 1786345013, 0xC00FA3E8, 100, 0x0201),
            struct.pack("<IIIII", 1002, 1786345014, 0xC00FA7D0, 1000, 0x0202),
        ))
        return (
            b"hd1.0\x00"
            + struct.pack("<IHHH", 2, 0x003A, 20, 5)
            + fields
            + bytes(shell)
            + rows
        )

    fields = bytes.fromhex(
        "01300004051000073830000452300004147000040d70000425300004"
    )
    side_order = 1001 if period == 7170 else 1002
    placed = 1786345013 if period == 7170 else 1786345014
    cancelled = placed + (4 if period == 7170 else 57)
    price_raw = 0xC00FA3E8 if period == 7170 else 0xC00FA7D0
    volume = 100 if period == 7170 else 1000
    row = (
        struct.pack("<I", 2000 + period)
        + b"\x21" + b"002428"
        + struct.pack(
            "<IIIII",
            placed,
            cancelled,
            price_raw,
            volume,
            side_order,
        )
    )
    return (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 1, 0x0042, 31, 7)
        + fields
        + bytes(shell)
        + row
    )


def test_build_order_detail_queries_match_captured_shapes():
    order = superorder_protocol.build_order_detail_query(
        "002428", market=33, period=7175, start_ts=-29, end_ts=0,
        seq=0x00B3,
    )
    body = order[12:]
    assert body[11:13] == b"\xfc\x02"
    middle = 23 + len(b"CodeList=33(002428,);\r\npageid=4214\r\n")
    assert body[middle + 10 : middle + 12] == b"\xe1\x02"
    inner = middle + 22 + len(b"CodeList=33(002428,);\r\npageid=4214\r\n")
    assert body[inner + 10 : inner + 12] == b"\xfc\x01"
    assert body[inner + 16 : inner + 18] == b"\x07\x1c"
    assert b"DataType=10,12,13," in body
    assert b"DateTime=7175(-29-0)" in body

    buy_cancel = superorder_protocol.build_order_detail_query(
        "002428", market=33, period=7170, start_ts=-29, end_ts=0,
    )[12:]
    sell_cancel = superorder_protocol.build_order_detail_query(
        "002428", market=33, period=7171, start_ts=-29, end_ts=0,
    )[12:]
    assert buy_cancel[11:13] == sell_cancel[11:13] == b"\xfc\x01"
    assert buy_cancel[16:19] == b"\x00\x02\x1c"
    assert sell_cancel[16:19] == b"\x00\x03\x1c"
    assert b"DataType=13,20,37,82," in buy_cancel


def test_parse_order_detail_buy_and_sell_rows():
    rows = superorder_protocol.parse_order_detail_response(
        _build_order_detail_frame(7175),
        period=7175,
    )
    assert [row["side"] for row in rows] == ["buy", "sell"]
    assert [row["order_id"] for row in rows] == [1001, 1002]
    assert [row["hands"] for row in rows] == [1.0, 10.0]
    assert rows[0]["price"] == pytest.approx(102.5)
    assert rows[1]["price"] == pytest.approx(102.6)
    assert rows[0]["dt12"] == 0x0201


@pytest.mark.parametrize(
    ("period", "side", "elapsed", "order_id"),
    [(7170, "buy", 4, 1001), (7171, "sell", 57, 1002)],
)
def test_parse_cancel_detail_links_original_order(period, side, elapsed, order_id):
    rows = superorder_protocol.parse_order_detail_response(
        _build_order_detail_frame(period),
        period=period,
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == "cancel"
    assert row["side"] == side
    assert row["elapsed_seconds"] == elapsed
    assert row["order_id"] == order_id
    assert row["dt37"] == order_id
    assert row["cancelled_ts"] - row["placed_ts"] == elapsed


def test_protocol_reexports_order_detail():
    assert protocol.build_order_detail_query is superorder_protocol.build_order_detail_query
    assert protocol.parse_order_detail_response is superorder_protocol.parse_order_detail_response
    assert protocol.ORDER_DETAIL_PERIOD == 7175
    assert protocol.BUY_CANCEL_PERIOD == 7170
    assert protocol.SELL_CANCEL_PERIOD == 7171


# ────────────────── 4096 盘口快照回放（超级盘口分时曲线）──────────────────

def test_build_snapshot_replay_query_4417_matches_capture_fixture():
    """4417@4096 单子帧请求与 2026-08-07 盘后抓包 fr1986 字节级一致。"""
    fixture = FIXTURES / "req_002384_4417_p4096.bin"
    if not fixture.exists():
        pytest.skip("本机无 4417@4096 抓包 fixture")
    ref = fixture.read_bytes()
    built = superorder_protocol.build_snapshot_replay_query(
        "002384",
        market=33,
        pageid=superorder_protocol.SNAPSHOT_REPLAY_HIST_PAGEID,
        seq=0x1195,
        start_ts=1785979800,
        end_ts=1785999660,
    )
    assert built[12:] == ref
    assert _sha256(built) == (
        "8176fac827f588fb448565c589af107a"
        "6f288ac5e539a718e3e8aaca46392d60"
    )


def test_build_snapshot_replay_query_4417_structure():
    """4417 历史请求文本：DataType/DateTime/pageid 与抓包一致。"""
    frame = superorder_protocol.build_snapshot_replay_query(
        "002384",
        market=33,
        pageid=superorder_protocol.SNAPSHOT_REPLAY_HIST_PAGEID,
        start_ts=1785979800,
        end_ts=1785999660,
    )
    body = frame[12:].decode("gbk", errors="replace")
    assert "pageid=4417" in body
    assert "DateTime=4096(1785979800-1785999660)" in body
    assert (
        "DataType=7,10,12,13,18,19,20,21,25,26,27,28,29,31,32,33,34,35,"
        "49,75,123,125,150,151,152,153,154,155,156,157,6,66,1110,"
    ) in body


def test_parse_snapshot_replay_response_0x9e_synthetic():
    """4417@4096 响应（flag=0x9E，hs=120，fc=30）合成帧可解析出价/时间。"""
    fields = [(1, 0x30, 4), (10, 0x70, 4), (13, 0x70, 4), (12, 0x30, 4)]
    fields += [(20 + i, 0x70, 4) for i in range(26)]
    field_table = b"".join(
        bytes((dt, fmt, 0, width)) for dt, fmt, width in fields
    )
    shell = bytes.fromhex(
        "16000100213030323338340000000000000000003813"
    )
    price_raw = 0x9000076C  # ths_float 190.0
    rows = b"".join(
        struct.pack("<II", 1786065300 + i * 3, price_raw) + b"\x00" * 112
        for i in range(3)
    )
    body = (
        b"hd1.0\x00"
        + struct.pack("<IHHH", 3, 0x009E, 120, 30)
        + field_table
        + shell
        + rows
    )
    recs = superorder_protocol.parse_snapshot_replay_response(body)
    assert len(recs) == 3
    assert [r["price"] for r in recs] == [190.0, 190.0, 190.0]
    assert [r["time"] for r in recs] == ["09:15:00", "09:15:03", "09:15:06"]


def test_build_snapshot_replay_query_77_matches_capture_fixture():
    """指数 4096@77 双查询对与 2026-08-07 盘后抓包 fr542 字节级一致。"""
    fixture = FIXTURES / "req_399001_77_p4096.bin"
    if not fixture.exists():
        pytest.skip("本机无 4096@77 抓包 fixture")
    ref = fixture.read_bytes()
    built = superorder_protocol.build_snapshot_replay_query(
        "399001",
        market=32,
        pageid=superorder_protocol.SNAPSHOT_REPLAY_INDEX_PAGEID,
        seq=0x123B,
        companion_seq=0x123D,
        start_ts=1785979800,
        end_ts=1785999660,
    )
    assert built[12:] == ref


def test_parse_snapshot_replay_response_index_multi_table():
    """指数 0x46/32/8 布局：一帧两张表（今日+历史日）全部返回。"""
    fields = [(1, 0x30, 0, 4), (10, 0x70, 0, 4), (13, 0x70, 0, 4),
              (19, 0x70, 0, 4), (49, 0x70, 0, 4), (18, 0x70, 0, 4),
              (123, 0x70, 0, 4), (125, 0x70, 0, 4)]
    field_table = b"".join(
        bytes((dt, fmt, flags, width)) for dt, fmt, flags, width in fields
    )
    shell = bytes.fromhex(
        "16000100203339393030310000000000000000003813"
    )
    price_raw = 0x9000076C  # 190.0

    def table(dc: int, base_ts: int) -> bytes:
        rows = b"".join(
            struct.pack("<II", base_ts + i * 3, price_raw) + b"\x00" * 24
            for i in range(3)
        )
        return (
            b"hd1.0\x00"
            + struct.pack("<IHHH", dc, 0x0046, 32, 8)
            + field_table
            + shell
            + rows
        )

    body = table(3, 1786065300) + table(0x04000003, 1785978900)
    recs = superorder_protocol.parse_snapshot_replay_response(body)
    assert len(recs) == 6
    assert [r["ts"] for r in recs] == [
        1786065300, 1786065303, 1786065306,
        1785978900, 1785978903, 1785978906,
    ]
