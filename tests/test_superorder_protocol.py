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
