"""list_quotes hd1.0 服务端截尾修复回归（2026-08-03 活网发现）。"""

from pathlib import Path

from thspypc.codecs.hd import parse_hd1_response
from thspypc.services.quote import _repair_short_record

FIXTURES = Path(__file__).parent / "fixtures" / "quote"


class TailSocket:
    """模拟 socket：recv 返回补读的 1 字节（服务端帧体外的末记录末字节）。"""

    def __init__(self, tail: bytes):
        self._tail = tail

    def settimeout(self, _value):
        pass

    def recv(self, _size):
        return self._tail


def test_repair_single_record_truncated_tail():
    body = (FIXTURES / "600519_single_hd1_trunc.bin").read_bytes()

    # 截尾帧直接解析为空（记录区 46/47）
    assert parse_hd1_response(body) == []

    repaired = _repair_short_record(TailSocket(b"\xb0"), body)
    records = parse_hd1_response(repaired)

    assert len(records) == 1
    assert records[0]["code"] == "600519"
    assert records[0]["dt10"] > 0  # 现价正常解码


def test_repair_two_records_truncated_tail():
    body = (FIXTURES / "600519_601318_double_hd1_trunc.bin").read_bytes()

    # 截尾帧只解出第 1 条（记录区 93/94，第 2 条行不足）
    assert [r.get("code") for r in parse_hd1_response(body)] == ["600519"]

    repaired = _repair_short_record(TailSocket(b"\xb0"), body)
    records = parse_hd1_response(repaired)

    assert [r.get("code") for r in records] == ["600519", "601318"]
