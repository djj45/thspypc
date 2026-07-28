"""Numeric encodings shared by market response formats."""
from __future__ import annotations


_FLOAT_TABLE = [
    1.0,
    10.0,
    100.0,
    1000.0,
    10000.0,
    100000.0,
    1000000.0,
    10000000.0,
]


def decode_ths_float(le32: int) -> float:
    """解码同花顺定点浮点（fmt=0x70 字段的 4 字节 LE32 值）。

    编码：bit31=是否除法，bit30..28=指数（查 _FLOAT_TABLE），bit27=符号，
    bit26..0=尾数。结果 = sign × (mantissa ×/÷ factor)。
    无效值哨兵：0xFFFFFFFF（未完成/占位）显式归零。
    """
    le32 &= 0xFFFFFFFF
    if le32 == 0xFFFFFFFF:
        return 0.0
    divide = bool(le32 & 0x80000000)
    exp = (le32 >> 28) & 7
    sign = -1.0 if (le32 & 0x08000000) else 1.0
    mantissa = le32 & 0x07FFFFFF
    factor = _FLOAT_TABLE[exp]
    return sign * (mantissa / factor if divide else mantissa * factor)

