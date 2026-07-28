"""公开业务结果的类型定义。

运行时仍使用字典以保持兼容；TypedDict 用于明确稳定字段，协议原始 ``dt<N>``
字段则保留在各结果的 ``fields`` 中。
"""
from __future__ import annotations

from typing import Literal, TypedDict


class DepthLevel(TypedDict):
    """单档盘口。"""

    level: str
    price: float
    qty: float
    amount: float


class DepthQuote(TypedDict, total=False):
    """五档盘口结果；空字典表示服务器未返回可识别盘口帧。"""

    code: str
    buy: list[DepthLevel]
    sell: list[DepthLevel]
    seal_amount: float
    seal_type: Literal["涨停", "跌停"] | None
    fields: dict[str, float]
