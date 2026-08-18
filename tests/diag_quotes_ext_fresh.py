"""诊断：全新客户端上 list_quotes（/api/quotes_ext 底层）是否正常。

背景：用户自起的 web 后端（8765）运行数小时后 MAIN 通道 quotes_ext 全部
返回空（ProtocolError 被逐批吞掉），但 L2 通道（stock_list_ranked）正常。
本脚本用独立的新客户端验证协议路径本身，排除/确认代码级问题。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from thspypc.testing import get_client

client = get_client()
print("connected:", client.is_connected)

CASES = [
    (["600519"], 17),
    (["601318"], 17),
    (["600519", "601318"], 17),
    (["300561"], 33),
    (["000001"], 33),
    (["300828", "301626", "300561"], 33),
    (["688826"], 17),
]

for codes, market in CASES:
    try:
        recs = client.list_quotes(
            codes, market=market, datatype=[5, 6, 7, 10, 17, 19, 48]
        )
        summary = [
            {k: r.get(k) for k in ("code", "dt10", "dt6", "dt19")} for r in recs
        ]
        print(f"market={market} {codes} -> {len(recs)} 条 {summary}")
    except Exception as exc:  # noqa: BLE001
        print(f"market={market} {codes} -> ERROR {type(exc).__name__}: {exc}")

# 直接走 facade 级接口（与 /api/quotes_ext 相同路径，含市场推断与派生）
rows = client.stock_quote_fields(
    ["600519", "000001", "300561", "300828", "301626", "688826"]
)
print("\nstock_quote_fields 混合市场 ->", len(rows), "条")
for r in rows:
    print(" ", r)

# 自愈验证：硬杀 MAIN socket，list_quotes 应重连后仍拿到数据
print("\n--- 杀死 MAIN 后的自愈测试 ---")
with client._sock_lock:
    client._sock.close()
print("socket killed, is_connected =", client.is_connected)
recs = client.list_quotes(["600519"], market=17, datatype=[5, 6, 7, 10, 17, 19, 48])
print("杀死后 list_quotes ->", len(recs), "条",
      {k: recs[0].get(k) for k in ("code", "dt10")} if recs else None)
rows2 = client.stock_quote_fields(["600519", "300561"])
print("杀死后 stock_quote_fields ->", len(rows2), "条", rows2)
