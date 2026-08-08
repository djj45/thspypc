# name16_oracle_tool.py - 可复用的 name_16_16 oracle 分析工具
"""Loads the known cipher/plain pair and prints per-record structure + token candidates.

用法:
  uv run python tests/name16_oracle_tool.py
  uv run python tests/name16_oracle_tool.py --records 10
  uv run python tests/name16_oracle_tool.py --tokens
"""
from __future__ import annotations

import argparse
import os

CIPHER = os.path.join(os.path.dirname(__file__), "..", "captures_live",
                      "name_dump_20260808_105709", "name16_cipher_mem.bin")
PLAIN = os.path.join(os.path.dirname(__file__), "..", "captures_live",
                     "stockname_16_0_full.txt")
SEG_HEAD = b"[name_16_16]\r\n"


def load_pair() -> tuple[bytes, bytes]:
    c = open(CIPHER, "rb").read()
    p = open(PLAIN, "rb").read()
    assert c.startswith(SEG_HEAD)
    stream = c[len(SEG_HEAD):362580]
    plain = p[len(SEG_HEAD):]
    return stream, plain


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=8)
    ap.add_argument("--tokens", action="store_true")
    args = ap.parse_args()

    stream, plain = load_pair()
    print(f"stream={len(stream)}B records={len(stream)//17} plain={len(plain)}B")

    if not args.tokens:
        for r in range(min(args.records, len(stream)//17)):
            rec = stream[r*17:(r+1)*17]
            print(f"rec{r:02d} ctrl=0x{rec[0]:02x} {rec[1:].hex(' ')}")
        return 0

    # 已知边界与最小 token 解（rec0..rec5），用于继续拟合 token 语义
    bounds = [0, 16, 32, 48, 68, 105]
    for r in range(1, min(args.records, len(bounds))):
        start, end = bounds[r-1], bounds[r]
        out = plain[start:end]
        print(f"rec{r-1} out[{start}:{end}] len={end-start}: {out!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
