"""从混合抓包切出历史分时 0x0082 子表的离线语料，并抓取 thsdk 真值。

背景见 docs/investigations/HISTORY_TIMELINE_OMISSION_CODEC_HANDOFF.md。本脚本只做两件事：

1. 读 ``captures_live/history_companion_000001_000938_*.bin``，做外层 LZ77
   归一化（``normalize_8901_response``），定位两张 ``flag=0x0082 / hs=92 /
   fc=23`` 的个股子表，把每张表的**裸记录区**（从 header 之后到下一张子表
   之前）连同 header 元数据写进 ``tests/fixtures/history_timeline/``。
2. 用 thsdk 1.7.18 ``min_snapshot`` 抓取 000001 / 000938 当日的 241 点
   核心价量额（dt1 时间、dt10 价格、dt13 成交量、dt19 成交额），写成
   golden JSON，作为后续 codec 的语义 oracle。

语料性质（必须牢记，避免误判）：

- 000001 表是「强状态省略型」，000938 表是「较完整锚点型」，但二者是
  **不同标的**，不能互为字段 oracle；只能各自独立做形态统计。
- thsdk 只覆盖 dt1/10/13/19 等核心字段，不能单独证明 dt54、dt201-230 正确。

抓包原文含实时行情且在 gitignore 中；本脚本切出的 fixture 只保留裸记录
区和已公开行情价量额，放入受版本控制的 ``tests/fixtures/`` 以便 CI 跑 codec。
"""
from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from thspypc.codecs.compression import normalize_8901_response  # noqa: E402


logger = logging.getLogger(__name__)

FIXTURE_DIR = ROOT / "tests" / "fixtures" / "history_timeline"
HD_MARK = b"hd1.0\x00"
OMISSION_FLAG = 0x0082
TARGET_FLAG = OMISSION_FLAG
TARGET_HS = 92
TARGET_FC = 23


def find_omission_tables(normalized: bytes) -> list[dict]:
    """Return metadata for every flag=0x0082 / hs=92 / fc=23 sub-table.

    记录区范围 ``record_start..record_end`` 是裸记录区：从字段表/记录区起点
    到下一张 ``hd1.0`` 子表或 normalized 末尾。注意 flag=0x0082 与
    flag=0x007E 不同，前者**有**内联字段表（23 字段 × 4 字节，紧跟 header），
    字段表之后还有壳段（含 ASCII 代码标签），再之后才是记录数据，因此
    record_start 直接取 base+10。
    """
    tables: list[dict] = []
    pos = 0
    markers: list[int] = []
    while True:
        m = normalized.find(HD_MARK, pos)
        if m < 0:
            break
        markers.append(m)
        pos = m + 6
    for idx, m in enumerate(markers):
        base = m + 6
        if base + 10 > len(normalized):
            continue
        dc, flag, hs, fc = struct.unpack_from("<IHHH", normalized, base)
        if flag != TARGET_FLAG or hs != TARGET_HS or fc != TARGET_FC:
            continue
        record_start = base + 10
        # 下一张 hd1.0 的 marker；若无则取末尾。
        next_base = markers[idx + 1] if idx + 1 < len(markers) else len(normalized)
        record_end = next_base
        tables.append(
            {
                "marker_offset": m,
                "base_offset": base,
                "record_start": record_start,
                "record_end": record_end,
                "record_length": record_end - record_start,
                "dc": dc,
                "flag": flag,
                "hs": hs,
                "fc": fc,
            }
        )
    return tables


def bind_codes(
    tables: list[dict], normalized: bytes, requested_codes: tuple[str, ...]
) -> list[tuple[str | None, dict]]:
    """按请求顺序绑定代码；显式 ASCII 标签优先（强省略表常省略标签）。

    返回 ``(code, table)`` 列表，code 为 None 表示无法绑定。
    """
    bound: list[tuple[str | None, dict]] = []
    assigned_idx = 0
    import re

    for table in tables:
        search = normalized[
            table["record_start"] : min(
                table["record_end"], table["record_start"] + 160
            )
        ]
        m = re.search(rb"(?<![0-9])([0-9]{6})(?![0-9])", search)
        explicit = m.group(1).decode("ascii") if m else None
        code = explicit
        if code is None and assigned_idx < len(requested_codes):
            code = requested_codes[assigned_idx]
        if code is not None:
            assigned_idx += 1
        bound.append((code, table))
    return bound


def fetch_oracle(code: str, date: str) -> list[dict] | None:
    """用 thsdk min_snapshot 抓 241 点核心字段。无数据返回 None。"""
    try:
        from thsdk import THS  # type: ignore
    except ModuleNotFoundError:
        logger.warning("thsdk 未安装，跳过真值抓取；请用 Python 3.14 site-packages")
        return None
    with THS() as ths:
        resp = ths.min_snapshot(f"USZA{code}", date=date)
        if not resp or not resp.data:
            logger.warning("thsdk %s %s 无数据: %s", code, date, getattr(resp, "error", "?"))
            return None
        # 只保留与历史分时 codec 直接可比的核心字段。
        out = []
        for row in resp.data:
            out.append(
                {
                    "时间": row.get("时间"),
                    "dt1_time": row.get("时间"),
                    "dt10_price": row.get("价格"),
                    "dt13_volume": row.get("成交量"),
                    "dt19_amount": row.get("总金额"),
                }
            )
        return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--bin",
        default="captures_live/history_companion_000001_000938_20260514_20260728_174530.bin",
        help="混合抓包文件路径",
    )
    ap.add_argument("--date", default="20260514", help="thsdk 真值日期 YYYYMMDD")
    ap.add_argument(
        "--requested-codes",
        default="000001,000938",
        help="请求 CodeList 顺序，用于绑定无显式标签的表",
    )
    ap.add_argument("--no-oracle", action="store_true", help="跳过 thsdk 真值抓取")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    bin_path = (ROOT / args.bin).resolve()
    raw = bin_path.read_bytes()
    logger.info("raw=%dB starts_0a=%s", len(raw), raw[:1] == b"\x0a")
    normalized = normalize_8901_response(raw)
    logger.info("normalized=%dB", len(normalized))

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    # 写整帧归一化语料（仅含市场行情价量额，无连接凭据）。
    (FIXTURE_DIR / "history_companion_normalized.bin").write_bytes(normalized)

    tables = find_omission_tables(normalized)
    logger.info("found %d flag=0x0082 tables", len(tables))
    requested = tuple(args.requested_codes.split(","))
    bound = bind_codes(tables, normalized, requested)

    manifest: list[dict] = []
    for code, table in bound:
        rec = normalized[table["record_start"] : table["record_end"]]
        stem = code or f"unbound_{table['marker_offset']}"
        rec_path = FIXTURE_DIR / f"{stem}_record_region.bin"
        rec_path.write_bytes(rec)
        meta = {
            "code": code,
            "date": args.date,
            "raw_bin": bin_path.name,
            "normalized_total_length": len(normalized),
            **{k: table[k] for k in ("marker_offset", "base_offset", "record_start", "record_end", "record_length", "dc", "flag", "hs", "fc")},
            "record_region_file": rec_path.name,
            "record_region_sha256": __import__("hashlib").sha256(rec).hexdigest(),
        }
        manifest.append(meta)
        logger.info(
            "table code=%s marker@%d rec=[%d,%d] len=%d sha=%s",
            code,
            table["marker_offset"],
            table["record_start"],
            table["record_end"],
            table["record_length"],
            meta["record_region_sha256"][:12],
        )

    (FIXTURE_DIR / "tables_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    if args.no_oracle:
        return 0
    for code, _ in bound:
        if code is None:
            continue
        oracle = fetch_oracle(code, args.date)
        if oracle is None:
            continue
        out = FIXTURE_DIR / f"{code}_thsdk_oracle_{args.date}.json"
        out.write_text(
            json.dumps(
                {"code": code, "date": args.date, "rows": oracle}, indent=2, ensure_ascii=False
            ),
            encoding="utf-8",
        )
        logger.info("oracle %s %s -> %d rows -> %s", code, args.date, len(oracle), out.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
