"""离线分析历史分时 0x0082 省略记录的字段编码规则（仿 analyze_auction_varlen）。

用 thsdk min_snapshot 当真值 oracle，反推 low2 省略记录里被控制字替换的字段
如何从前值恢复。竞价 dt49 就是这么破的（见 docs/handoffs/HANDOFF_SUPERORDER
_20260726.md §13），不依赖二进制逆向。

已知（STEP1/STEP2）：
- full 记录：裸 LE32，字段在 +0/+4/+8/+12/+16/+20...
- low2 省略记录：bar 高字、dt10 等字段槽被 ``00 16`` 控制字替换；
  dt13/dt19 从不省略。

本脚本逐字段、逐字节地比对 low2 记录的字节与 oracle 真值（含前一条真值），
统计省略的精确规则（哪几个字节被省略、用什么标记、如何从 prev 恢复）。
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from thspypc.codecs.numeric import decode_ths_float
from thspypc.features.history_timeline_protocol import (
    _HISTORY_TIMELINE_BAR_OFFSETS,
)

from analyze_history_timeline_records import (  # noqa: E402
    collect_bar_candidates,
    align_records_dp,
)

FIRST_BAR = 132477534
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "history_timeline"


def _load(code: str) -> tuple[bytes, list[dict], list[tuple[int, int, str]]]:
    region = (FIXTURE_DIR / f"{code}_record_region.bin").read_bytes()
    oracle = json.loads(
        (FIXTURE_DIR / f"{code}_thsdk_oracle_20260514.json").read_text("utf-8")
    )["rows"]
    cands = collect_bar_candidates(region, FIRST_BAR)
    path, _ = align_records_dp(region, cands, FIRST_BAR)
    return region, oracle, path


def _oracle_index(bar: int) -> int:
    return _HISTORY_TIMELINE_BAR_OFFSETS.index(bar - FIRST_BAR)


def analyze_dt10_omission(code: str) -> None:
    """逐字节分析 dt10 价格字段的省略规则。"""
    region, oracle, path = _load(code)
    print(f"===== {code} dt10 省略规则分析 =====")

    prev_raw_bytes = None  # 上一条真实 dt10 的 4 字节 LE
    for idx, (bar, off, kind) in enumerate(path):
        slot = region[off + 4 : off + 8]
        oi = _oracle_index(bar)
        oracle_price = oracle[oi]["dt10_price"]
        # oracle 的 raw：找一个 full 记录 dt10==oracle_price 的 raw
        # 这里直接用 oracle_price 反查太慢，改为从 prev/full 逐步推进
        if kind == "full":
            raw = struct.unpack_from("<I", slot, 0)[0]
            prev_raw_bytes = list(slot)
            # 验证 full 记录本身
            val = decode_ths_float(raw)
            match = "✓" if abs(val - oracle_price) < 1e-3 else "✗"
            continue

        # low2：打印 slot、oracle、prev，逐字节比较
        slot_hex = slot.hex(" ")
        print(
            f"  idx={idx:3d} bar_off={bar-FIRST_BAR:3d} "
            f"slot=[{slot_hex}] oracle={oracle_price} "
            f"prev={[f'{b:02x}' for b in prev_raw_bytes]}"
        )
        # 把 oracle_price 编码成 raw（从前值的高位+推测低位找）
        # 11.13 的 raw=0xc001b2c4，规律：高位固定 c001b2xx，只最低字节变
        # 打印 oracle 与 prev 的差异
        if prev_raw_bytes is not None:
            # 尝试：oracle raw 的高3字节应该和 prev 一致（如果只最低字节变）
            # 但我们没有 oracle 的 raw，只有 price。用 price 找 full raw：
            pass


def brute_force_dt10_rule(code: str) -> None:
    """暴力穷举 dt10 恢复规则。

    对每条 low2 记录，尝试所有可能的「后缀字节数 + 标记位置」组合，
    用 prev 的高位填充，看哪种组合能恢复出 oracle 价格。
    """
    region, oracle, path = _load(code)
    print(f"\n===== {code} dt10 暴力规则穷举 =====")

    # 先建一个 price→raw 的查找表（从所有 full 记录收集）
    price_to_raw = {}
    for bar, off, kind in path:
        if kind != "full":
            continue
        raw = struct.unpack_from("<I", region, off + 4)[0]
        val = decode_ths_float(raw)
        price_to_raw[round(val, 4)] = raw

    prev_raw = None
    for idx, (bar, off, kind) in enumerate(path):
        if kind == "full":
            prev_raw = struct.unpack_from("<I", region, off + 4)[0]
            continue
        oi = _oracle_index(bar)
        op = round(oracle[oi]["dt10_price"], 4)
        target_raw = price_to_raw.get(op)
        slot = list(region[off + 4 : off + 8])
        prev_bytes = list(struct.pack("<I", prev_raw))
        target_bytes = list(struct.pack("<I", target_raw)) if target_raw else None

        print(
            f"  idx={idx:3d} bar_off={bar-FIRST_BAR:3d} "
            f"slot={[f'{b:02x}' for b in slot]} "
            f"prev_raw={[f'{b:02x}' for b in prev_bytes]} "
            f"target_price={op} target_raw={[f'{b:02x}' for b in target_bytes] if target_bytes else '?'}"
        )
        if target_bytes:
            # 统计 prev 和 target 的公共 LE 前缀长度（从低字节起算）
            # 以及 target 后缀在 slot 中的位置
            common = 0
            for i in range(4):
                if prev_bytes[i] == target_bytes[i]:
                    common += 1
                else:
                    break
            changed = 4 - common
            print(
                f"         prev→target 公共低位前缀={common}字节 "
                f"变化后缀={changed}字节 "
                f"后缀={[f'{b:02x}' for b in target_bytes[common:]]}"
            )
            # slot 里的非标记字节
            non_marker = [b for b in slot if b not in (0x00, 0x16)]
            print(
                f"         slot 非标记字节={[f'{b:02x}' for b in non_marker]} "
                f"target后缀={[f'{b:02x}' for b in target_bytes[common:]]} "
                f"匹配={'✓' if non_marker == target_bytes[common:] else '✗'}"
            )
        prev_raw = target_raw if target_raw else prev_raw


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    for code in ("000001", "000938"):
        brute_force_dt10_rule(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
