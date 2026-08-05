#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""破译 4214 盘口推送帧的十档字段布局（离线分析 depth_push_anchor_*.json）。

配合 ``capture_kanpan_push.py --depth-anchor`` 使用。后者在盘中抓包时，
在 t=10/30/60s 三个锚点提示用户截图同花顺盘口面板，并把每个锚点 ±2s 的
snapshot4214 推送帧存入 JSON。本脚本读取 JSON，辅助破译十档字段。

破译方法
--------
1. 用户事后提供截图（或用 vision 读图），给出每个锚点时刻的十档数字
   （买1-5 价/量，卖1-5 价/量）
2. 本脚本在每个锚点的推送帧字节里，反查这些已知值（ths_float / LE16 / LE32）
   的出现位置
3. 跨多个锚点交叉验证，归纳出稳定的字段偏移表
4. 判定：全量快照（每帧含完整十档）vs 增量推送（每帧只含变化档位）

当前状态：骨架。读 JSON + 打印帧概览 + 截图清单。
字段反查逻辑待用户提供截图数字后迭代。

用法
----
    py tests/analyze_depth_push.py captures_live/depth_push_anchor_000938_*.json

产物：终端报告（帧字节概览 + 待填的十档数字 + 反查候选）。
"""
import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.codecs.numeric import decode_ths_float  # noqa: E402


def _scan_value_in_frame(frame_hex, target_float, label):
    """在帧字节里反查一个已知 ths_float 值的所有出现位置。

    返回 [(offset, raw_hex, decoded)] 列表。
    """
    frame = bytes.fromhex(frame_hex)
    hits = []
    for off in range(len(frame) - 3):
        raw = frame[off:off + 4]
        val = struct.unpack("<I", raw)[0]
        decoded = decode_ths_float(val)
        # 精确匹配或 ±0.5% 范围
        if target_float != 0 and abs(decoded - target_float) <= abs(target_float) * 0.005:
            hits.append((off, raw.hex(" "), round(decoded, 4)))
    return hits


def analyze(json_path):
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    code = data["code"]
    pcap = data["pcap"]
    anchors = data["anchors"]
    shots = data.get("screenshot_names", [])

    print(f"{'='*64}")
    print(f"破译 4214 盘口推送帧十档字段")
    print(f"{'='*64}")
    print(f"股票: {code}")
    print(f"pcap: {pcap}")
    print(f"锚点数: {len(anchors)}")
    print()

    # ── 截图清单 ──
    print(f"【1】截图清单（ground truth 来源）")
    print(f"{'-'*64}")
    for i, shot in enumerate(shots, 1):
        shot_path = ROOT / "captures_live" / shot
        exists = "✓已存" if shot_path.exists() else "✗未存"
        anchor = anchors[i - 1] if i - 1 < len(anchors) else {}
        print(f"  锚点 {i} (t={anchor.get('anchor_t','?')}s): {shot} [{exists}]")
    print()
    print("请提供每张截图的十档数字（格式示例）：")
    print("  买1: 37.75 / 200手   买2: 37.74 / 150手 ... 买5: 37.70 / 80手")
    print("  卖1: 37.76 / 180手   卖2: 37.77 / 120手 ... 卖5: 37.80 / 60手")
    print()

    # ── 帧概览 ──
    print(f"【2】推送帧概览")
    print(f"{'-'*64}")
    total = 0
    for i, anchor in enumerate(anchors, 1):
        frames = anchor["frames"]
        total += len(frames)
        print(f"  锚点 {i} (t={anchor['anchor_t']}s): {len(frames)} 帧")
        if frames:
            # 打印首帧 hex + 关键偏移
            f0 = frames[0]
            print(f"    首帧 ({f0['len']}B): {f0['hex'][:96]}...")
            # 已知字段：价(+58)、量(+62)、tick(+39)
            raw = bytes.fromhex(f0["hex"])
            if len(raw) >= 64:
                price58 = struct.unpack("<H", raw[58:60])[0] / 1000.0
                vol62 = struct.unpack("<H", raw[62:64])[0]
                print(f"    已知: 价(+58)={price58:.3f} 量(+62)={vol62} tick(+39)=0x{raw[39]:02x}")
    print(f"\n总推送帧: {total}")
    if total == 0:
        print("  ✗ 无推送帧，无法破译。需重新抓包（见 capture_kanpan_push.py --depth-anchor）")
        return
    print()

    # ── 反查框架（待用户填入十档数字后激活）──
    print(f"【3】字段反查（待填入截图十档数字后激活）")
    print(f"{'-'*64}")
    print("将截图里的十档数字填入下面的 dict，重新运行本脚本即可自动反查字节位置：")
    print()
    print("  # 在本脚本底部 GROUND_TRUTH 处填入（每个锚点一份）")
    print("  # 然后运行: py tests/analyze_depth_push.py <json> --reverse")
    print()

    # ── 帧大小分布（判断全量 vs 增量）──
    print(f"【4】帧大小分布（判断全量 vs 增量格式）")
    print(f"{'-'*64}")
    all_sizes = []
    for anchor in anchors:
        for f in anchor["frames"]:
            all_sizes.append(f["len"])
    if all_sizes:
        from collections import Counter
        size_dist = Counter(all_sizes)
        print(f"  帧大小: {dict(sorted(size_dist.items()))}")
        if len(size_dist) == 1:
            print(f"  → 全部 {list(size_dist)[0]}B 定长 → 可能是全量快照")
        else:
            print(f"  → 多种大小 → 可能是增量推送（每帧只含变化档位）")
    print()

    # ── 反查模式 ──
    if "--reverse" in sys.argv:
        _reverse_lookup(anchors)


def _reverse_lookup(anchors):
    """用 GROUND_TRUTH 里的已知十档数字，反查帧内字节位置。"""
    print(f"\n{'='*64}")
    print(f"【反向查找】已知十档数字 → 帧内字节位置")
    print(f"{'='*64}")
    for i, anchor in enumerate(anchors, 1):
        gt = GROUND_TRUTH.get(i, {})
        if not gt:
            print(f"\n锚点 {i}: 未填入十档数字（GROUND_TRUTH[{i}] 为空），跳过")
            continue
        print(f"\n锚点 {i} (t={anchor['anchor_t']}s):")
        frames = anchor["frames"]
        if not frames:
            print("  无推送帧")
            continue
        f0 = frames[0]
        for label, value in gt.items():
            hits = _scan_value_in_frame(f0["hex"], value, label)
            if hits:
                print(f"  {label}={value}: 命中 {len(hits)} 处")
                for off, hexs, decoded in hits[:3]:
                    print(f"    +{off}: {hexs} → {decoded}")
            else:
                print(f"  {label}={value}: 未命中（可能增量帧不含此值，或编码不同）")


# ── 用户填入截图十档数字（每个锚点一份）──
# 格式: {锚点编号: {"买1价": 37.75, "买1量": 200, "卖1价": 37.76, ...}}
# 从截读取数字后填这里，然后运行: py tests/analyze_depth_push.py <json> --reverse
GROUND_TRUTH = {
    # 1: {
    #     "买1价": 37.75, "买1量": 200,
    #     "买2价": 37.74, "买2量": 150,
    #     "卖1价": 37.76, "卖1量": 180,
    #     "卖2价": 37.77, "卖2量": 120,
    # },
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("json", help="depth_push_anchor_*.json 路径")
    args = ap.parse_args()
    if not Path(args.json).exists():
        print(f"✗ 文件不存在: {args.json}")
        sys.exit(1)
    analyze(args.json)


if __name__ == "__main__":
    main()
