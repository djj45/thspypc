#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""把新引导 builders 的输出与 pcap 抓包帧逐字节对比。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\软件\Wireshark-4.4.7-x64-with-Npcap-1.50-Portable\Wireshark\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.features.system_blocks_protocol import (  # noqa: E402
    build_board_classification_query,
    build_board_market_init,
    build_board_pageid_register,
    build_board_qureal_init,
    build_board_stockname_query,
    build_board_subreal_registration,
)


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def extract(pcap_name: str, sid: int) -> list[bytes]:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              f"tcp.stream=={sid} and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    data = bytes.fromhex(hexp) if hexp else b""
    frames = []
    for sub in data.split(MAGIC):
        if len(sub) >= 8:
            try:
                blen = int(sub[:8], 16)
            except ValueError:
                blen = 0
            frames.append(sub[8:8 + blen])
    return frames


def cmp(tag: str, mine: bytes, cap: bytes, exact: bool = True) -> None:
    match = mine == cap
    print(f"{tag}: mine={len(mine)}B cap={len(cap)}B "
          f"{'✓ 完全一致' if match else '✗ 不同'}")
    if not match:
        n = min(len(mine), len(cap))
        diffs = [i for i in range(n) if mine[i] != cap[i]]
        print(f"  前 {n} 字节中 {len(diffs)} 处差异" + 
              (f"，前 5: {[(i, mine[i], cap[i]) for i in diffs[:5]]}" if diffs else ""))
        if len(mine) != len(cap):
            print(f"  长度差 {abs(len(mine)-len(cap))}")
        if not exact:
            # 内容级对比
            mt = mine.decode("gbk", "replace")
            ct = cap.decode("gbk", "replace")
            print(f"  mine head: {mt[:80]!r}")
            print(f"  cap  head: {ct[:80]!r}")


def main():
    for level2, pcap, sid in (
        (True, "system_blocks_20260801_132302.pcap", 2),
        (False, "system_blocks_20260801_132439.pcap", 2),
    ):
        frames = extract(pcap, sid)
        print(f"===== level2={level2} {pcap} =====")
        # subreal 单帧
        sub_mine = build_board_subreal_registration(level2)[0]
        cmp("subreal[0]", sub_mine, frames[1], exact=False)
        # pageid register（与抓包首子帧内容对比）
        reg_mine = build_board_pageid_register(level2)
        reg_cap = frames[16] if level2 else frames[22]
        cmp("pageid-reg", reg_mine, reg_cap, exact=False)
        # MKT_INIT（结构对比，StockLinkVer 版本值不同）
        init_mine = build_board_market_init(level2)
        init_cap = frames[17] if level2 else frames[31]
        cmp("mkt-init", init_mine, init_cap, exact=False)
        # qureal-init 首帧（结构对比）
        q_mine = build_board_qureal_init(level2)[0]
        q_cap = frames[18] if level2 else frames[32]
        cmp("qureal-init[0]", q_mine, q_cap, exact=False)
        # [5],[55] 分类表（应逐字节一致）
        cls_mine = build_board_classification_query(level2)
        cls_cap = frames[56] if level2 else frames[65]
        cmp("classify[5],[55]", cls_mine, cls_cap)
        if cls_mine != cls_cap:
            mt_raw = cls_mine[23:]
            ct_raw = cls_cap[23:]
            print(f"    文本字节数: mine={len(mt_raw)} cap={len(ct_raw)}")
            print(f"    mine tail: {mt_raw[-24:]!r}")
            print(f"    cap  tail: {ct_raw[-24:]!r}")
            mt = cls_mine.decode("gbk", "replace")
            ct = cls_cap.decode("gbk", "replace")
            print(f"    mine text: {mt!r}")
            print(f"    cap  text: {ct!r}")
            n = min(len(mt), len(ct))
            diffs = [i for i in range(n) if mt[i] != ct[i]]
            print(f"    文本差异: {len(diffs)} 处 {[(i, repr(mt[i]), repr(ct[i])) for i in diffs[:8]]}")
            if len(mt) != len(ct):
                tail = (ct if len(ct) > len(mt) else mt)[n:]
                print(f"    多出尾部: {tail!r}")
        # StockNameVer（结构对比）
        sn_mine = build_board_stockname_query(level2)
        sn_cap = frames[62] if level2 else frames[84]
        cmp("stockname", sn_mine, sn_cap, exact=False)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
