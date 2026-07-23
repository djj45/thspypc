#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
改进 hfd1.0 解析器：对比已知 list_quotes 真值，校准数值字段偏移。

策略：
1. 用 list_quotes 查几只股票的精确行情 → 作为真值
2. 在 hfd1.0 中找到这些股票 → 校准每字段的偏移
3. 归纳通用偏移规则
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient
from thspypc.protocol import decode_ths_float

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
HFD1_PATH = os.path.join(DATA_DIR, "hfd1_0_response.bin")


def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


def fetch_quotes_truth(client: THSClient, codes: list[str]) -> dict:
    """用 list_quotes 查股票的精确行情作为真值。"""
    result = {}
    # 分批查询，每批 5 只
    for i in range(0, len(codes), 5):
        batch = codes[i:i+5]
        try:
            recs = client.list_quotes(batch, market=17, 
                                       datatype=[5, 7, 8, 9, 10, 13, 18, 19, 48, 49],
                                       timeout=10)
            for r in recs:
                code = r.get("code", "")
                if code:
                    result[code] = r
        except Exception as e:
            print(f"  查询 {batch} 失败: {e}")
    return result


def analyze_hfd1_truth(hfd1: bytes, anchors: list, truth: dict):
    """对比 hfd1.0 数值与真值，校准偏移。"""
    print("\n" + "=" * 70)
    print("【hfd1.0 数值 vs list_quotes 真值对照】")
    print("=" * 70)
    
    for a in sorted(anchors, key=lambda x: x["name_offset"]):
        code = a["code"]
        if code not in truth:
            continue
        t = truth[code]
        
        off = a["name_offset"]
        name_gbk = a["name"].encode("gbk")
        name_end = off + len(name_gbk)
        
        # 名称后 48B
        post = hfd1[name_end:name_end + 48]
        
        print(f"\n{code} {a['name']}")
        print(f"  名称后48B: {post.hex(' ')}")
        print(f"  真值: price={t.get('price')}, change={t.get('change_pct')}, "
              f"high={t.get('high')}, low={t.get('low')}, open={t.get('open')}, "
              f"amount={t.get('amount')}, volume={t.get('volume')}, prev_close={t.get('prev_close')}")
        
        # 逐 4B 尝试解码为 THS float，看是否匹配真值
        print(f"  逐4B THS float 解码:")
        for j in range(0, min(len(post) - 3, 44)):
            val = struct.unpack("<I", post[j:j+4])[0]
            try:
                fv = decode_ths_float(val)
                if abs(fv) < 1e-10 or abs(fv) > 1e12:
                    continue
                # 检查是否匹配任何真值
                matched = []
                for field, tv in [("price", t.get("price")), 
                                  ("change", t.get("change_pct")),
                                  ("high", t.get("high")),
                                  ("low", t.get("low")),
                                  ("open", t.get("open")),
                                  ("prev_close", t.get("prev_close"))]:
                    if tv is not None and abs(fv - tv) / max(abs(tv), 0.01) < 0.02:
                        matched.append(field)
                if matched:
                    print(f"    @{j}: {val:#010x} = {fv:.4f} ← {','.join(matched)}")
                else:
                    # 也显示金额/成交量
                    if abs(fv) > 10000:
                        print(f"    @{j}: {val:#010x} = {fv:.0f} (金额)")
                    elif 1 <= abs(fv) <= 10000000 and fv == int(fv):
                        print(f"    @{j}: {val:#010x} = {fv:.0f} (成交量)")
            except:
                pass


def main():
    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    if not user or not pwd:
        print("✗ 未配置账号")
        return 1
    
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(os.path.join(DATA_DIR, "hfd1_0_name_anchors.json"), encoding="utf-8"))
    
    # 选几只知名股票做真值对照
    test_codes = ["600000", "600004", "600005", "600006", "600007", "600008",
                  "600009", "600010", "600011", "600012", "600015", "600016",
                  "600019", "600028", "600030", "600036", "600048", "600085",
                  "600104", "600276", "600519", "600690", "600887",
                  "000001", "000002", "000333", "000651",
                  "002415", "002475", "300750",
                  "688981"]
    
    print(f"连接服务器采真值...")
    client = THSClient(user, pwd, enable_heartbeat=False)
    r = client.connect()
    if not r.success:
        print(f"✗ 登录失败: {r.error}")
        return 1
    print(f"✓ 登录: {r.server}")
    
    truth = fetch_quotes_truth(client, test_codes)
    print(f"采到 {len(truth)} 只真值")
    client.disconnect()
    
    analyze_hfd1_truth(hfd1, anchors, truth)
    return 0


if __name__ == "__main__":
    sys.exit(main())
