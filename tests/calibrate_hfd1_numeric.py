#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
用 list_quotes 真值校准 hfd1.0 数值字段偏移。

策略：
  1. 反复重试直到连上能响应 list_quotes 的 host
  2. 查几只股票的真值（价格、涨幅、最高、最低、开盘、金额、成交量）
  3. 在 hfd1.0 中找到这些股票的原始字节
  4. 逐偏移匹配 THS float 编码 → 精确定位每字段的字节偏移

用法：
    py tests/calibrate_hfd1_numeric.py
"""
from __future__ import annotations

import json
import os
import struct
import sys
import time

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


def try_connect_quote_host(username, password, imei, mac64, max_tries=5):
    """反复重连直到找到能响应 list_quotes 的 host。"""
    for attempt in range(max_tries):
        client = THSClient(username, password, imei=imei, mac64=mac64,
                           enable_heartbeat=False)
        r = client.connect()
        if not r.success:
            print(f"  尝试{attempt+1}: 登录失败 ({r.error})")
            continue
        # 验证能查 list_quotes
        try:
            test = client.list_quotes(["600000"], market=17, 
                                       datatype=[5, 10], timeout=8)
            if test and test[0].get("code") == "600000":
                print(f"  ✓ 尝试{attempt+1}: {r.server} 可用")
                return client
            else:
                print(f"  ✗ 尝试{attempt+1}: {r.server} list_quotes 返回空")
        except Exception as e:
            print(f"  ✗ 尝试{attempt+1}: {r.server} list_quotes 失败: {e}")
        client.disconnect()
    return None


def fetch_truth(client, codes):
    """采多只股票的真值。"""
    datatype = [5, 7, 8, 9, 10, 13, 18, 19, 48, 49]
    # 5=code, 7=最高, 8=最低, 9=开盘, 10=价格, 13=昨收
    # 18=总金额, 19=总手, 48=涨速, 49=涨跌幅
    truth = {}
    BATCH = 5
    for i in range(0, len(codes), BATCH):
        batch = codes[i:i+BATCH]
        try:
            recs = client.list_quotes(batch, market=17, datatype=datatype, timeout=10)
            for r in recs:
                code = r.get("code", "")
                if code:
                    truth[code] = {
                        "price": r.get("price"),
                        "change_pct": r.get("change_pct"),
                        "high": r.get("high"),
                        "low": r.get("low"),
                        "open": r.get("open"),
                        "prev_close": r.get("prev_close"),
                        "amount": r.get("amount"),
                        "volume": r.get("volume"),
                    }
        except Exception as e:
            print(f"  查询 {batch} 失败: {e}")
        time.sleep(0.2)
    return truth


def encode_ths_float(value: float) -> int | None:
    """将浮点值编码为 THS float LE32（用于反向搜索）。
    
    从 decode_ths_float 反推编码规则（验证过的）。
    """
    # 这是基于已知 THS float 格式的编码器
    # 格式：位31=符号, 位23-30=指数(偏移64), 位0-22=尾数
    if value == 0:
        return 0
    sign = 0 if value > 0 else 1
    v = abs(value)
    # 找到指数（使得 1 <= mantissa < 2）
    exp = 0
    while v >= 2:
        v /= 2
        exp += 1
    while v < 1:
        v *= 2
        exp -= 1
    # THS 指数偏移好像是 64
    exp_bias = 64
    exp_field = exp + exp_bias
    if exp_field < 0 or exp_field > 127:
        return None
    # 尾数（23位）
    mantissa = int((v - 1.0) * (1 << 23) + 0.5)
    if mantissa >= (1 << 23):
        mantissa = (1 << 23) - 1
    le32 = (sign << 31) | (exp_field << 23) | mantissa
    # 验证：解码应得到原始值
    decoded = decode_ths_float(le32)
    if abs(decoded - value) / max(abs(value), 1) > 0.01:
        return None  # 编码不精确
    return le32


def calibrate(hfd1, anchors, truth):
    """精确定位字段偏移。"""
    # 对每个有真值的股票
    offsets = {}  # {field_name: {offset: count}}
    for field in ["price", "change_pct", "high", "low", "open", "amount", "volume", "prev_close"]:
        offsets[field] = {}
    
    for code, t in truth.items():
        # 在 hfd1.0 中找到该股票
        a = next((x for x in anchors if x["code"] == code), None)
        if not a:
            continue
        pre = bytes.fromhex(a["pre_hex"])
        if pre[-1] != ord(code[-1]):
            continue
        
        name_gbk = a["name"].encode("gbk")
        name_end = a["name_offset"] + len(name_gbk)
        chunk = hfd1[name_end:name_end + 48]
        
        # 对每个真值字段，在 chunk 中搜索匹配的 THS float
        for field, expected in t.items():
            if expected is None:
                continue
            if isinstance(expected, float) and abs(expected) < 1e-10:
                continue
            
            # 尝试不同偏移
            for off in range(0, min(len(chunk) - 3, 44)):
                val = struct.unpack("<I", chunk[off:off+4])[0]
                try:
                    decoded = decode_ths_float(val)
                except:
                    continue
                # 允许 1% 误差
                if abs(expected) > 0:
                    error = abs(decoded - expected) / abs(expected)
                else:
                    error = abs(decoded)
                if error < 0.02:
                    key = f"{field}@{off}"
                    offsets[field][off] = offsets[field].get(off, 0) + 1
    
    return offsets


def main():
    _load_env()
    user = os.environ.get("THS_USERNAME", "").strip()
    pwd = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "")
    if not user or not pwd:
        print("✗ 未配置 .env")
        return 1
    
    # 1. 加载 hfd1.0 和锚点
    hfd1 = open(HFD1_PATH, "rb").read()
    anchors = json.load(open(os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")))
    print(f"hfd1.0: {len(hfd1):,}B, 锚点: {len(anchors)}")
    
    # 2. 连接采真值
    print("\n连接服务器采真值（自动重试 host）...")
    client = try_connect_quote_host(user, pwd, imei, None, max_tries=5)
    if not client:
        print("✗ 无法连到可用的 host")
        return 1
    
    # 采 20 只知名股票
    test_codes = [f"600{i:03d}" for i in range(0, 50, 3)]  # 600000, 600003, ...
    test_codes += ["600519", "600690", "600887", "600036", "600030",
                   "600104", "600276", "600085", "600048"]
    print(f"\n采 {len(test_codes)} 只股票的真值...")
    truth = fetch_truth(client, test_codes)
    client.disconnect()
    print(f"采到 {len(truth)} 只真值")
    
    # 3. 校准偏移
    print("\n校准字段偏移...")
    offsets = calibrate(hfd1, anchors, truth)
    
    print(f"\n=== 偏移校准结果 ===")
    for field in ["price", "change_pct", "high", "low", "open", "amount", "volume", "prev_close"]:
        off_counts = offsets[field]
        if off_counts:
            total = sum(off_counts.values())
            # 只显示匹配次数 > 1 的偏移
            significant = {k: v for k, v in sorted(off_counts.items(), key=lambda x: -x[1])}
            print(f"  {field}: {dict(significant)}")
        else:
            print(f"  {field}: (无匹配)")
    
    # 4. 输出每个有真值的股票的详细对照
    print(f"\n=== 逐股详细对照 ===")
    for code in sorted(truth.keys())[:5]:
        t = truth[code]
        a = next((x for x in anchors if x["code"] == code), None)
        if not a:
            continue
        pre = bytes.fromhex(a["pre_hex"])
        if pre[-1] != ord(code[-1]):
            continue
        
        name_gbk = a["name"].encode("gbk")
        name_end = a["name_offset"] + len(name_gbk)
        chunk = hfd1[name_end:name_end + 48]
        
        print(f"\n{code} {a['name']} @{a['name_offset']}")
        print(f"  名称后48B: {chunk.hex(' ')}")
        print(f"  真值对照:")
        for field in ["price", "change_pct", "high", "low", "open", "amount", "volume", "prev_close"]:
            ev = t.get(field)
            if ev is None:
                continue
            # 找到最佳匹配偏移
            best_off = None
            best_err = 999
            best_dv = None
            for off in range(0, min(len(chunk) - 3, 44)):
                val = struct.unpack("<I", chunk[off:off+4])[0]
                try:
                    dv = decode_ths_float(val)
                except:
                    continue
                if abs(ev) > 0:
                    err = abs(dv - ev) / abs(ev)
                else:
                    err = abs(dv)
                if err < best_err and err < 0.05:
                    best_err = err
                    best_off = off
                    best_dv = dv
            if best_off is not None:
                val = struct.unpack("<I", chunk[best_off:best_off+4])[0]
                print(f"    {field:12s}: 真值={ev:<14}  hfd1.0@{best_off}={best_dv:<14.4f} (err={best_err*100:.1f}%) val={val:#010x}")
            else:
                print(f"    {field:12s}: 真值={ev:<14}  未找到匹配")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
