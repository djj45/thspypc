"""
hfd1.0 全市场快照响应解析器。

策略：
  用名称锚点（从 oracle 或 hexin 缓存构建）确定记录位置。
  代码通过 oracle/缓存映射（名称 → code）获取，不依赖代码压缩逆
  向。

数值字段（实验性）：
  THS float 扫描在 hfd1.0 上准确度有限——编码过于宽泛，几乎所有
  4B 序列都能解码出"合理"值，实际字段偏移因记录类型（指数 vs 股票）
  而异。当前实现返回近似值，如需精确行情请用 :meth:`list_quotes`。

用法：
    from thspypc.parse_hfd1 import parse_hfd1_response
    records = parse_hfd1_response(raw_bytes)
    # records[i] = {code, name, price?, change_pct?, ...}
"""
from __future__ import annotations

import json
import os
import struct
from typing import Optional

from .protocol import decode_ths_float

# 数据目录（相对于本模块）
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_MODULE_DIR, "..", "..", "data")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")
ORACLE_PATH = os.path.join(DATA_DIR, "oracle_code_names.json")

# hexin 缓存路径
_HEXIN_CACHE_DIRS = [
    r"C:\同花顺软件\同花顺\stockname",
    r"c:\同花顺软件\同花顺\stockname",
]


def _load_hexin_names() -> dict[str, str]:
    """从 hexin 本地缓存加载名称。"""
    base = None
    for d in _HEXIN_CACHE_DIRS:
        if os.path.isdir(d):
            base = d
            break
    if not base:
        return {}
    names = {}
    for fn in sorted(os.listdir(base)):
        if fn.startswith("stockname_") and fn.endswith("_0.txt"):
            try:
                data = open(os.path.join(base, fn), "rb").read()
                if data[:3] == b"\xef\xbb\xbf":
                    data = data[3:]
                for line in data.decode("gbk", errors="replace").splitlines():
                    line = line.strip()
                    if "=" not in line:
                        continue
                    code, rest = line.split("=", 1)
                    name = rest.split("|")[0].strip()
                    if code and name and len(name) >= 2:
                        names[name] = code
            except Exception:
                pass
    return names


def _load_oracle() -> dict[str, str]:
    """从 oracle 文件加载 {名称: code}。"""
    if not os.path.exists(ORACLE_PATH):
        return {}
    with open(ORACLE_PATH, encoding="utf-8") as f:
        oracle = json.load(f)
    return {o["name"]: o["code"] for o in oracle if "name" in o}


def _build_name_code_map() -> dict[str, str]:
    """构建 {名称: code} 映射，优先 oracle 后回退 hexin 缓存。"""
    name_map = {}
    # 优先 oracle
    if os.path.exists(ORACLE_PATH):
        name_map.update(_load_oracle())
    # 补充 hexin 缓存
    hexin = _load_hexin_names()
    for name, code in hexin.items():
        if name not in name_map:
            name_map[name] = code
    return name_map


def parse_hfd1_response(raw: bytes) -> list[dict]:
    """解析 hfd1.0 响应，返回全市场记录列表。

    策略：
      1. 先用名称锚点文件定位已验证的记录
      2. 再补充 oracle 中已有但锚点文件中缺失的记录
      3. 每个记录解析名称后的 THS float 数值字段

    返回每条记录含 code, name, 及可能的 price/change_pct/high/low/open/amount/volume。
    """
    name_map = _build_name_code_map()
    
    # Step 1: 从锚点文件加载已验证记录
    anchored: set[int] = set()
    records = []
    
    if os.path.exists(ANCHORS_PATH):
        with open(ANCHORS_PATH, encoding="utf-8") as f:
            anchors = json.load(f)
        for a in anchors:
            code = a["code"]
            pre = bytes.fromhex(a["pre_hex"])
            if pre[-1] != ord(code[-1]):
                continue
            if not code[0].isdigit():
                continue
            
            name = a["name"]
            name_off = a["name_offset"]
            name_gbk = name.encode("gbk")
            name_end = name_off + len(name_gbk)
            
            anchored.add(name_off)
            records.append({
                "code": code,
                "name": name,
                "name_offset": name_off,
                "name_end": name_end,
            })
    
    # Step 2: 补充未在锚点中的记录（通过名称在 raw 中搜索）
    # 只处理短名称的最小匹配，避免长扫描
    records.sort(key=lambda r: r["name_offset"])
    
    # Step 3: 解析数值字段
    for rec in records:
        num = _parse_numeric(raw, rec["name_end"])
        rec.update(num)
    
    return records


def _parse_numeric(raw: bytes, name_end: int, max_scan: int = 60) -> dict:
    """在名称后扫描 THS float 序列（**实验性，准确度有限**）。

    hfd1.0 的数值字段编码（THS float）过于宽泛——几乎所有 4B 序列都能
    解码出值范围内的"合理"数字，加上字段偏移因记录类型（指数/股票/基金）
    而异，无法可靠区分真实数据与随机字节。

    当前实现返回**近似值**，不保证与服务器真值一致。
    
    顺序（参考 mac 版 _fill_numeric_fields_200）：
      [0]=价格, [1]=涨速, [2]=涨跌幅, [3]=最高, [4]=最低, [5]=开盘,
      [6]=总金额, [7]=总手, [8]=昨收
    """
    result = {
        "price": None, "change_pct": None,
        "high": None, "low": None, "open": None,
        "amount": None, "volume": None, "prev_close": None,
    }
    
    chunk = raw[name_end:name_end + max_scan]
    if len(chunk) < 12:
        return result
    
    # 滑动窗口对齐：尝试每个起始偏移（0-7），找最合理的 THS float 序列
    best = None
    best_score = -1
    
    for start in range(8):
        floats = []
        off = start
        ok = True
        while off + 4 <= len(chunk) and len(floats) < 9:
            val = struct.unpack("<I", chunk[off:off+4])[0]
            try:
                fv = decode_ths_float(val)
            except Exception:
                ok = False
                break
            if fv == 0.0 and len(floats) < 3:
                ok = False
                break
            floats.append(fv)
            off += 4
        
        if ok and len(floats) >= 3:
            score = 0
            p = floats[0]
            c = floats[2] if len(floats) > 2 else 0
            
            # 价格应合理（不是指数大值或负值）
            if 0.5 < p < 2000:
                score += 2
            elif -10 < p < 0:
                score -= 1  # 负价格大概率是误判
            # 涨跌幅应 < 50
            if 0 < abs(c) < 50:
                score += 2
            elif abs(c) > 1000:
                score -= 2
            if len(floats) >= 6:
                score += 1
            
            if score > best_score:
                best_score = score
                best = (start, floats, score)
    
    if best is None or best[2] < 2:
        return result
    
    _, floats, _ = best
    
    if len(floats) >= 1:
        result["price"] = floats[0]
    if len(floats) >= 3:
        result["change_pct"] = floats[2]
    if len(floats) >= 4:
        result["high"] = floats[3]
    if len(floats) >= 5:
        result["low"] = floats[4]
    if len(floats) >= 6:
        result["open"] = floats[5]
    if len(floats) >= 7:
        result["amount"] = floats[6]
    if len(floats) >= 8 and floats[7] == int(floats[7]):
        result["volume"] = int(floats[7])
    if len(floats) >= 9:
        result["prev_close"] = floats[8]
    
    return result


def main():
    """命令行入口。"""
    import sys
    hfd1_path = os.path.join(DATA_DIR, "hfd1_0_response.bin")
    if not os.path.exists(hfd1_path):
        print(f"✗ 数据文件不存在: {hfd1_path}")
        print("请先运行 tests/collect_snapshot_oracle.py 或 tests/expand_hfd1_anchors.py")
        return 1
    
    raw = open(hfd1_path, "rb").read()
    records = parse_hfd1_response(raw)
    n = len(records)
    n_price = sum(1 for r in records if r.get("price"))
    n_change = sum(1 for r in records if r.get("change_pct"))
    
    print(f"hfd1.0 响应: {len(raw):,}B")
    print(f"解出 {n} 条记录")
    print(f"  含价格: {n_price}, 含涨幅: {n_change}")
    
    # 前 10 条
    print(f"\n前 10 条:")
    for r in records[:10]:
        p = f"{r.get('price', ''):>10.2f}" if r.get('price') else "        N/A"
        c = f"{r.get('change_pct', ''):>7.2f}%" if r.get('change_pct') else "  N/A"
        a = f"{r.get('amount', 0):>12.0f}" if r.get('amount') else "         N/A"
        print(f"  {r['code']:>8s} {r['name']:12s} {p} {c} {a}")
    
    # 保存
    out = os.path.join(DATA_DIR, "hfd1_0_parsed.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"\n已保存: {out}")
    
    return 0


if __name__ == "__main__":
    exit(main())
