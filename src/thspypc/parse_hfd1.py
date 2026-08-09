"""
hfd1.0 全市场快照响应解析器。

策略：
  用名称锚点（从 oracle 或 hexin 缓存构建）确定记录位置。
  代码通过 oracle/缓存映射（名称 → code）获取，不依赖代码压缩逆
  向。

当前语料对应的请求只有 ``DataType=[5],[55]``，因此响应只包含代码和名称。
名称后的字节属于后续压缩记录，不能当作 THS float 数值区扫描。精确行情请用
``list_quotes``；研究数值字段前必须先采集带行情 datatype 的独立 HFD1 响应。

用法：
    from thspypc.parse_hfd1 import parse_hfd1_response
    records = parse_hfd1_response(raw_bytes)
    # records[i] = {code, name, name_offset, name_end}
"""
from __future__ import annotations

import json
import os

# 数据目录（相对于本模块）
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_MODULE_DIR, "..", "..", "data")
ANCHORS_PATH = os.path.join(DATA_DIR, "hfd1_0_name_anchors.json")


def parse_hfd1_response(raw: bytes) -> list[dict]:
    """解析 hfd1.0 响应，返回全市场记录列表。

    策略：
      1. 用名称锚点文件定位已验证的记录
      2. 在当前响应中重新核对每个名称字节，拒绝错位或其他语料

    返回每条记录的 code/name 与原始名称偏移。当前 ``[5,55]`` 语料不含行情
    datatype，故绝不从名称后的压缩流猜测 price/change_pct 等数值字段。
    """
    if b"hfd1.0" not in raw:
        return []
    # 从锚点文件加载已验证记录
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
            if raw[name_off:name_end] != name_gbk:
                continue
            
            records.append({
                "code": code,
                "name": name,
                "name_offset": name_off,
                "name_end": name_end,
            })
    
    records.sort(key=lambda r: r["name_offset"])
    
    return records


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
    print(f"hfd1.0 响应: {len(raw):,}B")
    print(f"解出 {n} 条记录")
    
    # 前 10 条
    print(f"\n前 10 条:")
    for r in records[:10]:
        print(f"  {r['code']:>8s} {r['name']:12s}")
    
    # 保存
    out = os.path.join(DATA_DIR, "hfd1_0_parsed.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"\n已保存: {out}")
    
    return 0


if __name__ == "__main__":
    exit(main())
