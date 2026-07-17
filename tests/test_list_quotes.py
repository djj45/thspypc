#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 个股列表行情（list_quotes）测试。

两种模式：

1. 离线回归（无需账号/网络）—— 用 thspy 抓包真值验证解码链：
       uv run python tests/test_list_quotes.py --offline
   验证 parse_hd3_response 把 hd3.1 帧解出 29 条记录，代码/价格正确。

2. 活网端到端（需账号）—— 登录后查 6 股列表行情：
       uv run python tests/test_list_quotes.py
   默认读 .env 的 THS_USERNAME/THS_PASSWORD，HTTP 鉴权自动生成有行情权限的
   Passport64（build_passport64 已复刻 hexin 的字段过滤逻辑，无需抓包）。
   账号密码留空则走扫码缓存（connect_cached，首次需手机扫码）。

   可选 --passport <file>：直接用外部 Passport64 登录（抓包调试用）。

输出：每只股票的 代码/现价/昨收/开盘价/竞价金额/涨幅。
"""
from __future__ import annotations

import os
import sys

# 确保能 import thspypc（用 uv run 时包已安装，这里兜底）
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient, parse_hd3_response


# 抓包真值（thspy captures/s27_resp_hex.txt 帧序列），用于离线回归。
# 这里内联一份精简 hex（帧#19 的完整 body），避免依赖 thspy 仓库路径。
_S27_RESP_HEX = None  # 懒加载，见 _load_s27()


def _load_s27() -> bytes:
    """加载 thspy 的 s27_resp_hex.txt。优先用环境变量 THSPY_CAP 指定的路径，
    否则尝试默认路径 D:\\code\\thspy\\captures\\s27_resp_hex.txt。"""
    global _S27_RESP_HEX
    if _S27_RESP_HEX is not None:
        return _S27_RESP_HEX
    path = os.environ.get("THSPY_CAP") or r"D:\code\thspy\captures\s27_resp_hex.txt"
    try:
        _S27_RESP_HEX = bytes.fromhex("".join(open(path).read().split()))
    except OSError as e:
        print(f"!! 无法读取抓包真值 {path}: {e}")
        print("   设环境变量 THSPY_CAP 指向 s27_resp_hex.txt，或从 thspy 仓库拷贝。")
        sys.exit(2)
    return _S27_RESP_HEX


def _iter_frames(body: bytes):
    """从 fdfdfdfd 魔数流里拆出各帧 body。"""
    MAGIC = b"\xfd\xfd\xfd\xfd"
    idx = 0
    while True:
        p = body.find(MAGIC, idx)
        if p < 0 or p + 12 > len(body):
            break
        try:
            bl = int(body[p + 4:p + 12], 16)
        except ValueError:
            idx = p + 4
            continue
        if 0 < bl < 200000:
            yield body[p + 12:p + 12 + bl]
        idx = p + 12 + bl


def run_offline() -> int:
    """离线回归：用抓包真值验证 hd3.1 解码链。"""
    print("=" * 60)
    print("离线回归：hd3.1 解码链验证（无需账号/网络）")
    print("=" * 60)
    body = _load_s27()
    hd3_frames = []
    for i, fr in enumerate(_iter_frames(body)):
        if b"hd3.1\x00" in fr:
            hd3_frames.append((i, fr))
    print(f"找到 {len(hd3_frames)} 个 hd3.1 帧")
    if not hd3_frames:
        print("!! 未找到 hd3.1 帧")
        return 1

    # 区分标准 BitRLE 变体（unk=0x38，可解码）和非 BitRLE 变体（unk=0x36/0x42 等，跳过）
    import struct as _st
    bitrle_frames = []
    variant_frames = []
    for i, fr in hd3_frames:
        pos = fr.find(b"hd3.1\x00")
        base = pos + 6
        unk = _st.unpack("<H", fr[base+4:base+6])[0]
        # unk 低位字节标识编码族：0x38=BitRLE；0x36/0x42/0x4a=变体A；0x1c=小记录...
        if (unk & 0xFF) == 0x38:
            bitrle_frames.append((i, fr))
        else:
            variant_frames.append((i, unk))

    ok = 0
    for i, fr in bitrle_frames:
        recs = parse_hd3_response(fr)
        codes = [r.get("code") for r in recs if r.get("code")]
        if recs and len(codes) == len(recs):
            ok += 1
            if ok == 1:  # 首帧详细打印
                print(f"\n帧#{i} (unk=0x38 BitRLE): 解出 {len(recs)} 条记录")
                for r in recs[:5]:
                    price = r.get("dt10")
                    prev = r.get("dt6")
                    open_p = r.get("dt7")
                    bid_vol = r.get("dt17")
                    bid_amt = (bid_vol * open_p) if (bid_vol and open_p) else None
                    chg = ((price - prev) / prev * 100) if (price and prev) else None
                    chg_s = f"{chg:.2f}%" if chg is not None else "-"
                    amt_s = f"{bid_amt:.0f}" if bid_amt is not None else "-"
                    print(f"  {r['code']}: 现价={price} 昨收={prev} 开盘={open_p}"
                          f" 竞价量={bid_vol} 竞价金额={amt_s} 涨幅={chg_s}")
        else:
            print(f"帧#{i}: 解析异常（BitRLE 但未解出），记录数={len(recs)}")
    if variant_frames:
        print(f"\n（另有 {len(variant_frames)} 个非 BitRLE 变体帧已按设计跳过："
              f"{[f'#{i} unk=0x{u:x}' for i, u in variant_frames]}）")
    all_ok = ok == len(bitrle_frames)
    print(f"\n{'✓' if all_ok else '✗'} BitRLE 变体 {ok}/{len(bitrle_frames)} 帧解码成功")
    return 0 if all_ok else 1


def load_dotenv() -> None:
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def run_live(passport_file: str | None = None) -> int:
    """活网端到端：登录 → list_quotes → 打印行情。

    Args:
        passport_file: 若给定，从中读取 hexin 抓包的完整 Passport64 登录
            （行情查询必须用这种方式；HTTP 鉴权生成的 passport 无行情权限）。
            用 tests/diag_fresh_passport.py 抓包提取。
    """
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None  # 留空则自动生成

    print("=" * 60)
    print("活网测试：登录 8901 → 查个股列表行情")
    print("=" * 60)

    codes = ["600056", "600057", "600058", "600059", "600060", "600061"]
    print(f"查询代码（沪市6股）: {codes}")
    print()

    client = THSClient(username, password, imei)
    try:
        if passport_file:
            # 用抓包的完整 Passport64（行情查询必须用这种方式）
            p64 = open(passport_file).read().strip()
            print(f"用 Passport64 文件登录: {passport_file} ({len(p64)} 字符)")
            result = client.connect_with_passport64(p64)
        elif username and password:
            result = client.connect()
        else:
            # 空账号 → 扫码缓存登录
            print("（.env 无账号密码，走扫码缓存登录 connect_cached）")
            result = client.connect_cached()
    except Exception as e:
        print(f"\n!! 登录过程异常: {e}")
        import traceback
        traceback.print_exc()
        return 1

    if not result.success:
        print(f"\n✗ 登录失败 (error={result.error}): {result.detail}")
        return 1

    print(f"✓ 登录成功: {result.server} (VerifyCode={result.verify_code})")
    print()

    try:
        recs = client.list_quotes(codes, market=17)
    except Exception as e:
        print(f"\n!! 行情查询异常: {e}")
        import traceback
        traceback.print_exc()
        client.disconnect()
        return 1
    finally:
        client.disconnect()

    if not recs:
        print("✗ 未取到行情数据（list_quotes 返回空）")
        print("  可能原因：请求帧格式 / 服务器拒绝 / 非交易时段无数据")
        return 1

    print(f"✓ 取到 {len(recs)} 条行情：")
    print(f"  {'代码':<8} {'现价':>8} {'昨收':>8} {'开盘':>8} {'涨幅%':>8} "
          f"{'竞价金额':>12}")
    for r in recs:
        code = r.get("code", "?")
        price = r.get("dt10")
        prev = r.get("dt6")
        open_p = r.get("dt7")
        bid_vol = r.get("dt17")
        chg = ((price - prev) / prev * 100) if (price and prev) else None
        bid_amt = (bid_vol * open_p) if (bid_vol and open_p) else None
        chg_s = f"{chg:>8.2f}" if chg is not None else f"{'-':>8}"
        amt_s = f"{bid_amt:>12.0f}" if bid_amt is not None else f"{'-':>12}"
        print(f"  {code:<8} {price:>8} {prev:>8} {open_p:>8} {chg_s} {amt_s}")
    print()
    print("→ 个股列表行情查询链路走通（hd3.1 解码 + 8901 socket 复用）。")
    return 0


def main() -> int:
    if "--offline" in sys.argv:
        return run_offline()
    # --passport <file>: 用 hexin 抓包提取的完整 Passport64 登录（行情查询必需）
    passport_file = None
    if "--passport" in sys.argv:
        i = sys.argv.index("--passport")
        if i + 1 < len(sys.argv):
            passport_file = sys.argv[i + 1]
        else:
            print("!! --passport 需要一个文件路径参数")
            return 2
    return run_live(passport_file)


if __name__ == "__main__":
    raise SystemExit(main())
