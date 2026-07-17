#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
二维码扫码登录端到端测试（带凭证缓存）。

用法:
    PYTHONPATH=src python tests/test_qr_login.py

流程:
    首次运行: 终端打印二维码 → 手机扫码（建议勾选「30天免登录」）→ 8901 登录
    后续运行: 读 ~/.ths_qr_credentials.json 免扫码秒登录
imei/Mac64 自动生成（已逆向），无需账号密码，无需抓包。
"""
from __future__ import annotations
import os, sys, logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient, generate_imei, generate_mac64


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    print("=" * 60)
    print("  同花顺二维码扫码登录测试")
    print("=" * 60)
    try:
        print(f"imei  (自动生成): {generate_imei()}")
        print(f"mac64 (自动生成): {generate_mac64()}")
    except Exception as e:
        print(f"!! 设备指纹生成失败: {e}")
        return 1
    print("=" * 60)

    # imei/mac64 都自动生成，THSClient 不传账号密码
    client = THSClient(username="", password="")
    # 二维码 PNG 备用路径（终端扫不了时用图片扫）
    import os
    png_path = os.path.join(os.path.dirname(__file__), "..", "qr_login.png")
    try:
        # connect_cached: 优先读缓存凭证，过期才弹二维码扫码
        result = client.connect_cached(qr_timeout=180, png_path=png_path)
    except Exception as e:
        print(f"\n!! 登录过程异常: {e}")
        import traceback; traceback.print_exc()
        return 1

    print("=" * 60)
    if result.passport_fields:
        pf = result.passport_fields
        sensitive = {"account", "userid", "msgcode", "imei"}
        print("  Passport 关键字段:")
        for key in ("account", "userclass", "qsuserclass", "M_qs",
                    "level2", "pro", "select", "userid"):
            if key in pf:
                val = pf[key]
                if key in sensitive and len(val) > 6:
                    val = val[:3] + "***" + val[-3:]
                print(f"    {key:14} = {val}")
    print("=" * 60)

    if result.success:
        print(f"\n✓ 扫码登录成功！服务器: {result.server}")
        print(f"  VerifyCode = {result.verify_code}")
        return 0
    else:
        print(f"\n✗ 登录失败: {result.error}")
        if result.detail:
            print(f"  详情: {result.detail}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
