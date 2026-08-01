#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""诊断：打印 login 响应的完整字段，找推送权限标志。

hexin 某些连接收推送、某些不收，差别可能在 login 响应字段。
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from thspypc import THSClient
from thspypc.protocol import parse_login_response


def load_dotenv():
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip(); v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def main():
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None

    client = THSClient(username=username, password=password, imei=imei,
                       enable_heartbeat=False)
    try:
        # connect 会读 login 响应，我们需要在它内部捕获
        # 直接调用底层，拿原始 login 响应
        print("→ 登录...")
        result = client.connect()
        if not result.success:
            print(f"✗ 登录失败: {result.error}")
            return 1
        print(f"✓ 登录成功 {result.server}")
        print()
        print("=== login 响应字段 ===")
        for k, v in sorted(result.reply_fields.items()):
            print(f"  {k} = {v[:80]!r}")
        print()
        print("=== passport 权限字段 ===")
        for k, v in sorted(result.passport_fields.items()):
            if len(v) < 100:
                print(f"  {k} = {v!r}")
        print()
        # 重点找 push/Push/MarketCode/M_qs 相关
        print("=== 推送/权限相关字段 ===")
        for k, v in result.reply_fields.items():
            if any(x in k.lower() for x in ("push", "market", "qs", "level", "right", "auth")):
                print(f"  reply.{k} = {v[:80]!r}")
        for k, v in result.passport_fields.items():
            if any(x in k.lower() for x in ("push", "market", "qs", "level", "right", "auth")):
                print(f"  passport.{k} = {v[:80]!r}")
        return 0
    finally:
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
