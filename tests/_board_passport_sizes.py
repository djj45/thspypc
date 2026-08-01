#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""多次 HTTP 鉴权，统计 passport64 长度分布并对比 2304/2316 内容。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from thspypc.client import THSClient  # noqa: E402


def load_env(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def decode_fields(passport64: str) -> bytes:
    return base64.b64decode(passport64)


def main():
    env = load_env(ROOT / ".env")
    client = THSClient(env["THS_USERNAME"], env["THS_PASSWORD"],
                       env.get("THS_IMEI") or None)
    seen = {}
    for i in range(6):
        material = client._auth_service.authenticate()
        n = len(material.passport64)
        seen.setdefault(n, material.passport64)
        print(f"auth#{i}: passport64 len={n} signature={material.auth_info.get('signature', '')[:24]}")
    for n, p64 in sorted(seen.items()):
        raw = decode_fields(p64)
        head = raw[:133]
        fields = raw[133:]
        print(f"\nlen={n}: head128+prefix {len(head)}B, fields {len(fields)}B")
        print(f"  head hex: {head[:24].hex(' ')}...")
        print(f"  fields: {fields[:160]!r}...")
    client.disconnect()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
