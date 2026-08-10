#!/usr/bin/env python -tt
# -*- coding: utf-8 -*-
"""逐字节对比：抓包板块 login 帧 vs 本机生成的 login 帧。

探针：不入库（tests/_*.py 约定）。
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TSHARK = r"D:\software\Wireshark_4.6.7_Portable\Wireshark\WiresharkPortable64\App\Wireshark\tshark.exe"
MAGIC = b"\xfd\xfd\xfd\xfd"

from thspypc.client import THSClient  # noqa: E402
from thspypc.features.auth_protocol import build_passport64  # noqa: E402


def _run(args):
    r = subprocess.run(args, capture_output=True, timeout=240)
    return r.stdout.decode("utf-8", errors="replace")


def load_env(path: Path) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def captured_login(pcap_name: str, sid: int) -> bytes:
    pcap = ROOT / "captures_live" / pcap_name
    hexp = "".join(
        _run([TSHARK, "-r", str(pcap), "-Y",
              f"tcp.stream=={sid} and tcp.dstport==8901",
              "-T", "fields", "-e", "tcp.payload"]).split()
    )
    data = bytes.fromhex(hexp) if hexp else b""
    for sub in data.split(MAGIC):
        if len(sub) < 8:
            continue
        try:
            blen = int(sub[:8], 16)
        except ValueError:
            continue
        fb = sub[8:8 + blen]
        if b"Ask=login" in fb:
            return fb
    return b""


def build_board_login(passport64: str, mac64: str, profile) -> bytes:
    if profile.supports_manual_identity:
        fields = [
            "Ask=login",
            f"C-Version={profile.tcp_version}",
            "VerifyType=1",
            f"Mac64={mac64}",
            "C-SupportPushVer=1.0",
            "C-SupReqDataVer=hq6.0",
            "C-SupPushDataVer=hq6.0",
        ]
        fixed = ("\n".join(fields) + "\nPassport64=").encode("gbk")
        suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    else:
        fixed = (
            "Ask=login\n"
            f"C-Version={profile.tcp_version}\n"
            "UserName=__manual\r\n\n"
            "Password=__manual\r\n\n"
            "VerifyType=1\n"
            f"Mac64={mac64}\n"
            "C-SupportPushVer=1.0\n"
            "C-SupReqDataVer=hq6.0\n"
            "C-SupPushDataVer=hq6.0\n"
            "Passport64="
        ).encode("gbk")
        suffix = bytes([(len(fixed) + 1) & 0xFF]) + b"\x09"
    prefix = b"\x09\x41\x09\x00" + b"zh_CN.GBK" + suffix
    return prefix + fixed + passport64.encode("ascii")


def diff(a: bytes, b: bytes, label_a: str, label_b: str) -> None:
    print(f"{label_a}: {len(a)}B  {label_b}: {len(b)}B")
    n = min(len(a), len(b))
    diffs = []
    for i in range(n):
        if a[i] != b[i]:
            diffs.append(i)
    print(f"  前 {n} 字节中差异数: {len(diffs)}")
    if diffs:
        for i in diffs[:20]:
            print(f"    offset {i}: {a[i]:02x} vs {b[i]:02x}  "
                  f"({a[max(0,i-12):i+12]!r} vs {b[max(0,i-12):i+12]!r})")
    if len(a) != len(b):
        print(f"  长度差 {abs(len(a)-len(b))} 字节")
        extra = a[len(b):] if len(a) > len(b) else b[len(a):]
        print(f"  多出尾部: {extra[:80]!r}")


def main() -> int:
    env = load_env(ROOT / ".env")
    user, pwd = env.get("THS_USERNAME", ""), env.get("THS_PASSWORD", "")
    imei = env.get("THS_IMEI") or None
    client = THSClient(username=user, password=pwd, imei=imei)
    client.authenticate()
    material = client._auth_service.require_current()
    mine = build_board_login(
        material.passport64,
        client.mac64,
        material.profile,
    )
    cap = captured_login("system_blocks_20260801_132302.pcap", 2)
    diff(mine, cap, "mine", "captured")
    print("\n头部对比:")
    print("  mine    :", mine[:24].hex(" "))
    print("  captured:", cap[:24].hex(" "))
    # Passport64 长度对比（账号相同，应一致）
    m64 = mine.split(b"Passport64=", 1)[1]
    c64 = cap.split(b"Passport64=", 1)[1]
    print(f"  passport64: mine={len(m64)} captured={len(c64)} 相同前缀: {m64[:20] == c64[:20]}")
    client.disconnect()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
