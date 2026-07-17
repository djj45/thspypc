#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
对比「30天免登录」勾选/不勾选的差异。

用法:
    PYTHONPATH=src py tests/compare_remember.py

流程:
    1. 生成二维码 → 终端显示
    2. 手机扫码（注意：手机上会显示「30天免登录」勾选框）
    3. 每次轮询的完整 getInfoNew 响应都会实时打印 + 存盘
    4. 扫码成功后，把完整响应保存到 JSON 文件

跑两次：
    - 第一次：手机上不勾选 30 天 → 结果存 remember_off.json
    - 第二次：手机上勾选 30 天   → 结果存 remember_on.json
然后对比两个 JSON。

可选第二步验证（免扫码测试）：
    用相同 imei 再跑一次，看 getInfoNew 是否自动返回 status=3（不用手机扫）。
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import generate_imei, generate_mac64
from thspypc.qr_login import (
    UPASS_BASE,
    _session,
    create_qrcode,
    get_scan_url,
    render_qr_ascii,
)


def run_once(label: str, out_path: str) -> dict:
    """跑一次扫码流程，记录所有 getInfoNew 响应。"""
    print("=" * 64)
    print(f"  场景: {label}")
    print(f"  输出: {out_path}")
    print("=" * 64)

    # 打印设备指纹（用于判断免登录是否绑定 imei）
    try:
        imei = generate_imei()
        mac64 = generate_mac64()
        print(f"  imei:  {imei}")
        print(f"  mac64: {mac64}")
    except Exception as e:
        print(f"  !! 设备指纹生成失败: {e}")
        imei = "(unknown)"

    session = _session()

    # 1. 生成二维码
    print("\n正在生成二维码...")
    qrid = create_qrcode(session)
    url = get_scan_url(qrid)
    print(f"qrid: {qrid}")
    print(f"URL:  {url}\n")
    print("请用手机同花顺扫描 ↓")
    print("-" * 64)
    print(render_qr_ascii(url))
    print("-" * 64)
    print(f"\n>>> 手机扫码时，请{'勾选' if '勾选' in label else '不勾选'}「30天免登录」 <<<\n")

    # 2. 轮询，捕获每一次响应
    body = {
        "qrid": qrid,
        "state": "1",
        "source": "pc_web",
        "page_source": "web_screen",
        "request_type": "login",
    }

    responses = []
    attempt = 0
    deadline = time.time() + 180

    while time.time() < deadline:
        attempt += 1
        resp = session.post(f"{UPASS_BASE}/scan/getInfoNew", data=body, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        # 记录每次响应（含时间戳和轮询次数）
        entry = {
            "attempt": attempt,
            "ts": datetime.now().strftime("%H:%M:%S"),
            "status": data.get("status"),
            "response": data,
        }
        responses.append(entry)

        # 实时打印
        status = data.get("status")
        print(f"  [{entry['ts']}] attempt={attempt} status={status} "
              f"keys={sorted(data.keys())}")

        if status == 3:
            # 扫码成功
            account = data.get("account", "?")
            print(f"\n✓ 扫码成功！account={account}")
            print(f"  完整响应: {json.dumps(data, ensure_ascii=False, indent=2)}")
            break
        elif data.get("expired") == 0:
            print("\n✗ 二维码已过期")
            break

        time.sleep(4)

    # 3. 保存结果
    result = {
        "label": label,
        "qrid": qrid,
        "imei": imei,
        "url": url,
        "total_polls": attempt,
        "responses": responses,
        "final_response": responses[-1]["response"] if responses else None,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n已保存到 {out_path}")
    return result


def main() -> int:
    # 交互式选择场景
    print("对比「30天免登录」选项的差异\n")
    print("选择场景:")
    print("  1) 不勾选 30 天（结果存 remember_off.json）")
    print("  2) 勾选 30 天    （结果存 remember_on.json）")
    print("  3) 免扫码测试    （用相同 imei，看是否自动 status=3）")
    print("  4) 对比已有结果  （diff remember_off.json vs remember_on.json）")
    choice = input("\n选择 [1-4]: ").strip()

    out_dir = os.path.dirname(__file__)

    if choice == "1":
        run_once("不勾选30天", os.path.join(out_dir, "remember_off.json"))
    elif choice == "2":
        run_once("勾选30天", os.path.join(out_dir, "remember_on.json"))
    elif choice == "3":
        # 免扫码测试：直接 creatCode 然后轮询，不显示二维码
        print("\n免扫码测试（不显示二维码，直接轮询）...")
        print("如果服务器记得这台设备（imei），应立即返回 status=3\n")
        run_once("免扫码测试(相同imei)", os.path.join(out_dir, "remember_auto.json"))
    elif choice == "4":
        # 对比两个 JSON
        off_path = os.path.join(out_dir, "remember_off.json")
        on_path = os.path.join(out_dir, "remember_on.json")
        if not (os.path.exists(off_path) and os.path.exists(on_path)):
            print("需要先跑场景 1 和 2")
            return 1
        with open(off_path, encoding="utf-8") as f:
            off = json.load(f)
        with open(on_path, encoding="utf-8") as f:
            on = json.load(f)

        print("\n" + "=" * 64)
        print("对比结果")
        print("=" * 64)
        off_final = off.get("final_response") or {}
        on_final = on.get("final_response") or {}
        all_keys = sorted(set(off_final.keys()) | set(on_final.keys()))
        print(f"\n{'字段':<20} {'不勾选':<30} {'勾选30天':<30}")
        print("-" * 80)
        for k in all_keys:
            ov = str(off_final.get(k, "(无)"))[:28]
            nv = str(on_final.get(k, "(无)"))[:28]
            diff = "" if off_final.get(k) == on_final.get(k) else " ← 差异"
            print(f"{k:<20} {ov:<30} {nv:<30}{diff}")

        # 检查是否有新字段
        new_keys = set(on_final.keys()) - set(off_final.keys())
        if new_keys:
            print(f"\n勾选30天后多出的字段: {new_keys}")
        removed_keys = set(off_final.keys()) - set(on_final.keys())
        if removed_keys:
            print(f"勾选30天后少的字段: {removed_keys}")
    else:
        print("无效选择")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
