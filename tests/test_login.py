#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
thspypc 端到端登录测试。

设备相关参数（THS_IMEI / THS_MAC64）需从抓包 login 帧的 passport 里取。
用 D:\\code\\ths\\compare_login.py 解析 login_lv2.pcapng 即可看到 imei 字段；
Mac64 在 login 帧明文里直接可见。

用法：
    # 方式 1：.env 文件（推荐）
    #   THS_USERNAME=账号
    #   THS_PASSWORD=密码
    #   THS_IMEI=4F7033C974D54C5CA39626B497CBEF54   (32位hex, 从抓包 passport 取)
    #   THS_MAC64=GHRdIuxqLKg7diotlao7dioNtao7diodpQ==  (从抓包 login 帧取)
    uv run python tests/test_login.py

    # 方式 2：交互输入
    uv run python tests/test_login.py

输出：完整的 HTTP 鉴权诊断 + 8901 登录结果，并明确区分失败类型。
"""
from __future__ import annotations

import getpass
import os
import sys

# 确保能 import thspypc（用 uv run 时包已安装，这里兜底）
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc import THSClient


def load_dotenv() -> None:
    """加载项目根目录的 .env 文件到 os.environ（已有环境变量不覆盖）。

    手动解析，不引入 python-dotenv 依赖。仅支持 KEY=VALUE 格式。
    """
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


def get_credentials() -> tuple[str, str, str | None]:
    """从 .env / 环境变量 / 交互输入读取账号/密码。imei/Mac64 均可自动生成。"""
    load_dotenv()
    username = os.environ.get("THS_USERNAME", "").strip()
    password = os.environ.get("THS_PASSWORD", "").strip()
    imei = os.environ.get("THS_IMEI", "").strip() or None  # 留空则自动生成

    if not username:
        username = input("账号: ").strip()
    if not password:
        password = getpass.getpass("密码: ").strip()

    if not (username and password):
        print("!! 账号、密码不能为空")
        sys.exit(2)
    return username, password, imei


def print_passport_diag(fields: dict) -> None:
    """打印 passport 关键字段（脱敏），用于判断账号类型/权限。"""
    if not fields:
        print("  (passport 无字段)")
        return
    # 脱敏的字段
    sensitive = {"account", "userid", "msgcode", "imei"}
    print("  Passport 关键字段:")
    for key in ("account", "userclass", "qsuserclass", "M_qs",
                "level2", "pro", "select", "userid"):
        if key in fields:
            val = fields[key]
            if key in sensitive and len(val) > 6:
                val = val[:3] + "***" + val[-3:]
            print(f"    {key:14} = {val}")


def main() -> int:
    username, password, imei = get_credentials()
    print(f"\n账号: {username[:2]}***")

    # imei 自动生成（已逆向：MD5(MAC大写连字符 + "0"*30)）
    from thspypc import generate_imei, generate_mac64
    if imei is None:
        try:
            imei = generate_imei()
            print(f"imei (自动生成): {imei}")
        except Exception as e:
            print(f"!! imei 自动生成失败: {e}")
            return 1
    else:
        print(f"imei (来自.env): {imei[:8]}...")

    # Mac64 自动生成（已逆向：base64(0x18 + 前4网卡MAC)）
    try:
        mac64 = generate_mac64()
        print(f"Mac64 (自动生成): {mac64}")
    except Exception as e:
        print(f"!! Mac64 自动生成失败: {e}")
        return 1
    print("=" * 60)

    client = THSClient(username, password, imei)  # mac64 默认自动生成
    try:
        result = client.connect()
    except Exception as e:
        print(f"\n!! 登录过程异常: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("=" * 60)
    print_passport_diag(result.passport_fields)
    print("=" * 60)

    if result.success:
        print(f"\n✓ 登录成功！服务器: {result.server}")
        print(f"  VerifyCode = {result.verify_code}")
        if result.reply_fields:
            print(f"  响应字段: {result.reply_fields}")
        print("\n  → PC 免费版 8901 登录链路走通。")
        print("  → 下一步可加行情查询（K线/盘口/逐笔）。")
        return 0
    else:
        print(f"\n✗ 登录失败 (error={result.error})")
        print(f"  VerifyCode = {result.verify_code or '(无)'}")
        if result.server:
            print(f"  服务器: {result.server}")
        if result.detail:
            print(f"  详情: {result.detail}")
        if result.reply_fields:
            print(f"  响应字段: {result.reply_fields}")
        print()
        # 明确区分失败类型 + 下一步建议
        if result.error == "http_auth_failed":
            print("  诊断: HTTP 三步鉴权就失败了。")
            print("    - 检查账号/密码是否正确")
            print("    - 检查网络能否访问 auth.10jqka.com.cn")
        elif result.error == "all_hosts_failed":
            print("  诊断: 所有 8901 服务器 IP 都连不上。")
            print("    - 检查网络/防火墙是否放行 8901 端口")
            print("    - 服务器 IP 可能已变更，需重新抓包取最新 IP")
        elif result.error == "login_rejected":
            print("  诊断: TCP 连上了、收到响应了，但 passport 被拒 (VerifyCode != 0)。")
            print("    → 这说明 Mac 至尊版参数拿到的 passport 不被 PC 版 8901 服务器接受。")
            print("    → 下一步需要用 Frida hook hexin.exe 的 hssl.dll，")
            print("      抓 mainverify 的真实 PC 参数 (product/qsid/version)。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
