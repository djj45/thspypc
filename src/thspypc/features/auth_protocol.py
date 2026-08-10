"""Authentication protocol profiles and byte-stable login contracts."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class LoginIdentity(str, Enum):
    """TCP login identity used by a managed connection role."""

    STANDARD = "standard"
    MANUAL = "manual"
    BOARD = "board"
    L2 = "l2"


@dataclass(frozen=True)
class LoginProtocolProfile:
    """Byte-affecting parameters for HTTP verification and TCP login."""

    name: str
    product: str
    securities: str
    http_version: str
    tcp_version: str
    qsid: str
    account_type: bytes
    supports_manual_identity: bool
    standard_username: str | None = None
    standard_password: str | None = None
    login_header_suffix: bytes | None = None


PC_LEVEL2_LOGIN_PROFILE = LoginProtocolProfile(
    name="pc-level2-verified",
    product="E02",
    securities="同花顺统一版",
    http_version="9.60.20.0031",
    tcp_version="E029.60.20.0031",
    qsid="6800",
    account_type=bytes((0xC8, 0x06, 0x06, 0x80, 0x00)),
    supports_manual_identity=True,
    standard_username="thsuser",
    standard_password="thsuser",
)

PC_STANDARD_LOGIN_PROFILE = LoginProtocolProfile(
    name="pc-standard-verified",
    product="E02",
    securities="同花顺统一版",
    http_version="9.60.20.0031",
    tcp_version="E029.60.20.0031",
    qsid="6800",
    account_type=bytes((0xE8, 0x04, 0x06, 0x80, 0x00)),
    supports_manual_identity=False,
    standard_username="thsuser",
    standard_password="thsuser",
    login_header_suffix=b"\x58\x07",
)

DEFAULT_LOGIN_PROTOCOL_PROFILE = PC_LEVEL2_LOGIN_PROFILE


PASSPORT_DROP_FIELDS = frozenset({
    "M_hq",
    "M_hqdns",
    "M_wg",
    "M_zx",
    "UpdateSvr",
    "download",
    "Foss_url",
    "DownloadSelfStock",
    "UploadSelfStock",
    "signlength",
})


def signature_to_nibbles(signature: str) -> bytes:
    """Decode the server signature into the legacy byte representation."""
    decoded = bytearray()
    for index in range(len(signature) // 2):
        even = ord(signature[index * 2])
        odd = ord(signature[index * 2 + 1])
        decoded.append((even + (odd << 4) - 0x51) & 0xFF)
    return bytes(decoded)


def build_head128(
    signature: str,
    *,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> tuple[bytes, bytes]:
    """Build the 128-byte account header and five-byte passport prefix."""
    decoded = signature_to_nibbles(signature)
    return profile.account_type + decoded[:123], decoded[123:128]


def parse_passport_fields(passport_bytes: bytes | str) -> dict[str, str]:
    """Parse server passport evidence without inferring account capability."""
    if isinstance(passport_bytes, str):
        passport_bytes = passport_bytes.encode()
    result: dict[str, str] = {}
    for field in passport_bytes.split(b"|"):
        text = field.decode("gbk", errors="replace")
        if "=" in text:
            key, _, value = text.partition("=")
            result[key.strip()] = value.strip()
    return result


def select_login_profile(
    passport_fields: Mapping[str, str],
    *,
    fallback: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> LoginProtocolProfile:
    """Select a byte-verified profile from the paired account signature."""
    userclass = passport_fields.get("userclass", "").strip()
    level2 = passport_fields.get("level2", "").strip()
    if userclass == "10000" and level2 == "255":
        return PC_STANDARD_LOGIN_PROFILE
    if userclass == "30002" and level2 == "16;32;48":
        return PC_LEVEL2_LOGIN_PROFILE
    return fallback


def build_passport64(
    auth_info: Mapping[str, object],
    mac_b64: str = "",
    *,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> str:
    """Build the filtered Passport64 value consumed by TCP login."""
    del mac_b64  # Historical compatibility parameter; not part of the bytes.
    signature = str(auth_info.get("signature", ""))
    passport_bytes = auth_info.get("passport_bytes", b"")
    if isinstance(passport_bytes, str):
        passport_bytes = passport_bytes.encode()
    if not isinstance(passport_bytes, bytes):
        raise TypeError("passport_bytes must be bytes or str")

    head128, prefix_5b = build_head128(signature, profile=profile)
    fields = [
        field
        for field in passport_bytes.split(b"|")
        if field.split(b"=", 1)[0]
        .decode("gbk", errors="replace")
        .strip()
        not in PASSPORT_DROP_FIELDS
    ]
    payload = head128 + prefix_5b + b"\r\n".join(fields) + b"\r\n\x00"
    return base64.b64encode(payload).decode()


def build_login_body(
    passport64: str,
    mac_b64: str,
    *,
    identity: LoginIdentity = LoginIdentity.STANDARD,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> bytes:
    """Build a TCP login body for a standard/``__manual``/board identity."""
    if identity is LoginIdentity.MANUAL:
        if not profile.supports_manual_identity:
            raise ValueError(
                f"login profile {profile.name!r} does not support manual identity"
            )
        fixed = (
            "Ask=login\n"
            f"C-Version={profile.tcp_version}\n"
            "UserName=__manual\r\n\n"
            "Password=__manual\r\n\n"
            "VerifyType=1\n"
            f"Mac64={mac_b64}\n"
            "C-SupportPushVer=1.0\n"
            "C-SupReqDataVer=hq6.0\n"
            "C-SupPushDataVer=hq6.0\n"
            "Passport64="
        ).encode("gbk")
    elif identity is LoginIdentity.L2:
        # L2 push 通道（shlv2/szlv2）的 login 壳：2026-08-10 hexin 抓包字节级确认。
        # 无 UserName/Password，7 字段 + Passport64，与 BOARD+supports_manual_identity
        # 结构相同但走 L2 行情服务器（非 fu4）。check 走通用 fallback（+13）。
        fields = [
            ("Ask", "login"),
            ("C-Version", profile.tcp_version),
            ("VerifyType", "1"),
            ("Mac64", mac_b64),
            ("C-SupportPushVer", "1.0"),
            ("C-SupReqDataVer", "hq6.0"),
            ("C-SupPushDataVer", "hq6.0"),
        ]
        fixed = (
            "\n".join(f"{key}={value}" for key, value in fields)
            + "\nPassport64="
        ).encode("gbk")
    elif identity is LoginIdentity.BOARD:
        # 板块专用通道（fu4 服务器）的 login 壳，2026-08-01 双账号抓包字节级确认：
        #   - Level2 账号（PC_LEVEL2，supports_manual_identity=True）：
        #     **无 UserName/Password**，直接 VerifyType=1 + Mac64 + 版本行 +
        #     Passport64；suffix = 计算 check 字节 + 0x09（抓包 ``aa 09``）。
        #   - 普通账号（PC_STANDARD，supports_manual_identity=False）：
        #     UserName=__manual/Password=__manual（\r\n\n 分隔），
        #     suffix 固定 ``5e 07``（抓包字节；不同于 MAIN 的 ``58 07``）。
        if profile.supports_manual_identity:
            fields = [
                ("Ask", "login"),
                ("C-Version", profile.tcp_version),
                ("VerifyType", "1"),
                ("Mac64", mac_b64),
                ("C-SupportPushVer", "1.0"),
                ("C-SupReqDataVer", "hq6.0"),
                ("C-SupPushDataVer", "hq6.0"),
            ]
            fixed = (
                "\n".join(f"{key}={value}" for key, value in fields)
                + "\nPassport64="
            ).encode("gbk")
            suffix = bytes([(len(fixed) + 13) & 0xFF, 0x09])
        else:
            fixed = (
                "Ask=login\n"
                f"C-Version={profile.tcp_version}\n"
                "UserName=__manual\r\n\n"
                "Password=__manual\r\n\n"
                "VerifyType=1\n"
                f"Mac64={mac_b64}\n"
                "C-SupportPushVer=1.0\n"
                "C-SupReqDataVer=hq6.0\n"
                "C-SupPushDataVer=hq6.0\n"
                "Passport64="
            ).encode("gbk")
            suffix = b"\x5e\x07"
    else:
        fields = [
            ("Ask", "login"),
            ("C-Version", profile.tcp_version),
        ]
        if profile.standard_username is not None:
            fields.append(("UserName", profile.standard_username))
        if profile.standard_password is not None:
            fields.append(("Password", profile.standard_password))
        fields.extend([
            ("VerifyType", "1"),
            ("Mac64", mac_b64),
            ("C-SupportPushVer", "1.0"),
            ("C-SupReqDataVer", "hq6.0"),
            ("C-SupPushDataVer", "hq6.0"),
        ])
        fixed = (
            "\n".join(f"{key}={value}" for key, value in fields)
            + "\nPassport64="
        ).encode("gbk")

    if identity is not LoginIdentity.BOARD:
        suffix = profile.login_header_suffix
    if suffix is None:
        suffix = bytes([(len(fixed) + 13) & 0xFF, 0x09])
    prefix = (
        b"\x09\x41\x09\x00"
        + b"zh_CN.GBK"
        + suffix
    )
    return prefix + fixed + passport64.encode("ascii")


def build_standard_login_body(
    passport64: str,
    mac_b64: str,
    *,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> bytes:
    return build_login_body(
        passport64,
        mac_b64,
        identity=LoginIdentity.STANDARD,
        profile=profile,
    )


def build_manual_login_body(
    passport64: str,
    mac_b64: str,
    *,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> bytes:
    return build_login_body(
        passport64,
        mac_b64,
        identity=LoginIdentity.MANUAL,
        profile=profile,
    )


def parse_login_response(body: bytes) -> dict[str, str]:
    """Parse the text fields in a TCP login response."""
    text_start = body.find(b"Reply=")
    if text_start < 0:
        return {"raw": body.hex()}
    text = body[text_start:].decode("gbk", errors="replace")
    result: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result
