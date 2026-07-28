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


PC_LEVEL2_LOGIN_PROFILE = LoginProtocolProfile(
    name="pc-level2-verified",
    product="E02",
    securities="同花顺统一版",
    http_version="9.60.20.0031",
    tcp_version="E029.60.20.0031",
    qsid="6800",
    account_type=bytes((0xBE, 0x06, 0x06, 0x80, 0x00)),
    supports_manual_identity=True,
)

# Keep the current verified profile as the default until ordinary-account
# captures establish whether any byte-affecting login parameter differs.
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
    payload = head128 + prefix_5b + b"\r\n".join(fields) + b"\r\n "
    return base64.b64encode(payload).decode()


def build_login_body(
    passport64: str,
    mac_b64: str,
    *,
    identity: LoginIdentity = LoginIdentity.STANDARD,
    profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
) -> bytes:
    """Build a TCP login body for a standard or ``__manual`` identity."""
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
    else:
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

    check_byte = (len(fixed) + 1) & 0xFF
    prefix = (
        b"\x09\x41\x09\x00"
        + b"zh_CN.GBK"
        + bytes([check_byte])
        + b"\x09"
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
