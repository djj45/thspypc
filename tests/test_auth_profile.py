"""Byte-stability contracts for authentication protocol profiles."""

import hashlib

from thspypc.features.auth_protocol import (
    DEFAULT_LOGIN_PROTOCOL_PROFILE,
    PC_LEVEL2_LOGIN_PROFILE,
    LoginIdentity,
)
from thspypc.protocol import (
    ACCOUNT_TYPE,
    C_VERSION_PC,
    PRODUCT,
    QSID,
    SECURITIES,
    VERSION_HTTP,
    build_login_body_pc,
    build_manual_login_body,
)


def test_default_profile_preserves_current_protocol_constants():
    profile = DEFAULT_LOGIN_PROTOCOL_PROFILE

    assert profile is PC_LEVEL2_LOGIN_PROFILE
    assert profile.name == "pc-level2-verified"
    assert profile.supports_manual_identity
    assert PRODUCT == profile.product
    assert SECURITIES == profile.securities
    assert VERSION_HTTP == profile.http_version
    assert C_VERSION_PC == profile.tcp_version
    assert QSID == profile.qsid
    assert ACCOUNT_TYPE == profile.account_type
    assert LoginIdentity.STANDARD.value == "standard"
    assert LoginIdentity.MANUAL.value == "manual"


def test_level2_standard_and_manual_login_frame_bytes():
    passport64 = "A" * 64
    mac64 = "GHRdIuxqLKg7diotlao7dioNtao7diodpQ=="

    standard = build_login_body_pc(passport64, mac64)
    manual = build_manual_login_body(passport64, mac64)

    assert len(standard) == 282
    assert hashlib.sha256(standard).hexdigest() == (
        "62c3138f4c418e466eb9ade102ce3ef8"
        "52530241cd00788d01504d1b19ada06e"
    )
    assert b"UserName=thsuser\nPassword=thsuser\n" in standard
    assert len(manual) == 288
    assert hashlib.sha256(manual).hexdigest() == (
        "0083c97726421118ec4a3459bef7e55"
        "247c6ca2ab437af93856b442a4f4bec26"
    )
