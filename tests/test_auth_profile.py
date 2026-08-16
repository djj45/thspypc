"""Byte-stability contracts for authentication protocol profiles."""

import hashlib

from thspypc.features.auth_protocol import (
    DEFAULT_LOGIN_PROTOCOL_PROFILE,
    PC_LEVEL2_LOGIN_PROFILE,
    LoginIdentity,
    build_login_body,
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
    assert profile.name == "pc-level2-length-framed-verified"
    assert profile.account_type == b"\x00\x00\x06\x80\x00"
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
        "9a20d3627d803eb06bc33a552ec14b1f"
        "89ef2dc568e06ab95c3705337f820652"
    )
    assert int.from_bytes(standard[13:15], "little") == len(standard) - 14
    assert b"UserName=thsuser\nPassword=thsuser\n" in standard
    assert len(manual) == 288
    assert hashlib.sha256(manual).hexdigest() == (
        "65624c0659a3ab7eba8475ba8920354d"
        "3d9928a8eb9669b5ecc226dd72b3759b"
    )


def test_login_suffix_is_wire_tail_length_for_all_captured_generations():
    mac64 = "GHRdIuxqLKg7diotlao7dioNtao7diodpQ=="
    expected = {
        1676: b"\x58\x07",
        2296: b"\xc4\x09",
        2304: b"\xcc\x09",
        2316: b"\xd8\x09",
    }

    for passport_length, suffix in expected.items():
        body = build_login_body("A" * passport_length, mac64)
        assert body[13:15] == suffix
        assert int.from_bytes(suffix, "little") == len(body) - 14
