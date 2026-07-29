"""Offline contracts for shared authentication material."""

import pytest

from thspypc.features.auth_protocol import (
    DEFAULT_LOGIN_PROTOCOL_PROFILE,
    LoginIdentity,
    LoginProtocolProfile,
    PC_STANDARD_LOGIN_PROFILE,
    build_manual_login_body,
    build_passport64,
    build_standard_login_body,
)
from thspypc.protocol import (
    build_login_body_pc,
    build_manual_login_body as public_manual_login_body,
    build_passport64 as public_build_passport64,
)
from thspypc.services import AuthService


MAC64 = "GHRdIuxqLKg7diotlao7dioNtao7diodpQ=="


def _auth_payload(marker: str = "one") -> dict:
    return {
        "userid": "user-id",
        "sessionid": f"session-{marker}",
        "signature": "AB" * 128,
        "passport_bytes": (
            f"account=test|level2=|userclass=ordinary|sk={marker}|"
            "M_hq=drop-me|signlength=999"
        ).encode("gbk"),
    }


def test_auth_service_builds_one_immutable_material_generation():
    calls = []

    def authenticate(username, password, imei):
        calls.append((username, password, imei))
        return _auth_payload()

    service = AuthService(
        "ordinary-user",
        "secret",
        "device-id",
        MAC64,
        authenticator=authenticate,
    )

    material = service.authenticate()

    assert calls == [("ordinary-user", "secret", "device-id")]
    assert material.generation == 1
    assert material.profile is DEFAULT_LOGIN_PROTOCOL_PROFILE
    assert material.passport_fields["userclass"] == "ordinary"
    assert material.passport_fields["level2"] == ""
    assert service.current is material
    with pytest.raises(TypeError):
        material.passport_fields["level2"] = "1"


def test_all_connection_identities_consume_the_same_passport_generation():
    service = AuthService(
        "user",
        "secret",
        "device",
        MAC64,
        authenticator=lambda *_args: _auth_payload(),
    )
    material = service.authenticate()

    standard = service.login_body(LoginIdentity.STANDARD)
    manual = service.login_body(LoginIdentity.MANUAL)

    assert standard == build_standard_login_body(material.passport64, MAC64)
    assert manual == build_manual_login_body(material.passport64, MAC64)
    assert material.passport64.encode("ascii") in standard
    assert material.passport64.encode("ascii") in manual


def test_refresh_atomically_replaces_the_current_generation():
    payloads = iter((_auth_payload("first"), _auth_payload("second")))
    service = AuthService(
        "user",
        "secret",
        "device",
        MAC64,
        authenticator=lambda *_args: next(payloads),
    )

    first = service.authenticate()
    second = service.authenticate()

    assert first.generation == 1
    assert second.generation == 2
    assert first.passport64 != second.passport64
    assert service.current is second
    assert first.auth_info["sessionid"] == "session-first"


def test_verified_standard_signature_selects_captured_login_bytes():
    payload = _auth_payload()
    payload["passport_bytes"] = (
        b"account=test|userclass=10000|level2=255|sk=normal"
    )
    service = AuthService(
        "user",
        "secret",
        "device",
        MAC64,
        authenticator=lambda *_args: payload,
    )

    material = service.authenticate()
    body = service.login_body()

    assert material.profile is PC_STANDARD_LOGIN_PROFILE
    assert service.profile is PC_STANDARD_LOGIN_PROFILE
    assert material.passport64.startswith("6AQGgA")
    assert (
        b"UserName=thsuser\nPassword=thsuser\nVerifyType=1"
        in body
    )
    assert body[:15] == (
        b"\x09\x41\x09\x00zh_CN.GBK\x58\x07"
    )
    with pytest.raises(ValueError, match="does not support manual"):
        service.login_body(LoginIdentity.MANUAL)


def test_future_ordinary_profile_can_disable_manual_identity_explicitly():
    ordinary_profile = LoginProtocolProfile(
        name="pc-standard-capture-placeholder",
        product="ordinary-product",
        securities="ordinary-securities",
        http_version="ordinary-http",
        tcp_version="ordinary-tcp",
        qsid="ordinary-qsid",
        account_type=b"\x01\x02\x03\x04\x05",
        supports_manual_identity=False,
    )
    service = AuthService(
        "user",
        "secret",
        "device",
        MAC64,
        authenticator=lambda *_args: _auth_payload(),
        profile=ordinary_profile,
    )
    material = service.authenticate()

    assert b"C-Version=ordinary-tcp" in service.login_body()
    assert material.profile is ordinary_profile
    with pytest.raises(ValueError, match="does not support manual"):
        service.login_body(LoginIdentity.MANUAL)


def test_protocol_compatibility_exports_are_the_extracted_functions():
    passport64 = build_passport64(_auth_payload())

    assert public_build_passport64 is build_passport64
    assert build_login_body_pc is build_standard_login_body
    assert public_manual_login_body is build_manual_login_body
    assert passport64.encode("ascii") in build_login_body_pc(
        passport64,
        MAC64,
    )
