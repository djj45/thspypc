"""Authentication material lifecycle shared by all connection roles."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from ..features.auth_protocol import (
    DEFAULT_LOGIN_PROTOCOL_PROFILE,
    LoginIdentity,
    LoginProtocolProfile,
    build_login_body,
    build_passport64,
    parse_passport_fields,
)

HttpAuthenticator = Callable[[str, str, str | None], dict]


@dataclass(frozen=True)
class AuthMaterial:
    """Immutable view of one HTTP-authenticated passport generation."""

    auth_info: Mapping[str, object]
    passport_fields: Mapping[str, str]
    passport64: str
    profile: LoginProtocolProfile
    generation: int

    @property
    def passport_bytes(self) -> bytes:
        value = self.auth_info.get("passport_bytes", b"")
        if isinstance(value, str):
            return value.encode()
        return value if isinstance(value, bytes) else b""

    def login_body(
        self,
        mac64: str,
        identity: LoginIdentity = LoginIdentity.STANDARD,
    ) -> bytes:
        return build_login_body(
            self.passport64,
            mac64,
            identity=identity,
            profile=self.profile,
        )

    def legacy_auth_info(self) -> dict:
        """Return the mutable dict historically exposed as ``client._auth``."""
        return dict(self.auth_info)


class AuthService:
    """Own HTTP passport refreshes and role-specific login body construction.

    Account capability classification deliberately does not happen here.
    Passport fields are evidence only; the account evidence recorder promotes or
    rejects capabilities after the corresponding connection behavior is seen.
    """

    def __init__(
        self,
        username: str,
        password: str,
        imei: str | None,
        mac64: str,
        *,
        authenticator: HttpAuthenticator,
        profile: LoginProtocolProfile = DEFAULT_LOGIN_PROTOCOL_PROFILE,
    ):
        self._username = username
        self._password = password
        self._imei = imei
        self._mac64 = mac64
        self._authenticator = authenticator
        self._profile = profile
        self._generation = 0
        self._current: AuthMaterial | None = None

    @property
    def current(self) -> AuthMaterial | None:
        return self._current

    @property
    def profile(self) -> LoginProtocolProfile:
        return self._profile

    def authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
    ) -> AuthMaterial:
        auth_info = self._authenticator(
            username if username is not None else self._username,
            password if password is not None else self._password,
            self._imei,
        )
        passport_fields = parse_passport_fields(
            auth_info.get("passport_bytes", b"")
        )
        self._generation += 1
        material = AuthMaterial(
            auth_info=MappingProxyType(dict(auth_info)),
            passport_fields=MappingProxyType(passport_fields),
            passport64=build_passport64(auth_info, profile=self._profile),
            profile=self._profile,
            generation=self._generation,
        )
        self._current = material
        return material

    def require_current(self) -> AuthMaterial:
        if self._current is None:
            raise RuntimeError("HTTP authentication material is not available")
        return self._current

    def login_body(
        self,
        identity: LoginIdentity = LoginIdentity.STANDARD,
    ) -> bytes:
        return self.require_current().login_body(self._mac64, identity)

    def login_body_for_passport(
        self,
        passport64: str,
        identity: LoginIdentity = LoginIdentity.STANDARD,
    ) -> bytes:
        return build_login_body(
            passport64,
            self._mac64,
            identity=identity,
            profile=self._profile,
        )
