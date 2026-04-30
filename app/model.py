# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from dataclasses import dataclass
from typing import Annotated, NewType

from pydantic import Field

from app.time.model import ExpiresAt
from app.verifier.model import Appraisal, Platform

Jkt = Annotated[str, Field(min_length=43, max_length=43)]

Jti = NewType("Jti", str)

Nonce = NewType("Nonce", str)

State = NewType("State", str)

LoginCode = NewType("LoginCode", str)

HandoffCode = NewType("HandoffCode", str)

SessionToken = NewType("SessionToken", str)

AuthorizationCode = NewType("AuthorizationCode", str)

PkceVerifier = NewType("PkceVerifier", str)

PkceChallenge = NewType("PkceChallenge", str)


@dataclass
class AuthorizationParameters:
    jkt: Jkt
    nonce: Nonce
    pkce_verifier: PkceVerifier


@dataclass
class AttestationResult:
    created_at: int
    platform: Platform
    appraisals: list[Appraisal]
    expires_at: ExpiresAt


@dataclass
class Session:
    jkt: Jkt
    user_name: str | None
    user_email: str | None
    scopes: list[str]
    expires_at: ExpiresAt
