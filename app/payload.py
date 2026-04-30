# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from typing import Any

from pydantic import BaseModel

from app.model import HandoffCode, Jkt, Platform, SessionToken
from app.time.model import ExpiresAt
from app.verifier.model import ChallengeNonce


class AttestationChallengeRequest(BaseModel):
    public_jwk: dict[str, Any]


class AttestationChallengeResponse(BaseModel):
    jkt: Jkt
    nonce: ChallengeNonce


class AttestationVerifyRequest(BaseModel):
    jkt: Jkt
    platform: Platform
    evidences: dict[str, Any] | None = None
    device_info: dict[str, Any] | None = None


class AttestationVerifyResponse(BaseModel):
    login_start_url: str


class AuthFinishRequest(BaseModel):
    app_handoff_code: HandoffCode


class SessionTokenResponse(BaseModel):
    session_token: SessionToken
    expires_at: ExpiresAt


class ErrorResponse(BaseModel):
    detail: str
