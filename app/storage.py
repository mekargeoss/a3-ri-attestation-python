# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from __future__ import annotations

from dataclasses import dataclass

from app.time.helpers import expires_after, now
from app.time.model import TTL, ExpiresAt
from app.verifier.model import ChallengeNonce

from .model import (
    AttestationResult,
    AuthorizationParameters,
    HandoffCode,
    Jkt,
    Jti,
    LoginCode,
    Session,
    SessionToken,
    State,
)


@dataclass
class ChallengeRecord:
    nonce: ChallengeNonce
    expires_at: ExpiresAt


@dataclass
class LoginCodeRecord:
    jkt: Jkt
    expires_at: ExpiresAt


@dataclass
class HandoffCodeRecord:
    session_token: SessionToken
    expires_at: ExpiresAt


_ATTESTATION_RESULTS: dict[Jkt, AttestationResult] = {}

_AUTHORIZATION_PARAMETERS: dict[State, AuthorizationParameters] = {}

_HANDOFF_CODES: dict[HandoffCode, HandoffCodeRecord] = {}

_LOGIN_CODES: dict[LoginCode, LoginCodeRecord] = {}

_SESSIONS: dict[SessionToken, Session] = {}

_DPOP_JTI_CACHE: dict[Jti, ExpiresAt] = {}

_CHALLENGES: dict[Jkt, ChallengeRecord] = {}


def put_attestation_result(jkt: Jkt, result: AttestationResult) -> None:
    _ATTESTATION_RESULTS[jkt] = result


def pop_attestation_result(jkt: Jkt) -> AttestationResult | None:
    return _ATTESTATION_RESULTS.pop(jkt, None)


def put_authz_parameters(state: State, data: AuthorizationParameters) -> None:
    _AUTHORIZATION_PARAMETERS[state] = data


def pop_authz_parameters(state: State) -> AuthorizationParameters | None:
    return _AUTHORIZATION_PARAMETERS.pop(state, None)


def put_login_code(code: LoginCode, jkt: Jkt, ttl: TTL) -> None:
    _LOGIN_CODES[code] = LoginCodeRecord(jkt=jkt, expires_at=expires_after(ttl))


def pop_login_code(code: LoginCode) -> Jkt | None:
    record = _LOGIN_CODES.pop(code, None)
    if not record:
        return None
    if record.expires_at < now():
        return None
    return record.jkt


def put_handoff_code(
    code: HandoffCode, session_token: SessionToken, ttl: TTL
) -> None:
    _HANDOFF_CODES[code] = HandoffCodeRecord(
        session_token=session_token, expires_at=expires_after(ttl)
    )


def pop_handoff_code(code: HandoffCode) -> SessionToken | None:
    record = _HANDOFF_CODES.pop(code, None)
    if not record:
        return None
    if record.expires_at < now():
        return None
    return record.session_token


def put_session(session_token: SessionToken, session: Session) -> None:
    _SESSIONS[session_token] = session


def get_session(session_token: SessionToken) -> Session | None:
    session = _SESSIONS.get(session_token)
    if not session:
        return None
    if session.expires_at < now():
        _SESSIONS.pop(session_token, None)
        return None
    return session


def revoke_session(session_token: SessionToken) -> None:
    _SESSIONS.pop(session_token, None)


def cache_dpop_jti(jti: Jti, ttl: TTL) -> bool:
    now_ts = now()
    expired_keys = [k for k, v in _DPOP_JTI_CACHE.items() if v < now_ts]
    for key in expired_keys:
        _DPOP_JTI_CACHE.pop(key, None)
    if jti in _DPOP_JTI_CACHE:
        return False
    _DPOP_JTI_CACHE[jti] = ExpiresAt(now_ts + ttl)
    return True


def put_challenge(jkt: Jkt, nonce: ChallengeNonce, ttl: TTL) -> None:
    _CHALLENGES[jkt] = ChallengeRecord(
        nonce=nonce, expires_at=expires_after(ttl)
    )


def pop_challenge(jkt: Jkt) -> ChallengeNonce | None:
    record = _CHALLENGES.pop(jkt, None)
    if not record:
        return None
    if record.expires_at < now():
        return None
    return record.nonce
