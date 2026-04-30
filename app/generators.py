# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import base64
import hashlib
import secrets

from app.model import (
    HandoffCode,
    LoginCode,
    Nonce,
    PkceChallenge,
    PkceVerifier,
    SessionToken,
    State,
)
from app.verifier.model import ChallengeNonce


def gen_session_token() -> SessionToken:
    return SessionToken(secrets.token_urlsafe(24))


def gen_login_code() -> LoginCode:
    return LoginCode(secrets.token_urlsafe(32))


def gen_handoff_code() -> HandoffCode:
    return HandoffCode(secrets.token_urlsafe(32))


def gen_challenge_nonce() -> ChallengeNonce:
    return ChallengeNonce(secrets.token_urlsafe(24))


def gen_state() -> State:
    return State(secrets.token_urlsafe(16))


def gen_nonce() -> Nonce:
    return Nonce(secrets.token_urlsafe(16))


def gen_pkce_challenge() -> tuple[PkceVerifier, PkceChallenge]:
    verifier = PkceVerifier(
        base64.urlsafe_b64encode(secrets.token_bytes(32))
        .rstrip(b"=")
        .decode("ascii")
    )
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = PkceChallenge(
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    )
    return verifier, challenge
