# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import time
from typing import Any

from jose import jwt

from app.a3_client import A3Issuer
from app.crypto_utils import compute_jwk_thumbprint
from app.model import Jkt
from app.storage import cache_dpop_jti
from app.time.model import TTL


class InvalidDPoP(Exception):
    pass


class InvalidToken(Exception):
    pass


def validate_dpop_jwt(
    dpop_header: str,
    method: str,
    url: str,
    expected_jkt: str,
    clock_skew: int = 300,
) -> tuple[Jkt, dict]:
    """
    Verify a DPoP proof.
    """
    if not dpop_header:
        raise InvalidDPoP("Missing DPoP header")

    header = jwt.get_unverified_header(dpop_header)
    jwk = header.get("jwk")
    if not jwk:
        raise InvalidDPoP("DPoP header missing jwk")

    jkt = compute_jwk_thumbprint(jwk)
    if jkt != expected_jkt:
        raise InvalidDPoP("DPoP key thumbprint mismatch")

    claims = jwt.decode(
        dpop_header, jwk, algorithms=[header.get("alg", "ES256")]
    )

    htm = claims.get("htm")
    htu = claims.get("htu")
    iat = claims.get("iat")
    jti = claims.get("jti")

    if not (htm and htu and iat and jti):
        raise InvalidDPoP("DPoP claims incomplete")

    if htm.upper() != method.upper():
        raise InvalidDPoP("DPoP htm mismatch")

    if htu != url:
        raise InvalidDPoP("DPoP htu mismatch")

    now_ts = int(time.time())
    if abs(now_ts - int(iat)) > clock_skew:
        raise InvalidDPoP("DPoP iat outside acceptable window")

    if not cache_dpop_jti(jti, TTL(300)):
        raise InvalidDPoP("DPoP jti replayed")

    return (jkt, claims)


def validate_token_jwt(
    token: str,
    issuer: A3Issuer,
    nonce: str | None,
    jwks: dict[str, Any],
    expected_aud: str,
) -> dict[str, Any]:
    def find_jwk(jwks: dict[str, Any], kid: str | None):
        for key in jwks.get("keys", []):
            if key.get("kid") == kid or kid is None:
                return key
        return None

    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    key = find_jwk(jwks, kid)
    if not key:
        raise InvalidToken("No matching JWK found")

    options = {
        "verify_signature": True,
        "verify_iss": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
    }

    claims: dict[str, Any] = jwt.decode(
        token,
        key,
        algorithms=key.get("alg", "RS256") if key.get("alg") else "RS256",
        audience=expected_aud,
        issuer=issuer.issuer_url(),
        options=options,
    )

    claim_nonce = claims.get("nonce")
    if claim_nonce is not None and nonce is not None and claim_nonce != nonce:
        raise InvalidToken("Invalid nonce")

    now = int(time.time())
    if claims.get("exp", 0) < now:
        raise InvalidToken("ID Token expired")

    return claims
