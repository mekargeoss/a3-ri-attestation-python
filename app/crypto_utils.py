# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import base64
import hashlib
import json

from app.model import Jkt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compute_jwk_thumbprint(jwk: dict) -> Jkt:
    """
    RFC 7638 JWK thumbprint
    Supports RSA and EC as commonly used in DPoP
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        ordered = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        ordered = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        ordered = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError("Unsupported kty for thumbprint")
    encoded = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return _b64url(hashlib.sha256(encoded).digest())
