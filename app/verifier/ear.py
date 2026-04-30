# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import time
from typing import Any

from jose import jwt

from app.verifier.model import Appraisal, EarToken, TrustworthinessClaim

TW_CLAIM_NONE: TrustworthinessClaim = 0
TW_CLAIM_AFFIRMING: TrustworthinessClaim = 2
TW_CLAIM_WARNING: TrustworthinessClaim = 32
TW_CLAIM_CONTRAINDICATED: TrustworthinessClaim = 96


def build_ear_jwt(
    verifier_secret: str, appraisals: list[Appraisal]
) -> EarToken:
    claims: dict[str, Any] = dict()
    claims["eat_profile"] = "tag:ietf.org,2025-07:ear"
    claims["iat"] = int(time.time())

    verifier_id: dict[str, Any] = dict()
    verifier_id["developer"] = "ri-attestation-python"
    verifier_id["build"] = "0.0.1"
    claims["ear.verifier-id"] = verifier_id

    submods: dict[str, Any] = dict()
    for appraisal in appraisals:
        appraisal_obj: dict[str, Any] = dict()
        appraisal_obj["ear.status"] = appraisal.status
        appraisal_obj["ear.trustworthiness-vector"] = (
            appraisal.trustworthiness_vector
        )
        submods[appraisal.label] = appraisal_obj

    claims["submods"] = submods

    token = jwt.encode(claims, verifier_secret, algorithm="HS256")

    return EarToken(token)
