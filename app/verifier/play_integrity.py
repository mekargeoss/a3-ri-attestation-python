# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

from app.time.helpers import now
from app.verifier.ear import (
    TW_CLAIM_AFFIRMING,
    TW_CLAIM_CONTRAINDICATED,
    TW_CLAIM_NONE,
    TW_CLAIM_WARNING,
)
from app.verifier.model import (
    Appraisal,
    TrustworthinessClaim,
    TrustworthinessTier,
)

PLAYINTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"
DECODE_URL_TEMPLATE = "https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"


@dataclass
class PlayIntegrityVerdict:
    request_package_name: str
    nonce: str | None
    timestamp_ms: int


def _get_access_token(service_account_file: str) -> str:
    credentials = service_account.Credentials.from_service_account_file(
        service_account_file,
        scopes=[PLAYINTEGRITY_SCOPE],
    )
    credentials.refresh(GoogleAuthRequest())
    if not credentials.token:
        raise RuntimeError("Could not obtain Google access token")
    return cast(str, credentials.token)


async def decode_integrity_token(
    integrity_token: str,
    package_name: str,
    service_account_file: str,
) -> dict[str, Any]:
    token = _get_access_token(service_account_file)
    url = DECODE_URL_TEMPLATE.format(package_name=package_name)

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"integrity_token": integrity_token},
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


def parse_verdict(decoded: dict[str, Any]) -> PlayIntegrityVerdict:
    payload = decoded.get("tokenPayloadExternal") or {}
    request_details = payload.get("requestDetails") or {}

    timestamp_ms = int(request_details.get("timestampMillis") or 0)

    return PlayIntegrityVerdict(
        request_package_name=request_details.get("requestPackageName") or "",
        nonce=request_details.get("nonce"),
        timestamp_ms=timestamp_ms,
    )


def validate_nonce(
    verdict: PlayIntegrityVerdict,
    expected_nonce: str | None,
) -> None:
    if expected_nonce is not None and verdict.nonce != expected_nonce:
        raise ValueError("Integrity verdict nonce mismatch")


def verdict_to_appraisal(
    verdict: PlayIntegrityVerdict, expected_package_name: str
) -> Appraisal:
    affirming_age_ms: int = 2 * 60 * 1000
    warning_age_ms: int = 5 * 60 * 1000

    overall_status: TrustworthinessTier = TrustworthinessTier.AFFIRMING
    trustworthiness_vector: dict[str, TrustworthinessClaim] = dict()

    if verdict.request_package_name == expected_package_name:
        trustworthiness_vector["request-package-name"] = TW_CLAIM_AFFIRMING
    else:
        trustworthiness_vector["request-package-name"] = (
            TW_CLAIM_CONTRAINDICATED
        )
        overall_status = TrustworthinessTier.CONTRAINDICATED

    now_ms = int(now() * 1000)
    if verdict.timestamp_ms <= 0:
        trustworthiness_vector["timestamp-millis"] = TW_CLAIM_NONE
        overall_status = TrustworthinessTier.NONE
    elif now_ms - verdict.timestamp_ms < affirming_age_ms:
        trustworthiness_vector["timestamp-millis"] = TW_CLAIM_AFFIRMING
    elif now_ms - verdict.timestamp_ms < warning_age_ms:
        trustworthiness_vector["timestamp-millis"] = TW_CLAIM_WARNING
        overall_status = TrustworthinessTier.WARNING
    else:
        trustworthiness_vector["timestamp-millis"] = TW_CLAIM_CONTRAINDICATED
        overall_status = TrustworthinessTier.CONTRAINDICATED

    return Appraisal("play-integrity", overall_status, trustworthiness_vector)
