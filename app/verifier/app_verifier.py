# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from typing import Any

from app.time.helpers import expires_after
from app.time.model import TTL, ExpiresAt
from app.verifier.ear import Appraisal
from app.verifier.model import ChallengeNonce, Platform, TrustworthinessTier
from app.verifier.play_integrity import (
    decode_integrity_token,
    parse_verdict,
    validate_nonce,
    verdict_to_appraisal,
)
from app.verifier.settings import settings


def calculate_expiry(appraisals: list[Appraisal]) -> ExpiresAt | None:
    if not appraisals:
        return None

    status_set = set(map(lambda appraisal: str(appraisal.status), appraisals))
    if TrustworthinessTier.NONE in status_set:
        return None
    elif TrustworthinessTier.CONTRAINDICATED in status_set:
        return expires_after(TTL(300))
    elif TrustworthinessTier.WARNING in status_set:
        return expires_after(TTL(3600))
    else:
        return expires_after(TTL(3600 * 24))


async def _verify_android_app(
    evidences: dict[str, Any] | None,
    expected_nonce: ChallengeNonce,
) -> Appraisal | None:
    if not evidences:
        return Appraisal("play-integrity", TrustworthinessTier.NONE, None)

    integrity_token = evidences.get("integrityToken")

    if not integrity_token:
        return Appraisal("play-integrity", TrustworthinessTier.NONE, None)

    if (
        integrity_token
        and settings.andorid_package_name
        and settings.google_service_account_file
    ):
        decoded = await decode_integrity_token(
            integrity_token=integrity_token,
            package_name=settings.andorid_package_name,
            service_account_file=settings.google_service_account_file,
        )
        verdict = parse_verdict(decoded)

        validate_nonce(
            verdict,
            expected_nonce=expected_nonce,
        )

        appraisal = verdict_to_appraisal(
            verdict,
            expected_package_name=settings.andorid_package_name,
        )
        return appraisal

    return Appraisal("play-integrity", TrustworthinessTier.NONE, None)


async def verify_app(
    platform: Platform,
    evidences: dict[str, Any] | None,
    expected_nonce: ChallengeNonce,
) -> Appraisal | None:
    match platform:
        case Platform.android:
            return await _verify_android_app(evidences, expected_nonce)
        case Platform.ios:
            # iOS stub
            return None
