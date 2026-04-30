# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    verifier_secret: str
    andorid_package_name: str | None
    google_service_account_file: str | None
    android_attestation_profile: str | None
    ios_attestation_profile: str | None


@lru_cache
def get_settings() -> Settings:
    load_dotenv()

    def mandatory(var: str) -> str:
        value = os.getenv(var)
        if value is None:
            raise ValueError(f"{var} is missing")
        return value

    def optional(var: str) -> str | None:
        return os.getenv(var)

    return Settings(
        verifier_secret=mandatory("VERIFIER_SECRET"),
        andorid_package_name=optional("ANDROID_PACKAGE_NAME"),
        google_service_account_file=optional("GOOGLE_SERVICE_ACCOUNT_FILE"),
        android_attestation_profile=optional("ATTESTATION_PROFILE_ANDROID"),
        ios_attestation_profile=optional("ATTESTATION_PROFILE_IOS"),
    )


settings = get_settings()
