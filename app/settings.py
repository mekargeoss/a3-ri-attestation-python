# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    issuer_path: str
    client_id: str
    client_secret: str
    redirect_uri: str
    resource_uri: str
    base_url: str
    deeplink_url: str


@lru_cache
def get_settings() -> Settings:
    load_dotenv()

    def mandatory(var: str) -> str:
        value = os.getenv(var)
        if value is None:
            raise ValueError(f"{var} is missing")
        return value

    return Settings(
        issuer_path=mandatory("ISSUER_PATH"),
        client_id=mandatory("CLIENT_ID"),
        client_secret=mandatory("CLIENT_SECRET"),
        redirect_uri=mandatory("REDIRECT_URI"),
        resource_uri=mandatory("RESOURCE_URI"),
        base_url=mandatory("BASE_URL"),
        deeplink_url=mandatory("DEEPLINK_URL"),
    )


settings = get_settings()
