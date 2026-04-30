# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, NewType

from pydantic import Field

EarToken = NewType("EarToken", str)

ChallengeNonce = NewType("ChallengeNonce", str)


class Platform(StrEnum):
    ios = "ios"
    android = "android"


class TrustworthinessTier(StrEnum):
    """The four tiers defined in draft-ietf-rats-ar4si-08 §2.3"""

    NONE = "none"
    AFFIRMING = "affirming"
    WARNING = "warning"
    CONTRAINDICATED = "contraindicated"

    def __str__(self) -> str:
        return self.value


TrustworthinessClaim = Annotated[
    int, Field(ge=-128, le=127, description="Signed 8-bit integer")
]


@dataclass
class Appraisal:
    label: str
    status: TrustworthinessTier
    trustworthiness_vector: dict[str, TrustworthinessClaim] | None
