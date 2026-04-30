# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

import time

from app.time.model import TTL, ExpiresAt


def now() -> int:
    return int(time.time())


def expires_after(ttl: TTL) -> ExpiresAt:
    return ExpiresAt(now() + ttl)
