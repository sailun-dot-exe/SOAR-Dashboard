"""Header-token authentication and HMAC-signed HITL decision links."""

from __future__ import annotations

import hashlib
import hmac
import time


def constant_time_equals(provided: str | None, expected: str) -> bool:
    return provided is not None and hmac.compare_digest(provided.encode(), expected.encode())


class LinkSigner:
    def __init__(self, key: str) -> None:
        self._key = key.encode()

    def sign(self, incident_id: str, decision: str, expires_at: int) -> str:
        message = f"{incident_id}:{decision}:{expires_at}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, incident_id: str, decision: str, expires_at: int, signature: str) -> bool:
        if expires_at < int(time.time()):
            return False
        return hmac.compare_digest(self.sign(incident_id, decision, expires_at), signature)
