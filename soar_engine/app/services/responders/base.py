"""Responder interface shared by all containment back-ends."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(slots=True)
class ResponderResult:
    target: str
    status_code: int | None
    response: dict[str, Any] = field(default_factory=dict)


class Responder(Protocol):
    name: str

    async def execute(self, params: dict[str, Any]) -> ResponderResult:
        """Perform one attempt. Raise RetryableError / PermanentError on failure."""
        ...


def validated_ip(value: Any) -> str:
    """Strictly validate an IP to avoid command/argument injection in responders."""
    from app.services.retry import PermanentError

    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise PermanentError(f"invalid IP address: {value!r}") from exc
