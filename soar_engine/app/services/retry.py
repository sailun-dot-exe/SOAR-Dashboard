"""Async retry helper with exponential backoff (default: max 3 retries)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

import httpx

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryableError(Exception):
    """Transient failure (timeouts, 5xx, expired auth) worth retrying."""


class PermanentError(Exception):
    """Failure that retrying will not fix (agent offline, bad input, 4xx)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    RetryableError,
    httpx.TransportError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
)


@dataclass(slots=True)
class RetryOutcome(Generic[T]):
    value: T
    attempts: int


async def retry_async(
    func: Callable[[], Awaitable[T]],
    *,
    max_retries: int = 3,
    backoff_seconds: float = 0.5,
    label: str = "operation",
) -> RetryOutcome[T]:
    attempt = 0
    while True:
        attempt += 1
        try:
            return RetryOutcome(value=await func(), attempts=attempt)
        except PermanentError:
            raise
        except RETRYABLE_EXCEPTIONS as exc:
            if attempt > max_retries:
                logger.error("%s failed after %d attempts: %s", label, attempt, exc)
                raise
            delay = backoff_seconds * (2 ** (attempt - 1))
            logger.warning("%s attempt %d failed (%s); retrying in %.2fs",
                           label, attempt, exc, delay)
            await asyncio.sleep(delay)
