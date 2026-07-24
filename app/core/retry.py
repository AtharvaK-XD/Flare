"""Async retry decorator with full-jitter backoff.

Retries only transient failures (timeouts, connection errors, 429, 5xx). Never
retries other 4xx and never a schema-validation failure — that just burns quota.
Honors ``Retry-After`` (capped at ``max_delay``). Full jitter keeps simultaneous
worker retries from resynchronizing.
"""

from __future__ import annotations

import asyncio
import functools
import random
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from app.api.errors import ProviderError, ValidationError
from app.core.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")

_TRANSIENT_NAME_HINTS = ("timeout", "connection", "unavailable", "deadline", "resourceexhausted")


def http_status_of(exc: BaseException) -> int | None:
    """Best-effort HTTP status extraction across SDK exception shapes."""
    for attr in ("status_code", "status", "code", "http_status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    resp = getattr(exc, "response", None)
    status = getattr(resp, "status_code", None)
    return status if isinstance(status, int) else None


def default_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (ValidationError, ProviderError)):
        return False
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return True
    status = http_status_of(exc)
    if status is not None:
        return status == 429 or 500 <= status < 600
    name = type(exc).__name__.lower()
    return any(hint in name for hint in _TRANSIENT_NAME_HINTS)


def retry_after_seconds(exc: BaseException) -> float | None:
    """Parse a Retry-After header (seconds form) if the exception carries one."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None) or getattr(exc, "headers", None)
    if not headers:
        return None
    try:
        value = headers.get("retry-after") or headers.get("Retry-After")
    except AttributeError:
        return None
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def with_retry(
    attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    retry_on: Callable[[BaseException], bool] = default_retryable,
    on_retry: Callable[[int, float, BaseException], None] | None = None,
    provider: str = "unknown",
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: BaseException | None = None
            for attempt in range(1, attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    if not retry_on(exc):
                        raise
                    if attempt >= attempts:
                        break
                    ra = retry_after_seconds(exc)
                    if ra is not None:
                        delay = min(ra, max_delay)
                    else:
                        computed = min(max_delay, base_delay * (2 ** (attempt - 1)))
                        delay = random.uniform(0, computed)
                    log.warning(
                        "retry.attempt",
                        provider=provider,
                        attempt=attempt,
                        delay=round(delay, 3),
                        reason=type(exc).__name__,
                    )
                    if on_retry is not None:
                        on_retry(attempt, delay, exc)
                    await asyncio.sleep(delay)
            pe = ProviderError(
                f"{provider} call failed after {attempts} attempts: {last_exc}",
                detail=str(last_exc)[:500],
            )
            pe.original = last_exc  # type: ignore[attr-defined]
            pe.attempts = attempts  # type: ignore[attr-defined]
            raise pe from last_exc

        return wrapper

    return decorator
