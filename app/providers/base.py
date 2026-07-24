"""Provider abstraction — the contract every LLM backend implements.

A ``complete`` call with a ``response_model`` MUST return a validated instance
or raise ProviderError. Never a half-parsed dict — a silently wrong severity
looks like a working demo and is the worst failure mode in this system.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel

from app.schemas import ProviderTier

HealthStatus = Literal["ok", "degraded", "down"]


@dataclass
class CompletionResult:
    text: str
    parsed: BaseModel | None
    tokens_in: int
    tokens_out: int
    latency_ms: float
    provider: str
    model: str
    finish_reason: str
    attempts: int = 1
    repaired: bool = False


@dataclass
class ProviderHealth:
    status: HealthStatus
    latency_ms: float | None = None
    note: str | None = None


@runtime_checkable
class LLMProvider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def tier(self) -> ProviderTier: ...

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        response_model: type[BaseModel] | None = None,
        timeout: float | None = None,
        model: str | None = None,
    ) -> CompletionResult: ...

    async def health(self) -> ProviderHealth: ...
