"""Provider registry — tier → provider, with async-safe per-context overrides.

``override`` uses a contextvar (not global mutation) so a benchmark run can
force one tier through another provider without corrupting concurrent live
traffic. Construction never fails on missing keys; ``get`` raises only when a
missing-key tier is actually used.
"""

from __future__ import annotations

import asyncio
import contextvars
from collections.abc import Iterator
from contextlib import contextmanager

from app.api.errors import ProviderError
from app.providers.base import LLMProvider, ProviderHealth
from app.providers.gemini import GeminiProvider
from app.providers.groq import GroqProvider
from app.schemas import ProviderTier

_overrides: contextvars.ContextVar[dict[str, LLMProvider] | None] = contextvars.ContextVar(
    "provider_overrides", default=None
)

_MISSING_KEY_HINT = {
    ProviderTier.FAST: "Groq unavailable — set GROQ_API_KEY to enable the fast tier",
    ProviderTier.QUALITY: "Gemini unavailable — set GOOGLE_API_KEY to enable the quality tier",
}


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[ProviderTier, LLMProvider] = {
            ProviderTier.FAST: GroqProvider(),
            ProviderTier.QUALITY: GeminiProvider(),
        }

    def get(self, tier: ProviderTier) -> LLMProvider:
        override = (_overrides.get() or {}).get(tier.value)
        if override is not None:
            return override
        provider = self._providers[tier]
        if not getattr(provider, "available", True):
            raise ProviderError(_MISSING_KEY_HINT.get(tier, f"{tier.value} tier unavailable"))
        return provider

    def base_provider(self, tier: ProviderTier) -> LLMProvider:
        """The registry's own provider for a tier, ignoring overrides."""
        return self._providers[tier]

    def set_provider(self, tier: ProviderTier, provider: LLMProvider) -> None:
        """Permanently replace a tier's provider (offline mode installs here).

        Distinct from :meth:`override`, which is contextvar-scoped and must stay
        that way so a benchmark cannot change what live traffic is served by.
        This one is a process-lifetime swap made once at startup.
        """
        self._providers[tier] = provider

    @contextmanager
    def override(self, tier: ProviderTier, provider: LLMProvider) -> Iterator[None]:
        current = _overrides.get() or {}
        token = _overrides.set({**current, tier.value: provider})
        try:
            yield
        finally:
            _overrides.reset(token)

    async def health_all(self) -> dict[str, ProviderHealth]:
        tiers = list(self._providers.items())
        results = await asyncio.gather(
            *(provider.health() for _, provider in tiers), return_exceptions=True
        )
        health: dict[str, ProviderHealth] = {}
        for (_, provider), res in zip(tiers, results, strict=True):
            if isinstance(res, ProviderHealth):
                health[provider.name] = res
            else:
                health[provider.name] = ProviderHealth(status="down", note=str(res))
        return health


_registry: ProviderRegistry | None = None


def get_registry() -> ProviderRegistry:
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry
