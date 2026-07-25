"""Groq provider (fast tier). Wraps the async Groq client."""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel

from app.api.errors import FlareError, ProviderError, RateLimitedError
from app.config import get_settings
from app.core.logging import get_logger
from app.core.metrics import metrics
from app.core.retry import http_status_of, is_rate_limit, with_retry
from app.providers.base import CompletionResult, ProviderHealth
from app.providers.parsing import build_schema_instruction, coerce_to_model, extract_json_meta
from app.schemas import ProviderTier

log = get_logger(__name__)

#: gpt-oss-120b is a reasoning model — it thinks before emitting, so a
#: first-token deadline sized for llama-3.1-8b-instant times it out under load.
DEFAULT_TIMEOUT = 30.0
ATTEMPTS = 3

#: Fallback when GROQ_FAST_MODEL is unset. Confirmed against Groq's live
#: /openai/v1/models listing — do not edit from memory, slugs change.
DEFAULT_FAST_MODEL = "openai/gpt-oss-120b"


class GroqProvider:
    tier: ProviderTier = ProviderTier.FAST

    def __init__(self, client: Any | None = None) -> None:
        settings = get_settings()
        self._api_key = settings.groq_api_key
        self._fast_model = settings.groq_fast_model or DEFAULT_FAST_MODEL
        self._quality_model = settings.groq_quality_model
        self._client = client
        #: Set when a call was retried because of a 429/TPM throttle. The
        #: benchmark reads this to flag a throttled tier rather than publishing
        #: free-tier queueing as the model's real latency.
        self.throttled = False

    @property
    def name(self) -> str:
        return "groq"

    @property
    def model(self) -> str:
        return self._fast_model

    @property
    def available(self) -> bool:
        return self._client is not None or bool(self._api_key)

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._api_key:
                raise ProviderError("Groq unavailable: set GROQ_API_KEY")
            from groq import AsyncGroq

            self._client = AsyncGroq(api_key=self._api_key)
        return self._client

    def _on_retry(self, model: str, node: str, exc: BaseException) -> None:
        """Count the retry, and remember whether the free tier throttled us."""
        throttled = is_rate_limit(exc)
        if throttled:
            self.throttled = True
            log.info("groq.throttled", model=model, node=node)
        metrics.record_retry(self.name, model, node, rate_limited=throttled)

    def _map_error(self, exc: BaseException, attempts: int) -> FlareError:
        status = http_status_of(exc)
        name = type(exc).__name__.lower()
        if status in (401, 403) or "authentication" in name or "permission" in name:
            return ProviderError(
                "Groq authentication failed — check GROQ_API_KEY", detail=str(exc)[:500]
            )
        if status == 429 or "ratelimit" in name:
            err: FlareError = RateLimitedError("Groq rate limit hit", detail=str(exc)[:500])
        else:
            err = ProviderError(f"Groq call failed: {exc}", detail=str(exc)[:500])
        err.attempts = attempts  # type: ignore[attr-defined]
        return err

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
        node: str = "-",
    ) -> CompletionResult:
        client = self._get_client()
        use_model = model or self._fast_model
        to = timeout or DEFAULT_TIMEOUT

        user_content = prompt
        create_kwargs: dict[str, Any] = {}
        if response_model is not None:
            user_content = f"{prompt}\n\n{build_schema_instruction(response_model)}"
            create_kwargs["response_format"] = {"type": "json_object"}

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": user_content})

        @with_retry(
            attempts=ATTEMPTS,
            base_delay=0.5,
            provider=self.name,
            on_retry=lambda a, d, e: self._on_retry(use_model, node, e),
        )
        async def _call() -> Any:
            return await client.chat.completions.create(
                model=use_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=to,
                **create_kwargs,
            )

        t0 = time.perf_counter()
        try:
            resp = await _call()
        except ProviderError as pe:
            metrics.record_call(self.name, use_model, node, 0.0, 0, 0, ok=False)
            raise self._map_error(
                getattr(pe, "original", pe), getattr(pe, "attempts", ATTEMPTS)
            ) from pe
        except Exception as exc:  # noqa: BLE001 — non-retryable
            metrics.record_call(self.name, use_model, node, 0.0, 0, 0, ok=False)
            raise self._map_error(exc, 1) from exc

        latency_ms = (time.perf_counter() - t0) * 1000.0
        choice = resp.choices[0]
        text = choice.message.content or ""
        usage = getattr(resp, "usage", None)
        tokens_in = int(getattr(usage, "prompt_tokens", 0) or 0)
        tokens_out = int(getattr(usage, "completion_tokens", 0) or 0)
        finish_reason = str(getattr(choice, "finish_reason", "") or "")

        metrics.record_call(self.name, use_model, node, latency_ms, tokens_in, tokens_out, ok=True)

        parsed: BaseModel | None = None
        repaired = False
        if response_model is not None:
            meta = extract_json_meta(text)
            parsed = coerce_to_model(meta.data, response_model)
            repaired = meta.repaired

        return CompletionResult(
            text=text,
            parsed=parsed,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            provider=self.name,
            model=use_model,
            finish_reason=finish_reason,
            attempts=1,
            repaired=repaired,
        )

    async def health(self) -> ProviderHealth:
        if not self.available:
            return ProviderHealth(status="down", note="no GROQ_API_KEY")
        try:
            t0 = time.perf_counter()
            await self.complete("ping", max_tokens=5, node="health")
            return ProviderHealth(status="ok", latency_ms=(time.perf_counter() - t0) * 1000.0)
        except RateLimitedError as exc:
            return ProviderHealth(status="degraded", note=str(exc.message))
        except FlareError as exc:
            return ProviderHealth(status="down", note=str(exc.message))
