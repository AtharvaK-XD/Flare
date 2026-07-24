"""Gemini provider (quality tier). Wraps google-generativeai (blocking → thread)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from app.api.errors import FlareError, ProviderError, RateLimitedError
from app.config import get_settings
from app.core.logging import get_logger
from app.core.metrics import metrics
from app.core.retry import http_status_of, with_retry
from app.providers.base import CompletionResult, ProviderHealth
from app.providers.parsing import build_schema_instruction, coerce_to_model, extract_json_meta
from app.schemas import ProviderTier

log = get_logger(__name__)

DEFAULT_TIMEOUT = 30.0
ATTEMPTS = 3

_BLOCK_FINISH = {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "RECITATION"}

GenerateFn = Callable[[str, dict, str | None], Any]


class GeminiProvider:
    tier: ProviderTier = ProviderTier.QUALITY

    def __init__(self, generate: GenerateFn | None = None) -> None:
        settings = get_settings()
        self._api_key = settings.google_api_key
        self._model = settings.gemini_model
        self._generate = generate

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def model(self) -> str:
        return self._model

    @property
    def available(self) -> bool:
        return self._generate is not None or bool(self._api_key)

    def _real_generate(self, prompt: str, gen_config: dict, system: str | None) -> Any:
        import google.generativeai as genai

        genai.configure(api_key=self._api_key)
        gm = genai.GenerativeModel(
            self._model,
            generation_config=gen_config,  # type: ignore[arg-type]
            system_instruction=system,
        )
        return gm.generate_content(prompt)

    def _map_error(self, exc: BaseException, attempts: int) -> FlareError:
        status = http_status_of(exc)
        name = type(exc).__name__.lower()
        if status in (401, 403) or "permission" in name or "unauthenticated" in name:
            return ProviderError(
                "Gemini authentication failed — check GOOGLE_API_KEY", detail=str(exc)[:500]
            )
        if status == 429 or "resourceexhausted" in name:
            err: FlareError = RateLimitedError("Gemini rate limit hit", detail=str(exc)[:500])
        else:
            err = ProviderError(f"Gemini call failed: {exc}", detail=str(exc)[:500])
        err.attempts = attempts  # type: ignore[attr-defined]
        return err

    @staticmethod
    def _finish_name(value: Any) -> str:
        return getattr(value, "name", None) or str(value or "")

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
        if not self.available:
            raise ProviderError("Gemini unavailable: set GOOGLE_API_KEY")
        use_model = model or self._model
        to = timeout or DEFAULT_TIMEOUT
        generate = self._generate or self._real_generate

        user_prompt = prompt
        gen_config: dict[str, Any] = {
            "max_output_tokens": max_tokens,
            "temperature": temperature,
        }
        if response_model is not None:
            gen_config["response_mime_type"] = "application/json"
            user_prompt = f"{prompt}\n\n{build_schema_instruction(response_model)}"

        @with_retry(
            attempts=ATTEMPTS,
            base_delay=0.5,
            provider=self.name,
            on_retry=lambda a, d, e: metrics.record_retry(self.name, use_model, node),
        )
        async def _call() -> Any:
            return await asyncio.wait_for(
                asyncio.to_thread(generate, user_prompt, gen_config, system), timeout=to
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

        feedback = getattr(resp, "prompt_feedback", None)
        block_reason = getattr(feedback, "block_reason", None)
        if block_reason:
            metrics.record_call(self.name, use_model, node, latency_ms, 0, 0, ok=False)
            err = ProviderError(
                f"Gemini blocked the prompt (safety): {block_reason}", detail=str(block_reason)
            )
            err.finish_reason = "blocked"  # type: ignore[attr-defined]
            raise err

        candidates = getattr(resp, "candidates", None) or []
        if not candidates:
            metrics.record_call(self.name, use_model, node, latency_ms, 0, 0, ok=False)
            raise ProviderError("Gemini returned no candidates")

        cand = candidates[0]
        finish_reason = self._finish_name(getattr(cand, "finish_reason", ""))
        parts = getattr(getattr(cand, "content", None), "parts", None) or []
        text = "".join(getattr(p, "text", "") or "" for p in parts)

        if finish_reason in _BLOCK_FINISH and not text:
            metrics.record_call(self.name, use_model, node, latency_ms, 0, 0, ok=False)
            err = ProviderError(f"Gemini candidate blocked: {finish_reason}")
            err.finish_reason = "blocked"  # type: ignore[attr-defined]
            raise err

        usage = getattr(resp, "usage_metadata", None)
        tokens_in = int(getattr(usage, "prompt_token_count", 0) or 0)
        tokens_out = int(getattr(usage, "candidates_token_count", 0) or 0)

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
            return ProviderHealth(status="down", note="no GOOGLE_API_KEY")
        try:
            t0 = time.perf_counter()
            await self.complete("ping", max_tokens=5, node="health")
            return ProviderHealth(status="ok", latency_ms=(time.perf_counter() - t0) * 1000.0)
        except RateLimitedError as exc:
            return ProviderHealth(status="degraded", note=str(exc.message))
        except FlareError as exc:
            return ProviderHealth(status="down", note=str(exc.message))
