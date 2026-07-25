"""Application settings — the ONE place that reads the environment.

Nothing else in the codebase may touch ``os.environ``; import :func:`get_settings`
instead. Missing API keys never crash startup — they default to ``None`` and
:attr:`Settings.available_providers` reports what is actually usable.
"""

from __future__ import annotations

import warnings
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Gemini models this project has observed returning a PERMANENT 429 on a plain
#: free-tier key: the quota violation reports ``limit: 0``, i.e. the model is not
#: served to free keys at all. That is a misconfiguration, not a transient rate
#: limit, and retrying it only burns the demo clock. Kept as data (not a hard
#: rejection) because a paid key CAN call these — the validator warns, and
#: ``scripts/smoke_providers.py`` proves it per key.
ZERO_FREE_QUOTA_GEMINI_MODELS: frozenset[str] = frozenset(
    {"gemini-2.0-flash", "gemini-2.0-flash-001", "gemini-2.0-flash-lite"}
)

#: Groq model ids retired from the free tier / renamed. Same policy as above.
DEPRECATED_GROQ_MODELS: frozenset[str] = frozenset(
    {"llama-3.1-70b-versatile", "mixtral-8x7b-32768"}
)


class ProviderSettings(BaseModel):
    """LLM provider config (Groq + Gemini)."""

    groq_api_key: str | None
    groq_fast_model: str
    groq_quality_model: str
    google_api_key: str | None
    gemini_model: str


class IntelSettings(BaseModel):
    """Threat-intel provider config (AbuseIPDB + VirusTotal)."""

    abuseipdb_api_key: str | None
    virustotal_api_key: str | None
    vt_rate_limit_per_min: int
    abuseipdb_rate_limit_per_day: int
    intel_cache_ttl_seconds: int


class StoreSettings(BaseModel):
    """Persistence config (SQLite + Chroma + embedding model)."""

    database_url: str
    chroma_persist_dir: Path
    chroma_collection: str
    embedding_model: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173"]

    groq_api_key: str | None = None
    # Back on llama-3.1-8b-instant: openai/gpt-oss-120b is a reasoning model and
    # measured 7.5s p50 on the classify node — too slow for the live fast path,
    # and the accuracy gain did not pay for it. Confirmed against Groq's live
    # /v1/models listing for this account — slugs on Groq change, so re-confirm
    # before editing this default rather than assuming.
    groq_fast_model: str = "llama-3.1-8b-instant"
    groq_quality_model: str = "llama-3.3-70b-versatile"

    google_api_key: str | None = None
    # Phase 13: gemini-2.0-flash returns a PERMANENT 429 (quota limit: 0) on a
    # free-tier key. gemini-flash-latest is what a free key can actually call.
    gemini_model: str = "gemini-flash-latest"

    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    vt_rate_limit_per_min: int = 4
    abuseipdb_rate_limit_per_day: int = 1000
    intel_cache_ttl_seconds: int = 86400

    database_url: str = "sqlite+aiosqlite:///./data/flare.db"
    chroma_persist_dir: Path = Path("./data/chroma")
    chroma_collection: str = "mitre_attack"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    dataset_path: Path = Path("./data/datasets")
    ground_truth_path: Path = Path("./data/labels")

    replay_events_per_second: int = 10
    triage_worker_concurrency: int = 4
    enrich_worker_concurrency: int = 1

    enable_benchmark_mode: bool = False

    # Offline demo mode (Phase 13). Every network leaf — both LLM tiers, both
    # intel sources, the embedding model — is served by deterministic in-process
    # stand-ins. The graph, routers, workers, queues, bus, DB and API are the
    # real ones, so the pipeline exercised is the production pipeline.
    offline_mode: bool = False

    # Agent / LangGraph orchestration (Phase 8)
    ioc_escalation_score: int = 80
    enrich_low_severity: bool = False
    # Wall-clock budget for a FULL run_triage (classify -> recommend).
    #
    # Measured on demo hardware with the configured models, warm:
    #   classify (llama-3.1-8b-instant) 1.6s
    #   enrich                      1.0s
    #   retrieve                    1.9s
    #   reason (gemini-flash-latest) 24.1s   <- reasoning model, thinks first
    #   recommend (gemini-flash-latest) 15.9s
    #   total                      ~44.6s
    #
    # The old 45s budget left ~0.4s of headroom and timed out on any slower
    # response. The live fast path is unaffected either way — the triage worker
    # calls stop_after="classify" and returns in ~2s — so this budget really only
    # bounds the full path (eval with enrichment on, seeding, demos).
    triage_timeout_seconds: float = 120.0
    # Load the sentence-transformers model in the BACKGROUND at startup. Cold
    # load is ~34s and, unwarmed, it lands inside the first alert's retrieve node
    # and consumes the entire triage budget. Backgrounded, boot stays instant and
    # the first alert is already warm.
    warm_embedding_model_on_startup: bool = True

    # Workers, queues & bus (Phase 9)
    event_bus_maxsize: int = 100
    triage_queue_maxsize: int = 1000
    enrich_queue_maxsize: int = 500
    shutdown_drain_seconds: float = 10.0
    enrich_requeue_delay_seconds: float = 2.0
    stats_publish_interval_seconds: float = 2.0
    worker_restart_cap_per_min: int = 5

    # Evaluation harness (Phase 11)
    eval_sample_size: int = 200
    eval_max_sample_size: int = 2000
    eval_concurrency: int = 4
    # Fixed seed => two runs draw the SAME stratified sample. LLM decoding may
    # still vary slightly between runs; that is noted in the run's completion notice.
    eval_seed: int = 20260725
    # Enrichment is OFF by default: eval measures classification quality, and 200
    # alerts through VirusTotal at 4 req/min is ~50 minutes. Flip to False to
    # measure the full pipeline (post-IOC-escalation severity) instead.
    eval_skip_enrich: bool = True
    # Below this many labeled rows the eval is scoring noise (a 6-row fallback
    # produces a real-looking macro-F1 that means nothing). Load-time checks warn
    # LOUDLY rather than proceeding quietly. See app/evaluation/ground_truth.py.
    eval_min_label_rows: int = 50

    # Provider benchmark (Phase 12)
    # Calls are sequential per tier and doubled across tiers, so the cap is low on
    # purpose: 50 alerts is already 100 live LLM calls.
    benchmark_max_sample: int = 50
    benchmark_sample_size: int = 25
    # Discarded per tier. Cold connection setup would otherwise be charged
    # entirely to whichever tier happened to run first.
    benchmark_warmup: int = 2

    # Stale-run reaping (Phase 13). A crashed process leaves an eval/benchmark row
    # in status=running forever, and the "already in flight" check then 409s every
    # subsequent POST /run permanently. A run whose started_at is older than this
    # is presumed dead and marked failed.
    run_stale_timeout_seconds: int = 300
    run_stale_sweep_interval_seconds: float = 60.0

    @field_validator("api_port")
    @classmethod
    def _port_in_range(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError("API_PORT must be between 1 and 65535")
        return v

    @field_validator("eval_concurrency")
    @classmethod
    def _eval_concurrency_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("EVAL_CONCURRENCY must be >= 1")
        return v

    @field_validator("vt_rate_limit_per_min")
    @classmethod
    def _vt_rate_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("VT_RATE_LIMIT_PER_MIN must be >= 1")
        return v

    @field_validator("database_url")
    @classmethod
    def _db_url_async(cls, v: str) -> str:
        if not v.startswith("sqlite+aiosqlite"):
            raise ValueError("DATABASE_URL must start with sqlite+aiosqlite")
        return v

    @field_validator("chroma_persist_dir")
    @classmethod
    def _chroma_dir_abs(cls, v: Path) -> Path:
        p = Path(v).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @field_validator("gemini_model")
    @classmethod
    def _gemini_model_callable(cls, v: str) -> str:
        """Blank falls back to the working default; a zero-quota model warns loudly.

        Not an error: a paid key can call these. But silently shipping a model
        that 429s on every call is exactly how Phase 11/12 lost a demo, so the
        misconfiguration has to be audible at import time.
        """
        model = v.strip()
        if not model:
            return "gemini-flash-latest"
        if model in ZERO_FREE_QUOTA_GEMINI_MODELS:
            warnings.warn(
                f"GEMINI_MODEL={model!r} has zero free-tier quota on Google's free keys "
                "and returns a PERMANENT 429 (not a transient rate limit). Use "
                "'gemini-flash-latest' unless this key is on a paid plan. Verify with "
                "`make smoke`.",
                RuntimeWarning,
                stacklevel=2,
            )
        return model

    @field_validator("groq_fast_model", "groq_quality_model")
    @classmethod
    def _groq_model_callable(cls, v: str) -> str:
        model = v.strip()
        if not model:
            raise ValueError("Groq model id must not be empty")
        if model in DEPRECATED_GROQ_MODELS:
            warnings.warn(
                f"Groq model {model!r} is decommissioned; calls will 404. Check "
                "https://console.groq.com/docs/models for the current slug.",
                RuntimeWarning,
                stacklevel=2,
            )
        return model


    @property
    def is_dev(self) -> bool:
        return self.app_env.lower() in {"dev", "development", "local"}

    @property
    def providers(self) -> ProviderSettings:
        return ProviderSettings(
            groq_api_key=self.groq_api_key,
            groq_fast_model=self.groq_fast_model,
            groq_quality_model=self.groq_quality_model,
            google_api_key=self.google_api_key,
            gemini_model=self.gemini_model,
        )

    @property
    def intel(self) -> IntelSettings:
        return IntelSettings(
            abuseipdb_api_key=self.abuseipdb_api_key,
            virustotal_api_key=self.virustotal_api_key,
            vt_rate_limit_per_min=self.vt_rate_limit_per_min,
            abuseipdb_rate_limit_per_day=self.abuseipdb_rate_limit_per_day,
            intel_cache_ttl_seconds=self.intel_cache_ttl_seconds,
        )

    @property
    def store(self) -> StoreSettings:
        return StoreSettings(
            database_url=self.database_url,
            chroma_persist_dir=self.chroma_persist_dir,
            chroma_collection=self.chroma_collection,
            embedding_model=self.embedding_model,
        )

    @property
    def available_providers(self) -> dict[str, bool]:
        """Which external providers have a key configured and are usable."""
        return {
            "groq": self.groq_api_key is not None,
            "gemini": self.google_api_key is not None,
            "abuseipdb": self.abuseipdb_api_key is not None,
            "virustotal": self.virustotal_api_key is not None,
        }


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — the only supported way to read config."""
    return Settings()
