"""Application settings — the ONE place that reads the environment.

Nothing else in the codebase may touch ``os.environ``; import :func:`get_settings`
instead. Missing API keys never crash startup — they default to ``None`` and
:attr:`Settings.available_providers` reports what is actually usable.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    groq_fast_model: str = "llama-3.1-8b-instant"
    groq_quality_model: str = "llama-3.3-70b-versatile"

    google_api_key: str | None = None
    gemini_model: str = "gemini-2.0-flash"

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

    # Agent / LangGraph orchestration (Phase 8)
    ioc_escalation_score: int = 80
    enrich_low_severity: bool = False
    triage_timeout_seconds: float = 45.0

    # Workers, queues & bus (Phase 9)
    event_bus_maxsize: int = 100
    triage_queue_maxsize: int = 1000
    enrich_queue_maxsize: int = 500
    shutdown_drain_seconds: float = 10.0
    enrich_requeue_delay_seconds: float = 2.0
    stats_publish_interval_seconds: float = 2.0
    worker_restart_cap_per_min: int = 5


    @field_validator("api_port")
    @classmethod
    def _port_in_range(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError("API_PORT must be between 1 and 65535")
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
