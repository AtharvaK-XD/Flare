.PHONY: bootstrap dev dev-offline test test-load lint typecheck check smoke \
        fetch-data labels index migrate seed eval benchmark clean-runs

# ── Cold start ────────────────────────────────────────────────────────
# Fresh clone -> working demo in ONE command. Everything below is
# idempotent, so re-running it is always safe.
#
#   git clone ... && cp .env.example .env && make bootstrap && make dev
#
# Needs no API keys: the app starts without them (features degrade visibly),
# and `make seed` populates the dashboard using the offline providers.
# Order matters: `labels` runs BEFORE `fetch-data` because the replay dataset
# falls back to the labeled subset when the download is unavailable, and
# `migrate` runs before `seed` because seeding writes alerts.
bootstrap: labels fetch-data index migrate seed
	@echo ""
	@echo "Bootstrap complete. Next:"
	@echo "  make dev           start the API (add keys to .env for live LLM calls)"
	@echo "  make dev-offline   start with no network at all"
	@echo "  make smoke         verify every external dependency"

dev:
	uv run uvicorn app.main:app --reload --host $${API_HOST:-0.0.0.0} --port $${API_PORT:-8000}

# Deterministic, no network: every LLM/intel/embedding call is served in
# process. Same graph, same workers, same DB, same API.
dev-offline:
	OFFLINE_MODE=true uv run uvicorn app.main:app --host $${API_HOST:-0.0.0.0} --port $${API_PORT:-8000}

# ── Data ──────────────────────────────────────────────────────────────
fetch-data:
	uv run python scripts/fetch_datasets.py

# Labeled evaluation subset. Skipped when already present — this is the only
# bootstrap step that needs the network, and a cold clone ships without it.
labels:
	@uv run python -m scripts.build_label_set --verify-only 2>/dev/null \
		|| uv run python -m scripts.build_label_set

index:
	uv run python -m scripts.index_mitre

migrate:
	uv run alembic upgrade head

# ~200 pre-triaged alerts so the dashboard is never empty on first load.
seed:
	uv run python -m scripts.seed_demo

# ── Checks ────────────────────────────────────────────────────────────
test:
	uv run pytest -m "not load"

# Sustained-load + backpressure suite. Minutes, not seconds — excluded from
# `make test` on purpose so the fast loop stays fast.
test-load:
	uv run pytest -m load -v

lint:
	uv run ruff check .

typecheck:
	uv run mypy app scripts

check: lint typecheck test

smoke:
	uv run python scripts/smoke_providers.py

# ── Evaluation ────────────────────────────────────────────────────────
# make eval                      -> EVAL_SAMPLE_SIZE from settings
# make eval ARGS="--sample-size 100"
eval:
	uv run python -m scripts.run_eval $(ARGS)

benchmark:
	uv run python -m scripts.run_benchmark $(ARGS)

# Reap eval/benchmark rows left in `running` by a crashed process. The app does
# this at startup and periodically; this is the manual escape hatch.
clean-runs:
	uv run python -m scripts.reap_runs
