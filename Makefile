.PHONY: dev test lint typecheck smoke fetch-data index

dev:
	uv run uvicorn app.main:app --reload --host $${API_HOST:-0.0.0.0} --port $${API_PORT:-8000}

test:
	uv run pytest

lint:
	uv run ruff check .

typecheck:
	uv run mypy app scripts

smoke:
	uv run python scripts/smoke_providers.py

fetch-data:
	uv run python scripts/fetch_datasets.py

index:
	uv run python -m scripts.index_mitre
