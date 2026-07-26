<div align="center">

<pre>
███████╗ ██╗       █████╗  ██████╗  ███████╗
██╔════╝ ██║      ██╔══██╗ ██╔══██╗ ██╔════╝
█████╗   ██║      ███████║ ██████╔╝ █████╗  
██╔══╝   ██║      ██╔══██║ ██╔══██╗ ██╔══╝  
██║      ███████╗ ██║  ██║ ██║  ██║ ███████╗
╚═╝      ╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝
</pre>

*AI that stands watch over your logs.*

</div>

<div align="center">

Flare is an AI security alert triage system. A network alert arrives — replayed from CICIDS2017
or Suricata EVE JSON, or posted by hand — and is classified for severity and attack type by a
fast LLM tier in about two seconds, enriched against live IP reputation databases, grounded in
MITRE ATT&CK technique text pulled from a vector index, reasoned over by a slower quality tier,
and finished with a numbered remediation playbook. Every stage streams to a live dashboard over
SSE as it lands.

**Threat intelligence outranks the language model, and the model is never trusted to cite its
own evidence.** An IOC reputation score at or above the escalation threshold upgrades severity
regardless of what the classifier decided, and every ATT&CK technique the remediation model
cites is dropped unless the retriever actually returned it. Accuracy is not a claim — a built-in
evaluation harness scores the pipeline against 450 labeled flows through the exact same code
path the live workers run.

</div>

## 🔍 How It Works

```
  CICIDS2017 / Suricata EVE record            POST /api/v1/ingest
             │                                        │
             ▼                                        ▼
      ReplayEngine (monotonic rate control,   EVE JSON | simplified body
      batch reads on a worker thread)         neither ──► 422 envelope
             │                                        │
             └────────────────┬───────────────────────┘
                              ▼
                    normalize()  ─► parser refuses ──► counted as `skipped`
                              │
                              ▼
                    extract_iocs()   public IPs / hashes only
                              │
                              ▼
                    triage_q  BoundedQueue(1000) ──► saturated ──► 503 rate_limited
                              │
                              ▼
  triage worker ─► repo.create() ─► run_triage(stop_after="classify")
                              │
                    ┌── classify ─────────────────────────────┐
                    │  Groq  llama-3.1-8b-instant             │
                    │  strict JSON ─► ClassificationResult    │
                    │  ANY failure ─► medium / unknown        │ ◄── degrade, never raise
                    └─────────────────────────────────────────┘
                              │
                              ├──► persist + SSE `alert.new`   (feed shows it immediately)
                              ▼
                    route_after_classify(state)
                              │
        critical / high / medium ──► enrich_q        low / info ──► finalize
                              │
                              ▼
  enrich worker  (concurrency 1 — VirusTotal free tier is 4 req/min)
                              │
                    ┌── enrich ───────────────────────────────┐
                    │  AbuseIPDB + VirusTotal, concurrent     │
                    │  TieredCache: memory ─► SQLite          │
                    │  partial failure ─► degraded, not error │
                    │  worst score ≥ IOC_ESCALATION_SCORE     │
                    │     └─► severity upgraded to HIGH       │ ◄── intel beats the model
                    └─────────────────────────────────────────┘
                              │
                              ├──► persist + SSE `alert.updated`
                              ▼
                    route_after_enrich(state)
                              │
     critical / high, or medium with worst IOC ≥ 40 ──► retrieve     else ──► finalize
                              │
                    ┌── retrieve ─────────────────────────────┐
                    │  Chroma, cosine, attack-type filtered   │
                    │  all-MiniLM-L6-v2, 384-dim, local       │
                    │  empty index ─► [] (never raises)       │
                    └─────────────────────────────────────────┘
                              │
                    ┌── reason ───────────────────────────────┐
                    │  Gemini  gemini-flash-latest            │
                    │  grounded in IOC verdicts + ATT&CK text │
                    │  quality tier fails ─► ONE fast retry,  │
                    │  and the trace records which tier won   │
                    └─────────────────────────────────────────┘
                              │
                    route_after_reason ── empty narrative ──► finalize
                              │
                    ┌── recommend ────────────────────────────┐
                    │  strict JSON ─► Remediation             │
                    │  drop every technique id NOT in         │
                    │    state["techniques"]                  │ ◄── hallucination guard
                    │  re-hydrate from OUR objects            │
                    │  renumber steps 1..N                    │
                    └─────────────────────────────────────────┘
                              │
                    ┌── finalize ─────────────────────────────┐
                    │  status = done                          │
                    │  synthesize a `skipped` TraceNode with  │
                    │  a human reason for every node that     │
                    │  never ran                              │
                    └─────────────────────────────────────────┘
                              │
                              ├──► persist + SSE `alert.updated`
                              ▼
                    GET /api/v1/stream   EventSource, 15s heartbeat
                              │
                              ▼
                      dashboard feed ──► drill-down drawer
                                                │
                                                ▼
                                   GET /api/v1/alerts/{id}
                              full trace + IOC verdicts + playbook

  ── evaluation ───────────────────────────────────────────────────────────
  POST /api/v1/evaluation/run ──► 202 { run_id }   one in flight at a time, else 409
              │
              ▼
  stratified sample (fixed EVAL_SEED) over 450 labeled CICIDS2017 flows
              │
              ▼
  run_triage()  ── the SAME function the live triage worker calls
              │
      classification failure ──► scored as medium / unknown,
                                 and STAYS in the denominator
              │
              ▼
  macro precision / recall / F1 + confusion matrix, on BOTH targets
  (severity and attack_type) ─► partials persisted every 10%
              │
              ▼
  GET /api/v1/evaluation/runs/{run_id}   polled every 2s by the dashboard
```

What makes this a system rather than a demo is where the guarantees sit. Every node is wrapped
by a `@traced` decorator that emits exactly one `TraceNode` per invocation — on success, on
skip, and even if the node body raises in violation of the no-raise rule — so the transparency
panel can never silently omit a stage. Nodes degrade instead of throwing: a dead classifier
yields `medium`/`unknown` with the error recorded, never `critical`, because a broken model must
not flood the critical queue. The whole run is bounded by a wall-clock budget, and on exhaustion
the partially accumulated state is returned with the completed nodes intact rather than a hung
worker. Queues are bounded and reject on saturation with an honest 503 instead of growing until
the process dies, and the queue registry is rebuilt inside the app lifespan so a reload can
never hand workers an `asyncio.Queue` bound to a dead event loop.

## ✨ Features

<table>
<tr>
<td width="33%" valign="top">

### 🧠 Two-tier LLM routing
Groq `llama-3.1-8b-instant` classifies **every** alert on the fast path — the worker calls
`stop_after="classify"` so enrichment never blocks the live feed. Gemini `gemini-flash-latest`
handles narrative and remediation. If the quality tier fails, reasoning retries **once** on the
fast tier and the trace records which tier actually served the text.

</td>
<td width="33%" valign="top">

### 🛡️ Intel outranks the model
IOCs fan out to AbuseIPDB and VirusTotal concurrently through a two-layer cache. A worst score
≥ `IOC_ESCALATION_SCORE` (default 80) **upgrades severity to HIGH** no matter what the
classifier said, and the upgrade is written into the trace note. Rate limits are an expected
outcome, not an error — they yield empty IOCs and a note.

</td>
<td width="33%" valign="top">

### 📚 Grounded RAG + hallucination guard
27 MITRE ATT&CK techniques indexed into Chroma (81 chunks) with local `all-MiniLM-L6-v2`
embeddings, filtered by predicted attack type. Every technique the remediation model cites is
**dropped unless the retriever returned it**, and survivors are re-hydrated from our objects so
name and URL cannot be fabricated.

</td>
</tr>
<tr>
<td width="33%" valign="top">

### 📊 Real eval, same code path
The harness pushes 450 labeled CICIDS2017 flows through `run_triage` — the identical function
the live worker calls, no eval-only branch anywhere. Failures score as `medium`/`unknown` and
stay in the denominator. Macro precision/recall/F1 and a confusion matrix, on **both** severity
and attack type.

</td>
<td width="33%" valign="top">

### ⚡ Progressive SSE fill
The fast path publishes `alert.new` within seconds; the enrich worker then persists and
publishes each stage **as it lands**, so cards upgrade in place — classified, then enriched with
a severity bump, then reasoned with a playbook. Heartbeat every 15s, and subscribers unsubscribe
in a `finally` so refreshes never leak queues.

</td>
<td width="33%" valign="top">

### 🔌 True offline mode
`OFFLINE_MODE=true` swaps only the four network leaves — both LLM tiers, both intel sources,
ATT&CK retrieval — for deterministic in-process stand-ins. The graph, routers, workers, queues,
bus, SQLite, and every API route are the real ones, and offline JSON goes through the **same**
parser the live path uses.

</td>
</tr>
</table>

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | FastAPI 0.139 + Uvicorn 0.51 | 18 routes, SSE, DI wiring, lifespan-managed workers |
| Agent orchestration | LangGraph 1.2 + langchain-core 1.5 | `classify → enrich → retrieve → reason → recommend → finalize` |
| Fast LLM tier | Groq `llama-3.1-8b-instant` (groq 1.5) | Sub-second severity + attack-type tagging on every alert |
| Quality LLM tier | Gemini `gemini-flash-latest` (google-generativeai 0.8) | Grounded analysis narrative + remediation playbook |
| Threat intel | AbuseIPDB + VirusTotal via httpx 0.28 | Live IP/hash reputation, token-bucket rate limited |
| Vector store | Chroma 1.5 (persistent, cosine) | 27 ATT&CK techniques → 81 indexed chunks |
| Embeddings | sentence-transformers 5.6 `all-MiniLM-L6-v2` | 384-dim, local, zero API cost |
| Database | SQLite + SQLAlchemy 2.0 (async) + aiosqlite | Alerts, enrichment, remediation, traces, eval/benchmark runs |
| Migrations | Alembic 1.18 — 3 revisions | Schema versioning |
| Validation | Pydantic 2.13 + pydantic-settings 2.14 | Frozen API contract, single env-reading surface |
| Resilience | tenacity 9.1, custom token bucket, TieredCache | Retry/backoff, quota caps, memory→SQLite cache |
| Streaming | sse-starlette 3.4 | `alert.new`, `alert.updated`, `stats.updated`, `replay.status`, `system.notice` |
| Logging | structlog 26.1 + orjson 3.11 | Structured JSON logs with request/alert context binding |
| Frontend | React 18.3 + Vite 5.4 + TypeScript 5.5 | Dashboard, drill-down drawer, eval + benchmark panels |
| UI | Tailwind CSS 3.4, Framer Motion 12, lucide-react | Design tokens, motion, iconography |
| 3D | three 0.185 + @react-three/fiber 8 + drei 9 | Landing hero, starfield backdrop |
| Data | pandas 3.0 + CICIDS2017 subset / Suricata EVE | Replay source + 450-row labeled ground truth |
| Quality | pytest 9.1, ruff 0.16, mypy 2.3 | 371 tests, lint and strict-optional type gates |

**Stack notes, verified against `pyproject.toml` and `package.json`:**
- **Model slugs are pinned deliberately and documented in `app/config.py`.** `gemini-2.0-flash`
  returns a *permanent* 429 (`limit: 0`) on a free key rather than a transient rate limit, so the
  default is `gemini-flash-latest`; retired Groq slugs raise a startup warning. `make smoke`
  proves both per key against the live model listings.
- **No Redis, no Celery, no separate worker service.** One process, one event loop — two bounded
  `asyncio.Queue` pools plus an in-process pub/sub bus, all started and stopped by the FastAPI
  lifespan.
- **There is no root `package.json` or root Python project.** `backend/` and `frontend/` are
  independent projects with their own dependency files, installed and run separately.

## 📁 Project Structure

```
Flare/
├── backend/                       # FastAPI + LangGraph, :8000
│   ├── app/
│   │   ├── agent/                 # The triage graph — imports NO db, bus, queue or FastAPI
│   │   │   ├── graph.py           # build_graph / build_enrich_graph, run_triage, finalize
│   │   │   ├── router.py          # Pure conditional-edge functions (exhaustively unit-tested)
│   │   │   ├── state.py           # TriageState + dependency resolution (the test seam)
│   │   │   ├── trace.py           # @traced — exactly one TraceNode per node, always
│   │   │   ├── nodes/             # classify, enrich, retrieve, reason, recommend
│   │   │   └── prompts/           # classify.md, reason.md, recommend.md
│   │   ├── api/
│   │   │   ├── errors.py          # Typed hierarchy → frozen { error: {code,message,detail} }
│   │   │   ├── router.py          # The single /api/v1 router
│   │   │   └── routes/            # alerts, ingest, replay, stream, health, evaluation, benchmark
│   │   ├── core/
│   │   │   ├── bus.py             # In-process pub/sub feeding SSE
│   │   │   ├── cache.py           # InMemoryTTLCache, DbBackedCache, TieredCache
│   │   │   ├── ratelimit.py       # FIFO token bucket, cancellation-safe
│   │   │   ├── quota.py           # Provider quota tracking from response headers
│   │   │   ├── retry.py           # Backoff + permanent-vs-transient 429 detection
│   │   │   ├── metrics.py         # Latency/token counters, one percentile impl
│   │   │   └── logging.py         # structlog config + contextvar binding
│   │   ├── evaluation/
│   │   │   ├── runner.py          # Eval through the production graph
│   │   │   ├── benchmark.py       # Fast vs quality tier, warmup-discarded
│   │   │   ├── ground_truth.py    # Label loading, stratified sampling, health checks
│   │   │   ├── metrics.py         # Macro precision/recall/F1, confusion matrix
│   │   │   └── staleness.py       # Reaps runs orphaned by a crashed process
│   │   ├── ingestion/
│   │   │   ├── replay.py          # ReplayEngine — dependency-inverted, non-drifting scheduler
│   │   │   ├── normalizer.py      # Source → parser dispatch + IOC extraction
│   │   │   ├── dedup.py           # Content-derived id / duplicate suppression
│   │   │   └── parsers/           # suricata_eve, zeek, cicids
│   │   ├── intel/                 # aggregator (single-flight, partial-failure), abuseipdb,
│   │   │                          #   virustotal, base (shared HTTP + limiter), models
│   │   ├── providers/             # registry (tier → provider), groq, gemini, parsing (JSON
│   │   │                          #   extraction + repair), base
│   │   ├── rag/
│   │   │   ├── indexer.py         # Embedding model singleton + Chroma upsert
│   │   │   ├── retriever.py       # Attack-type-filtered search, all calls thread-hopped
│   │   │   ├── chunker.py         # Technique doc → chunks
│   │   │   ├── mitre_loader.py    # Corpus loader + AttackType → technique-id map
│   │   │   └── corpus/            # 27 ATT&CK technique JSON files (T1018 … T1595)
│   │   ├── schemas/               # alert, enrichment, remediation, evaluation, events
│   │   ├── store/                 # db (async engine), models (ORM), repositories, chroma
│   │   ├── workers/               # manager, queue (BoundedQueue), triage_worker, enrich_worker
│   │   ├── config.py              # The ONLY module that reads the environment
│   │   ├── deps.py                # FastAPI DI providers — every collaborator overridable
│   │   ├── main.py                # App factory, lifespan, CORS, request-id middleware
│   │   └── offline.py             # Deterministic stand-ins for the four network leaves
│   ├── alembic/versions/          # 3 migrations
│   ├── data/
│   │   └── labels/                # cicids2017_labeled_subset.csv — 450 rows, committed
│   ├── scripts/                   # bootstrap + demo CLIs (see below)
│   ├── tests/                     # 32 test modules — 371 tests
│   │   ├── unit/                  # routers, parsers, providers, cache, limiter, repos, schemas
│   │   ├── integration/           # api, graph, workers, rag, eval, benchmark, hardening, load
│   │   └── fixtures/              # Suricata EVE, Zeek notice, CICIDS samples
│   ├── Makefile                   # bootstrap, dev, dev-offline, test, lint, typecheck, smoke
│   ├── pyproject.toml
│   └── .env.example
│
└── frontend/                      # React + Vite, :5173
    ├── src/
    │   ├── components/
    │   │   ├── drawer/            # AlertDrawer, PipelineTrace, IntelSections, ActionSections
    │   │   ├── eval/              # EvalPanel, BenchmarkPanel
    │   │   ├── feed/              # AlertFeed, InjectAlertModal
    │   │   ├── pipeline/          # Realistic3DHero (+ Pipeline3DHero, PipelineGraph variants)
    │   │   ├── replay/            # ReplayBar — transport controls
    │   │   ├── stats/             # StatsStrip, HealthPopover
    │   │   └── ui/                # LandingPage, CommandBar (⌘K), Card3D, BackgroundStars,
    │   │                          #   Primitives
    │   ├── hooks/useAlertStream.ts # SSE wiring, replay actions, live-vs-offline switching
    │   ├── lib/
    │   │   ├── api.ts             # Typed client for every backend route + EventSource stream
    │   │   ├── generator.ts       # Offline/demo simulation fallback only
    │   │   ├── format.ts          # fmtPct, fmtMs, clock helpers
    │   │   ├── isoGraph.ts        # Isometric layout math for the pipeline diagram
    │   │   └── evalData.ts        # Static panel scaffolding
    │   ├── types.ts               # Mirrors the backend contract shapes
    │   ├── App.tsx                # Landing ⇄ dashboard, drawer + command bar orchestration
    │   └── main.tsx
    ├── FLARE_BACKEND.md           # Full backend guide + API contract
    ├── PITCH.md                   # Problem framing, domain, industrial applications
    ├── tailwind.config.js
    └── vite.config.ts             # `@` → `src` alias
```

`backend/data/` beyond the committed label set — the Chroma index, the replay datasets, and
`flare.db` — is generated by the bootstrap steps and intentionally untracked.

## ⚙️ Getting Started

### Prerequisites

- **Python 3.11+** — `pyproject.toml` sets `requires-python = ">=3.11"`; the project is
  developed and type-checked against 3.12.
- **Node.js 18+** — required by Vite 5.
- **[uv](https://docs.astral.sh/uv/)** *(recommended)* — every `Makefile` target drives `uv run`.
  A plain `venv` + `pip` path is given below if you prefer.
- **API keys are optional.** The app starts with **zero** keys configured: missing providers are
  logged as warnings, the affected features degrade visibly, and `OFFLINE_MODE=true` runs the
  entire pipeline with no network at all. For live calls:
  [Groq](https://console.groq.com/keys), [Google AI Studio](https://aistudio.google.com/apikey),
  [AbuseIPDB](https://www.abuseipdb.com/account/api),
  [VirusTotal](https://www.virustotal.com/gui/my-apikey).

### 1. Clone

```bash
git clone <repo-url>
cd Flare
```

### 2. Backend

```bash
cd backend
cp .env.example .env
```

Install dependencies — with `uv`:

```bash
uv sync --extra dev
```

Or with a standard virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The keys in `.env` are all optional; leave them blank to run offline. The settings worth knowing:

```bash
GROQ_API_KEY=                      # fast tier — blank disables live classification
GOOGLE_API_KEY=                    # quality tier — blank disables reasoning/remediation
ABUSEIPDB_API_KEY=                 # IP reputation
VIRUSTOTAL_API_KEY=                # IP + hash reputation (free tier: 4 req/min)
OFFLINE_MODE=false                 # true = full pipeline, zero network
IOC_ESCALATION_SCORE=80            # worst IOC score that force-upgrades severity to HIGH
TRIAGE_TIMEOUT_SECONDS=120         # wall-clock budget for one full classify→recommend run
CORS_ORIGINS=["http://localhost:5173"]
```

> `CORS_ORIGINS` **must** be a JSON array. A comma-separated value raises a `SettingsError` and
> the app will not start. In `APP_ENV=development`, `"*"` is appended automatically.

Now build the index, the database, and a seeded dashboard. One command:

```bash
make bootstrap        # labels → fetch-data → index → migrate → seed
```

Or the same steps directly, if you don't have `make`:

```bash
python -m scripts.build_label_set     # labeled eval subset (skipped if present)
python scripts/fetch_datasets.py      # replay datasets
python -m scripts.index_mitre         # embed 27 ATT&CK techniques into Chroma
alembic upgrade head                  # create the schema
python -m scripts.seed_demo           # ~200 pre-triaged alerts so the feed is never empty
```

Every step is idempotent, so re-running is always safe.

### 3. Frontend

```bash
cd ../frontend
npm install
```

The frontend needs no `.env` for local use — it defaults to `http://localhost:8000`. To point it
elsewhere, create `frontend/.env`:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

### 4. Run

Two terminal panes:

```bash
# Pane 1 — API + workers + replay engine
cd backend && make dev               # :8000   (or: uvicorn app.main:app --reload)

# Pane 2 — dashboard
cd frontend && npm run dev           # :5173
```

Open <http://localhost:5173>. For a demo with no network at all — dead venue wifi, exhausted
free-tier quota, a provider outage — use:

```bash
cd backend && make dev-offline       # or: OFFLINE_MODE=true uvicorn app.main:app
```

The graph, workers, queues, database, SSE and every route stay real; only the four calls that
would leave the process are substituted, and the dashboard labels itself accordingly.

### 5. Verify

```bash
cd backend
make smoke        # one real call per dependency: both LLMs, both intel APIs,
                  # Chroma round-trip, SQLite, embeddings, ground-truth health
make check        # ruff + mypy + 371 tests
```

`make smoke` reports each dependency as OK / FAIL / SKIPPED and never prints a secret — keys are
truncated to their last four characters. It also distinguishes a permanent zero-quota 429 from
ordinary backpressure, and checks configured model slugs against the live model listings.

## 🔌 API

Every route is mounted under `/api/v1`. All errors — including router-level 404s and 405s —
return the same envelope: `{ "error": { "code", "message", "detail" } }`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness only. Zero dependency work, always fast |
| `GET` | `/health/deep` | Per-service status, latency, quota, Chroma doc count, worker stats |
| `GET` | `/alerts` | Feed list. `limit` (1–200, default 50), `offset`, `severity`/`status`/`attack_type` (csv), `src_ip`, `malicious_only`, `since`, `sort` |
| `GET` | `/alerts/stats` | Header counters + 1-minute timeline buckets over the last 30 minutes |
| `GET` | `/alerts/{alert_id}` | Full drill-down: raw event, trace, IOC verdicts, narrative, playbook |
| `POST` | `/ingest` | Manual alert. Accepts Suricata EVE JSON **or** a simplified body → `202` |
| `POST` | `/replay/start` | Start a dataset replay. `{ dataset, events_per_second, limit }` |
| `POST` | `/replay/pause` | Pause. `409` if not running |
| `POST` | `/replay/resume` | Resume. `409` if not paused |
| `POST` | `/replay/stop` | Stop and reset. `409` if idle |
| `GET` | `/replay/status` | State, dataset, emitted, skipped, live queue depths |
| `GET` | `/stream` | SSE feed — the dashboard's live wire |
| `POST` | `/evaluation/run` | Enqueue an eval → `202 { run_id }`. One in flight at a time |
| `GET` | `/evaluation/runs` | Past runs, newest first (list projection) |
| `GET` | `/evaluation/runs/{run_id}` | Full report: overall, per-class, confusion matrix, both targets |
| `POST` | `/benchmark/run` | Enqueue a fast-vs-quality benchmark → `202 { run_id }` |
| `GET` | `/benchmark/runs` | Past benchmark runs, newest first |
| `GET` | `/benchmark/runs/{run_id}` | Per-tier latency/accuracy/cost + disagreement examples |

Datasets accepted by `/replay/start` are `cicids2017`, `cicids`, and `suricata`. Illegal replay
transitions answer `409` with the current state named; an unknown dataset is `404`; a saturated
triage queue is `503` with code `rate_limited`.

### Ingesting an alert

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H 'Content-Type: application/json' \
  -d '{"signature":"ET TROJAN Cobalt Strike Beacon","src_ip":"45.13.2.99",
       "dst_ip":"10.0.0.5","dst_port":443,"protocol":"TCP"}'
```

```json
{ "id": "4ea645a8-c676-4272-b151-e6a405d77f18", "status": "ingested" }
```

The graph is **never** run inline — `202` returns in milliseconds and the triaged result arrives
over SSE. Fetching it once the full pipeline completes (node durations below are the warm
live-tier timings recorded in `app/config.py`):

```jsonc
// GET /api/v1/alerts/4ea645a8-c676-4272-b151-e6a405d77f18
{
  "id": "4ea645a8-c676-4272-b151-e6a405d77f18",
  "timestamp": "2026-07-26T18:13:52.055719Z",
  "status": "done",
  "severity": "critical",
  "confidence": 0.82,
  "attack_type": "malware_c2",
  "signature": "ET TROJAN Cobalt Strike Beacon",
  "src_ip": "45.13.2.99", "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP",
  "source": "manual",
  "has_enrichment": true, "has_remediation": true,
  "max_ioc_score": 95.0, "total_duration_ms": 44562,
  "trace": [
    { "node": "classify",  "status": "ok", "provider": "groq:llama-3.1-8b-instant",
      "duration_ms": 1612, "tokens_in": 829, "tokens_out": 36,
      "note": "signature keywords indicate malware_c2" },
    { "node": "enrich",    "status": "ok", "provider": null, "duration_ms": 1043,
      "tokens_in": null, "tokens_out": null,
      "note": "1 indicator(s) enriched, worst score 95" },
    { "node": "retrieve",  "status": "ok", "provider": null, "duration_ms": 1907,
      "tokens_in": null, "tokens_out": null,
      "note": "retrieved T1071, T1071.001, T1573, T1105" },
    { "node": "reason",    "status": "ok", "provider": "gemini:gemini-flash-latest",
      "duration_ms": 24118, "tokens_in": 792, "tokens_out": 331, "note": null },
    { "node": "recommend", "status": "ok", "provider": "gemini:gemini-flash-latest",
      "duration_ms": 15882, "tokens_in": 964, "tokens_out": 288,
      "note": "3 step(s), 4 technique(s); dropped 1 hallucinated/absent technique id(s)" }
  ],
  "enrichment": { "iocs": [ { "indicator": "45.13.2.99", "indicator_type": "ip",
                             "score": 95.0, "malicious": true, "cached": false,
                             "sources": [ { "source": "abuseipdb", "raw_score": 95.0,
                                            "categories": ["hacking", "exploited_host"],
                                            "link": "https://www.abuseipdb.com/check/45.13.2.99" } ] } ] },
  "remediation": { "summary": "…", "steps": [ /* 3 steps, order 1..N, urgency-tagged */ ],
                   "techniques": [ /* only ids the retriever actually returned */ ] }
}
```

The `dropped N hallucinated/absent technique id(s)` note is the guard reporting itself — the
model cited a technique the retriever never returned, and it was removed before persistence.

### SSE event shape

`GET /api/v1/stream` opens with a `flare stream connected` comment and `retry: 3000`, then sends
a heartbeat comment every 15s. Five event types are published:

```
event: alert.new
data: {"id":"4ea645a8…","timestamp":"2026-07-26T18:13:52.055719Z","status":"classified",
       "severity":"critical","confidence":0.82,"attack_type":"malware_c2",
       "signature":"ET TROJAN Cobalt Strike Beacon","src_ip":"45.13.2.99",
       "dst_ip":"10.0.0.5","dst_port":443,"protocol":"TCP","source":"manual",
       "has_enrichment":false,"has_remediation":false,"max_ioc_score":null}
```

`alert.new` and `alert.updated` both carry an `AlertSummary` — never the full detail; the drawer
fetches that separately. `stats.updated` carries the same payload as `GET /alerts/stats`,
`replay.status` mirrors `GET /replay/status`, and `system.notice` carries
`{ level, message }` for run completions and degradation warnings.

## ⚠️ Known Limitations

- **Single-process, single-node by design.** SQLite, in-process `asyncio` queues and an in-memory
  event bus mean the whole system is one self-contained unit with no broker to operate — excellent
  for a self-contained triage appliance, and a vertical-scaling story rather than a horizontal
  one.
- **Enrichment throughput is bounded by free-tier intel quotas.** VirusTotal allows 4 requests
  per minute, so the enrich worker runs at concurrency 1 on purpose; extra parallelism there
  would only buy 429s. Verdicts are cached for 24 hours to make the budget go further.
- **The API is unauthenticated.** It is built for a single-operator lab or demo environment,
  where the dashboard and the API share a trust boundary.

## 🔮 Future Improvements

- **Per-service intel health checks** — `/health/deep` currently evaluates AbuseIPDB and
  VirusTotal under one shared timeout budget; splitting them isolates a slow source from a
  healthy one, and caching the result keeps a polled endpoint from consuming live quota.
- **Push stats over SSE instead of re-fetching** — the `stats.updated` event already carries the
  full `AlertStats` payload, so the dashboard can render from the frame it already has and drop a
  round-trip per update.
- **Adaptive VirusTotal quota handling** — read the remaining-quota header into the limiter so
  the enrich worker paces itself against the real budget and parks cleanly when it is exhausted,
  instead of relying on a fixed 4/min cap.
- **Authentication and multi-tenancy** — API keys or OIDC, per-tenant alert isolation, and
  role-gated access to the replay and evaluation controls.
- **CI pipeline** — GitHub Actions running `ruff`, `mypy`, and the 371-test suite on every PR,
  plus an accuracy gate that fails the build on macro-F1 regression against the labeled set.
- **Live capture instead of replay** — consume Suricata EVE or Zeek logs from a socket or file
  tail so the pipeline runs against a real sensor rather than a recorded dataset.
- **Broader ATT&CK coverage** — the corpus is 27 hand-picked techniques; ingesting the full
  enterprise matrix would widen grounding, with an approximate-nearest-neighbour index to keep
  retrieval fast at that size.
- **Human-in-the-loop corrections** — let an analyst override severity or attack type from the
  drawer and capture those overrides as an additional ground-truth corpus for evaluation.
