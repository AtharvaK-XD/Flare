# Flare — Backend Guide & API Contract (for the Frontend)

**Project:** Flare — AI-Powered Security Incident Triage Agent
**Backend:** FastAPI + LangGraph + SQLite + Chroma
**Audience:** the frontend dev building the React + Vite dashboard
**Status of this doc:** written against the code as it actually runs on branch `backend`. Where the earlier hand-written contract disagreed with the running backend, **the backend wins** and the difference is called out in §14.

---

## 1. What the backend actually is

Flare replays a stream of real security alerts (CICIDS2017 flows, Suricata EVE JSON) and triages each one through a multi-stage AI pipeline. It is one FastAPI process containing:

- **an HTTP API** (`/api/v1/...`) — everything you call,
- **an SSE stream** (`/api/v1/stream`) — how the dashboard stays live,
- **two in-process worker pools** consuming two bounded queues,
- **a LangGraph state machine** that does the actual triage,
- **SQLite** (alerts, enrichment, remediation, traces, eval/benchmark runs) and **Chroma** (MITRE ATT&CK vectors).

There is no separate worker service, no Redis, no Celery. One process, one event loop.

### The moving parts

```
                POST /ingest ─┐
                              ├──> triage queue ──> triage workers (4)
   replay engine (dataset) ───┘                        │
                                                       │  classify only (Groq, fast)
                                                       │  persist + publish alert.new
                                                       ▼
                                              route_after_classify
                                              ┌────────┴────────┐
                                     "enrich" │                 │ "finalize"
                                              ▼                 ▼
                                     enrich queue ──> enrich worker (1)
                                                       │
                                                       │ enrich → retrieve → reason → recommend
                                                       │ publish alert.updated after EACH stage
                                                       ▼
                                                    SQLite
                                                       │
                          event bus ──> GET /api/v1/stream (SSE) ──> your dashboard
```

**Why two pools:** the triage pool must stay responsive so cards appear instantly, so it runs *only* the classify node (`stop_after="classify"`). Everything slow — threat intel with a 4 req/min VirusTotal cap, MITRE retrieval, Gemini reasoning — is pushed to a **single** enrich worker (concurrency 1 on purpose; more concurrency against a free-tier intel API buys nothing but 429s).

---

## 2. Mental model — read this before writing any component

**Alerts are not returned fully-formed.** They arrive fast and cheap, then get *upgraded in place* as slower stages finish.

```
ingested → classified → enriched → reasoned → done
   |           |            |          |
   |           |            |          └─ remediation steps generated (Gemini + MITRE RAG)
   |           |            └─ IOC reputation attached (AbuseIPDB / VirusTotal)
   |           └─ severity + attack type tagged (Groq, sub-second)
   └─ raw alert parsed & normalized
```

**Critical frontend implication:** a card appears within ~1–2s showing severity, then the IOC badge fills in a few seconds later, then the remediation panel fills in after that. Build the UI so fields can be `null` and arrive later. Do **not** wait for a complete object before rendering.

**Not every alert reaches every stage — by design.** That skipping *is* the product (it is what makes the system cheap). Real routing rules, from `app/agent/router.py`:

| Transition | Rule |
|---|---|
| classify → **enrich** | severity is `critical`, `high`, or `medium` |
| classify → **finalize** | severity is `low` or `info` (unless `ENRICH_LOW_SEVERITY=true` *and* the alert has public IOCs) |
| enrich → **retrieve** | severity is `critical` or `high`, **or** severity is `medium` and worst IOC score ≥ 40 |
| enrich → **finalize** | otherwise |
| retrieve → **reason** | always |
| reason → **recommend** | a non-empty narrative was produced |
| reason → **finalize** | model returned nothing usable |
| recommend → **finalize** | always |

So a `low` alert goes straight to `done` with `enrichment: null`, `remediation: null`, `reasoning: null`. **That is a success, not an error.** Its `trace` will contain `status: "skipped"` entries with a human-readable `note` explaining why each stage was bypassed — render those, they are the transparency story.

**One more escalation rule worth showing in the UI:** if threat intel returns a worst IOC score ≥ `IOC_ESCALATION_SCORE` (default **80**) and the model said something below `high`, the backend **overrides the model** and upgrades severity to `high`. The trace note says so verbatim: `severity upgraded medium -> high (IOC score 92 >= 80)`. That is the single best thing to surface in a drill-down — real threat intel outranking an LLM's first impression.

---

## 3. Running the backend locally

```bash
git clone <repo> && cd Flare && cp .env.example .env && make bootstrap
```

Then either:

```bash
make dev
```

```bash
make dev-offline
```

- `make dev` — normal server on `http://localhost:8000`, live LLM/intel calls if keys are in `.env`.
- `make dev-offline` — `OFFLINE_MODE=true`. **No network at all.** Both LLM tiers, both intel sources, and ATT&CK retrieval are served by deterministic in-process stand-ins. The graph, routers, workers, queues, bus, DB, SSE and every API route are the real ones — the API responses are shape-identical. **Use this for frontend development.** It is fast, free, deterministic, and cannot run out of quota.
- The app starts fine with **zero API keys**; features degrade visibly rather than crashing.
- `make seed` (already part of `bootstrap`) preloads ~200 triaged alerts so the dashboard is never empty on first load.

Other useful targets: `make smoke` (verify every external dependency), `make check` (lint + typecheck + tests), `make clean-runs` (unstick a crashed eval/benchmark run).

In offline mode `/health/deep` reports the four external services as `ok` with the note `served by the offline stand-in (OFFLINE_MODE=true)`, and the trace `provider` reads `offline:offline-deterministic`. Worth a small badge in the header so a demo audience is never misled about what is real.

---

## 4. Conventions

| Thing | Value |
|---|---|
| Base URL (local) | `http://localhost:8000` |
| Base URL (deployed) | `https://<render-app>.onrender.com` — set via `VITE_API_BASE_URL` |
| Prefix | every endpoint below is under `/api/v1` |
| Content type | `application/json` |
| Timestamps | ISO-8601 UTC |
| IDs | UUID v4 strings |
| Auth | **none** — no tokens, no headers |
| CORS | `CORS_ORIGINS` from env (default `http://localhost:5173`); in dev `*` is added too. `X-Request-ID` is exposed. |
| Request tracing | every response carries `X-Request-ID`. If you report a bug, send that id — it joins to the backend logs. |

---

## 5. Enums (hardcode these)

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";

type AlertStatus = "ingested" | "classified" | "enriched" | "reasoned" | "done" | "failed";

type AttackType =
  | "port_scan" | "brute_force" | "ddos" | "web_attack" | "malware_c2"
  | "data_exfiltration" | "privilege_escalation" | "recon" | "benign" | "unknown";

type IntelSource = "abuseipdb" | "virustotal";
type ProviderTier = "fast" | "quality";
type RunStatus  = "running" | "completed" | "failed";
type ReplayState = "idle" | "running" | "paused" | "completed";
```

Suggested severity colors: `critical` #DC2626 · `high` #EA580C · `medium` #D97706 · `low` #2563EB · `info` #6B7280

An IOC counts as **malicious** at score **≥ 50** (that is the threshold the `malicious_only` filter and the `malicious_iocs` counter use). Escalation to `high` happens at **≥ 80**. Two different numbers, both worth respecting in the badge design.

---

## 6. Core data models

These are transcribed from the pydantic models in `app/schemas/`. Numbers are `float` unless noted — do not assume integers for scores or confidence.

```ts
interface AlertSummary {          // list endpoint + every alert.* SSE event
  id: string;
  timestamp: string;
  status: AlertStatus;
  severity: Severity | null;      // null until classified
  confidence: number | null;      // 0.0–1.0, float
  attack_type: AttackType | null;
  signature: string;              // e.g. "ET SCAN Suricata port scan detected"
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;        // "TCP" | "UDP" | "ICMP" | ...
  source: string;                 // "suricata" | "cicids2017" | "manual"
  has_enrichment: boolean;
  has_remediation: boolean;
  max_ioc_score: number | null;   // 0–100 float, worst IOC on this alert
}

interface IocSourceEntry {
  source: IntelSource;
  raw_score: number;
  categories: string[];           // e.g. ["ssh_bruteforce", "port_scan"]
  last_seen: string | null;
  link: string | null;            // deep link to the vendor page, safe to render
}

interface IocVerdict {
  indicator: string;              // IP or file hash
  indicator_type: "ip" | "hash";
  score: number;                  // 0–100 normalized (higher = worse)
  malicious: boolean;
  sources: IocSourceEntry[];
  cached: boolean;                // true = served from cache, not a live call
}

interface Enrichment {
  iocs: IocVerdict[];
  enriched_at: string;
  duration_ms: number;            // int
}

interface MitreTechnique {
  id: string;                     // "T1046"
  name: string;                   // "Network Service Discovery"
  tactic: string;                 // "Discovery"
  url: string;
  excerpt: string;                // the retrieved chunk used as grounding
}

interface RemediationStep {
  order: number;
  action: string;                 // short imperative — good list-item text
  detail: string;                 // 1–3 sentences
  urgency: "immediate" | "soon" | "monitor";
}

interface Remediation {
  summary: string;                // 1–2 sentence analyst-facing explanation
  steps: RemediationStep[];
  techniques: MitreTechnique[];   // citations — render as chips linking to url
  generated_at: string;
  duration_ms: number;
}

interface TraceNode {
  node: "classify" | "enrich" | "retrieve" | "reason" | "recommend";
  status: "ok" | "skipped" | "failed";
  provider: string | null;        // "groq:llama-3.1-8b-instant" | "gemini:gemini-flash-latest"
                                  // | "offline:offline-deterministic" | null
  duration_ms: number;
  tokens_in: number | null;
  tokens_out: number | null;
  note: string | null;            // e.g. "retrieval skipped: severity 'low' ... below the threshold"
}

interface AlertDetail extends AlertSummary {
  raw: Record<string, unknown>;   // original parsed alert — collapsed <pre>
  reasoning: string | null;       // the model's analysis narrative
  enrichment: Enrichment | null;
  remediation: Remediation | null;
  trace: TraceNode[];
  total_duration_ms: number | null;
}
```

**About `trace`:** once an alert reaches `done` the trace contains an entry for **all five** pipeline nodes — the ones that ran (`ok`/`failed`, with provider + tokens + duration) and the ones that did not (`skipped`, `duration_ms: 0`, with a `note` that explains why in plain English). Order in the array follows insertion order (execution order, then the backfilled skips). Sort by the fixed pipeline order client-side if you want a stable column layout.

---

## 7. REST endpoints

### `GET /api/v1/health`
Liveness, zero dependency work, always fast. Returns `{"status": "ok"}`. Use it for the connection dot.

### `GET /api/v1/health/deep`
Every dependency checked concurrently under a 5s budget. A check that fails or times out marks *that service* degraded — the endpoint itself never fails.

```json
{
  "status": "degraded",
  "services": {
    "groq":       { "status": "ok",       "latency_ms": 210 },
    "gemini":     { "status": "ok",       "latency_ms": 640 },
    "abuseipdb":  { "status": "ok",       "quota_remaining": 940 },
    "virustotal": { "status": "degraded", "quota_remaining": 0, "note": "rate limited" },
    "chroma":     { "status": "ok",       "documents": 27 },
    "database":   { "status": "ok",       "latency_ms": 1 }
  },
  "workers": {
    "triage": { "active": 4, "configured": 4, "restarts": 0 },
    "enrich": { "active": 1, "configured": 1, "restarts": 0 },
    "queues": {
      "triage": { "name": "triage", "depth": 4, "maxsize": 1000, "enqueued": 312,
                  "dequeued": 308, "rejected": 0, "avg_wait_ms": 12.4 },
      "enrich": { "name": "enrich", "depth": 11, "maxsize": 500, "enqueued": 90,
                  "dequeued": 79, "rejected": 0, "avg_wait_ms": 4210.7 }
    },
    "degraded": false
  }
}
```

- Per-service `status`: `ok` | `degraded` | `down`. Top-level `status` is worst-wins across all services.
- **Null fields are omitted from the JSON entirely** (`response_model_exclude_none=True`). Type every optional field as `field?: T | undefined`, not `T | null`. A service object may legitimately be just `{ "status": "ok" }`.
- The six service keys are always present. `workers` is **additive** (not in the original contract) — it is a free "4/4 triage workers, 1/1 enrich worker" strip if you want it.
- Calling this hits the live providers (a `ping` completion each). Poll it at ~10s, not 1s.

---

### `GET /api/v1/alerts`
The main feed/table. All query params optional.

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | 50 | 1–200, out of range → 422 |
| `offset` | int | 0 | offset past the end = empty page, never 404 |
| `severity` | csv | — | `?severity=critical,high` |
| `status` | csv | — | |
| `attack_type` | csv | — | |
| `src_ip` | string | — | exact match |
| `malicious_only` | bool | false | alerts whose worst IOC score ≥ 50 |
| `since` | ISO ts | — | |
| `sort` | string | `-timestamp` | `-timestamp` \| `timestamp` \| `-severity` |

```json
{ "items": [ /* AlertSummary[] */ ], "total": 1284, "limit": 50, "offset": 0 }
```

An unknown csv value or an unknown `sort` is a **422** whose `detail` names the offending value *and* lists the allowed set — surface it, it is designed to be readable:

```json
{ "error": { "code": "validation_error", "message": "invalid severity value(s): urgent",
  "detail": { "field": "severity", "invalid": ["urgent"],
              "allowed": ["critical","high","info","low","medium"] } } }
```

`-severity` sorts critical → info, then newest-first inside each severity.

### `GET /api/v1/alerts/stats`
Header counters + charts. **Declared before `/alerts/{id}`**, so `stats` is never treated as an id.

```json
{
  "total": 1284,
  "by_severity":    { "critical": 12, "high": 48, "medium": 190, "low": 604, "info": 430 },
  "by_attack_type": { "port_scan": 310, "brute_force": 120, "benign": 700 },
  "by_status":      { "done": 1240, "reasoned": 20, "enriched": 15, "classified": 9 },
  "malicious_iocs": 37,
  "avg_triage_ms": 890.4,
  "alerts_per_min": 42.0,
  "timeline": [ { "bucket": "2026-08-07T14:20:00Z", "count": 40, "critical": 1 } ]
}
```

- The `by_*` maps only contain keys that exist in the data — **a severity with zero alerts is absent, not `0`**. Merge against the full enum list before rendering a chart or your bars will jump around.
- `avg_triage_ms` is `null` when nothing has completed yet.
- `alerts_per_min` = alerts in the last 30 minutes ÷ 30. It is a 30-minute average, not an instantaneous rate — it ramps up slowly at the start of a replay. Label it accordingly.
- `timeline` = 1-minute buckets over the last 30 minutes. Feed it straight to a chart.

### `GET /api/v1/alerts/{id}`
Full `AlertDetail`. Drives the drill-down drawer. `404` with `code: "not_found"` for an unknown id.

---

### Replay control

| Method | Path | Body | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/replay/start` | `{ "dataset": "cicids2017", "events_per_second": 5, "limit": 500 }` | begin feed |
| `POST` | `/api/v1/replay/pause` | — | pause |
| `POST` | `/api/v1/replay/resume` | — | resume |
| `POST` | `/api/v1/replay/stop` | — | stop + reset cursor |
| `GET` | `/api/v1/replay/status` | — | current state |

**Every one of these — including the POSTs — returns the full `ReplayStatus` object.** You do not need to follow a POST with a GET.

```json
{
  "state": "running",
  "dataset": "cicids2017",
  "events_per_second": 5.0,
  "emitted": 312,
  "total": 500,
  "queue_depth": { "triage": 4, "enrich": 11 },
  "started_at": "2026-08-07T14:20:00Z",
  "skipped": 18
}
```

- Valid `dataset` values: **`cicids2017`**, **`cicids`** (alias), **`suricata`**. Anything else → `404`.
- `events_per_second` and `limit` are both optional; omitted `events_per_second` falls back to `REPLAY_EVENTS_PER_SECOND` (default 10).
- **`total` is the `limit` you passed, and is `null` if you passed none.** A progress bar needs a limit — either always send one, or fall back to an indeterminate bar when `total` is null.
- `skipped` (**additive**) counts records the parsers refused: malformed rows and down-sampled benign flows. Without it, "500 records replayed, 380 alerts" looks like 120 lost alerts. Show it as "N records skipped" next to the progress bar.
- Illegal transitions are **`409` with `code: "conflict"`** and a message naming the current state (`"cannot resume replay while it is running"`), never a 500 and never a silent no-op. Disable the buttons by `state` and treat a 409 as "your view was stale — refetch status".
- Every state change also republishes `replay.status` on the SSE bus, so all connected dashboards update without polling.
- `queue_depth.enrich` climbing is **normal and intentional** — enrichment is deliberately rate-capped at one worker. Surface it as an "enrichment backlog" number; it is a good talking point for judges.

---

### `POST /api/v1/ingest`
Manually push one alert — the "try your own alert" demo button.

Body is **either** raw Suricata EVE JSON (detected by the presence of an `event_type` key) **or** the simplified shape:

```json
{ "signature": "SSH brute force", "src_ip": "45.13.2.99", "dst_ip": "10.0.0.5", "dst_port": 22, "protocol": "TCP" }
```

`signature`, `src_ip` and `dst_ip` are required in the simplified form; everything else is optional.

Returns **`202`** `{ "id": "...", "status": "ingested" }` in milliseconds. **The triaged result arrives over SSE** — the graph is never run inline. Watch for `alert.new` carrying that id.

- Unparseable body → `422`, `detail.received_keys` lists what you sent.
- Triage queue saturated → **`503`** with `code: "rate_limited"`. Retry shortly; do not treat it as a crash.
- The same body can be submitted twice — each submission gets a fresh UUID.

---

### Evaluation (judge-facing accuracy)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/evaluation/run` | body `{ "sample_size": 200 }` (optional) → **202** `{ run_id, status: "running" }` |
| `GET` | `/api/v1/evaluation/runs` | past runs, newest first, summary projection |
| `GET` | `/api/v1/evaluation/runs/{run_id}` | full report |

```json
{
  "run_id": "…",
  "status": "completed",
  "sample_size": 200,
  "started_at": "…",
  "completed_at": "…",
  "overall": { "precision": 0.91, "recall": 0.87, "f1": 0.89, "accuracy": 0.93 },
  "per_class": [ { "label": "critical", "precision": 0.95, "recall": 0.88, "f1": 0.91, "support": 24 } ],
  "confusion_matrix": {
    "labels": ["critical","high","medium","low","info"],
    "matrix": [[21,3,0,0,0],[2,40,6,0,0],[0,5,170,15,0],[0,0,9,580,15],[0,0,0,12,418]]
  },
  "attack_type": { "overall": { }, "per_class": [ ], "confusion_matrix": { } },
  "error": null
}
```

- Top-level `overall` / `per_class` / `confusion_matrix` are the **severity** target.
- **`attack_type` is additive**: the *same* report shape for the second classification target. The system is scored on both. Rendering only severity shows half the truth — a tab switcher between the two targets is cheap and impressive.
- Poll `GET /runs/{run_id}` every 2s while `status === "running"`. The runner persists partial metrics as it goes, so a mid-run poll returns real numbers with `status: "running"` — render them live rather than showing a spinner.
- `overall` and `confusion_matrix` can be `null` early in a run and when `status === "failed"`. `error` carries the failure text.
- **One run at a time.** A second `POST` while one is in flight → **`409` `conflict`**. Disable the button while a run is running.
- `sample_size` above `EVAL_MAX_SAMPLE_SIZE` (default 2000) → **`400`** with `code: "validation_error"` (refused loudly, never silently truncated). Default sample size is 200.
- A crashed process no longer wedges this endpoint forever — stale `running` rows are reaped at startup, periodically, and before every launch check.

Render `overall` as big stat cards, `confusion_matrix` as a heatmap grid, `per_class` as a table.

---

### Provider benchmark (fast tier vs quality tier)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/benchmark/run` | body `{ "sample_size": 25 }` (optional) → **202** `{ run_id, status }` |
| `GET` | `/api/v1/benchmark/runs` | past runs, newest first (**additive** — was not in the original contract) |
| `GET` | `/api/v1/benchmark/runs/{run_id}` | full report |

```json
{
  "run_id": "…",
  "status": "completed",
  "sample_size": 25,
  "results": [
    { "tier": "fast", "provider": "groq", "model": "llama-3.1-8b-instant",
      "avg_latency_ms": 210, "p95_latency_ms": 380, "accuracy": 0.84,
      "avg_tokens": 220, "failures": 0,
      "p50_latency_ms": 190, "min_latency_ms": 120, "max_latency_ms": 500,
      "avg_tokens_in": 180, "avg_tokens_out": 40,
      "attack_type_accuracy": 0.79, "estimated_cost": 0.0004,
      "calls": 25, "warmup_calls": 2,
      "throttled": false, "throttle_retries": 0 }
  ],
  "agreement_rate": 0.86,
  "disagreement_examples": [
    { "alert_id": "…", "signature": "…", "fast_prediction": "medium",
      "quality_prediction": "high", "ground_truth": "high" }
  ],
  "error": null
}
```

The first eight result fields are the frozen contract shape; everything after them is additive detail. Two of them matter for honesty and are worth putting in the UI:

- **`throttled` / `throttle_retries`** — true when that tier hit a 429/TPM throttle during the run. Its latency numbers then include free-tier queueing and understate the model's real speed (measured: 248ms p50 unthrottled vs 8.6s avg throttled, *same model*). If `throttled` is true, show a warning icon on that column instead of presenting the number as a clean comparison.
- **`estimated_cost`** is `null` when no price is configured for that model — render "—", never "$0.00".
- **`disagreement_examples`** is the panel's money shot: the specific alerts where the cheap tier and the expensive tier disagreed, with ground truth. A three-column table of those sells the whole product.

Same lifecycle rules as evaluation: 202 + detached task, one run at a time (409), poll every 2s, default sample 25, cap 50 (`BENCHMARK_MAX_SAMPLE`). The cap is low because every alert is run through **both** tiers — 50 alerts is 100 live LLM calls.

---

## 8. Live stream (SSE)

```
GET /api/v1/stream
```

Plain SSE — use the browser's native `EventSource`, not websockets. No auth, no headers.

```ts
const es = new EventSource(`${BASE}/api/v1/stream`);

es.addEventListener("alert.new",     e => upsert(JSON.parse(e.data)));   // AlertSummary
es.addEventListener("alert.updated", e => upsert(JSON.parse(e.data)));   // AlertSummary
es.addEventListener("stats.updated", e => setStats(JSON.parse(e.data))); // AlertStats
es.addEventListener("replay.status", e => setReplay(JSON.parse(e.data)));// ReplayStatus
es.addEventListener("system.notice", e => toast(JSON.parse(e.data)));    // { level, message }
```

| Event | Payload | Fires when |
|---|---|---|
| `alert.new` | `AlertSummary` | classification landed — first render of the card |
| `alert.updated` | `AlertSummary` | enrichment landed, remediation landed, or the alert reached `done`/`failed` |
| `stats.updated` | `AlertStats` (same shape as `/alerts/stats`) | every 2s (`STATS_PUBLISH_INTERVAL_SECONDS`) |
| `replay.status` | `ReplayStatus` | on every replay state change |
| `system.notice` | `{ level: "info" \| "warn" \| "error", message: string }` | eval/benchmark run milestones, quota problems, offline-mode warnings |

**Rules:**

1. **Key the alert store by `id` and upsert.** `alert.updated` fires 2–4 times per alert on the slow path.
2. `alert.*` carries `AlertSummary`, **never** `AlertDetail`. If the drawer is open on that alert, refetch `GET /alerts/{id}` when its `alert.updated` arrives.
3. On connect the server sends a comment line plus `retry: 3000`, and a heartbeat comment every 15s. Both are invisible to `EventSource` handlers — you do not parse them, they just keep proxies from reaping the connection.
4. **Reconnect on `es.onerror` with backoff, and refetch `/alerts` once on reconnect to resync.** The stream does not replay missed events.
5. Every connected browser gets its own subscription; the server unsubscribes on disconnect. Refreshing the page is safe.
6. **Fallback:** poll `GET /alerts?sort=-timestamp&limit=50` every 2s. Identical shapes, works fine. Build the store so the transport is swappable.

---

## 9. Errors

Every non-2xx response — including 404s on unknown routes and framework validation errors — uses one envelope:

```json
{ "error": { "code": "rate_limited", "message": "VirusTotal quota exhausted, enrichment degraded", "detail": null } }
```

**Switch on `code`, not on the HTTP status** — two codes intentionally appear at more than one status.

| Code | HTTP | Meaning | UI treatment |
|---|---|---|---|
| `validation_error` | 422 | bad params/body; `detail` names the field and the allowed values | inline field error |
| `validation_error` | 400 | a *refused value* (e.g. sample size over the cap) — it parsed fine, policy rejected it | inline error, show the message |
| `not_found` | 404 | unknown id, unknown dataset, unknown route | empty state |
| `conflict` | 409 | illegal state transition; a run already in flight | non-blocking toast + refetch status |
| `rate_limited` | 429 | upstream provider quota hit | warning banner, keep the UI running |
| `rate_limited` | 503 | a queue is saturated (backpressure) — work was refused, not throttled | "system busy, retry shortly" |
| `provider_error` | 502 | an LLM/intel provider failed | warning banner |
| `internal_error` | 500 | a bug; `detail.request_id` joins to backend logs | generic error toast, log the request id |

`rate_limited` and `provider_error` are **expected** during a live demo on free tiers. Handle them as a non-blocking warning banner — never a crash, never a blank screen.

---

## 10. What a single alert looks like over time

Concrete sequence for one `critical` alert, so you can build against the real timing:

| t | What the backend does | What you receive |
|---|---|---|
| 0ms | replay/ingest enqueues the alert; worker persists it (`ingested`) | — |
| ~400ms–2s | classify node runs on Groq (`llama-3.1-8b-instant`) | `alert.new` — severity, confidence, attack_type, `status: "classified"`, `has_enrichment: false` |
| +1–10s | enrich node fans indicators out to AbuseIPDB/VirusTotal (rate-capped, may queue) | `alert.updated` — `has_enrichment: true`, `max_ioc_score` set, `status: "enriched"`, possibly a **severity upgrade** |
| +2s | retrieve node pulls MITRE techniques from Chroma | — (visible in `trace` on the detail call) |
| +10–25s | reason node runs on Gemini | — |
| +10–16s | recommend node produces the remediation | `alert.updated` — `has_remediation: true` |
| end | finalize backfills skipped-node traces, stamps `total_duration_ms` | `alert.updated` — `status: "done"` |

A `low` alert collapses that to: `alert.new` (classified) → `alert.updated` (done), ~1–2s total, with everything else `null`.

Failure path: an alert whose pipeline throws is marked `status: "failed"` and published as `alert.updated`. The worker keeps going — one bad alert never stalls the feed. Render `failed` as a distinct pill, not as an empty card.

The whole full path is bounded by `TRIAGE_TIMEOUT_SECONDS` (default 120s). On timeout the alert is still returned/persisted as `done` with a partial trace — never stuck.

---

## 11. Backend config knobs that change what you see

Set in `.env`. You do not need to touch these, but knowing them explains behavior.

| Var | Default | Frontend-visible effect |
|---|---|---|
| `OFFLINE_MODE` | `false` | everything deterministic, no network, no quota limits |
| `REPLAY_EVENTS_PER_SECOND` | `10` | default feed rate when `/replay/start` omits it |
| `TRIAGE_WORKER_CONCURRENCY` | `4` | how fast cards appear |
| `ENRICH_WORKER_CONCURRENCY` | `1` | why `queue_depth.enrich` grows |
| `IOC_ESCALATION_SCORE` | `80` | threshold for intel overriding the model's severity |
| `ENRICH_LOW_SEVERITY` | `false` | when true, low-severity alerts with IOCs also get enriched |
| `STATS_PUBLISH_INTERVAL_SECONDS` | `2.0` | `stats.updated` cadence |
| `EVAL_SAMPLE_SIZE` / `EVAL_MAX_SAMPLE_SIZE` | `200` / `2000` | eval default and cap |
| `BENCHMARK_SAMPLE_SIZE` / `BENCHMARK_MAX_SAMPLE` | `25` / `50` | benchmark default and cap |
| `TRIAGE_TIMEOUT_SECONDS` | `120` | worst-case time before an alert is force-finalized |
| `CORS_ORIGINS` | `http://localhost:5173` | add the Vercel domain before deploying |

---

## 12. Screens the API is shaped for

1. **Live feed** — `/stream` + `/alerts`. Color-coded rows, severity chip, IOC badge (`max_ioc_score`), status pill.
2. **Drill-down drawer** — `/alerts/{id}`. Overview → IOC verdicts (with vendor links) → MITRE technique chips → remediation steps (grouped by `urgency`) → pipeline trace (including the skip reasons) → raw JSON, collapsed.
3. **Header stats bar** — `/alerts/stats` + `/health/deep`. Counters, per-minute chart, service status dots, offline-mode badge.
4. **Replay control bar** — `/replay/*`. Play/pause/stop, progress (`emitted`/`total`), `skipped`, queue depths.
5. **Eval panel** — `/evaluation/*`. Precision/recall cards, confusion heatmap, per-class table, severity ↔ attack_type toggle.
6. **Benchmark panel** — `/benchmark/*`. Fast vs quality comparison, agreement rate, disagreement examples, throttle warnings.

---

## 13. Working before the backend is up

Don't block, but you probably don't need to mock at all: **`make dev-offline` gives you the real API with zero keys and zero network.** That is strictly better than fixtures because the shapes cannot drift.

If you do mock:

- Generate fixtures from the TS interfaces in §6.
- Mock the stream with a `setInterval` that emits `alert.new`, then `alert.updated` ~3s later with `has_enrichment: true`, then another ~15s later with `has_remediation: true` and `status: "done"`. That is the real timing, so the UI you build against it works unchanged.
- Keep `VITE_API_BASE_URL` in `.env` from day one so the swap is one variable.
- Interactive API docs are live at `http://localhost:8000/docs` (Swagger) and `/redoc` — generated from the same pydantic models, so it is never stale. The OpenAPI JSON at `/openapi.json` can generate your TS types directly.

---

## 14. Where the running backend differs from the earlier contract doc

Everything here is **additive or stricter** — nothing that the earlier doc promised was removed. Listed so nobody debugs a phantom.

1. **Replay POSTs return the full `ReplayStatus`**, not an empty ack.
2. **`ReplayStatus.total` is `null` unless you pass `limit`.** Progress bars must handle that.
3. **`ReplayStatus.skipped`** added — records the parsers refused.
4. **`409 conflict`** is a real error code (illegal replay transition, run already in flight). It was not in the original error table.
5. **`rate_limited` also appears at `503`** for queue-full backpressure, and **`validation_error` also at `400`** for refused values.
6. **`/health/deep` omits null fields entirely** and adds a `workers` block.
7. **`/health/deep` service `latency_ms` is an int**; intel services carry `quota_remaining`, chroma carries `documents`.
8. **`GET /benchmark/runs`** (list) exists.
9. **Eval detail adds `attack_type`** — a full second metric report — plus `error`.
10. **Benchmark results add** `p50/min/max` latency, token in/out split, `attack_type_accuracy`, `estimated_cost`, `calls`, `warmup_calls`, `throttled`, `throttle_retries`, and top-level `disagreement_examples`.
11. **Eval/benchmark `overall`, `confusion_matrix`, `agreement_rate` are nullable** while running or on failure.
12. **`/alerts/stats` `by_*` maps omit zero-count keys.** Merge against the enum.
13. **`alerts_per_min` is a 30-minute average**, not an instantaneous rate.
14. **Scores and confidence are floats**, not ints (`max_ioc_score`, `score`, `raw_score`, `confidence`, `avg_triage_ms`, `alerts_per_min`).
15. **Dataset ids are `cicids2017`, `cicids`, `suricata`** — an unknown one is a 404.
16. **`source` can be `"manual"`** for alerts pushed through `POST /ingest`.
17. **Trace `provider` format is `"<provider>:<model>"`** — e.g. `groq:llama-3.1-8b-instant`, `gemini:gemini-flash-latest`, `offline:offline-deterministic`.
18. Every response carries **`X-Request-ID`**, echoed in `detail.request_id` on a 500.

---

## 15. Integration notes

- Branches: `frontend` is yours, push freely. `backend` is where the API lives. `main` is protected — PR only, no approvals required.
- Need a field that isn't in §6? Ask — it is cheaper to add it backend-side than to compute it in the browser.
- If a shape here disagrees with what the running backend returns, **the running backend wins** — flag it and this doc gets fixed.
- `http://localhost:8000/docs` is the live, always-accurate version of §7.
