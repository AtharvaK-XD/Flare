# Flare — Backend API Contract (for Frontend)

**Project:** Flare — AI-Powered Security Incident Triage Agent
**Audience:** frontend dev (React + Vite dashboard)
**Backend:** FastAPI + LangGraph

This doc is the single source of truth for everything the frontend touches. If something isn't here, it isn't built yet — ask before assuming.

---

## 1. Mental model (read this first)

Flare replays a stream of real security alerts and triages each one through a multi-stage AI pipeline. **Alerts are not returned fully-formed.** They arrive fast and cheap, then get *upgraded in place* as slower stages finish.

Pipeline stages per alert:

```
ingested → classified → enriched → reasoned → done
   |           |            |          |
   |           |            |          └─ remediation steps generated (Gemini + MITRE RAG)
   |           |            └─ IOC reputation attached (AbuseIPDB / VirusTotal)
   |           └─ severity + attack type tagged (Groq, sub-second)
   └─ raw alert parsed & normalized
```

**Critical frontend implication:** a card appears within ~1s showing severity, then the IOC badge fills in a few seconds later, then the remediation panel fills in after that. Build the UI so fields can be `null` and arrive later. Do **not** wait for a complete object before rendering.

Not every alert reaches every stage — low-severity alerts skip enrichment and reasoning by design (that's the whole cost-saving point of the product). Those go straight to `done` with `enrichment: null` and `remediation: null`. This is expected, not an error.

---

## 2. Conventions

| Thing | Value |
|---|---|
| Base URL (local) | `http://localhost:8000` |
| Base URL (deployed) | `https://<render-app>.onrender.com` — set via `VITE_API_BASE_URL` |
| Prefix | all endpoints under `/api/v1` |
| Content type | `application/json` |
| Timestamps | ISO-8601 UTC, e.g. `2026-08-07T14:23:11.482Z` |
| IDs | UUID v4 strings |
| Auth | **none** — no tokens, no headers needed |
| CORS | open in dev; `localhost:5173` + the Vercel domain allowed in prod |

---

## 3. Enums (hardcode these, they won't change)

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";

type AlertStatus = "ingested" | "classified" | "enriched" | "reasoned" | "done" | "failed";

type AttackType =
  | "port_scan" | "brute_force" | "ddos" | "web_attack" | "malware_c2"
  | "data_exfiltration" | "privilege_escalation" | "recon" | "benign" | "unknown";

type IntelSource = "abuseipdb" | "virustotal";

type ProviderTier = "fast" | "quality";
```

Suggested severity colors (align with backend semantics):
`critical` #DC2626 · `high` #EA580C · `medium` #D97706 · `low` #2563EB · `info` #6B7280

---

## 4. Core data models

```ts
interface AlertSummary {          // returned by list endpoint
  id: string;
  timestamp: string;
  status: AlertStatus;
  severity: Severity | null;      // null until classified
  confidence: number | null;      // 0.0–1.0
  attack_type: AttackType | null;
  signature: string;              // e.g. "ET SCAN Suricata port scan detected"
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;        // "TCP" | "UDP" | "ICMP" | ...
  source: string;                 // "suricata" | "zeek" | "cicids2017"
  has_enrichment: boolean;
  has_remediation: boolean;
  max_ioc_score: number | null;   // 0–100, worst IOC on this alert; drives the badge
}

interface IocVerdict {
  indicator: string;              // IP or file hash
  indicator_type: "ip" | "hash";
  score: number;                  // 0–100 normalized (higher = worse)
  malicious: boolean;
  sources: {
    source: IntelSource;
    raw_score: number;
    categories: string[];         // e.g. ["ssh_bruteforce", "port_scan"]
    last_seen: string | null;
    link: string | null;          // deep link to vendor page, safe to render
  }[];
  cached: boolean;                // true = served from cache, not a live call
}

interface Enrichment {
  iocs: IocVerdict[];
  enriched_at: string;
  duration_ms: number;
}

interface MitreTechnique {
  id: string;                     // "T1046"
  name: string;                   // "Network Service Discovery"
  tactic: string;                 // "Discovery"
  url: string;
  excerpt: string;                // retrieved chunk used as grounding
}

interface RemediationStep {
  order: number;
  action: string;                 // short imperative, good for a list item
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

interface TraceNode {             // pipeline transparency panel
  node: "classify" | "enrich" | "retrieve" | "reason" | "recommend";
  status: "ok" | "skipped" | "failed";
  provider: string | null;        // "groq:llama-3.1-8b" | "gemini:flash" | null
  duration_ms: number;
  tokens_in: number | null;
  tokens_out: number | null;
  note: string | null;            // e.g. "skipped: severity below threshold"
}

interface AlertDetail extends AlertSummary {
  raw: Record<string, unknown>;   // original parsed alert — render in a collapsed <pre>
  reasoning: string | null;       // model's analysis narrative
  enrichment: Enrichment | null;
  remediation: Remediation | null;
  trace: TraceNode[];
  total_duration_ms: number | null;
}
```

---

## 5. REST endpoints

### `GET /api/v1/health`
Liveness. Returns `{"status":"ok"}`. Use for a connection indicator dot.

### `GET /api/v1/health/deep`
Per-dependency status. Good for a small "system status" strip in the dashboard header.

```json
{
  "status": "degraded",
  "services": {
    "groq":        { "status": "ok",       "latency_ms": 210 },
    "gemini":      { "status": "ok",       "latency_ms": 640 },
    "abuseipdb":   { "status": "ok",       "quota_remaining": 940 },
    "virustotal":  { "status": "degraded", "quota_remaining": 0, "note": "rate limited" },
    "chroma":      { "status": "ok",       "documents": 27 },
    "database":    { "status": "ok" }
  }
}
```
`status` per service: `ok` | `degraded` | `down`. Top-level `status`: `ok` | `degraded` | `down`.

---

### `GET /api/v1/alerts`
Paginated alert feed. This is the main table/list view.

Query params — all optional:

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | 50 | max 200 |
| `offset` | int | 0 | |
| `severity` | csv | — | `?severity=critical,high` |
| `status` | csv | — | |
| `attack_type` | csv | — | |
| `src_ip` | string | — | exact match |
| `malicious_only` | bool | false | only alerts with a flagged IOC |
| `since` | ISO ts | — | |
| `sort` | string | `-timestamp` | `-timestamp` \| `timestamp` \| `-severity` |

Response:
```json
{
  "items": [ /* AlertSummary[] */ ],
  "total": 1284,
  "limit": 50,
  "offset": 0
}
```

---

### `GET /api/v1/alerts/{id}`
Full `AlertDetail`. Drives the drill-down drawer/modal. `404` if unknown id.

---

### `GET /api/v1/alerts/stats`
Header counters + charts.

```json
{
  "total": 1284,
  "by_severity": { "critical": 12, "high": 48, "medium": 190, "low": 604, "info": 430 },
  "by_attack_type": { "port_scan": 310, "brute_force": 120, "benign": 700, "...": 0 },
  "by_status": { "done": 1240, "reasoned": 20, "enriched": 15, "classified": 9 },
  "malicious_iocs": 37,
  "avg_triage_ms": 890,
  "alerts_per_min": 42,
  "timeline": [ { "bucket": "2026-08-07T14:20:00Z", "count": 40, "critical": 1 } ]
}
```
`timeline` is 1-minute buckets, last 30 minutes — feed it straight to a chart.

---

### Replay control

The demo runs off a replayed dataset. These drive the play/pause bar.

| Method | Path | Body | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/replay/start` | `{ "dataset": "cicids2017", "events_per_second": 5, "limit": 500 }` | begin feed |
| `POST` | `/api/v1/replay/pause` | — | pause |
| `POST` | `/api/v1/replay/resume` | — | resume |
| `POST` | `/api/v1/replay/stop` | — | stop + reset cursor |
| `GET` | `/api/v1/replay/status` | — | current state |

`GET /replay/status`:
```json
{
  "state": "running",
  "dataset": "cicids2017",
  "events_per_second": 5,
  "emitted": 312,
  "total": 500,
  "queue_depth": { "triage": 4, "enrich": 11 },
  "started_at": "2026-08-07T14:20:00Z"
}
```
`state`: `idle` | `running` | `paused` | `completed`.
`queue_depth.enrich` climbing is normal — enrichment is deliberately rate-capped. Worth surfacing as a small "enrichment backlog" number; it's a good talking point for judges.

---

### `POST /api/v1/ingest`
Manually push one alert (useful for a "try your own alert" demo button).

Body: either raw Suricata EVE JSON, or:
```json
{ "signature": "SSH brute force", "src_ip": "45.13.2.99", "dst_ip": "10.0.0.5", "dst_port": 22, "protocol": "TCP" }
```
Returns `202 Accepted` with `{ "id": "...", "status": "ingested" }`. The triaged result arrives over SSE — do not expect it in this response.

---

### Evaluation

Judge-facing accuracy numbers.

`POST /api/v1/evaluation/run` → `202` `{ "run_id": "...", "status": "running" }`
`GET /api/v1/evaluation/runs` → list of past runs (summary fields only)
`GET /api/v1/evaluation/runs/{run_id}` →

```json
{
  "run_id": "…",
  "status": "completed",
  "sample_size": 200,
  "started_at": "…",
  "completed_at": "…",
  "overall": { "precision": 0.91, "recall": 0.87, "f1": 0.89, "accuracy": 0.93 },
  "per_class": [
    { "label": "critical", "precision": 0.95, "recall": 0.88, "f1": 0.91, "support": 24 }
  ],
  "confusion_matrix": {
    "labels": ["critical","high","medium","low","info"],
    "matrix": [[21,3,0,0,0],[2,40,6,0,0],[0,5,170,15,0],[0,0,9,580,15],[0,0,0,12,418]]
  }
}
```
`status`: `running` | `completed` | `failed`. Poll every 2s while `running`.

Render `overall` as big stat cards, `confusion_matrix` as a heatmap grid, `per_class` as a table.

---

### Provider benchmark

Speed-tier vs quality-tier side-by-side.

`POST /api/v1/benchmark/run` body `{ "sample_size": 25 }` → `202` `{ "run_id": "..." }`
`GET /api/v1/benchmark/runs/{run_id}` →

```json
{
  "run_id": "…",
  "status": "completed",
  "sample_size": 25,
  "results": [
    { "tier": "fast",    "provider": "groq",   "model": "llama-3.1-8b-instant",
      "avg_latency_ms": 210, "p95_latency_ms": 380, "accuracy": 0.84, "avg_tokens": 220, "failures": 0 },
    { "tier": "quality", "provider": "gemini", "model": "gemini-flash",
      "avg_latency_ms": 1180, "p95_latency_ms": 1900, "accuracy": 0.93, "avg_tokens": 610, "failures": 1 }
  ],
  "agreement_rate": 0.86
}
```
Two-column comparison card + a grouped bar chart is the intended UI.

---

## 6. Live stream (SSE)

**This is how the dashboard stays live.** Use the browser's native `EventSource` — it's plain SSE, not websockets.

```
GET /api/v1/stream
```

```ts
const es = new EventSource(`${BASE}/api/v1/stream`);

es.addEventListener("alert.new",      e => upsert(JSON.parse(e.data)));
es.addEventListener("alert.updated",  e => upsert(JSON.parse(e.data)));
es.addEventListener("stats.updated",  e => setStats(JSON.parse(e.data)));
es.addEventListener("replay.status",  e => setReplay(JSON.parse(e.data)));
es.addEventListener("system.notice",  e => toast(JSON.parse(e.data)));
```

| Event | Payload | When |
|---|---|---|
| `alert.new` | `AlertSummary` | alert classified, first render |
| `alert.updated` | `AlertSummary` | enrichment or remediation landed; status changed |
| `stats.updated` | same shape as `/alerts/stats` | ~every 2s |
| `replay.status` | same as `/replay/status` | on state change |
| `system.notice` | `{ level: "info"\|"warn"\|"error", message: string }` | quota exhausted, provider down, etc. |

**Rules:**
- Key your alert store by `id` and **upsert** — `alert.updated` fires multiple times per alert.
- `alert.updated` carries `AlertSummary`, not `AlertDetail`. Refetch `/alerts/{id}` if the drawer is open on that alert.
- Reconnect on `es.onerror` with backoff. On reconnect, refetch `/alerts` once to resync — the stream does not replay missed events.
- Fallback if SSE is a problem: poll `GET /alerts?sort=-timestamp&limit=50` every 2s. Same shapes, works fine.

---

## 7. Errors

Every non-2xx uses one envelope:

```json
{
  "error": {
    "code": "rate_limited",
    "message": "VirusTotal quota exhausted, enrichment degraded",
    "detail": null
  }
}
```

| Code | HTTP | Meaning |
|---|---|---|
| `validation_error` | 422 | bad params/body; `detail` has field errors |
| `not_found` | 404 | unknown id |
| `rate_limited` | 429 | upstream quota hit — show a banner, keep the UI running |
| `provider_error` | 502 | LLM/intel provider failed |
| `internal_error` | 500 | |

`rate_limited` and `provider_error` are **expected** during a live demo on free tiers. Handle them as a non-blocking warning banner, never a crash or a blank screen.

---

## 8. Screens the API is shaped for

1. **Live feed** — `/stream` + `/alerts`. Color-coded rows, severity chip, IOC badge, status pill.
2. **Drill-down drawer** — `/alerts/{id}`. Sections: overview → IOC verdicts → MITRE technique chips → remediation steps → pipeline trace → raw JSON (collapsed).
3. **Header stats bar** — `/alerts/stats` + `/health/deep`. Counters, per-min chart, service status dots.
4. **Replay control bar** — `/replay/*`. Play/pause/stop, progress, queue depth.
5. **Eval panel** — `/evaluation/*`. Precision/recall cards, confusion heatmap, per-class table.
6. **Benchmark panel** — `/benchmark/*`. Fast vs quality comparison + agreement rate.

---

## 9. Working before the backend is up

Don't block. Mock it:

- Every shape in §4 is stable — generate fixtures from the TS interfaces above.
- Mock the stream with a `setInterval` that emits a fake `alert.new`, then a follow-up `alert.updated` 3s later with `enrichment` filled in. That's the exact real-world timing behavior, so the UI you build against it will work unchanged.
- Keep `VITE_API_BASE_URL` in `.env` from day one so the swap is one variable.

---

## 10. Integration notes

- Branches: `frontend` is yours, push freely. `main` is protected — PR only, no approvals required. Merge to `main` when ready to integrate.
- Ping if you need a field that isn't in §4 — cheaper to add it backend-side than to compute it in the browser.
- If a shape here disagrees with what the running backend returns, the running backend wins — flag it and this doc gets fixed.
