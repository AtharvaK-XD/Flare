# Flare
**"AI that stands watch over your logs."**
AI-Powered Security Incident Triage Agent — MECIA HACKS 3.0 (24-Hour Build)

---

## Summary
Flare watches incoming security alerts, quickly flags how dangerous each one is, checks shady IPs against real threat databases, then tells you exactly what to do about the serious ones — all on a live dashboard with real accuracy numbers.

---

## Domain & Category
- **Domain:** Cyber Security & Network Systems *(or custom: "AI Agents & Threat Intelligence")*
- **Project Category:** Software

---

## Problem It Solves
SOC teams drown in IDS/SIEM alert volume (Suricata, Zeek, Wazuh) — most alerts are noise, real threats get buried. Most hackathon cybersecurity projects show static malware classifiers or toy anomaly detectors; none show a live multi-agent triage pipeline that reasons over real threat intel and grounds its recommendations in actual attack frameworks.

## What It Does
- Ingests a replayed stream of real-world alerts (Suricata/Zeek EVE JSON or CICIDS2017 subset)
- Fast-pass classification: severity + attack-type tagging on every alert in sub-second time
- Enriches medium/high-severity alerts via live IOC reputation lookups (IP/hash)
- Deep-reasoning pass: generates remediation steps grounded in MITRE ATT&CK technique data (RAG)
- Live dashboard: color-coded alert feed, drill-down per incident, remediation panel
- Built-in eval panel: precision/recall against a labeled ground-truth subset, shown live to judges
- Provider benchmark toggle: side-by-side latency/quality comparison (speed-tier vs quality-tier model)

## Tech Stack (100% free tier)

| Component | Choice | Role |
|---|---|---|
| Fast classification | Groq (Llama 3.1 8B / 3.3 70B) | Sub-second first-pass severity + type tagging at high alert volume |
| Deep reasoning + RAG | Gemini Flash (free tier) | Grounded remediation generation, MITRE ATT&CK RAG lookups, quality check on ambiguous alerts |
| Threat intel enrichment | AbuseIPDB free tier, VirusTotal free tier (4 req/min) | Real IOC reputation lookups on IPs/hashes |
| Agent orchestration | LangGraph | classify → enrich → reason → recommend pipeline |
| Backend | FastAPI | Alert ingestion + agent orchestration endpoint |
| Vector store | Chroma (in-memory) | RAG corpus: ~20-30 MITRE ATT&CK technique docs |
| Frontend | React + Vite | Live alert dashboard, drill-down, eval panel |
| Sample data | CICIDS2017 subset / replayed Suricata EVE JSON | Real labeled traffic for demo + eval |
| Eval harness | Custom precision/recall script vs labeled subset | Displayed live on dashboard |
| Deploy | Render (backend) + Vercel (frontend) | Free-tier hosted demo link |

## 24-Hour Scope Cuts
- No auth/multi-tenant layer
- Pre-loaded dataset replay instead of live network capture
- RAG corpus capped small (~20-30 docs) to keep indexing fast
- Eval = one precision/recall pass on a fixed labeled subset, not a full test suite

## Why It Stands Out to Judges
- Two LLM providers used with justified, distinct roles (speed vs. quality) — not just one API call
- Real threat intel APIs, not synthetic-only data
- Visible eval numbers, not just a demo
- Multi-node LangGraph pipeline, easy to diagram and explain in Q&A

---

## Industrial Applications
- **SOC teams (mid-size companies)** — reduces alert fatigue by auto-triaging IDS/SIEM noise so analysts only look at what matters
- **MSSPs (Managed Security Service Providers)** — handle alerts across many client networks at once; fast-tier triage scales without hiring more analysts
- **Critical infrastructure (power grids, water utilities)** — SCADA/ICS network monitoring where alert volume is high and analyst headcount is low
- **Financial institutions** — real-time fraud/intrusion alert triage where speed-to-response has direct monetary impact
- **Cloud-native startups without a dedicated SOC** — plug-and-play triage layer on top of existing IDS tools instead of building an in-house security team
- **University/campus networks** — high alert volume, limited security staff, low budget

**Pitch line:** *"Any org running an IDS but too small to staff a 24/7 SOC."*
