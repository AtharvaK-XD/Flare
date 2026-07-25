"""Diagnostic smoke test for every Flare external dependency.

Makes ONE minimal real call per dependency and reports OK / FAIL / SKIPPED.
Never prints secret values — keys are truncated to last 4 chars.

WHY THE MODEL CHECKS ARE MORE THAN "DID IT 200"
-----------------------------------------------
Two misconfigurations broke a demo and neither was visible from a plain success
check, so both are now first-class outcomes here:

* **PERMANENT 429.** A Gemini model a free key may not call AT ALL still answers
  429 — the same status as ordinary backpressure. The tell is in the body: the
  quota violation reads ``limit: 0``. Treated as transient it is retried
  forever and every reasoning call fails; this script names it, calls it
  permanent, and checks whether a DIFFERENT model on the same key succeeds
  (quota headroom elsewhere = wrong model id, not an exhausted account).

* **RETIRED MODEL SLUG.** Groq renames and retires model ids. The configured id
  is checked against the live ``/v1/models`` listing for THIS key before the
  call, so "model not found" is reported as a config error with the available
  ids rather than a generic API failure.

The generation checks also use a realistic token budget, not ``max_tokens=5``:
both configured models are reasoning models that spend the output allowance on
hidden thinking first, so a 5-token probe "succeeds" with an empty body and
tells you nothing about whether the pipeline can actually parse a response.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

RESULTS: list[tuple[str, str, str]] = []

#: Big enough to clear a reasoning model's thinking overhead AND return a body.
#: Mirrors app/agent/nodes/classify.py — a smoke check at a budget the app never
#: uses proves nothing about the app.
PROBE_MAX_TOKENS = 1200

#: What the app falls back to when the env var is unset.
DEFAULT_GROQ_FAST_MODEL = "openai/gpt-oss-120b"
DEFAULT_GEMINI_MODEL = "gemini-flash-latest"

#: Known-callable on a bare free key. Used ONLY to tell "this key has no quota
#: anywhere" apart from "this key has no quota for the configured model".
GEMINI_CONTROL_MODEL = "gemini-flash-latest"


def record(component: str, status: str, notes: str = "") -> None:
    RESULTS.append((component, status, notes))
    print(f"[{status:7}] {component}: {notes}", flush=True)


def mask(key: str | None) -> str:
    if not key:
        return "<none>"
    return f"...{key[-4:]}"


def _is_permanent_quota(body: str) -> bool:
    """A 429 whose quota violation reports a limit of zero will never clear."""
    lowered = body.lower()
    return "limit: 0" in lowered or "limit:0" in lowered


def check_groq() -> None:
    key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_FAST_MODEL", DEFAULT_GROQ_FAST_MODEL)
    if not key:
        record("Groq", "SKIPPED", "no GROQ_API_KEY")
        return

    # 1. Is the configured slug one this key can actually address?
    try:
        listing = httpx.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=30.0,
        )
        available = sorted(m["id"] for m in listing.json().get("data", []))
    except Exception as exc:  # noqa: BLE001 — listing is advisory, keep going
        available = []
        record("Groq models", "SKIPPED", f"could not list models: {type(exc).__name__}: {exc}")
    else:
        if model not in available:
            chat = [m for m in available if "whisper" not in m and "guard" not in m]
            record(
                "Groq",
                "FAIL",
                f"GROQ_FAST_MODEL={model} is NOT in this key's model list - "
                f"available chat models: {', '.join(chat)}",
            )
            return
        record("Groq models", "OK", f"{len(available)} models listed; {model} present")

    # 2. Does it actually serve a parseable completion at the app's budget?
    try:
        from groq import Groq

        client = Groq(api_key=key)
        t0 = time.perf_counter()
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with the single word: pong"}],
            max_tokens=PROBE_MAX_TOKENS,
        )
        dt = (time.perf_counter() - t0) * 1000
        text = (resp.choices[0].message.content or "").strip()
        used = getattr(getattr(resp, "usage", None), "completion_tokens", 0)
        if not text:
            record(
                "Groq",
                "FAIL",
                f"model={model} returned an EMPTY body at max_tokens={PROBE_MAX_TOKENS} "
                f"(finish_reason={resp.choices[0].finish_reason}) - raise the budget",
            )
            return
        record(
            "Groq",
            "OK",
            f"model={model} key={mask(key)} latency={dt:.0f}ms "
            f"out_tokens={used} body={text[:40]!r}",
        )
    except Exception as exc:  # noqa: BLE001
        record("Groq", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")


def _gemini_probe(key: str, model: str) -> tuple[int, str, float]:
    """One raw generateContent call. Returns (status, body, latency_ms).

    Raw HTTP on purpose: the SDK flattens a 429 into an exception whose text
    drops the quota detail this check exists to read.
    """
    t0 = time.perf_counter()
    response = httpx.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        params={"key": key},
        json={
            "contents": [{"parts": [{"text": "Reply with the single word: pong"}]}],
            "generationConfig": {"maxOutputTokens": PROBE_MAX_TOKENS},
        },
        timeout=90.0,
    )
    return response.status_code, response.text, (time.perf_counter() - t0) * 1000


def _gemini_text(body: str) -> str:
    import json

    try:
        payload: Any = json.loads(body)
        parts = payload["candidates"][0]["content"]["parts"]
        return "".join(part.get("text", "") for part in parts).strip()
    except (ValueError, KeyError, IndexError, TypeError):
        return ""


def check_gemini() -> None:
    key = os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    if not key:
        record("Gemini", "SKIPPED", "no GOOGLE_API_KEY")
        return

    try:
        status, body, latency = _gemini_probe(key, model)
    except Exception as exc:  # noqa: BLE001
        record("Gemini", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")
        return

    if status == 200:
        text = _gemini_text(body)
        if not text:
            record(
                "Gemini",
                "FAIL",
                f"model={model} returned an EMPTY body at maxOutputTokens="
                f"{PROBE_MAX_TOKENS} - thinking consumed the whole allowance",
            )
            return
        record(
            "Gemini",
            "OK",
            f"model={model} key={mask(key)} latency={latency:.0f}ms body={text[:40]!r}",
        )
        return

    if status != 429:
        record("Gemini", "FAIL", f"model={model} http={status} {body[:200]}")
        return

    # 429: permanent (this key may not call this model) or transient (backpressure)?
    permanent = _is_permanent_quota(body)
    if not permanent:
        record(
            "Gemini",
            "DEGRADED",
            f"model={model} http=429 but quota is non-zero - transient rate limit, "
            "retry will clear it",
        )
        return

    # Zero quota here. Does the key have headroom on ANOTHER model? If so this is
    # a wrong-model-id misconfiguration, not an exhausted account — and that
    # distinction is the whole point of this check.
    if model == GEMINI_CONTROL_MODEL:
        record(
            "Gemini",
            "FAIL",
            f"model={model} http=429 with quota limit:0 - this key has NO quota even "
            "for the default model; the account itself is exhausted or unbilled",
        )
        return

    try:
        control_status, control_body, _ = _gemini_probe(key, GEMINI_CONTROL_MODEL)
    except Exception as exc:  # noqa: BLE001 — the control probe is diagnostic only
        record(
            "Gemini",
            "FAIL",
            f"model={model} http=429 quota limit:0 (PERMANENT); control probe failed: "
            f"{type(exc).__name__}: {exc}",
        )
        return

    if control_status == 200:
        record(
            "Gemini",
            "FAIL",
            f"MISCONFIGURED: GEMINI_MODEL={model} has ZERO free-tier quota on this key "
            f"(429, limit:0, permanent - retrying will never help), but "
            f"{GEMINI_CONTROL_MODEL} answers 200 on the SAME key. "
            f"Set GEMINI_MODEL={GEMINI_CONTROL_MODEL}.",
        )
    else:
        record(
            "Gemini",
            "FAIL",
            f"model={model} http=429 quota limit:0 and control model "
            f"{GEMINI_CONTROL_MODEL} also failed (http={control_status} "
            f"{control_body[:120]}) - the key/account has no quota at all",
        )


def check_abuseipdb() -> None:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        record("AbuseIPDB", "SKIPPED", "no ABUSEIPDB_API_KEY")
        return
    try:
        import httpx

        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
            timeout=20.0,
        )
        remaining = resp.headers.get("X-RateLimit-Remaining", "?")
        status = "OK" if resp.status_code == 200 else "FAIL"
        record(
            "AbuseIPDB", status, f"http={resp.status_code} remaining={remaining} key={mask(key)}"
        )
    except Exception as exc:  # noqa: BLE001
        record("AbuseIPDB", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")


def check_virustotal() -> None:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        record("VirusTotal", "SKIPPED", "no VIRUSTOTAL_API_KEY")
        return
    try:
        import httpx

        resp = httpx.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": key},
            timeout=20.0,
        )
        remaining = resp.headers.get("X-RateLimit-Remaining", "?")
        status = "OK" if resp.status_code == 200 else "FAIL"
        record(
            "VirusTotal", status, f"http={resp.status_code} remaining={remaining} key={mask(key)}"
        )
    except Exception as exc:  # noqa: BLE001
        record("VirusTotal", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")


def check_chroma() -> None:
    try:
        import chromadb

        persist = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma")
        Path(persist).mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=persist)
        name = "smoke_roundtrip"
        try:
            client.delete_collection(name)
        except Exception as exc:  # noqa: BLE001 — absent is the normal case
            print(f"[  info ] Chroma: no leftover {name} collection to drop ({exc})", flush=True)
        col = client.create_collection(name)
        col.add(ids=["a"], documents=["hello flare"], metadatas=[{"k": "v"}])
        got = col.get(ids=["a"])
        ok = got["documents"] == ["hello flare"]
        client.delete_collection(name)
        rt = "ok" if ok else "bad"
        record("Chroma", "OK" if ok else "FAIL", f"persist={persist} roundtrip={rt}")
    except Exception as exc:  # noqa: BLE001
        record("Chroma", "FAIL", f"{type(exc).__name__}: {exc}")


def check_sqlite() -> None:
    try:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("DROP TABLE t")
        conn.commit()
        conn.close()
        os.unlink(path)
        record("SQLite", "OK", f"version={sqlite3.sqlite_version}")
    except Exception as exc:  # noqa: BLE001
        record("SQLite", "FAIL", f"{type(exc).__name__}: {exc}")


def check_embedding() -> None:
    try:
        from sentence_transformers import SentenceTransformer

        model = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        st = SentenceTransformer(model)
        vec = st.encode("flare test string")
        record("Embedding", "OK", f"model={model} dim={len(vec)}")
    except Exception as exc:  # noqa: BLE001
        record("Embedding", "FAIL", f"{type(exc).__name__}: {exc}")


def check_ground_truth() -> None:
    """The eval's label set is a dependency too - a missing one breaks the demo."""
    try:
        from app.evaluation.ground_truth import check_label_health

        health = check_label_health()
        record("GroundTruth", "OK" if health.ok else "FAIL", health.message())
    except Exception as exc:  # noqa: BLE001
        record("GroundTruth", "FAIL", f"{type(exc).__name__}: {exc}")


def main() -> int:
    print("=== Flare provider smoke test ===", flush=True)
    check_groq()
    check_gemini()
    check_abuseipdb()
    check_virustotal()
    check_chroma()
    check_sqlite()
    check_embedding()
    check_ground_truth()

    print("\n=== Summary ===", flush=True)
    for comp, status, notes in RESULTS:
        print(f"{comp:13} {status:8} {notes}")

    fails = [c for c, s, _ in RESULTS if s == "FAIL"]
    degraded = [c for c, s, _ in RESULTS if s == "DEGRADED"]
    if fails:
        print(f"\nFAILED: {', '.join(fails)}")
    elif degraded:
        print(f"\nOK with degradation: {', '.join(degraded)}")
    else:
        print("\nAll checks OK.")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
