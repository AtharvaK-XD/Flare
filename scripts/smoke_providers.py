"""Diagnostic smoke test for every Flare external dependency.

Makes ONE minimal real call per dependency and reports OK / FAIL / SKIPPED.
Never prints secret values — keys are truncated to last 4 chars.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

RESULTS: list[tuple[str, str, str]] = []


def record(component: str, status: str, notes: str = "") -> None:
    RESULTS.append((component, status, notes))
    print(f"[{status:7}] {component}: {notes}", flush=True)


def mask(key: str | None) -> str:
    if not key:
        return "<none>"
    return f"...{key[-4:]}"


def check_groq() -> None:
    key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_FAST_MODEL", "llama-3.1-8b-instant")
    if not key:
        record("Groq", "SKIPPED", "no GROQ_API_KEY")
        return
    try:
        from groq import Groq

        client = Groq(api_key=key)
        t0 = time.perf_counter()
        client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
        )
        dt = (time.perf_counter() - t0) * 1000
        record("Groq", "OK", f"model={model} key={mask(key)} latency={dt:.0f}ms")
    except Exception as exc:  # noqa: BLE001
        record("Groq", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")


def check_gemini() -> None:
    key = os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    if not key:
        record("Gemini", "SKIPPED", "no GOOGLE_API_KEY")
        return
    try:
        import google.generativeai as genai

        genai.configure(api_key=key)
        gm = genai.GenerativeModel(model)
        t0 = time.perf_counter()
        gm.generate_content(
            "ping",
            generation_config={"max_output_tokens": 5},
        )
        dt = (time.perf_counter() - t0) * 1000
        record("Gemini", "OK", f"model={model} key={mask(key)} latency={dt:.0f}ms")
    except Exception as exc:  # noqa: BLE001
        record("Gemini", "FAIL", f"key={mask(key)} {type(exc).__name__}: {exc}")


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
        except Exception:  # noqa: BLE001
            pass
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


def main() -> int:
    print("=== Flare provider smoke test ===", flush=True)
    check_groq()
    check_gemini()
    check_abuseipdb()
    check_virustotal()
    check_chroma()
    check_sqlite()
    check_embedding()

    print("\n=== Summary ===", flush=True)
    for comp, status, notes in RESULTS:
        print(f"{comp:12} {status:7} {notes}")
    fails = [c for c, s, _ in RESULTS if s == "FAIL"]
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
