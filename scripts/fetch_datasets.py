"""Download-only dataset fetcher for Flare.

Downloads a CICIDS2017 subset (CSV) and a Suricata EVE JSON sample into
DATASET_PATH. NO parsing. If a source is unreachable, writes a small
structurally-valid placeholder and logs clearly that it is a placeholder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

DATASET_PATH = Path(os.getenv("DATASET_PATH", "./data/datasets"))

SOURCES = [
    (
        "cicids2017_sample.csv",
        "https://raw.githubusercontent.com/flare-nonexistent/cicids2017/master/sample.csv",
        "csv",
    ),
    (
        "suricata_eve_sample.json",
        "https://raw.githubusercontent.com/FrankHassanabad/suricata-sample-data/master/samples/honeypot-2018/alerts-only.json",
        "eve",
    ),
]


def validate(kind: str, data: bytes) -> None:
    """Raise if downloaded bytes are not structurally the expected dataset."""
    text = data.decode("utf-8", errors="replace").strip()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("no content")
    if kind == "csv":
        if "," not in lines[0]:
            raise ValueError("first line has no comma — not CSV")
    elif kind == "eve":
        try:
            json.loads(text)
        except json.JSONDecodeError:
            json.loads(lines[0])


def log(msg: str) -> None:
    print(f"[fetch_datasets] {msg}", flush=True)


def csv_placeholder() -> bytes:
    header = (
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,"
        "Protocol,Timestamp,Flow Duration,Label\n"
    )
    row = (
        "192.168.10.5-8.8.8.8-49876-53-17,192.168.10.5,49876,8.8.8.8,53,"
        "17,05/07/2017 09:00:00,120,BENIGN\n"
    )
    return (header + row).encode()


def eve_placeholder() -> bytes:
    events = [
        {
            "timestamp": "2017-07-05T09:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.10.5",
            "src_port": 49876,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "alert": {
                "signature": "PLACEHOLDER TEST SIGNATURE",
                "category": "Misc",
                "severity": 3,
            },
        }
    ]
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


PLACEHOLDERS = {"csv": csv_placeholder, "eve": eve_placeholder}


def fetch_one(name: str, url: str, kind: str) -> None:
    dest = DATASET_PATH / name
    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.content
            if not data:
                raise ValueError("empty response body")
        validate(kind, data)
        dest.write_bytes(data)
        log(f"OK downloaded {name} ({len(data)} bytes) from {url}")
    except Exception as exc:  # noqa: BLE001
        data = PLACEHOLDERS[kind]()
        dest.write_bytes(data)
        log(f"PLACEHOLDER wrote {name} ({len(data)} bytes) — source unreachable: {exc}")


def main() -> int:
    DATASET_PATH.mkdir(parents=True, exist_ok=True)
    log(f"target dir: {DATASET_PATH.resolve()}")
    for name, url, kind in SOURCES:
        fetch_one(name, url, kind)
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
