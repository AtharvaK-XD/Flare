"""Build the labeled evaluation subset at ``GROUND_TRUTH_PATH``.

WHY THIS SCRIPT EXISTS
----------------------
``data/labels/`` was empty, so :mod:`app.evaluation.ground_truth` fell back to the
6-row replay placeholder and every eval since produced real-looking, meaningless
numbers (a macro-F1 quoted off n=6). This script sources a genuine labeled
CICIDS2017 subset once and commits it, so the fallback can never be what the
demo scores.

SOURCE
------
``bvk/CICIDS-2017`` on the Hugging Face Hub — a re-flowed CICIDS2017 distribution
(2.1M labeled flows) that, unlike the widely mirrored ``MachineLearningCVE``
CSVs, still carries per-flow addresses and ports. Rows are pulled through the
datasets-server ``/filter`` API so only the sampled rows are downloaded, not the
200MB day files.

WHAT IS ORIGINAL AND WHAT IS RECONSTRUCTED — read before quoting these numbers
-----------------------------------------------------------------------------
ORIGINAL, untouched: the label, the addresses, the ports, the protocol number,
and the flow statistics. Those are what the evaluation actually scores.

RECONSTRUCTED, and only these two:
  * ``Source IP`` / ``Destination IP`` — the source stores addresses as decimal
    integers; they are rendered back to dotted quad. Lossless.
  * ``Timestamp`` — the upstream CSVs were written through a spreadsheet that
    truncated every timestamp to ``MM:SS.s``; the date is simply gone. The
    recovered minute/second is placed on the real CICIDS2017 capture day for
    that attack class (Mon 3 – Fri 7 July 2017, per the dataset's published
    schedule). Ordering within a class is preserved; absolute wall-clock is not
    recoverable from the source and is not scored by anything.

``Flow ID`` is rebuilt in the upstream ``src-dst-sport-dport-proto`` convention.

STRATIFICATION
--------------
Sampling is per CANONICAL class (the classes ``ground_truth.LABEL_TO_ATTACK_TYPE``
scores), not per raw label, because that is the axis the metrics are computed on.
A uniform draw from a set that is 75% BENIGN would leave several attack classes
with single-digit support, i.e. per-class F1 computed on noise.

Usage:
    python -m scripts.build_label_set                  # default ~440 rows
    python -m scripts.build_label_set --out other.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from app.config import get_settings

DATASET = "bvk/CICIDS-2017"
API = "https://datasets-server.huggingface.co/filter"

DEFAULT_FILENAME = "cicids2017_labeled_subset.csv"

#: Column order written out — the shape ``app.ingestion.parsers.cicids`` reads.
COLUMNS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Label",
]

#: canonical class -> (raw labels upstream uses, rows wanted, capture day).
#: Days are the published CICIDS2017 schedule: Tue = brute force, Wed = DoS +
#: Heartbleed, Thu = web attacks + infiltration, Fri = botnet, portscan, DDoS.
PLAN: dict[str, tuple[list[str], int, str]] = {
    "benign": (["BENIGN"], 120, "03/07/2017"),
    "brute_force": (
        ["FTP-Patator", "FTP-Patator - Attempted", "SSH-Patator", "SSH-Patator - Attempted"],
        60,
        "04/07/2017",
    ),
    "ddos": (
        [
            "DDoS",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS Slowloris",
            "DoS Slowhttptest",
            "DoS Hulk - Attempted",
        ],
        60,
        "05/07/2017",
    ),
    "web_attack": (
        [
            "Web Attack - Brute Force",
            "Web Attack - Brute Force - Attempted",
            "Web Attack - XSS",
            "Web Attack - XSS - Attempted",
            "Web Attack - Sql Injection",
            "Heartbleed",
        ],
        50,
        "06/07/2017",
    ),
    "data_exfiltration": (
        ["Infiltration", "Infiltration - Attempted", "Infiltration - Portscan"],
        50,
        "06/07/2017",
    ),
    "malware_c2": (["Botnet", "Botnet - Attempted"], 50, "07/07/2017"),
    "port_scan": (["Portscan", "Portscan - Attempted"], 60, "07/07/2017"),
}

#: The upstream index warms lazily; a cold /filter answers 500 for a minute.
RETRIES = 8
RETRY_DELAY = 10.0
PAGE = 100  # datasets-server caps a /filter page at 100 rows


def log(message: str) -> None:
    print(f"[build_label_set] {message}", flush=True)


def _dotted(value: Any) -> str:
    """Decimal-encoded IPv4 back to dotted quad; unparseable stays as-is."""
    try:
        return str(ipaddress.IPv4Address(int(value)))
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return str(value or "")


def _recover_clock(raw: Any) -> tuple[int, int, int]:
    """``MM:SS.s`` (a spreadsheet's idea of a timestamp) -> (hour, minute, second).

    The hour is unrecoverable from the source, so minutes are spread across the
    working day deterministically: same input always yields the same output, and
    the within-class ordering the source implied is preserved.
    """
    text = str(raw or "").strip()
    minute = second = 0
    if ":" in text:
        head, _, tail = text.partition(":")
        try:
            minute = int(float(head))
            second = int(float(tail))
        except ValueError:
            minute = second = 0
    hour = 9 + (minute // 10) % 8  # 09:00-16:59, the capture's working window
    return hour, minute % 60, second % 60


def _fetch(where: str, limit: int, offset: int = 0) -> list[dict[str, Any]]:
    """One /filter page, retrying while the upstream index warms up."""
    params: dict[str, str | int] = {
        "dataset": DATASET,
        "config": "default",
        "split": "train",
        "where": where,
        "limit": limit,
        "offset": offset,
    }
    last = ""
    for attempt in range(RETRIES):
        response = httpx.get(API, params=params, timeout=120.0, follow_redirects=True)
        if response.status_code == 200:
            return [row["row"] for row in response.json().get("rows", [])]
        last = f"http={response.status_code} {response.text[:120]}"
        log(f"  retry {attempt + 1}/{RETRIES}: {last}")
        time.sleep(RETRY_DELAY)
    raise RuntimeError(f"datasets-server /filter failed after {RETRIES} attempts: {last}")


def _where(labels: list[str]) -> str:
    """OR-chain of equality tests.

    The datasets-server ``where`` grammar rejects ``IN (...)``; an OR chain of
    ``"Label"='x'`` is the supported way to express a label set.
    """
    return " OR ".join(f"\"Label\"='{label}'" for label in labels)


def _row_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Flow identity — what makes two upstream rows the same observation."""
    return (
        row.get("Src IP dec"),
        row.get("Dst IP dec"),
        row.get("Src Port"),
        row.get("Dst Port"),
        row.get("Protocol"),
        row.get("Timestamp"),
        row.get("Flow Duration"),
        row.get("Label"),
    )


def _sample_label(label: str, wanted: int) -> list[dict[str, Any]]:
    """Rows for ONE raw label, sampled from spread-out offsets.

    Offsets are spread on purpose: the upstream file is time-ordered, so the
    first N rows of a class are one contiguous minute of one attack run, not a
    sample of the class.
    """
    where = _where([label])
    collected: list[dict[str, Any]] = []
    for step in range((wanted // PAGE) + 1):
        if len(collected) >= wanted:
            break
        take = min(PAGE, wanted - len(collected))
        page = _fetch(where, take, step * 5_000)
        if not page and step:  # past the end of this label — take from the start
            page = _fetch(where, take, 0)
        if not page:
            break
        collected.extend(page)
    return collected[:wanted]


def _rows_for(canonical: str, labels: list[str], wanted: int, day: str) -> list[dict[str, Any]]:
    """Sample ``wanted`` rows for one canonical class, spread across its sub-labels.

    Each raw label is queried separately with its own share of the quota. A
    single OR-chained query would return whichever sub-label happens to sit at
    the sampled offsets — that is how an earlier draft produced 50 rows of
    "Web Attack - Brute Force - Attempted" and zero XSS, SQLi or Heartbleed, all
    of which the model must actually tell apart.
    """
    collected: list[dict[str, Any]] = []
    share = max(1, wanted // len(labels))
    present: list[str] = []

    for label in labels:
        page = _sample_label(label, share)
        if page:
            present.append(f"{label}={len(page)}")
        collected.extend(page)

    # Sub-labels are rare at wildly different rates (Heartbleed has 11 rows in
    # 2.1M). Top up from whichever labels still have rows so the CLASS keeps the
    # support the stratification promised — de-duplicating by flow identity,
    # because the same flow drawn twice is one alert, not two, and would land in
    # the scored set as a duplicate primary key.
    seen = {_row_key(row) for row in collected}
    for label in labels:
        if len(collected) >= wanted:
            break
        for row in _sample_label(label, wanted - len(collected) + share):
            if len(collected) >= wanted:
                break
            key = _row_key(row)
            if key not in seen:
                seen.add(key)
                collected.append(row)

    out: list[dict[str, Any]] = []
    for index, row in enumerate(collected[:wanted]):
        hour, minute, second = _recover_clock(row.get("Timestamp"))
        # The fractional part is a sequence number, not a measurement: two flows
        # whose recovered clock lands on the same second must still normalize to
        # distinct alert ids (the id is derived from timestamp + 5-tuple), or the
        # scored set silently collapses two alerts into one row.
        stamp = datetime.strptime(day, "%d/%m/%Y").replace(
            hour=hour, minute=minute, second=second, tzinfo=UTC
        ) + timedelta(microseconds=index * 1000)
        src = _dotted(row.get("Src IP dec"))
        dst = _dotted(row.get("Dst IP dec"))
        sport = row.get("Src Port")
        dport = row.get("Dst Port")
        proto = row.get("Protocol")
        out.append(
            {
                "Flow ID": f"{src}-{dst}-{sport}-{dport}-{proto}",
                "Source IP": src,
                "Source Port": sport,
                "Destination IP": dst,
                "Destination Port": dport,
                "Protocol": proto,
                "Timestamp": stamp.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3],
                "Flow Duration": row.get("Flow Duration"),
                "Total Fwd Packets": row.get("Total Fwd Packet"),
                "Total Backward Packets": row.get("Total Bwd packets"),
                "Total Length of Fwd Packets": row.get("Total Length of Fwd Packet"),
                "Total Length of Bwd Packets": row.get("Total Length of Bwd Packet"),
                "Flow Bytes/s": row.get("Flow Bytes/s"),
                "Flow Packets/s": row.get("Flow Packets/s"),
                "Label": row.get("Label"),
            }
        )
    log(f"  {canonical:<18} {len(out):>4} rows  [{', '.join(present) or 'none'}]")
    return out


def build(out_path: Path) -> int:
    rows: list[dict[str, Any]] = []
    for canonical, (labels, wanted, day) in PLAN.items():
        rows.extend(_rows_for(canonical, labels, wanted, day))

    if not rows:
        log("FAILED: no rows collected")
        return 1

    # Interleave by timestamp so a replay of this file is not one class at a time.
    rows.sort(key=lambda r: str(r["Timestamp"]))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    log(f"wrote {len(rows)} rows -> {out_path}")
    return 0


def verify(out_path: Path) -> int:
    """Load the file back through the REAL loader and print the support table.

    Returns non-zero (rather than raising) when the file is missing or unusable:
    ``make labels`` uses the exit status to decide whether to rebuild, and a
    traceback on a cold clone reads like a crash rather than "not built yet".
    """
    from app.evaluation import ground_truth as gt

    try:
        population = gt.load_population(out_path)
    except (gt.GroundTruthError, OSError) as exc:
        log(f"not usable yet: {exc}")
        return 1

    support = gt.support(population)
    log(f"loader sees {len(population)} scorable alerts across {len(support)} classes")
    for label, count in support.items():
        flag = "  <-- LOW SUPPORT" if count < gt.LOW_SUPPORT_THRESHOLD else ""
        log(f"  {label:<20} {count:>4}{flag}")

    # Duplicate alert ids would collapse two scored alerts into one — the
    # benchmark keys predictions by alert id, so a collision silently shrinks the
    # comparison instead of failing.
    ids = {item.alert.id for item in population}
    if len(ids) != len(population):
        log(f"FAILED: {len(population) - len(ids)} duplicate alert id(s) after normalization")
        return 1

    minimum = get_settings().eval_min_label_rows
    if len(population) < minimum:
        log(f"FAILED: {len(population)} < EVAL_MIN_LABEL_ROWS ({minimum})")
        return 1
    log("OK: unique ids, every class above the low-support threshold")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the labeled eval subset")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"output CSV (default: GROUND_TRUTH_PATH/{DEFAULT_FILENAME})",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="skip the download; just load and report on the existing file",
    )
    args = parser.parse_args()

    out_path = args.out or Path(get_settings().ground_truth_path) / DEFAULT_FILENAME

    if not args.verify_only:
        log(f"source: {DATASET} via datasets-server /filter")
        code = build(out_path)
        if code:
            return code
    return verify(out_path)


if __name__ == "__main__":
    sys.exit(main())
