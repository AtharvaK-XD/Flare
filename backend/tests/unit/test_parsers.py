"""Parser tests — golden fixtures, None for non-alerts, no raising."""

from __future__ import annotations

import json
from pathlib import Path

from app.ingestion.parsers import cicids, suricata_eve, zeek

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_suricata_alert_golden() -> None:
    rec = json.loads((FIXTURES / "suricata_eve.json").read_text())
    a = suricata_eve.parse(rec)
    assert a is not None
    assert a.source == "suricata"
    assert a.signature == "ET SCAN Potential SSH Scan"
    assert a.src_ip == "45.13.2.99"
    assert a.dst_ip == "10.0.0.5"
    assert a.src_port == 51000
    assert a.dst_port == 22
    assert a.protocol == "TCP"
    assert a.ground_truth_label is None
    assert a.raw["severity_hint"] == "medium"


def test_suricata_non_alert_returns_none() -> None:
    rec = json.loads((FIXTURES / "suricata_flow.json").read_text())
    assert suricata_eve.parse(rec) is None


def test_suricata_malformed_returns_none() -> None:
    assert suricata_eve.parse("{not json") is None
    assert suricata_eve.parse(12345) is None  # type: ignore[arg-type]


def test_zeek_json_notice_golden() -> None:
    lines = (FIXTURES / "zeek_notice.jsonl").read_text().splitlines()
    notice = zeek.parse(lines[0])
    assert notice is not None
    assert notice.source == "zeek"
    assert notice.signature == "SSH::Password_Guessing"
    assert notice.src_ip == "8.8.8.8"
    assert notice.dst_ip == "192.168.1.10"
    assert notice.dst_port == 22
    assert notice.protocol == "TCP"


def test_zeek_conn_log_returns_none() -> None:
    lines = (FIXTURES / "zeek_notice.jsonl").read_text().splitlines()
    assert zeek.parse(lines[1]) is None


def test_zeek_tsv_stream() -> None:
    lines = (FIXTURES / "zeek_notice.tsv").read_text().splitlines()
    records = list(zeek.iter_tsv(lines))
    assert len(records) == 1
    a = zeek.parse(records[0])
    assert a is not None
    assert a.signature == "Scan::Port_Scan"
    assert a.src_ip == "8.8.4.4"
    assert a.dst_port == 80


def _cicids_rows() -> list[dict]:
    import csv

    with (FIXTURES / "cicids_sample.csv").open() as fh:
        return list(csv.DictReader(fh))


def test_cicids_portscan_golden() -> None:
    row = _cicids_rows()[0]
    a = cicids.parse(row)
    assert a is not None
    assert a.source == "cicids2017"
    assert a.ground_truth_label == "port_scan"
    assert a.src_ip == "45.13.2.99"
    assert a.dst_port == 80
    assert "PortScan" in a.signature


def test_cicids_ddos_maps() -> None:
    row = _cicids_rows()[2]
    a = cicids.parse(row)
    assert a is not None
    assert a.ground_truth_label == "ddos"


def test_cicids_strips_whitespace_columns() -> None:
    row = _cicids_rows()[0]
    a = cicids.parse(row)
    assert a is not None
    assert a.src_port == 51000


def test_cicids_benign_sampling() -> None:
    base = _cicids_rows()[1]
    results = []
    for i in range(60):
        r = dict(base)
        r["Flow ID"] = f"flow-{i}"
        results.append(cicids.parse(r))
    kept = [x for x in results if x is not None]
    dropped = [x for x in results if x is None]
    assert dropped, "sampling should drop most benign rows"
    assert all(x.ground_truth_label == "benign" for x in kept)


def test_cicids_unknown_label() -> None:
    row = dict(_cicids_rows()[0])
    row[" Label"] = "SomethingNew"
    a = cicids.parse(row)
    assert a is not None
    assert a.ground_truth_label == "unknown"
