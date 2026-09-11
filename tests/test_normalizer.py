"""Normalizer unit tests (FR-N1) — real fixture in, contract-valid records out."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from detections.normalizer import normalize, normalize_alert

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "contracts" / "sample_zap_output.json"
DET_SCHEMA = ROOT / "contracts" / "detection.schema.json"

APP_ID = "juice-shop"
SCAN_ID = "20260909T170000Z"


@pytest.fixture(scope="module")
def report():
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def validator():
    return Draft202012Validator(json.loads(DET_SCHEMA.read_text()))


def test_every_record_validates_against_schema(report, validator):
    records = normalize(report, APP_ID, SCAN_ID)
    assert records, "fixture produced no records"
    for rec in records:
        errors = sorted(validator.iter_errors(rec), key=lambda e: e.path)
        assert not errors, f"{rec['rule_id']}: {[e.message for e in errors]}"


def test_record_count_matches_fixture(report):
    assert len(normalize(report, APP_ID, SCAN_ID)) == len(report["alerts"])


def test_high_sqli_mapped_correctly(report):
    sqli = next(a for a in report["alerts"] if a.get("pluginId") == "40018")
    rec = normalize_alert(sqli, APP_ID, SCAN_ID)
    assert rec["severity"] == "high"
    assert rec["cwe_id"] == "CWE-89"
    assert rec["endpoint"] == "/rest/products/search"
    assert rec["parameter"] == "q"
    assert rec["title"] == "SQL Injection"
    # matches the README worked example digest
    assert rec["fingerprint"] == "ece130214d0131cf2c0d71334a6719a0442d794cc6dfe9faababed15c7fcf3db"


def test_passive_alert_has_null_parameter(report):
    csp = next(a for a in report["alerts"] if a.get("pluginId") == "10038")
    rec = normalize_alert(csp, APP_ID, SCAN_ID)
    assert rec["parameter"] is None  # empty ZAP param -> null in record


def test_normalization_is_deterministic(report):
    a = normalize(report, APP_ID, SCAN_ID)
    b = normalize(report, APP_ID, SCAN_ID)
    assert a == b


def test_fixture_meets_the_bar(report):
    recs = normalize(report, APP_ID, SCAN_ID)
    highs = [r for r in recs if r["severity"] in ("high", "critical")]
    rules = {r["rule_id"] for r in recs}
    assert len(highs) >= 1 and len(rules) >= 2
