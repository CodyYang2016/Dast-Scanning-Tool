"""Normalizer unit tests (FR-N1) — real fixture in, contract-valid records out."""

import io
import json
import types
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from detections.normalizer import (
    iter_alerts,
    normalize,
    normalize_alert,
    write_json_array,
)

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
    records = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    assert records, "fixture produced no records"
    for rec in records:
        errors = sorted(validator.iter_errors(rec), key=lambda e: e.path)
        assert not errors, f"{rec['rule_id']}: {[e.message for e in errors]}"


def test_record_count_matches_fixture(report):
    assert len(list(normalize(report["alerts"], APP_ID, SCAN_ID))) == len(report["alerts"])


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
    a = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    b = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    assert a == b


def test_fixture_meets_the_bar(report):
    recs = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    highs = [r for r in recs if r["severity"] in ("high", "critical")]
    rules = {r["rule_id"] for r in recs}
    assert len(highs) >= 1 and len(rules) >= 2


# ---- streaming-interface tests (scalability convention) ---------------------------------

def test_normalize_is_a_lazy_generator():
    # Streaming by default: normalize() must not materialize its input. Feed an endless
    # source and take just one — if it were eager, this would hang/OOM.
    def endless():
        alert = {"pluginId": "1", "url": "http://h/a", "risk": "Low", "param": "", "cweid": "-1", "alert": "x"}
        while True:
            yield alert
    gen = normalize(endless(), APP_ID, SCAN_ID)
    assert isinstance(gen, types.GeneratorType)
    first = next(gen)
    assert first["rule_id"] == "1"


def test_iter_alerts_yields_from_report_stream():
    stream = io.StringIO(json.dumps({"alerts": [{"pluginId": "1"}, {"pluginId": "2"}]}))
    assert [a["pluginId"] for a in iter_alerts(stream)] == ["1", "2"]


def test_write_json_array_roundtrips(report):
    # The streaming writer must emit valid JSON identical in content to the records.
    records = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    buf = io.StringIO()
    write_json_array(iter(records), buf)
    assert json.loads(buf.getvalue()) == records


def test_write_json_array_handles_empty():
    buf = io.StringIO()
    write_json_array(iter([]), buf)
    assert json.loads(buf.getvalue()) == []
