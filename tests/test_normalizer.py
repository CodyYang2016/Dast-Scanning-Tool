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


# ---- actionable findings: carry ZAP's remediation content (W1-1) -------------------------
#
# Oracle: counts transcribed from the committed fixture by hand, not computed by the code under
# test. ZAP supplies description on 38/38 alerts, solution on 32, evidence on 26, attack on 7,
# a reference on 27 (8 of them several newline-separated URLs), confidence on all 38.

# sha256 of the sorted fixture fingerprints, captured BEFORE this change. None of the new fields
# may feed identity: if this moves, every lifecycle history and GitHub alert loses its identity.
_FINGERPRINTS_BEFORE = "7dbc605a024b164c475457ba829890ed114520c7040cd3d2f4d36b695c12eebb"


def _records(report):
    return list(normalize(report["alerts"], APP_ID, SCAN_ID))


def test_adding_remediation_does_not_change_any_fingerprint(report):
    import hashlib
    fps = sorted(r["fingerprint"] for r in _records(report))
    assert hashlib.sha256("\n".join(fps).encode()).hexdigest() == _FINGERPRINTS_BEFORE


def test_remediation_content_is_conserved_from_the_fixture(report):
    recs = _records(report)
    assert sum(1 for r in recs if r.get("description")) == 38
    assert sum(1 for r in recs if r.get("solution")) == 32
    assert sum(1 for r in recs if r.get("evidence_excerpt")) == 26
    assert sum(1 for r in recs if r.get("attack")) == 7
    assert sum(1 for r in recs if r.get("references")) == 27
    assert sum(1 for r in recs if r.get("confidence")) == 38


def test_references_are_split_into_separate_urls(report):
    recs = _records(report)
    multi = [r["references"] for r in recs if len(r.get("references") or []) > 1]
    assert len(multi) == 8
    for refs in multi:
        assert all(u.startswith("http") and "\n" not in u and u == u.strip() for u in refs)


def test_confidence_is_normalised_like_severity(report):
    assert {r["confidence"] for r in _records(report)} <= {"high", "medium", "low"}


def test_empty_remediation_fields_are_omitted_not_blank():
    rec = normalize_alert({"pluginId": "1", "alert": "x", "risk": "Low",
                           "url": "http://a/b", "evidence": "", "attack": "  "}, APP_ID, SCAN_ID)
    for f in ("description", "solution", "references", "evidence_excerpt", "attack"):
        assert f not in rec


# The one genuinely risky part: evidence and attack are strings lifted from the TARGET's
# responses and the scanner's payloads, so they can carry live session material.
_SECRETS = {
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl",
    "bearer": "Bearer abc123SECRETtoken",
    "session": '"session": "s3ss10n-VALUE-xyz"',
    "email": "victim.person@example.com",
}


def test_evidence_is_redacted_before_it_reaches_the_record():
    leaky = " | ".join(_SECRETS.values())
    rec = normalize_alert({"pluginId": "1", "alert": "x", "risk": "High", "url": "http://a/b",
                           "evidence": leaky, "attack": leaky}, APP_ID, SCAN_ID)
    blob = json.dumps(rec)
    for raw in ("eyJhbGciOiJIUzI1NiJ9", "abc123SECRETtoken", "s3ss10n-VALUE-xyz",
                "victim.person@example.com"):
        assert raw not in blob, f"{raw!r} leaked into the record"
    assert "REDACTED" in rec["evidence_excerpt"] and "REDACTED" in rec["attack"]


def test_a_long_evidence_string_is_capped_with_a_marker():
    rec = normalize_alert({"pluginId": "1", "alert": "x", "risk": "High", "url": "http://a/b",
                           "evidence": "A" * 2000}, APP_ID, SCAN_ID)
    assert len(rec["evidence_excerpt"]) <= 520
    assert rec["evidence_excerpt"].endswith("[truncated]")


def test_enriched_records_still_validate(report, validator):
    for rec in _records(report):
        assert not list(validator.iter_errors(rec))


def test_a_record_without_any_new_field_still_validates(validator):
    old = {"app_id": "a", "scan_id": SCAN_ID, "fingerprint": "0" * 64, "rule_id": "1",
           "title": "t", "severity": "low", "endpoint": "/", "status": "open"}
    assert not list(validator.iter_errors(old))


def test_a_secret_crossing_the_cap_is_redacted_whole():
    # Redaction runs on the whole string before the cap. A JWT starting just inside the kept 500
    # characters and running well past them must not leave its prefix behind.
    jwt = "eyJ" + "A" * 1800 + ".eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    rec = normalize_alert({"pluginId": "1", "alert": "x", "risk": "High", "url": "http://a/b",
                           "evidence": "B" * 480 + " " + jwt}, APP_ID, SCAN_ID)
    assert "eyJAAAA" not in rec["evidence_excerpt"]
    assert "REDACTED" in rec["evidence_excerpt"]
