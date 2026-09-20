"""Objective acceptance suite for the SARIF exporter (FR-X1).

Oracles independent of our code (see docs/junior_engineer/validation_and_testing.md):
  - the VENDORED OFFICIAL OASIS SARIF 2.1.0 schema (third-party validator),
  - published facts (SQL Injection is CWE-89; GitHub's security-severity bands),
  - the input records themselves (conservation, fingerprint carry-through),
  - SARIF's own structural rules (ruleId <-> rules referential integrity),
  - a documented mapping table transcribed independently in this file.
"""

import json
from pathlib import Path

import pytest
from jsonschema.validators import validator_for

from detections.normalizer import normalize
from detections.sarif_export import FINGERPRINT_KEY, to_sarif

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "contracts" / "sample_zap_output.json"
SARIF_SCHEMA = ROOT / "contracts" / "sarif-2.1.0.schema.json"

APP_ID = "juice-shop"
SCAN_ID = "20260909T170000Z"

# severity -> level, transcribed INDEPENDENTLY from the design doc (not imported from code).
DOCUMENTED_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


@pytest.fixture(scope="module")
def records():
    report = json.loads(FIXTURE.read_text())
    return list(normalize(report["alerts"], APP_ID, SCAN_ID))


@pytest.fixture(scope="module")
def sarif(records):
    return to_sarif(records, driver_version="2.17.0")


def _results(sarif):
    return sarif["runs"][0]["results"]


def _rules(sarif):
    return sarif["runs"][0]["tool"]["driver"]["rules"]


# ---- Official schema (oracle: vendored OASIS SARIF 2.1.0 schema) -------------------------

def test_sarif_validates_against_official_schema(sarif):
    schema = json.loads(SARIF_SCHEMA.read_text())
    Validator = validator_for(schema)          # picks the schema's declared draft
    Validator.check_schema(schema)
    errors = sorted(Validator(schema).iter_errors(sarif), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]


# ---- Conservation & fingerprint carry-through (oracle: the input records) ----------------

def test_result_count_conserved(records, sarif):
    assert len(_results(sarif)) == len(records)


def test_every_fingerprint_carried(records, sarif):
    for rec, res in zip(records, _results(sarif)):
        assert res["partialFingerprints"][FINGERPRINT_KEY] == rec["fingerprint"]


# ---- Mapping vs. published facts + independent table -------------------------------------

def test_sqli_level_is_error_and_high_band(sarif):
    res = next(r for r in _results(sarif) if r["ruleId"] == "40018")
    assert res["level"] == "error"
    rule = next(rl for rl in _rules(sarif) if rl["id"] == "40018")
    sec = float(rule["properties"]["security-severity"])
    assert 7.0 <= sec < 9.0  # GitHub's "high" band


def test_cwe_tag_present_for_sqli(sarif):
    rule = next(rl for rl in _rules(sarif) if rl["id"] == "40018")
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]  # SQLi is CWE-89


def test_level_mapping_matches_table(records, sarif):
    for rec, res in zip(records, _results(sarif)):
        assert res["level"] == DOCUMENTED_LEVEL[rec["severity"]]


# ---- SARIF structural rule: referential integrity ---------------------------------------

def test_referential_integrity(sarif):
    rules = _rules(sarif)
    rule_ids = {rl["id"] for rl in rules}
    for res in _results(sarif):
        assert res["ruleId"] in rule_ids
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


def test_rules_are_deduped(records, sarif):
    assert len(_rules(sarif)) == len({r["rule_id"] for r in records})


# ---- D1: single-pass over a one-shot iterator -------------------------------------------

def test_export_is_single_pass_iterable(records):
    one_shot = iter(records)  # a generator/iterator consumable exactly once
    sarif = to_sarif(one_shot)
    assert len(sarif["runs"][0]["results"]) == len(records)


def test_evidence_path_becomes_attachment():
    # FR-E1: a record with evidence_path must reference it from the SARIF result.
    rec = {
        "app_id": "juice-shop", "scan_id": SCAN_ID, "fingerprint": "a" * 64,
        "rule_id": "40018", "title": "SQL Injection", "severity": "high", "cwe_id": "CWE-89",
        "endpoint": "/rest/products/search", "parameter": "q", "status": "open",
        "evidence_path": "evidence/20260101T000000Z/active-scan.har",
    }
    sarif = to_sarif([rec])
    result = sarif["runs"][0]["results"][0]
    assert result["attachments"][0]["artifactLocation"]["uri"] == rec["evidence_path"]
    # and it still validates against the official schema
    schema = json.loads(SARIF_SCHEMA.read_text())
    Validator = validator_for(schema)
    assert not list(Validator(schema).iter_errors(sarif))


# ---- Coverage-aware publishing: never let GitHub close a finding we did not test for -------
# GitHub auto-closes ("fixed") any alert absent from the newest upload. Feeding it labeled
# records from lifecycle_diff, the export must DROP only `resolved` (pair exercised, finding
# gone = real fix) and CARRY FORWARD `not_scanned` (pair not exercised this scan), alongside
# new/open. Observed live 2026-09-19: an LLM-explored journey that skipped /rest/continue-code
# made GitHub mark 13 real findings there "fixed".

def _labeled(records):
    a, b, c, d = records[0], records[1], records[2], records[3]
    return [dict(a, status="new"), dict(b, status="open"),
            dict(c, status="resolved"), dict(d, status="not_scanned")]


def test_export_drops_resolved_but_keeps_not_scanned(records):
    labeled = _labeled(records)
    out = to_sarif(labeled)
    fps = {r["partialFingerprints"][FINGERPRINT_KEY] for r in _results(out)}
    assert labeled[0]["fingerprint"] in fps          # new
    assert labeled[1]["fingerprint"] in fps          # open
    assert labeled[2]["fingerprint"] not in fps      # resolved -> let GitHub close it
    assert labeled[3]["fingerprint"] in fps          # not_scanned -> carried forward


def test_export_keeps_unlabeled_records(records):
    # Raw normalizer output (status "open") is unaffected.
    assert len(_results(to_sarif(records))) == len(records)
