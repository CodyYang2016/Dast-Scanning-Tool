"""Objective acceptance suite for the detection pipeline.

Every expected value here is anchored to something INDEPENDENT of our implementation, so a
pass means the code is right — not merely self-consistent. The five independent oracles:

  1. A different SHA implementation (OS `shasum -a 256` via subprocess) — not Python hashlib.
  2. Published external facts (SQL Injection is CWE-89; ZAP "High" -> "high").
  3. The raw ZAP fixture as ground truth (conservation, param preservation, query dropped).
  4. A third-party schema validator (jsonschema) — neither we nor our code is the judge.
  5. Sensitivity / negative checks — mutate one input, require the output to change.

See docs/junior_engineer/validation_and_testing.md for the methodology behind this file.
"""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from detections.fingerprint import endpoint_pattern, fingerprint
from detections.normalizer import normalize, normalize_alert

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "contracts" / "sample_zap_output.json"
DET_SCHEMA = ROOT / "contracts" / "detection.schema.json"
README = ROOT / "contracts" / "README.md"

APP_ID = "juice-shop"
SCAN_ID = "20260909T170000Z"

# ZAP risk -> severity, stated here INDEPENDENTLY from the production code's table (oracle 2:
# this is the documented mapping, transcribed from the contract/ZAP docs, not imported).
DOCUMENTED_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


@pytest.fixture(scope="module")
def report():
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def records(report):
    return list(normalize(report["alerts"], APP_ID, SCAN_ID))


def _external_sha256(preimage: str) -> str:
    """Hash with the OS `shasum -a 256` — a SHA implementation independent of hashlib.

    Falls back to a fresh hashlib call if shasum is unavailable *or* unusable; the point is to
    avoid routing through our module, which both paths satisfy. On Windows, `shasum` can be
    discoverable via PATH (e.g. Git for Windows' usr/bin) but not directly executable — since
    it's a script relying on shebang support the OS process launcher doesn't have — so any
    launch failure falls back rather than crashing the test.
    """
    if shutil.which("shasum"):
        try:
            out = subprocess.run(
                ["shasum", "-a", "256"], input=preimage.encode(), capture_output=True, check=True
            ).stdout.decode()
            return out.split()[0]
        except (OSError, subprocess.SubprocessError):
            pass
    return hashlib.sha256(preimage.encode()).hexdigest()


# ---- A. Fingerprint vs. an independent hasher (oracle 1) ---------------------------------

def test_fingerprint_matches_external_shasum():
    # Preimage constructed BY HAND here, hashed by an EXTERNAL tool. If our fingerprint()
    # matches, both the field assembly and the digest are correct.
    preimage = "40018|/rest/products/search|q|sqli"
    assert fingerprint("40018", "/rest/products/search", "q", "sqli") == _external_sha256(preimage)


def test_contract_worked_examples_are_self_consistent():
    # The two examples FROZEN in contracts/README.md. Independently re-hash the preimages the
    # README states, and require: (a) they equal the digests the README publishes, and
    # (b) our fingerprint() reproduces them. Catches a bug in the code OR in the contract.
    text = README.read_text()
    cases = [
        ("40018|/rest/products/search|q|sqli", ("40018", "/rest/products/search", "q", "sqli")),
        ("10038|/||headers", ("10038", "/", "", "headers")),
    ]
    for preimage, args in cases:
        published = _external_sha256(preimage)
        assert published in text, f"README does not contain digest for {preimage!r}"
        assert fingerprint(*args) == published


# ---- B. Sensitivity / negative checks (oracle 5) ----------------------------------------

def test_each_field_changes_the_fingerprint():
    # Proves all four inputs actually participate. A rubber-stamp test would never check this;
    # it would pass even if, say, payload_family were silently ignored.
    base = fingerprint("40018", "/rest/products/search", "q", "sqli")
    assert fingerprint("99999", "/rest/products/search", "q", "sqli") != base   # rule_id
    assert fingerprint("40018", "/rest/products/other", "q", "sqli") != base    # endpoint
    assert fingerprint("40018", "/rest/products/search", "x", "sqli") != base   # parameter
    assert fingerprint("40018", "/rest/products/search", "q", "xss") != base    # payload_family


def test_field_order_matters():
    # Swapping two field values must change the digest, or the fields aren't positionally bound.
    assert fingerprint("a", "b", "c", "d") != fingerprint("b", "a", "c", "d")


# ---- C. Field mapping vs. raw ZAP + external facts (oracles 2, 3) ------------------------

def test_record_count_conserved(report, records):
    # Ground truth: one record per raw alert. No silent drops or duplications.
    assert len(records) == len(report["alerts"])


def test_sqli_is_cwe_89(report):
    # External fact from the CWE catalog: SQL Injection is CWE-89.
    sqli = next(a for a in report["alerts"] if a.get("alert") == "SQL Injection")
    assert normalize_alert(sqli, APP_ID, SCAN_ID)["cwe_id"] == "CWE-89"


def test_severity_mapping_matches_zap_risk(report, records):
    # For every alert, the record severity must equal the documented mapping of its raw ZAP
    # risk — computed here from the raw fixture, independently of the code's own table.
    for raw, rec in zip(report["alerts"], records):
        assert rec["severity"] == DOCUMENTED_SEVERITY[raw["risk"]]


def test_endpoint_is_path_only(records):
    # The endpoint must be a bare path: no query string, no scheme, no host.
    for rec in records:
        ep = rec["endpoint"]
        assert "?" not in ep and "://" not in ep and not ep.startswith("http")
        assert ep.startswith("/")


def test_parameter_preserved_or_nulled(report, records):
    # Ground truth: a non-empty ZAP param survives verbatim; an empty one becomes null.
    for raw, rec in zip(report["alerts"], records):
        if raw.get("param"):
            assert rec["parameter"] == raw["param"]
        else:
            assert rec["parameter"] is None


def test_every_fingerprint_is_64_lowercase_hex(records):
    pat = re.compile(r"^[a-f0-9]{64}$")
    assert all(pat.match(rec["fingerprint"]) for rec in records)


# ---- D. Contract conformance via a third party (oracle 4) -------------------------------

def test_all_records_validate_against_schema(records):
    validator = Draft202012Validator(json.loads(DET_SCHEMA.read_text()))
    for rec in records:
        errors = sorted(validator.iter_errors(rec), key=lambda e: list(e.path))
        assert not errors, f"{rec['rule_id']}: {[e.message for e in errors]}"


# ---- E. Invariants ----------------------------------------------------------------------

def test_normalization_is_deterministic(report):
    a = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    b = list(normalize(report["alerts"], APP_ID, SCAN_ID))
    assert a == b


def test_endpoint_pattern_is_idempotent(records):
    # Re-patterning an already-patterned endpoint must not change it.
    for rec in records:
        assert endpoint_pattern("http://h" + rec["endpoint"]) == rec["endpoint"]
