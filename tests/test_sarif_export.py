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


# ---- Automation category: one analysis per application -----------------------------------
#
# GitHub keys a code-scanning analysis by (tool name, category, ref). Every app exports under
# the same driver name, so with no category a second application's upload REPLACES the first
# one's alerts in the Security tab. The category is carried in the SARIF itself as
# runs[].automationDetails.id — the REST API has no such field.

def test_a_category_is_carried_as_automation_details(records):
    s = to_sarif(records, driver_version="2.17.0", category="dast/dvwa")
    assert s["runs"][0]["automationDetails"]["id"] == f"dast/dvwa/{SCAN_ID}"


def test_a_categorised_document_still_validates_against_the_official_schema(records):
    s = to_sarif(records, driver_version="2.17.0", category="dast/dvwa")
    schema = json.loads(SARIF_SCHEMA.read_text())
    validator_for(schema)(schema).validate(s)


def test_two_applications_do_not_share_an_analysis(records):
    # The regression test for the overwrite bug: these two ids must differ, or GitHub treats
    # the uploads as the same analysis and the second deletes the first.
    a = to_sarif(records, category="dast/dvwa")["runs"][0]["automationDetails"]["id"]
    b = to_sarif(records, category="dast/juice-shop")["runs"][0]["automationDetails"]["id"]
    assert a != b


def test_no_category_leaves_automation_details_out(records):
    # An empty id is worse than none: it is a category, and every app would share it.
    assert "automationDetails" not in to_sarif(records)["runs"][0]
    assert "automationDetails" not in to_sarif(records, category="")["runs"][0]


# ---- actionable findings in the Security tab (W1-2) --------------------------------------
#
# GitHub's alert page renders a result's MESSAGE and its rule's HELP. It does not render
# `properties` — which is why the parameter has been invisible in GitHub despite being in the
# SARIF all along. Anything a developer needs must therefore be in the message or the help.

def _by_rule(sarif, rule_id):
    return next(r for r in _rules(sarif) if r["id"] == rule_id)


def _sqli_result(sarif):
    return next(r for r in _results(sarif)
                if r["ruleId"] == "40018" and r["properties"].get("parameter") == "q")


def test_the_sqli_alert_says_where_how_and_how_sure(sarif):
    # The acceptance criterion from the plan, pinned: the fixture's High SQL injection.
    assert _sqli_result(sarif)["message"]["text"] == (
        "SQL Injection in parameter `q` — ZAP sent `apple'` and the server answered "
        "`HTTP/1.1 500 Internal Server Error`. Confidence: Low."
    )


def test_what_a_developer_needs_is_in_the_message_not_only_in_properties(sarif):
    msg = _sqli_result(sarif)["message"]["text"]
    for visible in ("`q`", "apple'", "500", "Low"):
        assert visible in msg


def test_a_finding_with_no_parameter_attack_or_evidence_has_no_empty_slots():
    rec = {"rule_id": "10020", "title": "Missing Anti-clickjacking Header", "severity": "medium",
           "endpoint": "/", "fingerprint": "0" * 64, "scan_id": SCAN_ID}
    msg = to_sarif([rec])["runs"][0]["results"][0]["message"]["text"]
    assert msg == "Missing Anti-clickjacking Header."
    assert "``" not in msg and "parameter" not in msg and "sent" not in msg


def test_the_rule_carries_the_fix_and_the_reading(sarif):
    rule = _by_rule(sarif, "40018")
    assert rule["fullDescription"]["text"] == "SQL injection may be possible."
    assert "PreparedStatement" in rule["help"]["markdown"]
    assert "cheatsheetseries.owasp.org" in rule["help"]["markdown"]
    assert rule["helpUri"].startswith("https://cheatsheetseries.owasp.org/")
    assert rule["help"]["text"]            # plain-text fallback for clients without markdown


def test_every_reference_url_is_listed_in_the_help(records, sarif):
    for rec in records:
        for url in rec.get("references") or []:
            assert url in _by_rule(sarif, rec["rule_id"])["help"]["markdown"]


def test_a_rule_without_remediation_has_no_empty_help():
    rec = {"rule_id": "1", "title": "t", "severity": "low", "endpoint": "/",
           "fingerprint": "0" * 64, "scan_id": SCAN_ID}
    rule = to_sarif([rec])["runs"][0]["tool"]["driver"]["rules"][0]
    assert "help" not in rule and "fullDescription" not in rule and "helpUri" not in rule


def test_help_is_carried_once_per_rule_not_per_finding(records, sarif):
    # 38 findings, 8 rules: the bulky text travels 8 times, which is what keeps the upload small.
    assert len(_results(sarif)) == len(records)
    assert len(_rules(sarif)) == len({r["rule_id"] for r in records})


def test_zap_gives_identical_help_for_every_finding_of_a_rule(records):
    # The rule entry takes its help from the FIRST record seen. That is only correct because ZAP
    # describes the plugin, not the instance. Pin the assumption so a source that varies it
    # fails here instead of silently showing one finding's text on another.
    seen = {}
    for r in records:
        key = (r.get("description"), r.get("solution"), tuple(r.get("references") or []))
        assert seen.setdefault(r["rule_id"], key) == key, r["rule_id"]


def test_confidence_and_attack_are_also_machine_readable(sarif):
    props = _sqli_result(sarif)["properties"]
    assert props["confidence"] == "low" and props["attack"] == "apple'"


def test_the_enriched_document_still_validates_against_the_official_schema(sarif):
    schema = json.loads(SARIF_SCHEMA.read_text())
    validator_for(schema)(schema).validate(sarif)


def test_no_secret_reaches_the_sarif_even_through_evidence():
    from detections.normalizer import normalize_alert
    rec = normalize_alert({"pluginId": "1", "alert": "x", "risk": "High", "url": "http://a/b",
                           "evidence": "Bearer abc123SECRETtoken victim.person@example.com"},
                          APP_ID, SCAN_ID)
    blob = json.dumps(to_sarif([rec]))
    assert "abc123SECRETtoken" not in blob and "victim.person@example.com" not in blob


# ---- size guard: GitHub rejects SARIF over 10 MB gzipped ----------------------------------

def test_the_worst_case_github_allows_stays_under_the_upload_limit():
    # GitHub accepts at most 25,000 results per run and 10 MB gzipped. Build 1,000 noisy
    # findings over 60 rules with oversized text everywhere, measure, and project linearly to
    # 25,000: the per-rule help is a fixed cost (carried once per rule), the rest scales.
    import gzip
    from detections.normalizer import normalize_alert

    def build(n):
        alerts = [{"pluginId": str(10000 + i % 60), "alert": f"Rule {i % 60}", "risk": "Medium",
                   "url": f"http://a/route{i}?p={i}", "param": "p", "confidence": "Medium",
                   "description": "D" * 2000, "solution": "S" * 2000,
                   "reference": "\n".join(f"https://ref/{j}" for j in range(10)),
                   "evidence": "E" * 700 + str(i), "attack": "A" * 700 + str(i)} for i in range(n)]
        # ~700 chars: just over the 500 cap so truncation is exercised, and close to the
        # largest real evidence in the fixture (620).
        recs = [normalize_alert(a, APP_ID, SCAN_ID) for a in alerts]
        return recs, len(gzip.compress(json.dumps(to_sarif(recs)).encode()))

    recs, small = build(500)
    assert all(r["evidence_excerpt"].endswith("[truncated]") for r in recs)   # the cap bit
    _, large = build(1000)
    per_finding = (large - small) / 500
    projected = large + per_finding * (25_000 - 1000)
    assert projected < 10 * 1024 * 1024, f"projected {projected / 1e6:.1f} MB at 25k results"


def test_evidence_from_the_target_cannot_inject_markdown_into_the_alert():
    # Evidence is lifted from the TARGET's response. A backtick in it would close a naive code
    # span and let the rest render as live markdown — a link inside the Security tab, authored by
    # whoever controls the scanned application. CommonMark: a code span delimited by N+1
    # backticks cannot be closed by a run of N inside it.
    hostile = "ok` [click](http://evil.example) `"
    rec = {"rule_id": "1", "title": "Reflected", "severity": "high", "endpoint": "/",
           "fingerprint": "0" * 64, "scan_id": SCAN_ID, "evidence_excerpt": hostile}
    md = to_sarif([rec])["runs"][0]["results"][0]["message"]["markdown"]
    start = md.index("evidence: ") + len("evidence: ")
    fence = md[start:len(md) - len(md[start:].lstrip("`"))]    # the opening delimiter run
    assert len(fence) >= 2, md
    body = md[start + len(fence):]
    assert body.index(fence) > body.index("http://evil.example"), md  # closes AFTER the payload


def test_the_plain_text_message_is_unchanged_by_markdown_escaping(sarif):
    assert _sqli_result(sarif)["message"]["text"].startswith("SQL Injection in parameter `q`")


def test_a_multi_line_solution_keeps_its_lines_in_markdown(sarif):
    md = _by_rule(sarif, "40018")["help"]["markdown"]
    assert "place.  \nIn general" in md          # hard line break, not a collapsed paragraph


# ---- W1-3: the alert says how to replay it ------------------------------------------------

def _repro(**extra):
    return {"rule_id": "40018", "title": "SQL Injection", "severity": "high", "endpoint": "/x",
            "fingerprint": "0" * 64, "scan_id": SCAN_ID, **extra}


def test_the_message_says_how_to_reproduce():
    rec = _repro(parameter="email", attack="'", request_line="POST /rest/user/login",
                 response_status=500)
    msg = to_sarif([rec])["runs"][0]["results"][0]["message"]["text"]
    assert msg.endswith("Reproduce: `POST /rest/user/login` → 500.")


def test_a_request_line_without_a_status_still_reads_cleanly():
    msg = to_sarif([_repro(request_line="GET /a")])["runs"][0]["results"][0]["message"]["text"]
    assert msg.endswith("Reproduce: `GET /a`.")


def test_no_reproduction_adds_nothing():
    msg = to_sarif([_repro()])["runs"][0]["results"][0]["message"]["text"]
    assert "Reproduce" not in msg


def test_a_hostile_request_line_cannot_inject_markdown():
    # The path carries the attack payload, which is attacker-shaped text.
    rec = _repro(request_line="GET /s?q=` [x](http://evil.example) `")
    md = to_sarif([rec])["runs"][0]["results"][0]["message"]["markdown"]
    assert "`` GET /s?q=` [x](http://evil.example) ` ``" in md


# ---- W1-5: a suppressed finding is still published, and marked ---------------------------

def _sup_rec(status="suppressed"):
    return {"rule_id": "40018", "title": "SQL Injection", "severity": "high", "endpoint": "/x",
            "fingerprint": "0" * 64, "scan_id": SCAN_ID, "status": status,
            "suppression": {"reason": "false_positive", "justification": "checked by hand",
                            "expired": False, "was": "open"}}


def test_a_suppressed_finding_stays_in_the_upload():
    # Dropping it would be how GitHub decides it was "fixed".
    assert len(to_sarif([_sup_rec()])["runs"][0]["results"]) == 1


def test_it_carries_a_sarif_suppression_with_the_justification():
    (s,) = to_sarif([_sup_rec()])["runs"][0]["results"][0]["suppressions"]
    assert s == {"kind": "external", "status": "accepted", "justification": "checked by hand"}


def test_an_expired_suppression_is_not_marked():
    rec = _sup_rec(status="open"); rec["suppression"]["expired"] = True
    assert "suppressions" not in to_sarif([rec])["runs"][0]["results"][0]


def test_a_suppressed_document_validates_against_the_official_schema():
    schema = json.loads(SARIF_SCHEMA.read_text())
    validator_for(schema)(schema).validate(to_sarif([_sup_rec()]))


# ---- the category as GITHUB derives it --------------------------------------------------
#
# GitHub splits runs[].automationDetails.id at its LAST "/": the part before is the category, the
# part after is a run id. Measured on an upload: id "dast/juice-shop" became category "dast" — so
# every app got the same category and two apps in one repo would overwrite each other, the very bug
# a per-app category exists to prevent. Tests that only compared our own ids could not see it.

def _github_category(sarif):
    run_id = sarif["runs"][0]["automationDetails"]["id"]
    return run_id[: run_id.rfind("/")]


def test_github_derives_the_full_per_app_category(records):
    assert _github_category(to_sarif(records, category="dast/juice-shop")) == "dast/juice-shop"


def test_two_apps_get_different_categories_as_github_sees_them(records):
    a = _github_category(to_sarif(records, category="dast/dvwa"))
    b = _github_category(to_sarif(records, category="dast/juice-shop"))
    assert a != b and a == "dast/dvwa" and b == "dast/juice-shop"


def test_the_run_id_is_the_scan(records):
    run_id = to_sarif(records, category="dast/juice-shop")["runs"][0]["automationDetails"]["id"]
    assert run_id == f"dast/juice-shop/{SCAN_ID}"


def test_a_trailing_slash_in_config_is_not_doubled(records):
    assert _github_category(to_sarif(records, category="dast/juice-shop/")) == "dast/juice-shop"
