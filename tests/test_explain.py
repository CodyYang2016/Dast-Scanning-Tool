"""Objective tests for `dast explain` — why did a finding disappear? (W6-9)

The lifecycle diff gives the honest label (`resolved` or `not_scanned`) and never the reason.
Working out why five high-severity findings became zero took an hour of curling ZAP and
reading container logs, and the answer — the application was not in the same state — was
sitting in nobody's artifact. Every input needed to answer it is now recorded, so the answer
should be a line of output.

Oracles: hand-built scan pairs whose correct attribution is known by construction.
"""

import pytest

from detections import explain


def _rec(fp, endpoint="/a", rule="40018", severity="high"):
    return {"fingerprint": fp, "endpoint": endpoint, "rule_id": rule, "severity": severity,
            "title": "SQL Injection"}


BASE_COV = {"routes": ["/a"], "rules": ["40018"],
            "rule_outcomes": {"40018": {"name": "SQL Injection", "state": "Complete",
                                        "requests": 660, "alerts": 0}},
            "truncated_rules": [], "policy": {"write_mode": "deny"},
            "app_state": {"probes": {"/security.php": {"status": 200, "digest": "aaaa"}}}}


def test_a_route_that_was_not_visited_this_time():
    cov = {**BASE_COV, "routes": []}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "route_not_covered" and why["fingerprint"] == "f1"


def test_a_rule_that_was_switched_off():
    cov = {**BASE_COV, "rules": [], "rule_outcomes": {}}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "rule_not_enabled"


def test_a_rule_that_ran_out_of_time():
    cov = {**BASE_COV, "truncated_rules": ["40018"]}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "rule_truncated"


def test_the_application_was_in_a_different_state():
    # The case that actually happened: rule ran to completion, sent hundreds of requests,
    # raised nothing — and the app's own state had changed underneath.
    cov = {**BASE_COV, "app_state": {"probes": {"/security.php": {"status": 200,
                                                                  "digest": "bbbb"}}}}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "app_state_changed"
    assert "/security.php" in why["detail"]


def test_a_write_enabled_scan_cannot_claim_a_fix():
    cov = {**BASE_COV, "policy": {"write_mode": "allow"}}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "scan_changed_the_app"


def test_everything_checks_out_so_it_is_genuinely_gone():
    (why,) = explain.explain_disappearance([_rec("f1")], [], BASE_COV, BASE_COV)
    assert why["reason"] == "fixed"
    assert "660 requests" in why["detail"]           # the evidence for the claim


def test_findings_still_present_are_not_explained():
    assert explain.explain_disappearance([_rec("f1")], [_rec("f1")], BASE_COV, BASE_COV) == []


def test_reasons_are_ordered_most_specific_first():
    # A scan can be wrong in several ways at once; report the one that explains it best.
    cov = {**BASE_COV, "routes": [], "rules": [], "truncated_rules": ["40018"]}
    (why,) = explain.explain_disappearance([_rec("f1")], [], cov, BASE_COV)
    assert why["reason"] == "route_not_covered"


def test_a_previous_scan_without_state_recorded_does_not_invent_a_difference():
    old = {k: v for k, v in BASE_COV.items() if k != "app_state"}
    (why,) = explain.explain_disappearance([_rec("f1")], [], BASE_COV, old)
    assert why["reason"] == "fixed"


def test_the_summary_counts_by_reason():
    findings = [_rec("f1"), _rec("f2", endpoint="/gone")]
    cov = {**BASE_COV, "routes": ["/a"]}
    out = explain.explain_disappearance(findings, [], cov, BASE_COV)
    assert explain.summarize(out) == {"fixed": 1, "route_not_covered": 1}


# ---- W6-10: "fixed" must not be said about a parameter nobody tested --------------------

PARAM_COV = {**BASE_COV, "routes": ["/sqli"], "route_params": {"/sqli": ["id"]}}


def _sqli(param):
    return _rec("f1", endpoint="/sqli", rule="40018")| {"parameter": param}


def test_a_parameter_that_was_exercised_can_be_called_fixed():
    (why,) = explain.explain_disappearance([_sqli("id")], [], PARAM_COV, PARAM_COV)
    assert why["reason"] == "fixed"


def test_a_parameter_that_was_never_exercised_is_not_a_fix():
    # The measured case: /vulnerabilities/sqli visited bare, so ?id= was never tested.
    cov = {**PARAM_COV, "route_params": {"/sqli": []}}
    (why,) = explain.explain_disappearance([_sqli("id")], [], cov, PARAM_COV)
    assert why["reason"] == "parameter_not_exercised"
    assert "id" in why["detail"]


def test_a_finding_without_a_parameter_is_unaffected():
    cov = {**PARAM_COV, "route_params": {"/sqli": []}}
    (why,) = explain.explain_disappearance([_sqli(None)], [], cov, PARAM_COV)
    assert why["reason"] == "fixed"


def test_coverage_predating_parameter_recording_keeps_its_old_answer():
    old = {k: v for k, v in PARAM_COV.items() if k != "route_params"}
    (why,) = explain.explain_disappearance([_sqli("id")], [], old, old)
    assert why["reason"] == "fixed"


def test_an_excluded_route_is_named_as_excluded_not_merely_uncovered():
    cov = {**BASE_COV, "routes": [], "excluded": [r"(?i).*setup.*"]}
    rec = _rec("f9", endpoint="/setup.php", rule="40018")
    (why,) = explain.explain_disappearance([rec], [], cov, cov)
    assert why["reason"] == "route_excluded"
    assert "setup" in why["detail"]


def test_a_route_absent_for_other_reasons_is_still_route_not_covered():
    cov = {**BASE_COV, "routes": [], "excluded": [r"(?i).*setup.*"]}
    rec = _rec("f9", endpoint="/other.php", rule="40018")
    (why,) = explain.explain_disappearance([rec], [], cov, cov)
    assert why["reason"] == "route_not_covered"
