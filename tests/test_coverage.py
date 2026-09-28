"""Objective tests for runner/coverage.py's rule set (R2).

Live ZAP is not needed: `_api` is monkeypatched with the exact JSON shapes ZAP returns. Oracle:
hand-built scanner lists with known enabled/disabled ids.

Why passive rules matter: coverage `rules` decides whether a vanished finding is `resolved`
(pair exercised) or `not_scanned`. Passive rules (e.g. 90022 Application Error Disclosure,
10098 Cross-Domain Misconfiguration) fire on every scanned route, but an active-only rule list
excluded them, so a passive finding could never honestly be `resolved`. Observed 2026-09-19.
"""

import json

from runner import coverage


def _fake_api(payloads):
    def _api(zap_api, path, params=None, timeout=30.0):
        return payloads[path]
    return _api


def test_enabled_rules_include_active_and_passive(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({
        "/JSON/ascan/view/scanners/": {"scanners": [
            {"id": "40018", "enabled": "true"}, {"id": "40026", "enabled": "false"}]},
        "/JSON/pscan/view/scanners/": {"scanners": [
            {"id": "90022", "enabled": "true"}, {"id": "10098", "enabled": "true"},
            {"id": "10021", "enabled": "false"}]},
    }))
    rules = coverage.enabled_rule_ids("http://zap")
    assert rules == {"40018", "90022", "10098"}


def test_enabled_rules_survive_missing_pscan_endpoint(monkeypatch):
    # An older ZAP without the pscan view must not break coverage capture (fail soft to active).
    def _api(zap_api, path, params=None, timeout=30.0):
        if path.startswith("/JSON/pscan/"):
            raise OSError("404")
        return {"scanners": [{"id": "40018", "enabled": "true"}]}
    monkeypatch.setattr(coverage, "_api", _api)
    assert coverage.enabled_rule_ids("http://zap") == {"40018"}


# ---- W6-2: what each rule actually did ---------------------------------------------------
# "No finding" and "never looked" are the same sentence in an artifact that records only
# which rules were ENABLED. ZAP knows the difference — scanProgress reports, per rule, its
# state, how many requests it sent and how many alerts it raised. Recording that answered in
# seconds a question that had cost an hour: rule 40018 read Complete / 660 requests / 0
# alerts, which ruled out the time budget and pointed at the application's state instead.

_PROGRESS = {"scanProgress": [
    "http://app",
    {"HostProcess": [
        {"Plugin": ["SQL Injection", "40018", "release", "Complete", "660", "700", "0"]},
        {"Plugin": ["Path Traversal", "6", "release", "Complete", "658", "681", "3"]},
        {"Plugin": ["Log4Shell", "40043", "release", "Skipped, no OAST service", "0", "0", "0"]},
        {"Plugin": ["Slow One", "90099", "release", "Skipped, exceeded max rule time",
                    "144", "200", "0"]},
    ]},
]}


def test_rule_outcomes_are_read_from_the_scan(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({
        "/JSON/ascan/view/scanProgress/": _PROGRESS}))
    out = coverage.rule_outcomes("http://zap", "0")
    assert out["40018"] == {"name": "SQL Injection", "state": "Complete",
                            "requests": 660, "alerts": 0}


def test_a_rule_that_ran_and_found_nothing_is_distinguishable_from_one_that_did_not_run(
        monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({
        "/JSON/ascan/view/scanProgress/": _PROGRESS}))
    out = coverage.rule_outcomes("http://zap", "0")
    assert out["40018"]["state"] == "Complete" and out["40018"]["requests"] > 0
    assert out["40043"]["state"].startswith("Skipped") and out["40043"]["requests"] == 0


def test_rules_skipped_for_time_are_surfaced_as_truncation(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({
        "/JSON/ascan/view/scanProgress/": _PROGRESS}))
    assert coverage.truncated_rules(coverage.rule_outcomes("http://zap", "0")) == ["90099"]


def test_an_unavailable_progress_view_does_not_break_the_scan(monkeypatch):
    def boom(zap_api, path, params=None, timeout=30.0):
        raise OSError("404")
    monkeypatch.setattr(coverage, "_api", boom)
    assert coverage.rule_outcomes("http://zap", "0") == {}


# ---- W6-8: was the application even in the same condition? ------------------------------
# The same bundle and policy produced 5 highs, then 0, with the SQL-injection rule running
# 660 requests and raising nothing — while the app was exploitable by hand minutes later.
# DVWA's security level rides in a cookie the tool never set and never noticed changing.
# Recording a fingerprint of a few probe responses makes "the app was different" a fact in
# the artifact rather than a theory in someone's shell history.

def test_a_state_fingerprint_is_stable_when_the_app_is_unchanged(monkeypatch):
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u: (200, "Security Level: low"))
    a = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    b = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    assert a == b and a["probes"]["/security.php"]["status"] == 200


def test_a_state_fingerprint_changes_when_the_app_does(monkeypatch):
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u: (200, "Security Level: low"))
    low = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u: (200, "Security Level: impossible"))
    impossible = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    assert low != impossible


def test_the_fingerprint_stores_a_digest_not_the_page(monkeypatch):
    # Probe responses can contain anything; only a digest is kept.
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u: (200, "token=SECRET-VALUE"))
    fp = coverage.state_fingerprint("http://zap", "http://app", ["/x"])
    assert "SECRET" not in json.dumps(fp)
    assert len(fp["probes"]["/x"]["digest"]) == 16


def test_no_probes_configured_means_no_fingerprint(monkeypatch):
    assert coverage.state_fingerprint("http://zap", "http://app", []) == {}


def test_an_unreachable_probe_is_recorded_rather_than_skipped(monkeypatch):
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u: (None, ""))
    fp = coverage.state_fingerprint("http://zap", "http://app", ["/gone"])
    assert fp["probes"]["/gone"]["status"] is None
