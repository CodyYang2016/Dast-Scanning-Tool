"""Objective tests for runner/coverage.py's rule set (R2).

Live ZAP is not needed: `_api` is monkeypatched with the exact JSON shapes ZAP returns. Oracle:
hand-built scanner lists with known enabled/disabled ids.

Why passive rules matter: coverage `rules` decides whether a vanished finding is `resolved`
(pair exercised) or `not_scanned`. Passive rules (e.g. 90022 Application Error Disclosure,
10098 Cross-Domain Misconfiguration) fire on every scanned route, but an active-only rule list
excluded them, so a passive finding could never honestly be `resolved`. Observed 2026-09-19.
"""

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
