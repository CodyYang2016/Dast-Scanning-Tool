"""Pure unit tests for the scan safety pre-check.

The live ZAP orchestration (spider/ascan/export) is validated by driving the real containers
(see runner_design.md). Here we cover the one pure, safety-critical branch: scan() must refuse
an out-of-scope target BEFORE touching ZAP (NFR-2). If it raised only after calling ZAP, a
misconfig could send traffic — so this asserts the refusal happens with no network.
"""

import json

import pytest

from runner.scan import ScanScopeError, scan

# A ZAP API that would explode if used — proves scan() never touches the network on refusal.
EXPLODING_API = "http://zap.invalid:1"


def test_scan_refuses_out_of_scope_target():
    with pytest.raises(ScanScopeError):
        scan(EXPLODING_API, "http://evil.example.com/", allow_hosts=["juice"])


def test_scan_refuses_target_with_no_host():
    with pytest.raises(ScanScopeError):
        scan(EXPLODING_API, "/relative/path", allow_hosts=["juice"])


def test_scan_scope_check_is_case_insensitive():
    # 'JUICE' host normalizes to 'juice' which is allow-listed -> passes the check and then
    # tries to reach ZAP (which fails on the bogus API). We only assert it did NOT raise
    # ScanScopeError, i.e. the safety check let an in-scope host through.
    with pytest.raises(Exception) as exc:
        scan(EXPLODING_API, "http://JUICE:3000/", allow_hosts=["juice"])
    assert not isinstance(exc.value, ScanScopeError)


# ---- W2-4: the generated policy actually drives the scan --------------------------------
# zap-policy.yaml was emitted by `generate` and read by nobody: configure_policy() took a time
# budget and disabled one hard-coded scanner. Scan depth was therefore an accident of the
# wall clock and of whatever a previous run left enabled on the daemon — which is exactly the
# "silent coverage decay" that makes a lifecycle diff untrustworthy. Oracle: the exact ZAP API
# calls each policy must produce, captured from a fake daemon.

from runner.scan import configure_policy, load_policy, resolved_policy

POLICY = {"intensity": "high", "attack_strength": "high", "alert_threshold": "low",
          "disabled_scanners": ["40026", "10095"]}


class FakeZap:
    """Records the API calls configure_policy makes, in order."""
    def __init__(self):
        self.calls = []

    def __call__(self, zap_api, path, params=None, timeout=30.0):
        self.calls.append((path, dict(params or {})))
        if path == "/JSON/ascan/view/policies/":
            return {"policies": [{"id": "0"}, {"id": "4"}]}
        return {"Result": "OK"}

    def paths(self):
        return [p for p, _ in self.calls]

    def params_for(self, path):
        return [q for p, q in self.calls if p == path]


def _configure(monkeypatch, **kw):
    fake = FakeZap()
    monkeypatch.setattr("runner.scan._api", fake)
    configure_policy("http://zap", **kw)
    return fake


def test_attack_strength_and_threshold_are_applied_to_every_category(monkeypatch):
    fake = _configure(monkeypatch, policy=POLICY)
    strengths = fake.params_for("/JSON/ascan/action/setPolicyAttackStrength/")
    thresholds = fake.params_for("/JSON/ascan/action/setPolicyAlertThreshold/")
    assert {p["attackStrength"] for p in strengths} == {"HIGH"}
    assert {p["alertThreshold"] for p in thresholds} == {"LOW"}
    assert {p["id"] for p in strengths} == {"0", "4"}      # every category ZAP reports


def test_the_rule_set_is_reset_before_disabling_so_runs_do_not_drift(monkeypatch):
    # Without enableAllScanners first, a rule disabled by a previous run stays disabled and
    # this scan silently covers less than its policy says.
    fake = _configure(monkeypatch, policy=POLICY)
    paths = fake.paths()
    assert paths.index("/JSON/ascan/action/enableAllScanners/") < \
           paths.index("/JSON/ascan/action/disableScanners/")


def test_disabled_scanners_come_from_the_policy_not_a_constant(monkeypatch):
    fake = _configure(monkeypatch, policy=POLICY)
    assert fake.params_for("/JSON/ascan/action/disableScanners/")[0]["ids"] == "40026,10095"


def test_a_policy_may_re_enable_everything(monkeypatch):
    fake = _configure(monkeypatch, policy={**POLICY, "disabled_scanners": []})
    assert "/JSON/ascan/action/enableAllScanners/" in fake.paths()
    assert "/JSON/ascan/action/disableScanners/" not in fake.paths()


def test_time_budgets_still_bound_the_scan(monkeypatch):
    fake = _configure(monkeypatch, policy=POLICY, max_scan_min=7, max_rule_min=2)
    assert fake.params_for("/JSON/ascan/action/setOptionMaxScanDurationInMins/")[0]["Integer"] == 7
    assert fake.params_for("/JSON/ascan/action/setOptionMaxRuleDurationInMins/")[0]["Integer"] == 2


def test_no_policy_keeps_the_previous_behaviour(monkeypatch):
    # Callers that pass no policy (compose, a hand-run scan) must be unaffected.
    fake = _configure(monkeypatch)
    assert "/JSON/ascan/action/setPolicyAttackStrength/" not in fake.paths()
    assert fake.params_for("/JSON/ascan/action/disableScanners/")[0]["ids"] == "40026"


def test_load_policy_reads_the_generated_file(tmp_path):
    p = tmp_path / "zap-policy.yaml"
    p.write_text(json.dumps(POLICY))          # generate writes JSON, which is valid YAML
    assert load_policy(str(p))["attack_strength"] == "high"


def test_load_policy_returns_none_when_there_is_no_policy(tmp_path):
    assert load_policy(str(tmp_path / "absent.yaml")) is None


def test_resolved_policy_records_what_was_asked_for(monkeypatch):
    # The coverage artifact must say which policy produced it, so two scans of the same app
    # can be compared honestly (R2).
    resolved = resolved_policy(POLICY, max_scan_min=7, max_rule_min=2)
    assert resolved["attack_strength"] == "high" and resolved["alert_threshold"] == "low"
    assert resolved["disabled_scanners"] == ["40026", "10095"]
    assert resolved["max_scan_min"] == 7


# ---- a dead or busy daemon must not surface as a socket traceback -----------------------
# Observed 2026-09-27: re-enabling DOM-XSS (40026) at HIGH strength OOM-killed the ZAP
# container mid-scan, and the 6-minute run ended in a raw TimeoutError from http.client with
# no indication of what had happened. Polling must tolerate a slow answer and say something
# useful when the daemon is actually gone.

from runner.scan import ZapUnavailableError, _poll


def test_polling_survives_a_transient_timeout(monkeypatch):
    calls = {"n": 0}

    def flaky(zap_api, path, params=None, timeout=30.0):
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("timed out")
        return {"status": "100"}

    monkeypatch.setattr("runner.scan._api", flaky)
    monkeypatch.setattr("runner.scan.time.sleep", lambda s: None)
    _poll("http://zap", "/JSON/ascan/view/status/", "0", poll_s=0, max_polls=10)
    assert calls["n"] == 3          # two failures absorbed, then the real answer


def test_a_daemon_that_stops_answering_raises_something_actionable(monkeypatch):
    def dead(zap_api, path, params=None, timeout=30.0):
        raise TimeoutError("timed out")

    monkeypatch.setattr("runner.scan._api", dead)
    monkeypatch.setattr("runner.scan.time.sleep", lambda s: None)
    with pytest.raises(ZapUnavailableError) as exc:
        _poll("http://zap", "/JSON/ascan/view/status/", "0", poll_s=0, max_polls=10)
    assert "stopped responding" in str(exc.value)
