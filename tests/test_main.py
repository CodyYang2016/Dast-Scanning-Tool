"""Pure unit tests for the Phase 1 gate logic.

The end-to-end run() is validated live (real ZAP + browser). The gate decision itself is pure
and gets objective tests here: it must fail closed unless the scan authenticated, stayed in
scope, AND found a high/medium detection.
"""

from runner.main import evaluate_gate


def _rec(severity):
    return {"severity": severity}


def test_gate_passes_when_all_true():
    gate = evaluate_gate(authenticated=True, scope_ok=True, records=[_rec("medium")])
    assert gate["passed"] is True


def test_gate_fails_without_auth():
    assert evaluate_gate(False, True, [_rec("high")])["passed"] is False


def test_gate_fails_on_scope_violation():
    assert evaluate_gate(True, False, [_rec("high")])["passed"] is False


def test_gate_fails_without_high_or_medium():
    gate = evaluate_gate(True, True, [_rec("low"), _rec("info")])
    assert gate["passed"] is False
    assert gate["has_high_or_medium"] is False


def test_gate_counts_detections():
    gate = evaluate_gate(True, True, [_rec("low"), _rec("medium"), _rec("info")])
    assert gate["detections"] == 3
    assert gate["has_high_or_medium"] is True


# ---- evidence belongs with the scan that produced it ------------------------------------
# runner.main derives the evidence directory from the scope file's parent, which puts HARs
# and screenshots inside the *bundle* — mixing one scan's evidence into the reusable config,
# and leaving `dast scan`'s artifact directory incomplete. An explicit override keeps each
# scan's evidence with its records and coverage (DoD: one artifact directory per scan).

def test_evidence_dir_defaults_to_the_app_directory(tmp_path):
    from runner.main import resolve_evidence_dir
    scope = tmp_path / "app" / "scope.json"
    scope.parent.mkdir(parents=True)
    got = resolve_evidence_dir(str(scope), None, "20260101T000000Z")
    assert got == tmp_path / "app" / "evidence" / "20260101T000000Z"


def test_explicit_evidence_dir_wins(tmp_path):
    from runner.main import resolve_evidence_dir
    scope = tmp_path / "app" / "scope.json"
    scope.parent.mkdir(parents=True)
    run_dir = tmp_path / "out" / "app" / "scans" / "20260101T000000Z"
    got = resolve_evidence_dir(str(scope), str(run_dir), "20260101T000000Z")
    assert got == run_dir / "evidence"


# ---- the bundle's policy reaches the scan, and the coverage says which one ---------------

def test_runner_finds_the_policy_next_to_the_scope(tmp_path):
    from runner.main import bundle_policy
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "zap-policy.yaml").write_text('{"attack_strength": "high", "disabled_scanners": []}')
    assert bundle_policy(str(bundle / "scope.json"))["attack_strength"] == "high"


def test_runner_tolerates_a_bundle_without_a_policy(tmp_path):
    from runner.main import bundle_policy
    assert bundle_policy(str(tmp_path / "scope.json")) is None


def test_scan_budget_comes_from_the_policy_when_the_caller_does_not_say(tmp_path):
    from runner.main import resolve_max_scan_min
    policy = {"max_scan_min": 12}
    assert resolve_max_scan_min(None, policy) == 12       # the bundle decides
    assert resolve_max_scan_min(3, policy) == 3           # an explicit flag still wins
    assert resolve_max_scan_min(None, None) == 4          # historical default
