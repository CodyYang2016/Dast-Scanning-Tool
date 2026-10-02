"""Pure unit tests for the scan gate.

The end-to-end run() is validated live (real ZAP + browser). The gate decision itself is pure.

Two modes (W3-2). The DEFAULT is a health gate: the scan authenticated, stayed in scope, and
tested at least one route. It used to require a high/medium finding — which made sense for a demo
against deliberately vulnerable apps and made a CLEAN application fail every pipeline. That old
condition survives as `expect_findings`, for self-tests where zero findings means the scanner is
broken. Whether findings should fail a build is the report stage's policy gate, which can see
which findings are NEW.
"""

from runner.main import evaluate_gate

COVERED = {"routes": ["/a", "/b"]}
NOTHING_TESTED = {"routes": []}


def _rec(severity):
    return {"severity": severity}


# ---- health gate (the default) -----------------------------------------------------------

def test_a_clean_healthy_scan_passes():
    # The whole point of the change: no findings is a PASS, not a failure.
    gate = evaluate_gate(True, True, [], COVERED)
    assert gate["passed"] is True and gate["mode"] == "health"


def test_findings_do_not_fail_the_health_gate():
    assert evaluate_gate(True, True, [_rec("high")], COVERED)["passed"] is True


def test_health_fails_without_auth():
    assert evaluate_gate(False, True, [], COVERED)["passed"] is False


def test_health_fails_on_scope_violation():
    assert evaluate_gate(True, False, [], COVERED)["passed"] is False


def test_a_scan_that_tested_nothing_never_passes():
    # W6-13: a hash-routed login excluded all of Juice Shop, the old gate passed on 60 passive
    # findings, and coverage reported 0 routes. A scan of nothing must not be green.
    gate = evaluate_gate(True, True, [_rec("high")], NOTHING_TESTED)
    assert gate["passed"] is False and gate["routes_tested"] == 0


def test_unknown_coverage_fails_closed():
    assert evaluate_gate(True, True, [], None)["passed"] is False


# ---- expect_findings (self-test against deliberately vulnerable apps) ----------------------

def test_expect_findings_passes_when_all_true():
    gate = evaluate_gate(True, True, [_rec("medium")], COVERED, expect_findings=True)
    assert gate["passed"] is True and gate["mode"] == "expect-findings"


def test_expect_findings_fails_without_high_or_medium():
    gate = evaluate_gate(True, True, [_rec("low"), _rec("info")], COVERED, expect_findings=True)
    assert gate["passed"] is False
    assert gate["has_high_or_medium"] is False


def test_expect_findings_still_requires_health():
    assert evaluate_gate(False, True, [_rec("high")], COVERED, expect_findings=True)["passed"] is False
    assert evaluate_gate(True, True, [_rec("high")], NOTHING_TESTED,
                         expect_findings=True)["passed"] is False


def test_gate_counts_detections_and_routes():
    gate = evaluate_gate(True, True, [_rec("low"), _rec("medium"), _rec("info")], COVERED)
    assert gate["detections"] == 3 and gate["routes_tested"] == 2
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


# ---- recorded evidence paths must point at where the files actually are -------------------
#
# Measured: with an explicit evidence directory (how `dast scan` always runs) the files landed at
# <dir>/evidence/messages/<fp>.txt while records said evidence/<scan_id>/messages/<fp>.txt — a
# directory that never exists. The recorded prefix is now derived from the same rule that decides
# where files are written.


from runner.main import evidence_prefix, resolve_evidence_dir


def test_with_an_evidence_dir_the_recorded_prefix_matches_the_files(tmp_path):
    written = resolve_evidence_dir("security/dast/x/scope.json", str(tmp_path), "20261001T000000Z")
    assert tmp_path / evidence_prefix(str(tmp_path), "20261001T000000Z") == written


def test_without_one_the_legacy_layout_still_matches(tmp_path):
    scope = tmp_path / "app" / "scope.json"
    written = resolve_evidence_dir(str(scope), None, "20261001T000000Z")
    assert scope.resolve().parent / evidence_prefix(None, "20261001T000000Z") == written
