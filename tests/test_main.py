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
