"""The report stage's policy gate (W3-2): should these findings fail the build?

It can only be decided after the lifecycle diff, which is the first point that knows which
findings are NEW. An existing finding already fails or passes someone's review elsewhere; failing
every build on it forever is how a gate gets switched off.
"""

import pytest

from detections.gate import policy_gate


def _r(severity, status="new", rule="1", endpoint="/x"):
    return {"severity": severity, "status": status, "rule_id": rule, "endpoint": endpoint,
            "title": f"{severity} thing"}


def test_a_new_finding_at_the_threshold_fails():
    g = policy_gate([_r("high")], "high")
    assert g["passed"] is False and len(g["blocking"]) == 1


def test_a_new_finding_above_the_threshold_fails():
    assert policy_gate([_r("critical")], "high")["passed"] is False


def test_a_new_finding_below_the_threshold_passes():
    assert policy_gate([_r("medium")], "high")["passed"] is True


@pytest.mark.parametrize("status", ["open", "resolved", "not_scanned", "suppressed"])
def test_only_new_findings_can_fail_it(status):
    assert policy_gate([_r("critical", status)], "high")["passed"] is True


def test_none_disables_it():
    assert policy_gate([_r("critical")], "none")["passed"] is True


def test_no_findings_passes():
    assert policy_gate([], "low")["passed"] is True


def test_info_never_blocks():
    assert policy_gate([_r("info")], "low")["passed"] is True


def test_an_unknown_threshold_is_refused():
    with pytest.raises(ValueError):
        policy_gate([], "severe")
