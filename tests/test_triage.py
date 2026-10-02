"""Triage: the recorded decision that a finding is a false positive, accepted, or not ours (W1-5).

Without it a dismissed false positive stays `open` in our records, counts and gate forever, and
1,353 findings on one Juice Shop scan cannot be worked through by any real team.
"""

import datetime as dt

import jsonschema
import pytest

from detections import triage
from detections.fingerprint import fingerprint, payload_family

TODAY = dt.date(2026, 10, 1)


def _fp(rule, endpoint, param=""):
    return fingerprint(rule, endpoint, param or "", payload_family(rule))


def _rec(rule="40018", endpoint="/rest/user/login", param="email", status="new", sev="high"):
    return {"fingerprint": _fp(rule, endpoint, param), "rule_id": rule, "endpoint": endpoint,
            "parameter": param or None, "status": status, "severity": sev, "title": "SQL Injection"}


def _sup(fp, reason="false_positive", expires=None, **extra):
    e = {"fingerprint": fp, "reason": reason, "justification": "checked by hand", "owner": "a"}
    if expires:
        e["expires"] = expires
    return {**e, **extra}


# ---- the contract -------------------------------------------------------------------------

def test_a_false_positive_needs_no_expiry():
    triage.validate({"suppressions": [_sup("0" * 64)]})


@pytest.mark.parametrize("reason", ["accepted_risk", "wont_fix"])
def test_accepted_risk_must_expire(reason):
    # Accepted risk without a date becomes permanent by accident; it must be revisited.
    with pytest.raises(jsonschema.ValidationError):
        triage.validate({"suppressions": [_sup("0" * 64, reason)]})
    triage.validate({"suppressions": [_sup("0" * 64, reason, "2027-01-01")]})


def test_a_justification_is_required():
    e = _sup("0" * 64); del e["justification"]
    with pytest.raises(jsonschema.ValidationError):
        triage.validate({"suppressions": [e]})


def test_an_unknown_reason_is_refused():
    with pytest.raises(jsonschema.ValidationError):
        triage.validate({"suppressions": [_sup("0" * 64, "meh")]})


# ---- applying it ----------------------------------------------------------------------------

def test_an_active_suppression_marks_the_finding():
    r = _rec()
    out = triage.apply([r], [_sup(r["fingerprint"])], TODAY)
    assert out[0]["status"] == "suppressed"
    assert out[0]["suppression"]["reason"] == "false_positive"
    assert out[0]["suppression"]["was"] == "new"          # the lifecycle fact is kept


def test_an_expired_suppression_returns_the_finding_and_says_so():
    r = _rec(status="open")
    out = triage.apply([r], [_sup(r["fingerprint"], "accepted_risk", "2026-09-01")], TODAY)
    assert out[0]["status"] == "open"
    assert out[0]["suppression"]["expired"] is True


def test_a_resolved_finding_stays_resolved():
    r = _rec(status="resolved")
    assert triage.apply([r], [_sup(r["fingerprint"])], TODAY)[0]["status"] == "resolved"


def test_suppressions_for_other_findings_change_nothing():
    r = _rec()
    assert triage.apply([r], [_sup("f" * 64)], TODAY)[0] == r


def test_the_input_records_are_not_mutated():
    r = _rec()
    triage.apply([r], [_sup(r["fingerprint"])], TODAY)
    assert r["status"] == "new" and "suppression" not in r


def test_a_missing_file_means_no_suppressions(tmp_path):
    assert triage.load(tmp_path / "nope.yaml") == []


# ---- importing GitHub dismissals --------------------------------------------------------
#
# GitHub's API does not expose SARIF fingerprints, so a dismissed alert is matched by RECOMPUTING
# ours from rule, path and the parameter named in the message (W1-2 onwards).

def _alert(rule="40018", path="/rest/user/login", msg="SQL Injection in parameter `email` — x.",
           reason="false positive", number=7):
    return {"number": number, "state": "dismissed", "dismissed_reason": reason,
            "dismissed_comment": "tested by hand, not injectable",
            "dismissed_by": {"login": "reviewer"}, "rule": {"id": rule},
            "most_recent_instance": {"location": {"path": path}, "message": {"text": msg}}}


def test_a_dismissal_naming_its_parameter_matches_exactly():
    recs = [_rec(param="email"), _rec(param="password")]
    got = triage.from_github([_alert()], recs, [], TODAY)
    assert [p["fingerprint"] for p in got["proposed"]] == [recs[0]["fingerprint"]]
    assert got["proposed"][0]["reason"] == "false_positive"
    assert got["proposed"][0]["owner"] == "reviewer"


def test_an_old_message_matches_only_when_it_is_unambiguous():
    old = _alert(msg="SQL Injection")                     # pre-W1-2: no parameter named
    one = triage.from_github([old], [_rec(param="email")], [], TODAY)
    assert len(one["proposed"]) == 1
    two = triage.from_github([old], [_rec(param="email"), _rec(param="password")], [], TODAY)
    assert two["proposed"] == [] and two["ambiguous"][0]["number"] == 7


def test_a_dismissal_with_no_local_finding_is_listed_not_invented():
    got = triage.from_github([_alert(path="/elsewhere")], [_rec()], [], TODAY)
    assert got["proposed"] == [] and got["unmatched"][0]["number"] == 7


def test_an_already_suppressed_finding_is_not_proposed_twice():
    r = _rec()
    got = triage.from_github([_alert()], [r], [_sup(r["fingerprint"])], TODAY)
    assert got["proposed"] == []


def test_wont_fix_gets_a_review_date_because_the_contract_requires_one():
    got = triage.from_github([_alert(reason="won't fix")], [_rec()], [], TODAY)
    p = got["proposed"][0]
    assert p["reason"] == "wont_fix" and p["expires"] == "2026-12-30"     # +90 days
    triage.validate({"suppressions": got["proposed"]})
