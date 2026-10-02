"""Make ZAP's attacks carry a fresh session (W5-2).

The active scan replays requests with the cookies they were RECORDED with, so logging in again
changes nothing on its own. A Replacer rule rewrites the session headers on the active scanner's
and spider's requests, and is updated when the session is re-established.
"""

from runner import session_refresh as sr


def _calls(monkeypatch):
    calls = []
    def api(z, path, params=None, timeout=30.0):
        calls.append((path, dict(params or {})))
        return {}
    monkeypatch.setattr(sr, "_api", api)
    return calls


def test_the_cookie_rule_carries_the_whole_jar_for_scanner_and_spider_only():
    (rule,) = sr.rules({"PHPSESSID": "abc", "security": "low"})
    assert rule["description"] == "dast-session-cookie"
    assert rule["matchType"] == "REQ_HEADER" and rule["matchString"] == "Cookie"
    assert rule["replacement"] == "PHPSESSID=abc; security=low"
    assert rule["initiators"] == "2,3"           # never the probe's anonymous baseline (6)


def test_a_bearer_rule_is_added_from_a_named_cookie():
    rules = sr.rules({"token": "eyJ.x.y"}, bearer_cookie="token")
    bearer = [r for r in rules if r["matchString"] == "Authorization"][0]
    assert bearer["replacement"] == "Bearer eyJ.x.y"


def test_no_bearer_rule_when_the_cookie_is_absent():
    assert len(sr.rules({"a": "b"}, bearer_cookie="token")) == 1


def test_install_replaces_any_previous_rule(monkeypatch):
    calls = _calls(monkeypatch)
    sr.install("http://zap", {"a": "1"})
    paths = [p for p, _ in calls]
    assert paths.index("/JSON/replacer/action/removeRule/") < \
        paths.index("/JSON/replacer/action/addRule/")


def test_remove_takes_both_rules_out_and_tolerates_absence(monkeypatch):
    def api(z, path, params=None, timeout=30.0):
        raise RuntimeError("no such rule")
    monkeypatch.setattr(sr, "_api", api)
    sr.remove("http://zap")                     # does not raise
