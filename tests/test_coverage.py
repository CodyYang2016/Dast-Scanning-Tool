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
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (200, "Security Level: low"))
    a = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    b = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    assert a == b and a["probes"]["/security.php"]["status"] == 200


def test_a_state_fingerprint_changes_when_the_app_does(monkeypatch):
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (200, "Security Level: low"))
    low = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (200, "Security Level: impossible"))
    impossible = coverage.state_fingerprint("http://zap", "http://app", ["/security.php"])
    assert low != impossible


def test_the_fingerprint_stores_a_digest_not_the_page(monkeypatch):
    # Probe responses can contain anything; only a digest is kept.
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (200, "token=SECRET-VALUE"))
    fp = coverage.state_fingerprint("http://zap", "http://app", ["/x"])
    assert "SECRET" not in json.dumps(fp)
    assert len(fp["probes"]["/x"]["digest"]) == 16


def test_no_probes_configured_means_no_fingerprint(monkeypatch):
    assert coverage.state_fingerprint("http://zap", "http://app", []) == {}


def test_an_unreachable_probe_is_recorded_rather_than_skipped(monkeypatch):
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (None, ""))
    fp = coverage.state_fingerprint("http://zap", "http://app", ["/gone"])
    assert fp["probes"]["/gone"]["status"] is None


# ---- W6-10: a parameter nobody exercised is not covered ---------------------------------
# Coverage recorded routes, and a finding's identity includes its PARAMETER. So
# /vulnerabilities/sqli visited without ?id= counted as covered, and the two findings on that
# parameter would have been labelled `fixed` when nothing had ever tested them. ZAP's URL
# list carries the query strings; endpoint_pattern was throwing them away.

def test_parameters_are_recorded_per_route(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({"/JSON/core/view/urls/": {"urls": [
        "http://app/search?q=x&page=2",
        "http://app/orders/7",
        "http://app/search",
    ]}}))
    params = coverage.accessed_params("http://zap", "http://app")
    assert params["/search"] == ["page", "q"]          # sorted, deduped
    assert params.get("/orders/{id}", []) == []        # visited, no parameters seen


def test_the_same_route_unions_parameters_across_visits(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({"/JSON/core/view/urls/": {"urls": [
        "http://app/s?a=1", "http://app/s?b=2",
    ]}}))
    assert coverage.accessed_params("http://zap", "http://app")["/s"] == ["a", "b"]


def test_parameters_from_another_host_are_ignored(monkeypatch):
    monkeypatch.setattr(coverage, "_api", _fake_api({"/JSON/core/view/urls/": {"urls": [
        "http://app/s?a=1", "http://elsewhere/s?secret=1",
    ]}}))
    assert coverage.accessed_params("http://zap", "http://app") == {"/s": ["a"]}


# ---- authenticated state probes -------------------------------------------------------

def _state(monkeypatch, pages, cookies=None):
    """state_fingerprint over a fake app whose page depends on whether a session was sent."""
    monkeypatch.setattr(coverage, "_fetch_probe",
                        lambda z, u, c=None: (200, pages[bool(c)]))
    return coverage.state_fingerprint("http://zap", "http://app", ["/security.php"],
                                      cookies=cookies)


def test_a_probe_carries_the_scans_session(monkeypatch):
    sent = {}
    monkeypatch.setattr(coverage, "_fetch_probe",
                        lambda z, u, c=None: (sent.update(c or {}), (200, "ok"))[1])
    coverage.state_fingerprint("http://zap", "http://app", ["/x"],
                               cookies={"PHPSESSID": "abc", "security": "low"})
    assert sent == {"PHPSESSID": "abc", "security": "low"}


def test_the_authenticated_view_differs_from_the_anonymous_one(monkeypatch):
    # The measured failure: probes without a session saw the login page every time, so the
    # digest was constant and a changed app could never be detected.
    pages = {False: "Please login", True: "Security Level: low"}
    anon = _state(monkeypatch, pages)
    authed = _state(monkeypatch, pages, cookies={"PHPSESSID": "abc"})
    assert anon["probes"]["/security.php"]["digest"] != authed["probes"]["/security.php"]["digest"]


def test_the_fingerprint_says_whether_it_was_authenticated(monkeypatch):
    pages = {False: "Please login", True: "Security Level: low"}
    assert _state(monkeypatch, pages)["authenticated"] is False
    assert _state(monkeypatch, pages, cookies={"PHPSESSID": "a"})["authenticated"] is True


def test_an_authenticated_probe_still_notices_the_app_changing(monkeypatch):
    low = _state(monkeypatch, {True: "Security Level: low"}, cookies={"s": "1"})
    high = _state(monkeypatch, {True: "Security Level: high"}, cookies={"s": "1"})
    assert low["probes"]["/security.php"]["digest"] != high["probes"]["/security.php"]["digest"]


# ---- where the probe's cookies come from ----------------------------------------------

def _storage(tmp_path, cookies):
    import json
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"cookies": cookies, "origins": []}))
    return str(p)


def test_probe_cookies_come_from_the_recorded_session(tmp_path):
    ss = _storage(tmp_path, [{"name": "PHPSESSID", "value": "abc", "domain": "app"}])
    assert coverage.probe_cookies(ss, "http://app") == {"PHPSESSID": "abc"}


def test_another_hosts_cookies_are_not_sent(tmp_path):
    ss = _storage(tmp_path, [{"name": "PHPSESSID", "value": "abc", "domain": "app"},
                             {"name": "tracker", "value": "x", "domain": "ads.example"}])
    assert coverage.probe_cookies(ss, "http://app") == {"PHPSESSID": "abc"}


def test_configured_state_cookies_are_added(tmp_path):
    ss = _storage(tmp_path, [{"name": "PHPSESSID", "value": "abc", "domain": "app"}])
    got = coverage.probe_cookies(ss, "http://app", extra={"security": "low"})
    assert got == {"PHPSESSID": "abc", "security": "low"}


def test_config_wins_over_a_stale_session_cookie(tmp_path):
    # The config states the state the scan depends on; a cookie captured earlier does not.
    ss = _storage(tmp_path, [{"name": "security", "value": "high", "domain": "app"}])
    assert coverage.probe_cookies(ss, "http://app", extra={"security": "low"}) == {"security": "low"}


def test_no_session_file_still_yields_the_configured_cookies():
    assert coverage.probe_cookies(None, "http://app", extra={"security": "low"}) == {"security": "low"}


def test_an_unreadable_session_file_does_not_break_the_scan(tmp_path):
    p = tmp_path / "broken.json"; p.write_text("{not json")
    assert coverage.probe_cookies(str(p), "http://app", extra={"a": "b"}) == {"a": "b"}


def test_config_cookies_alone_are_not_a_session(tmp_path, monkeypatch):
    # A scan with no recorded session still sends `security=low`; that is app state, not proof
    # of a login, and the artifact must not imply the probe saw the authenticated app.
    monkeypatch.setattr(coverage, "_fetch_probe", lambda z, u, c=None: (200, "Please login"))
    fp = coverage.state_fingerprint("http://zap", "http://app", ["/x"],
                                    cookies={"security": "low"}, authenticated=False)
    assert fp["authenticated"] is False


def test_session_cookies_are_separable_from_configured_state(tmp_path):
    ss = _storage(tmp_path, [{"name": "PHPSESSID", "value": "abc", "domain": "app"}])
    assert coverage.session_cookies(ss, "http://app") == {"PHPSESSID": "abc"}
    assert coverage.session_cookies(None, "http://app") == {}


# ---- an excluded route was not scanned -------------------------------------------------

def test_excluded_routes_are_not_counted_as_covered(monkeypatch):
    monkeypatch.setattr(coverage, "accessed_routes",
                        lambda z, t: {"/index.php", "/setup.php", "/login.php"})
    monkeypatch.setattr(coverage, "accessed_params", lambda z, t: {})
    monkeypatch.setattr(coverage, "enabled_rule_ids", lambda z: {"40018"})
    out = coverage.capture("http://zap", "http://app",
                           excluded=[r"(?i).*setup.*", r"(?i).*/login\.php.*"])
    assert out["routes"] == ["/index.php"]
    assert out["excluded"] == [r"(?i).*setup.*", r"(?i).*/login\.php.*"]


def test_parameters_of_an_excluded_route_are_dropped_too(monkeypatch):
    monkeypatch.setattr(coverage, "accessed_routes", lambda z, t: {"/setup.php"})
    monkeypatch.setattr(coverage, "accessed_params", lambda z, t: {"/setup.php": ["create_db"]})
    monkeypatch.setattr(coverage, "enabled_rule_ids", lambda z: set())
    out = coverage.capture("http://zap", "http://app", excluded=[r"(?i).*setup.*"])
    assert out["route_params"] == {}


def test_no_exclusions_leaves_coverage_untouched(monkeypatch):
    monkeypatch.setattr(coverage, "accessed_routes", lambda z, t: {"/a", "/b"})
    monkeypatch.setattr(coverage, "accessed_params", lambda z, t: {"/a": ["x"]})
    monkeypatch.setattr(coverage, "enabled_rule_ids", lambda z: set())
    out = coverage.capture("http://zap", "http://app")
    assert out["routes"] == ["/a", "/b"] and "excluded" not in out


def test_a_malformed_exclusion_does_not_silently_drop_everything(monkeypatch):
    monkeypatch.setattr(coverage, "accessed_routes", lambda z, t: {"/a"})
    monkeypatch.setattr(coverage, "accessed_params", lambda z, t: {})
    monkeypatch.setattr(coverage, "enabled_rule_ids", lambda z: set())
    out = coverage.capture("http://zap", "http://app", excluded=["(["])
    assert out["routes"] == ["/a"]


def test_the_full_probe_reports_where_the_redirects_ended(monkeypatch):
    # Liveness needs the FINAL url: a session that died shows up as a bounce to the login page.
    hops = [{"requestHeader": "GET http://dvwa/index.php HTTP/1.1\r\n",
             "responseHeader": "HTTP/1.1 302 Found\r\n", "responseBody": ""},
            {"requestHeader": "GET http://dvwa/login.php HTTP/1.1\r\n",
             "responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "<form>"}]
    monkeypatch.setattr(coverage, "_api", lambda z, p, params=None, timeout=30.0: {"sendRequest": hops})
    assert coverage.fetch_probe_full("http://zap", "http://dvwa/index.php", {"a": "b"}) == \
        (200, "<form>", "http://dvwa/login.php")
