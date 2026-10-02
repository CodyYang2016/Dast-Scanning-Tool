"""DOM-XSS in its own bounded pass (W6-3).

Rule 40026 drives a real browser per payload. Enabled inside the main scan on DVWA it ran ZAP
out of memory six minutes in (exit 137) and took the whole scan with it. Run separately — only
40026, one thread so one browser at a time, its own time limit, AFTER the main results are
safe — a failure costs the DOM pass, not the scan.
"""


from runner import scan as scan_mod


class Zap:
    def __init__(self, fail_on=None, threads="4"):
        self.calls, self.fail_on, self.threads = [], fail_on, threads

    def __call__(self, z, path, params=None, timeout=30.0):
        self.calls.append((path, dict(params or {})))
        if self.fail_on and self.fail_on in path:
            raise scan_mod.ZapUnavailableError("ZAP stopped responding")
        if path.endswith("optionThreadPerHost/"):
            return {"ThreadPerHost": self.threads}
        if path.endswith("newContext/"):
            return {"contextId": "9"}
        if path.endswith("ascan/action/scan/"):
            return {"scan": "5"}
        if path.endswith("ascan/view/status/"):
            return {"status": "100"}
        if path.endswith("scanProgress/"):
            return {"scanProgress": ["http://dvwa", {"HostProcess": [
                {"Plugin": ["Cross Site Scripting (DOM Based)", "40026", "release", "Complete",
                            "12", "0", "1"]}]}]}
        if path.endswith("alert/view/alerts/"):
            return {"alerts": [{"pluginId": "40026", "url": "http://dvwa/vulnerabilities/xss_d/"},
                               {"pluginId": "10020", "url": "http://dvwa/"}]}
        return {}


def _paths(z):
    return [p for p, _ in z.calls]


def test_only_the_dom_rule_runs_one_browser_at_a_time_on_its_own_clock(monkeypatch):
    z = Zap(); monkeypatch.setattr(scan_mod, "_api", z)
    scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5)
    params = dict(z.calls)
    assert params["/JSON/ascan/action/disableAllScanners/"] == {}
    assert {"ids": "40026"} in [q for p, q in z.calls if p.endswith("enableScanners/")]
    assert {"Integer": 1} in [q for p, q in z.calls if p.endswith("setOptionThreadPerHost/")]
    assert params["/JSON/ascan/action/setOptionMaxScanDurationInMins/"] == {"Integer": 5}


def test_the_thread_count_is_put_back_afterwards(monkeypatch):
    # ZAP's options are daemon-global: left at 1, the NEXT scan would crawl along.
    z = Zap(threads="4"); monkeypatch.setattr(scan_mod, "_api", z)
    scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5)
    thread_sets = [q for p, q in z.calls if p.endswith("setOptionThreadPerHost/")]
    assert thread_sets[-1] == {"Integer": 4}


def test_it_is_bounded_by_a_context_and_returns_only_dom_alerts(monkeypatch):
    from runner import coverage
    z = Zap(); monkeypatch.setattr(scan_mod, "_api", z); monkeypatch.setattr(coverage, "_api", z)
    out = scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], ["(?i).*setup.*"], max_min=5)
    assert ("/JSON/ascan/action/scan/", {"url": "http://dvwa", "recurse": "true",
                                         "contextId": "9"}) in z.calls
    assert "/JSON/context/action/removeContext/" in _paths(z)
    assert [a["pluginId"] for a in out["alerts"]] == ["40026"]
    assert out["record"] == {"state": "Complete", "requests": 12, "alerts": 1, "error": None}


def test_named_routes_narrow_it(monkeypatch):
    z = Zap(); monkeypatch.setattr(scan_mod, "_api", z)
    scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5,
                          routes=["/vulnerabilities/xss_d/"])
    scans = [q for p, q in z.calls if p == "/JSON/ascan/action/scan/"]
    assert scans == [{"url": "http://dvwa/vulnerabilities/xss_d/", "recurse": "false",
                      "contextId": "9"}]


def test_a_dom_pass_that_kills_zap_is_recorded_not_raised(monkeypatch):
    z = Zap(fail_on="ascan/view/status/"); monkeypatch.setattr(scan_mod, "_api", z)
    monkeypatch.setattr(scan_mod.time, "sleep", lambda s: None)
    out = scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5)
    assert out["alerts"] == [] and "ZAP stopped responding" in out["record"]["error"]


def test_config_and_contract():
    from authoring import appconfig
    assert appconfig.dom_xss({"scan": {}}) == {"enabled": False, "max_min": 5, "routes": []}
    assert appconfig.dom_xss({"scan": {"dom_xss": {"enabled": True}}})["enabled"] is True


def test_the_rule_set_is_put_back_afterwards(monkeypatch):
    # Coverage reads ZAP's ENABLED rules after the scan; left with only 40026 enabled, the
    # scan would claim it ran one rule.
    class Z(Zap):
        def __call__(self, z, path, params=None, timeout=30.0):
            if path.endswith("ascan/view/scanners/"):
                self.calls.append((path, {}))
                return {"scanners": [{"id": "40018", "enabled": "true"},
                                     {"id": "40012", "enabled": "true"},
                                     {"id": "40026", "enabled": "false"}]}
            return super().__call__(z, path, params, timeout)
    z = Z(); monkeypatch.setattr(scan_mod, "_api", z)
    scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5)
    enables = [q for p, q in z.calls if p.endswith("enableScanners/")]
    assert enables[-1] == {"ids": "40018,40012"}


def test_the_pass_carries_the_scans_session_for_its_browsers(monkeypatch):
    # Measured on DVWA: without it, 159 of the rule's requests to the DOM-XSS page were
    # redirected to login.php — the rule tested the login page and found nothing.
    from runner import session_refresh
    installed, removed = [], []
    monkeypatch.setattr(session_refresh, "install",
                        lambda z, jar, bearer=None, initiators=None: installed.append((jar, initiators)))
    monkeypatch.setattr(session_refresh, "remove", lambda z: removed.append(1))
    z = Zap(); monkeypatch.setattr(scan_mod, "_api", z)
    scan_mod.dom_xss_pass("http://zap", "http://dvwa", ["dvwa"], [], max_min=5,
                          session={"PHPSESSID": "abc", "security": "low"})
    assert installed == [({"PHPSESSID": "abc", "security": "low"}, "")]     # every initiator
    assert removed == [1]


def test_rules_can_cover_every_initiator():
    from runner.session_refresh import rules
    assert rules({"a": "b"}, initiators="")[0]["initiators"] == ""
