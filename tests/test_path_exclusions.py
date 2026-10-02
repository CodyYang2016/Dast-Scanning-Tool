"""Per-app endpoint exclusions (W4-5): paths the scanner must never touch, by path pattern.

`avoid_actions` are substrings — fine for "logout", too blunt for "/api/payments/". A path
pattern names an endpoint and everything beneath it, and is enforced everywhere at once: ZAP's
spider and active scan, the per-scan ZAP context, and exploration.
"""

import re

import pytest

from runner.scope_guard import path_exclusion_regex, path_excluded


@pytest.mark.parametrize("pattern,url,hit", [
    ("/api/payments", "http://app/api/payments", True),
    ("/api/payments", "https://app:8443/api/payments/42?x=1", True),
    ("/api/payments/", "http://app/api/payments/42", True),           # trailing / = beneath
    ("/api/payments", "http://app/api/paymentsx", False),            # segment boundary
    ("/api/payments", "http://app/x?next=/api/payments", False),     # not in a query string
    ("/api/*/delete", "http://app/api/Users/delete", True),
    ("/api/*/delete", "http://app/api/Users/7/delete", False),       # * stays in one segment
    ("/api/*/delete", "/api/{id}/delete", True),                     # route form (our side)
    ("/notify", "/notify", True),
    ("/notify", "/notify/sms", True),
    ("/Admin/Reset", "http://app/admin/reset", True),               # case-insensitive: safer
])
def test_path_patterns(pattern, url, hit):
    assert bool(re.match(path_exclusion_regex(pattern), url)) is hit
    assert path_excluded(url, [pattern]) is hit


def test_the_root_is_refused_as_a_pattern():
    with pytest.raises(ValueError):
        path_exclusion_regex("/")
    with pytest.raises(ValueError):
        path_exclusion_regex("*")


def test_a_pattern_must_be_a_path():
    with pytest.raises(ValueError):
        path_exclusion_regex("payments")


def test_scan_exclusions_include_the_paths():
    from runner.scan import exclusion_regexes
    rx = exclusion_regexes(["logout"], "/login.php", paths=["/api/payments"])
    assert any(re.match(r, "http://app/api/payments/1") for r in rx)
    assert any(re.match(r, "http://app/logout") for r in rx)


def test_exploration_refuses_an_excluded_path():
    from runner.action_policy import validate_action
    scope = {"fqdn_allow_list": ["app"], "exclude_paths": ["/api/payments"]}
    d = validate_action({"action": "navigate", "target": {"path": "/api/payments/new"}}, scope)
    assert not d.allowed and "exclude" in d.reason
    ok = validate_action({"action": "navigate", "target": {"path": "/api/products"}}, scope)
    assert ok.allowed


def test_the_scope_carries_the_paths():
    from authoring import appconfig
    cfg = {"app_id": "a", "environment_class": "dev", "base_url": "http://app",
           "scope": {"allow": ["app"], "exclude": ["/api/payments"]}}
    assert appconfig.scope_from_config(cfg)["exclude_paths"] == ["/api/payments"]
    assert appconfig.exclude_paths(cfg) == ["/api/payments"]


def test_contracts_accept_the_field():
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "contracts"
    app = json.loads((root / "app.schema.json").read_text())
    props = app["properties"]["scope"]["properties"]
    assert props["exclude"]["items"]["pattern"] == "^/"
    scope = json.loads((root / "scope.schema.json").read_text())
    assert "exclude_paths" in scope["properties"]


# ---- the browser honours them too ----------------------------------------------------------
# Measured on DVWA: with /vulnerabilities/csrf excluded, ZAP never spidered or attacked it, but
# the replayed walk still visited it and ZAP's passive checks raised 4 findings there. An
# endpoint the app team named as off-limits must not be touched by the browser either. Not a
# scope VIOLATION — a declared decision — so it is refused without failing the scan.

class _Route:
    def __init__(self, url):
        self.request = type("R", (), {"url": url})()
        self.done = None
    def continue_(self): self.done = "continue"
    def abort(self): self.done = "abort"
    def fulfill(self, status=200, **k): self.done = f"fulfill {status}"


def test_the_browser_guard_refuses_an_excluded_path_without_failing_the_scan():
    from runner.scope_guard import ScopeGuard
    g = ScopeGuard({"fqdn_allow_list": ["dvwa"], "exclude_paths": ["/vulnerabilities/csrf"]})
    r = _Route("http://dvwa/vulnerabilities/csrf/")
    g.route_handler(r)
    assert r.done == "fulfill 403" and g.ok          # answered locally: never reaches ZAP
    assert g.excluded == ["http://dvwa/vulnerabilities/csrf/"]
    ok = _Route("http://dvwa/vulnerabilities/sqli/")
    g.route_handler(ok)
    assert ok.done == "continue"
    g.finalize()                                           # does not raise


def test_the_runner_takes_exclusions_from_app_yaml_even_for_an_older_bundle():
    from runner.main import with_exclusions
    scope = {"fqdn_allow_list": ["dvwa"]}                  # generated before scope.exclude existed
    cfg = {"scope": {"exclude": ["/a"]}}
    assert with_exclusions(scope, cfg)["exclude_paths"] == ["/a"]
    assert with_exclusions({**scope, "exclude_paths": ["/b"]}, cfg)["exclude_paths"] == ["/b", "/a"]
