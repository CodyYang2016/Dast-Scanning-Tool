"""Login-only hosts: reachable for authentication, never attacked (scope.traverse).

An SSO login passes through an identity provider. Listing it in `allow` would let ZAP spider and
attack it; leaving it out blocks the login. A traverse origin is the third answer: the browser
may reach it, ZAP forwards it without recording it (measured: `excludeFromProxy` traffic loads
normally and leaves nothing in the site tree), and nothing ever targets it.
"""

import pytest

from runner.scope_guard import ScopeGuard

IDP = "https://idp.corp.example"
SCOPE = {"app_id": "a", "environment_class": "test", "target_fqdn": "x",
         "fqdn_allow_list": ["https://app.test.internal"], "traverse_list": [IDP],
         "fqdn_deny_list": ["*.evil.example"]}


class _Route:
    def __init__(self, url):
        self.request = type("R", (), {"url": url})()
        self.done = None
    def continue_(self): self.done = "continue"
    def abort(self): self.done = "abort"
    def fulfill(self, **k): self.done = "fulfill"


def test_the_browser_may_reach_a_traverse_origin_and_it_is_recorded_as_such():
    g = ScopeGuard(SCOPE)
    r = _Route(IDP + "/oauth2/authorize?client_id=x")
    g.route_handler(r)
    assert r.done == "continue" and g.ok
    assert g.decisions[-1].reason.startswith("traverse")


def test_only_the_exact_origin_is_traversable():
    g = ScopeGuard(SCOPE)
    for url in ("http://idp.corp.example/x", "https://idp.corp.example:8443/x",
                "https://other.corp.example/x"):
        r = _Route(url); g.route_handler(r)
        assert r.done == "abort"
    assert not g.ok


def test_the_deny_list_wins_over_traverse():
    g = ScopeGuard({**SCOPE, "traverse_list": ["https://login.evil.example"]})
    r = _Route("https://login.evil.example/"); g.route_handler(r)
    assert r.done == "abort"


def test_a_redirect_into_the_idp_is_how_sso_works():
    class Req:
        def __init__(self, url, src=None): self.url, self.redirected_from = url, src
    g = ScopeGuard(SCOPE)
    g.on_request(Req(IDP + "/login", Req("https://app.test.internal/")))
    assert g.ok
    g.on_request(Req("https://elsewhere.example/", Req(IDP + "/login")))
    assert not g.ok


def test_exploration_never_targets_a_traverse_origin():
    from runner.action_policy import validate_action
    d = validate_action({"action": "navigate", "target": {"path": IDP + "/profile"}}, SCOPE)
    assert not d.allowed and "login-only" in d.reason


def test_preflight_rules():
    from runner.env_registry import Registry
    from runner.preflight import PreflightError, check_scope
    reg = Registry(prod_host_patterns=["*.prod.*"],
                   hosts={"app.test.internal": "test"})
    # A production IdP is normal, and never attacked: not subject to the registry.
    check_scope({**SCOPE, "traverse_list": ["https://login.prod.example"]}, registry=reg)
    with pytest.raises(PreflightError, match="origin"):
        check_scope({**SCOPE, "traverse_list": ["idp.corp.example"]}, registry=reg)
    with pytest.raises(PreflightError, match="either attacked or traversed"):
        check_scope({**SCOPE, "traverse_list": ["https://app.test.internal"]}, registry=reg)


def test_zap_is_told_to_forward_but_not_record_them(monkeypatch):
    from runner import scan as scan_mod
    calls = []
    monkeypatch.setattr(scan_mod, "_api", lambda z, p, params=None, timeout=30.0:
                        calls.append((p, params)) or {})
    rx = scan_mod.traverse_regexes([IDP])
    scan_mod.exclude_traverse("http://zap", [IDP])
    assert calls == [("/JSON/core/action/excludeFromProxy/", {"regex": rx[0]})]
    import re
    assert re.match(rx[0], IDP + "/oauth2/x") and not re.match(rx[0], "https://idp.corp.example.evil.com/")


def test_findings_on_a_traverse_origin_are_dropped_and_counted():
    from runner.main import drop_traverse_alerts
    alerts = [{"url": IDP + "/login", "pluginId": "1"},
              {"url": "https://app.test.internal/a", "pluginId": "2"}]
    kept, dropped = drop_traverse_alerts(alerts, [IDP])
    assert [a["pluginId"] for a in kept] == ["2"] and dropped == 1


def test_config_carries_traverse_into_the_scope():
    from authoring import appconfig
    cfg = {"app_id": "a", "environment_class": "test", "base_url": "https://app.test.internal",
           "scope": {"allow": ["https://app.test.internal"], "traverse": [IDP]}}
    assert appconfig.scope_from_config(cfg)["traverse_list"] == [IDP]


def test_an_older_bundle_takes_traverse_from_app_yaml_and_is_still_checked():
    from runner.main import with_exclusions
    from runner.preflight import PreflightError
    scope = {"fqdn_allow_list": ["https://app.test.internal"]}
    assert with_exclusions(scope, {"scope": {"traverse": [IDP]}})["traverse_list"] == [IDP]
    with pytest.raises(PreflightError):
        with_exclusions(scope, {"scope": {"traverse": ["https://app.test.internal"]}})


def test_a_failure_after_a_block_is_reported_as_the_scope_violation():
    from runner.replay import scope_first
    from runner.scope_guard import ScopeViolation
    g = ScopeGuard(SCOPE)
    scope_first(g)                                   # nothing blocked: the caller re-raises
    g.check("http://webgoat:8083/WebGoat/")
    with pytest.raises(ScopeViolation, match="webgoat"):
        scope_first(g)
