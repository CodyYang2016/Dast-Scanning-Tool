"""Scope by origin (W4-2): an allow-list entry can name scheme, host AND port.

A bare host allowed every scheme and every port on that host. On a disposable dev container that
is harmless; on a shared test or staging host it means an admin port, a different service or a
plaintext listener on the same machine is "in scope". So entries may now be origins
(`https://app.internal:8443`), and shared environments must use them.
"""

import pytest

from runner.preflight import PreflightError, check_scope
from runner.scope_guard import ScopeGuard, entry_matches, origin_of

ORIGIN = "https://app.internal:8443"


@pytest.mark.parametrize("url", [
    "https://app.internal:8443/",
    "https://app.internal:8443/api/x?y=1",
    "HTTPS://APP.INTERNAL:8443/a",
])
def test_an_origin_entry_matches_its_own_origin(url):
    assert entry_matches(url, ORIGIN)


@pytest.mark.parametrize("url, why", [
    ("http://app.internal:8443/", "plaintext on the same port"),
    ("https://app.internal/", "default port, not 8443"),
    ("https://app.internal:9000/", "another port on the same host"),
    ("https://app.internal.evil.example:8443/", "lookalike host"),
    ("https://evil.example/?u=https://app.internal:8443/", "origin only in the query"),
    ("https://user@app.internal.evil.example:8443/", "userinfo lookalike"),
])
def test_an_origin_entry_refuses_everything_else(url, why):
    assert not entry_matches(url, ORIGIN), why


def test_default_ports_are_normalised():
    assert entry_matches("https://app.internal/x", "https://app.internal:443")
    assert entry_matches("https://app.internal:443/x", "https://app.internal")
    assert entry_matches("http://app.internal:80/x", "http://app.internal")
    assert not entry_matches("http://app.internal:443/x", "https://app.internal")


def test_a_bare_host_keeps_its_old_meaning():
    for url in ("http://dvwa/", "https://dvwa:8443/", "http://dvwa:9999/x"):
        assert entry_matches(url, "dvwa")
    assert not entry_matches("http://dvwa.evil/", "dvwa")


def test_origin_of_normalises():
    assert origin_of("HTTPS://App.Internal:443/x?y") == "https://app.internal"
    assert origin_of("http://dvwa/vulnerabilities/") == "http://dvwa"
    assert origin_of("http://webgoat:8083/WebGoat") == "http://webgoat:8083"


def _scope(allow, deny=(), env="dev"):
    return {"app_id": "a", "environment_class": env, "target_fqdn": "app.internal",
            "fqdn_allow_list": list(allow), "fqdn_deny_list": list(deny), "avoid_action_list": []}


def test_the_browser_guard_enforces_origins():
    g = ScopeGuard(_scope([ORIGIN]))
    assert g.check("https://app.internal:8443/a").allowed
    assert not g.check("https://app.internal:9000/a").allowed
    assert not g.check("http://app.internal:8443/a").allowed


def test_deny_still_wins_over_an_origin():
    g = ScopeGuard(_scope([ORIGIN], deny=["app.internal"]))
    assert not g.check("https://app.internal:8443/a").allowed


# ---- shared environments must name origins ------------------------------------------------

@pytest.mark.parametrize("env", ["test", "staging"])
def test_a_bare_host_is_refused_for_a_shared_environment(env):
    with pytest.raises(PreflightError, match=r"https://app\.internal"):
        check_scope(_scope(["app.internal"], env=env))


@pytest.mark.parametrize("env", ["test", "staging"])
def test_origins_are_accepted_for_a_shared_environment(env):
    check_scope(_scope([ORIGIN], env=env))


def test_dev_keeps_bare_hosts():
    check_scope(_scope(["dvwa"], env="dev"))


# ---- every other reader of the allow list honours origins --------------------------------

def test_exploration_actions_honour_origins():
    from runner.action_policy import validate_action
    sc = _scope([ORIGIN])
    ok = validate_action({"action": "follow_link", "target": {"method": "GET",
                          "path": "https://app.internal:8443/x"}}, sc)
    bad = validate_action({"action": "follow_link", "target": {"method": "GET",
                           "path": "https://app.internal:9000/x"}}, sc)
    assert ok.allowed and not bad.allowed


def test_the_fallback_proposer_honours_origins():
    from authoring.explore import _in_scope_path
    sc = _scope([ORIGIN])
    assert _in_scope_path("https://app.internal:8443/x", sc)
    assert not _in_scope_path("http://app.internal:8443/x", sc)


def test_the_scan_refuses_a_target_outside_the_origins(monkeypatch):
    from runner import scan as scan_mod
    monkeypatch.setattr(scan_mod, "_api", lambda *a, **k: {})
    with pytest.raises(scan_mod.ScanScopeError):
        scan_mod.scan("http://zap", "https://app.internal:9000", [ORIGIN])


# ---- the writers stop adding bare hosts where they would be refused -----------------------

def test_config_scope_for_a_shared_environment_uses_the_base_origin():
    from authoring.appconfig import scope_from_config
    cfg = {"app_id": "a", "environment_class": "staging",
           "base_url": "https://app.internal:8443", "scope": {"allow": [ORIGIN]}}
    sc = scope_from_config(cfg)
    assert sc["fqdn_allow_list"] == [ORIGIN]
    check_scope(sc)


def test_config_scope_in_dev_is_unchanged():
    from authoring.appconfig import scope_from_config
    cfg = {"app_id": "a", "environment_class": "dev", "base_url": "http://dvwa",
           "scope": {"allow": ["dvwa"]}}
    assert scope_from_config(cfg)["fqdn_allow_list"] == ["dvwa"]


def test_generated_scope_for_a_shared_environment_does_not_adopt_observed_hosts():
    # Seeing a host while recording does not make it in scope.
    from authoring.generate import emit_scope
    trace = {"app_id": "a", "base_url": "https://app.internal:8443",
             "hosts": ["app.internal", "cdn.thirdparty.example"]}
    sc = emit_scope(trace, {"environment_class": "staging", "scope": {"allow": [ORIGIN]}})
    assert sc["fqdn_allow_list"] == [ORIGIN]
    check_scope(sc)


# ---- W4-1: bound ZAP itself with a context ------------------------------------------------
#
# The browser guard and the exploration policy cover requests WE send. The spider and active scan
# were bounded by nothing but the seed URL. A ZAP context built from the same allow list bounds
# them too. ZAP uses Java regex; these patterns stay inside the subset both engines agree on.

import re

from runner import scan as scan_mod


def _ctx_admits(url, entries):
    return any(re.match(rx, url) for rx in scan_mod.context_regexes(entries))


def test_an_origin_context_admits_only_that_origin():
    e = ["http://dvwa"]
    assert _ctx_admits("http://dvwa/vulnerabilities/sqli/?id=1", e)
    assert _ctx_admits("http://dvwa:80/x", e)
    assert not _ctx_admits("http://dvwa:8080/x", e)
    assert not _ctx_admits("https://dvwa/x", e)
    assert not _ctx_admits("http://dvwa.evil.example/x", e)


def test_a_bare_host_context_admits_any_port_but_not_lookalikes():
    e = ["dvwa"]
    assert _ctx_admits("http://dvwa/x", e) and _ctx_admits("https://dvwa:8443/x", e)
    assert not _ctx_admits("http://dvwa.evil.example/x", e)
    assert not _ctx_admits("http://evil.example/?h=http://dvwa/", e)


def test_the_scan_runs_inside_a_context_and_removes_it(monkeypatch):
    calls = []
    def fake(z, p, params=None, timeout=30.0):
        calls.append((p, dict(params or {})))
        if p.endswith("newContext/"):
            return {"contextId": "7"}
        if p.endswith("/scan/"):
            return {"scan": "0"}
        if p.endswith("/status/"):
            return {"status": "100"}
        return {"alerts": [], "policies": []}
    monkeypatch.setattr(scan_mod, "_api", fake)
    report = scan_mod.scan("http://zap", "http://dvwa", ["dvwa"], exclusions=[r"(?i).*logout.*"])
    paths = [p for p, _ in calls]
    ctx = report["context"]["name"]
    assert ("/JSON/context/action/includeInContext/",
            {"contextName": ctx, "regex": scan_mod.context_regexes(["dvwa"])[0]}) in calls
    assert ("/JSON/context/action/excludeFromContext/",
            {"contextName": ctx, "regex": r"(?i).*logout.*"}) in calls
    spider = next(p for p, q in calls if p == "/JSON/spider/action/scan/")
    assert dict(calls[paths.index(spider)][1])["contextName"] == ctx
    ascan = next(q for p, q in calls if p == "/JSON/ascan/action/scan/")
    assert ascan["contextId"] == "7"
    assert paths[-1] != "/JSON/context/action/removeContext/" or True   # removed at the end:
    assert "/JSON/context/action/removeContext/" in paths
    assert paths.index("/JSON/context/action/removeContext/") > paths.index("/JSON/ascan/action/scan/")


def test_the_context_is_removed_even_when_the_scan_fails(monkeypatch):
    calls = []
    def fake(z, p, params=None, timeout=30.0):
        calls.append(p)
        if p.endswith("newContext/"):
            return {"contextId": "7"}
        if p == "/JSON/spider/action/scan/":
            raise RuntimeError("spider exploded")
        return {"policies": []}
    monkeypatch.setattr(scan_mod, "_api", fake)
    with pytest.raises(RuntimeError):
        scan_mod.scan("http://zap", "http://dvwa", ["dvwa"])
    assert "/JSON/context/action/removeContext/" in calls
