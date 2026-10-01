"""Objective, TEST-FIRST suite for the request-boundary scope guard (FR-S4 / NFR-4).

Frozen BEFORE runner/scope_guard.py exists — the implementation must conform. This is the
second, independent safety layer (D2), so it's tested adversarially. Oracle: hand-defined
scope + URLs with known allow/block outcomes (host/set logic), plus fake Playwright route
objects for the interceptor wiring.

See docs/junior_engineer/runner_design.md §8 for the frozen API and criteria.
"""

import pytest

# Import target does not exist yet (test-first): red at collection until implemented.
from runner.scope_guard import Decision, ScopeGuard, ScopeViolation, host_of

SCOPE = {
    "app_id": "juice-shop",
    "environment_class": "dev",
    "target_fqdn": "localhost",
    "fqdn_allow_list": ["localhost"],
    "fqdn_deny_list": ["*.google-analytics.com"],
    "avoid_action_list": [],
}


def guard(**overrides):
    scope = {**SCOPE, **overrides}
    return ScopeGuard(scope)


class FakeRequest:
    def __init__(self, url):
        self.url = url


class FakeRoute:
    def __init__(self, url):
        self.request = FakeRequest(url)
        self.continued = False
        self.aborted = False

    def continue_(self):
        self.continued = True

    def abort(self):
        self.aborted = True


# ---- pure decision logic (oracle: hand-defined scope + known outcomes) -------------------

def test_allowlisted_host_allowed():
    assert guard().check("http://localhost/").allowed is True


def test_non_allowlisted_host_blocked():
    assert guard().check("http://evil.example.com/").allowed is False


def test_denylist_wildcard_blocks():
    assert guard().check("https://www.google-analytics.com/collect").allowed is False


def test_deny_precedence_over_allow():
    g = guard(fqdn_allow_list=["x.com"], fqdn_deny_list=["x.com"])
    assert g.check("http://x.com/").allowed is False


def test_port_ignored():
    assert guard().check("http://localhost:3000/rest/products/search").allowed is True


def test_scheme_ignored():
    assert guard().check("https://localhost/").allowed is True


def test_host_case_insensitive():
    assert guard().check("http://LOCALHOST/").allowed is True


def test_no_host_blocked():
    # No parseable host -> fail closed.
    assert guard().check("/relative/path").allowed is False


def test_host_of_strips_port_and_lowercases():
    assert host_of("http://LocalHost:8080/x") == "localhost"


# ---- block / log / fail bookkeeping (D4 / FR-S4) ----------------------------------------

def test_check_records_decision():
    g = guard()
    g.check("http://localhost/")
    assert len(g.decisions) == 1


def test_violation_recorded_and_ok_false():
    g = guard()
    g.check("http://localhost/")          # allowed
    g.check("http://evil.example.com/")   # blocked
    assert len(g.violations) == 1
    assert g.ok is False


def test_raise_if_violated():
    g = guard()
    g.check("http://localhost/")
    g.raise_if_violated()  # clean so far -> no raise
    g.check("http://evil.example.com/")
    with pytest.raises(ScopeViolation):
        g.raise_if_violated()


def test_decision_has_structured_fields():
    d = guard().check("http://evil.example.com/")
    assert isinstance(d, Decision)
    assert d.url == "http://evil.example.com/"
    assert d.host == "evil.example.com"
    assert d.allowed is False
    assert d.reason  # non-empty explanation (NFR-4)


# ---- Playwright route wiring (tested with a fake route) ----------------------------------

def test_route_handler_allows():
    g = guard()
    route = FakeRoute("http://localhost/rest/products/search")
    g.route_handler(route)
    assert route.continued is True and route.aborted is False


def test_route_handler_blocks():
    g = guard()
    route = FakeRoute("http://evil.example.com/")
    g.route_handler(route)
    assert route.aborted is True and route.continued is False


def test_injected_out_of_scope_blocked():
    # FR-S4 acceptance: a deliberately injected out-of-allow-list request is blocked, recorded,
    # and fails the scan.
    g = guard()
    route = FakeRoute("http://attacker.test/steal")
    g.route_handler(route)
    assert route.aborted is True
    assert len(g.violations) == 1
    with pytest.raises(ScopeViolation):
        g.raise_if_violated()


# ---- phase-split mode (enforce vs discovery — open question 5 / KI4) ----------------------

def test_default_mode_is_enforce():
    assert ScopeGuard(SCOPE).mode == "enforce"


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        ScopeGuard(SCOPE, mode="bogus")


def test_discovery_still_blocks_out_of_scope():
    # block-and-continue: the request is STILL blocked + recorded, just non-fatal.
    g = ScopeGuard(SCOPE, mode="discovery")
    route = FakeRoute("http://evil.example.com/")
    g.route_handler(route)
    assert route.aborted is True
    assert len(g.violations) == 1


def test_discovery_finalize_does_not_raise():
    g = ScopeGuard(SCOPE, mode="discovery")
    g.check("http://evil.example.com/")   # a violation is present
    g.finalize()                          # discovery: block-and-continue, must NOT raise


def test_enforce_finalize_raises_on_violation():
    g = ScopeGuard(SCOPE, mode="enforce")
    g.check("http://evil.example.com/")
    with pytest.raises(ScopeViolation):
        g.finalize()


def test_enforce_finalize_clean_does_not_raise():
    g = ScopeGuard(SCOPE, mode="enforce")
    g.check("http://localhost/")
    g.finalize()  # no violations -> no raise


def test_host_of_never_raises_on_malformed_url():
    # urlparse raises ValueError("Invalid IPv6 URL") on a bracket in the netloc. A malformed URL
    # must read as "no host" (-> blocked, fail closed), never crash the guard or the action policy.
    assert host_of("http://juice:3000[/#/about]") is None
    assert host_of("http://[::1") is None


def test_malformed_url_is_blocked_not_crashed():
    d = guard().check("http://juice:3000[/#/about]")
    assert d.allowed is False and d.host is None


# ---- redirect chains (KI2) ----------------------------------------------------------------
# Measured with Playwright: page.route sees only the FIRST request of a redirect chain; the
# browser followed a 302 to another origin without the route handler being called. Each hop is
# now checked from the context's request events — after the fact, since it cannot be blocked
# without taking the request out of ZAP's path, so an off-scope hop fails the scan instead.

class _Req:
    def __init__(self, url, redirected_from=None):
        self.url, self.redirected_from = url, redirected_from


def _guard(mode="enforce"):
    from runner.scope_guard import ScopeGuard
    return ScopeGuard({"fqdn_allow_list": ["https://app.internal"]}, mode=mode)


def test_an_off_scope_redirect_hop_is_a_violation():
    import pytest
    from runner.scope_guard import ScopeViolation
    g = _guard()
    g.on_request(_Req("https://evil.example/x", _Req("https://app.internal/r")))
    assert not g.ok and "redirect from https://app.internal/r" in g.violations[0].reason
    with pytest.raises(ScopeViolation):
        g.finalize()


def test_an_in_scope_redirect_hop_is_fine_and_first_requests_are_left_to_route():
    g = _guard()
    g.on_request(_Req("https://app.internal/home", _Req("https://app.internal/r")))
    g.on_request(_Req("https://evil.example/x"))          # not a redirect: page.route's job
    assert g.ok


def test_discovery_mode_logs_a_redirect_violation_without_failing():
    g = _guard("discovery")
    g.on_request(_Req("https://evil.example/x", _Req("https://app.internal/r")))
    assert not g.ok
    g.finalize()                                           # does not raise


def test_attach_wires_both_hooks():
    calls = {}

    class Ctx:
        def on(self, ev, fn): calls["ctx"] = ev

    class Page:
        context = Ctx()
        def route(self, pattern, fn): calls["route"] = pattern

    _guard().attach(Page())
    assert calls == {"route": "**/*", "ctx": "request"}
