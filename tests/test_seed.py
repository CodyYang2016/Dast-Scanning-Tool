"""Objective tests for the Phase A seed step.

Oracles: the seed JSON Schema (third-party jsonschema validator) for config loading, and hand-built
fake pages with known-correct liveness answers for prove_auth_live. Neither touches a real browser
or ZAP — the browser-driving parts (capture_session / replay_seeded) are validated by running them.
"""

import json

import jsonschema
import pytest

from authoring.seed import (SeedPreflightError, leading_selectors, load_seed,
                            preflight_login_page)
from runner.replay import SessionDeadError, prove_auth_live

BASE = "http://juice:3000"


def _valid_cfg():
    return {
        "target": {"base_url": BASE, "scope_file": "security/dast/juice-shop/scope.json"},
        "session": {"storage_state": ".secrets/storageState.json"},
        "seed_routes": ["/#/basket", "/#/profile"],
        "deny_actions": ["logout", "delete-account"],
        "exploration": {"max_pages": 50, "max_depth": 4, "time_budget_minutes": 8},
    }


# ---- seed config loading (oracle: seed.schema.json) -------------------------------------

def test_load_seed_accepts_valid_config(tmp_path):
    p = tmp_path / "seed.json"
    p.write_text(json.dumps(_valid_cfg()))
    cfg = load_seed(str(p))
    assert cfg["session"]["storage_state"] == ".secrets/storageState.json"
    assert cfg["seed_routes"] == ["/#/basket", "/#/profile"]


def test_load_seed_minimal_required_only(tmp_path):
    p = tmp_path / "seed.json"
    p.write_text(json.dumps({
        "target": {"base_url": BASE},
        "session": {"storage_state": ".secrets/s.json"},
        "seed_routes": ["/#/basket"],
    }))
    assert load_seed(str(p))["seed_routes"] == ["/#/basket"]


def test_load_seed_rejects_missing_session(tmp_path):
    cfg = _valid_cfg()
    del cfg["session"]
    p = tmp_path / "seed.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(jsonschema.ValidationError):
        load_seed(str(p))


def test_load_seed_rejects_empty_seed_routes(tmp_path):
    cfg = _valid_cfg()
    cfg["seed_routes"] = []
    p = tmp_path / "seed.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(jsonschema.ValidationError):
        load_seed(str(p))


def test_load_seed_rejects_non_json(tmp_path):
    p = tmp_path / "seed.json"
    p.write_text("not: [valid json")
    with pytest.raises(ValueError):
        load_seed(str(p))


# ---- prove_auth_live (oracle: fake pages with known answers) -----------------------------

class FakePage:
    """Minimal page-like: goto returns a response with .status, and .url / .evaluate are stubbed."""
    def __init__(self, *, landed_url, status=200, token="jwt"):
        self._landed = landed_url
        self._status = status
        self._token = token

    def goto(self, url, wait_until=None):
        return type("Resp", (), {"status": self._status})()

    @property
    def url(self):
        return self._landed

    def evaluate(self, _expr):
        return bool(self._token)


def test_prove_auth_live_alive_on_authenticated_route():
    page = FakePage(landed_url=BASE + "/#/basket", status=200, token="jwt")
    res = prove_auth_live(page, BASE, "/#/basket", token_check="window.localStorage.getItem('token')")
    assert res["alive"] is True


def test_prove_auth_live_dead_on_login_redirect():
    page = FakePage(landed_url=BASE + "/#/login", status=200, token="jwt")
    res = prove_auth_live(page, BASE, "/#/basket")
    assert res["alive"] is False and "login" in res["reason"]


def test_prove_auth_live_dead_on_401():
    page = FakePage(landed_url=BASE + "/#/basket", status=401, token="jwt")
    res = prove_auth_live(page, BASE, "/#/basket")
    assert res["alive"] is False and "401" in res["reason"]


def test_prove_auth_live_dead_when_target_unreachable():
    # ZAP answers 502 when it cannot reach the target (app down). The seeded localStorage token
    # is still present on that error page, so the token check alone would say "alive". Any
    # non-2xx/3xx on the seed route is dead — fail closed, never "explore" a dead app.
    page = FakePage(landed_url=BASE + "/#/basket", status=502, token="jwt")
    res = prove_auth_live(page, BASE, "/#/basket", token_check="window.localStorage.getItem('token')")
    assert res["alive"] is False and "502" in res["reason"]


def test_prove_auth_live_dead_when_no_response():
    class NoResp(FakePage):
        def goto(self, url, wait_until=None):
            return None
    page = NoResp(landed_url=BASE + "/#/basket", token="jwt")
    res = prove_auth_live(page, BASE, "/#/basket", token_check="window.localStorage.getItem('token')")
    assert res["alive"] is False


def test_prove_auth_live_dead_when_token_missing():
    page = FakePage(landed_url=BASE + "/#/basket", status=200, token="")
    res = prove_auth_live(page, BASE, "/#/basket", token_check="window.localStorage.getItem('token')")
    assert res["alive"] is False and "token" in res["reason"]


def test_session_dead_error_is_raisable():
    with pytest.raises(SessionDeadError):
        raise SessionDeadError("expired")

# ---- login preflight (oracle: fake login pages with known selector sets) -----------------

STEPS = [
    {"action": "fill", "selector": "input[name=username]", "value": "identifier"},
    {"action": "fill", "selector": "input[name=password]", "value": "secret"},
    {"action": "click", "selector": "button[type=submit]"},
]
LOGIN = "http://webgoat:8083/WebGoat/login"


class FakeLoginPage:
    """Page-like whose DOM is a known selector set; wait_for_selector fails for anything else."""

    def __init__(self, selectors, *, landed_url=LOGIN, title="Login Page"):
        self._selectors = set(selectors)
        self._landed = landed_url
        self._title = title

    @property
    def url(self):
        return self._landed

    def title(self):
        return self._title

    def wait_for_selector(self, selector, state=None, timeout=None):
        if selector not in self._selectors:
            raise TimeoutError(f"Timeout {timeout}ms exceeded waiting for {selector}")
        return object()


def test_preflight_passes_when_the_login_form_is_rendered():
    page = FakeLoginPage({"input[name=username]", "input[name=password]"})
    preflight_login_page(page, LOGIN, 200, STEPS, timeout_ms=1)


def test_preflight_names_the_missing_selector_instead_of_timing_out_on_fill():
    # The WebGoat/DVWA failure mode: the app answers, but the page holds no login form.
    page = FakeLoginPage(set(), title="Setup DVWA")
    with pytest.raises(SeedPreflightError) as exc:
        preflight_login_page(page, LOGIN, 200, STEPS, timeout_ms=1)
    msg = str(exc.value)
    assert "input[name=username]" in msg and "input[name=password]" in msg
    assert "Setup DVWA" in msg and LOGIN in msg


def test_preflight_reports_a_redirect_to_another_page():
    page = FakeLoginPage(set(), landed_url="http://dvwa/setup.php")
    with pytest.raises(SeedPreflightError) as exc:
        preflight_login_page(page, LOGIN, 200, STEPS, timeout_ms=1)
    assert "http://dvwa/setup.php" in str(exc.value)


def test_preflight_rejects_an_error_status_before_touching_the_dom():
    page = FakeLoginPage({"input[name=username]", "input[name=password]"})
    with pytest.raises(SeedPreflightError) as exc:
        preflight_login_page(page, LOGIN, 502, STEPS, timeout_ms=1)
    assert "502" in str(exc.value)


def test_preflight_tolerates_an_unknown_status():
    # A data: or file: navigation has no response; absence of a status is not a failure.
    page = FakeLoginPage({"input[name=username]", "input[name=password]"})
    preflight_login_page(page, LOGIN, None, STEPS, timeout_ms=1)


def test_leading_selectors_stops_at_the_first_non_fill_step():
    assert leading_selectors(STEPS) == ["input[name=username]", "input[name=password]"]


def test_leading_selectors_ignores_fields_reached_after_a_navigation():
    # Microsoft-style two-page login: the password field does not exist until the first submit,
    # so asserting it up front would fail a working config.
    steps = [
        {"action": "fill", "selector": "#user", "value": "identifier"},
        {"action": "click", "selector": "#next"},
        {"action": "fill", "selector": "#pass", "value": "secret"},
    ]
    assert leading_selectors(steps) == ["#user"]


def test_leading_selectors_of_a_click_only_flow_is_empty():
    assert leading_selectors([{"action": "click", "selector": "#sso"}]) == []


def test_preflight_lets_a_non_timeout_page_fault_propagate():
    # An invalid selector in app.yaml is a config fault, not a login form that failed to render;
    # reporting it as the latter would send the operator looking at the wrong thing.
    class BadSelectorPage(FakeLoginPage):
        def wait_for_selector(self, selector, state=None, timeout=None):
            raise ValueError(f"Unexpected token while parsing selector: {selector}")

    with pytest.raises(ValueError):
        preflight_login_page(BadSelectorPage(set()), LOGIN, 200, STEPS, timeout_ms=1)
