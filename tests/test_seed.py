"""Objective tests for the Phase A seed step.

Oracles: the seed JSON Schema (third-party jsonschema validator) for config loading, and hand-built
fake pages with known-correct liveness answers for prove_auth_live. Neither touches a real browser
or ZAP — the browser-driving parts (capture_session / replay_seeded) are validated by running them.
"""

import json

import jsonschema
import pytest

from authoring.seed import load_seed
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


def test_prove_auth_live_dead_when_token_missing():
    page = FakePage(landed_url=BASE + "/#/basket", status=200, token="")
    res = prove_auth_live(page, BASE, "/#/basket", token_check="window.localStorage.getItem('token')")
    assert res["alive"] is False and "token" in res["reason"]


def test_session_dead_error_is_raisable():
    with pytest.raises(SessionDeadError):
        raise SessionDeadError("expired")
