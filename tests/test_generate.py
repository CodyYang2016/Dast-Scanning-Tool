"""TEST-FIRST suite for generate's deterministic pieces (FR-G2/G3/G4 + plan handling).

Frozen before authoring/generate.py exists. The live LLM call is verified with the provided
key at run time; here we pin the pure transforms. Oracles: the committed schemas (scope +
journey), Python's own compiler (rendered flow must compile), and determinism/identity checks.
"""

import ast
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from authoring.appconfig import load_app_config
from authoring.generate import (
    emit_lock,
    emit_manifest,
    emit_scope,
    emit_zap_policy,
    journey_from_trace,
    parse_plan_text,
    render_flow,
    validate_plan,
)

ROOT = Path(__file__).resolve().parent.parent
SCOPE_SCHEMA = ROOT / "contracts" / "scope.schema.json"
JOURNEY_SCHEMA = ROOT / "contracts" / "journey.schema.json"

TRACE = {
    "app_id": "juice-shop",
    "base_url": "http://juice:3000",
    "hosts": ["juice"],
    "index": ["/#/login", "/#/basket"],
    "interactions": [
        {"type": "goto", "url": "http://juice:3000/#/login"},
        {"type": "fill", "selector": "#email", "field": "email"},
        {"type": "click", "selector": "#loginButton"},
    ],
    "forms": [{"url": "http://juice:3000/#/login", "fields": ["email", "password"]}],
    "api": [{"method": "GET", "url": "http://juice:3000/rest/user/whoami", "params": []}],
}

# The operator config that used to be hard-coded inside generate.py. A fixture rather than the
# committed juice-shop file, so these stay pure unit tests with no dependency on an app dir.
CONFIG = {
    "app_id": "juice-shop",
    "environment_class": "dev",
    "base_url": "http://juice:3000",
    "scope": {"allow": ["juice"], "deny": ["*.google-analytics.com"],
              "avoid_actions": ["logout", "delete-account"]},
    "auth": {
        "mode": "form",
        "login_url": "/#/login",
        "selectors": {"email": "#email", "password": "#password", "submit": "#loginButton"},
        "proof": {"js": "window.localStorage.getItem('token')"},
        "credentials": {"email_env": "AUTH_EMAIL", "password_env": "AUTH_PASSWORD"},
    },
    "ui": {"dismiss_selectors": ["button[aria-label='Close Welcome Banner']"]},
}

PLAN = {
    "app_id": "juice-shop",
    "base_url": "http://juice:3000",
    "login": {
        "url": "/#/login",
        "email_selector": "#email",
        "password_selector": "#password",
        "submit_selector": "#loginButton",
        "token_check": "window.localStorage.getItem('token')",
    },
    "journey": [
        {"action": "goto", "target": "/#/basket"},
        {"action": "api_get", "target": "/rest/user/whoami"},
    ],
}


# ---- FR-G2: scope emission ---------------------------------------------------------------

def test_emit_scope_validates_and_allowlists_host():
    scope = emit_scope(TRACE, CONFIG)
    Draft202012Validator(json.loads(SCOPE_SCHEMA.read_text())).validate(scope)
    assert "juice" in scope["fqdn_allow_list"]
    assert scope["environment_class"] != "prod"


# ---- FR-G4 + safety: deterministic render of a validated plan ----------------------------

def test_journey_from_trace_is_schema_valid():
    plan = journey_from_trace(TRACE, CONFIG)
    Draft202012Validator(json.loads(JOURNEY_SCHEMA.read_text())).validate(plan)


def test_render_flow_is_deterministic():
    assert render_flow(PLAN, CONFIG) == render_flow(PLAN, CONFIG)


def test_rendered_flow_compiles_and_defines_run():
    src = render_flow(PLAN, CONFIG)
    tree = ast.parse(src)  # raises SyntaxError if not valid Python
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "run" in funcs


def test_rendered_flow_has_no_hardcoded_secrets():
    # Creds must come from env (auth.json), never baked into generated code (NFR-3).
    src = render_flow(PLAN, CONFIG)
    assert "os.environ" in src


# ---- plan validation + LLM output parsing -----------------------------------------------

def test_validate_plan_accepts_good_and_rejects_bad():
    validate_plan(PLAN)  # no raise
    bad = {"app_id": "x", "base_url": "y", "journey": []}  # missing login, empty journey
    with pytest.raises(Exception):
        validate_plan(bad)


def test_parse_plan_text_handles_fenced_json():
    fenced = "here you go:\n```json\n" + json.dumps(PLAN) + "\n```\n"
    assert parse_plan_text(fenced) == PLAN


def test_parse_plan_text_raises_on_garbage():
    with pytest.raises(ValueError):
        parse_plan_text("no json here at all")


# ---- FR-G3: policy / manifest / lock emission (parse correctly) --------------------------

def test_zap_policy_has_intensity():
    assert emit_zap_policy()["intensity"] in ("low", "medium", "high")


# ---- config-driven behaviour (W2-1/W2-2/W2-9): no app knowledge left in the code ---------

def test_emit_scope_takes_environment_class_from_config_not_a_default():
    staging = {**CONFIG, "environment_class": "staging"}
    assert emit_scope(TRACE, staging)["environment_class"] == "staging"


def test_emit_scope_fails_when_the_config_omits_environment_class():
    with pytest.raises(KeyError):
        emit_scope(TRACE, {k: v for k, v in CONFIG.items() if k != "environment_class"})


def test_deny_list_and_avoid_actions_come_from_config():
    scope = emit_scope(TRACE, {**CONFIG, "scope": {"allow": ["juice"], "deny": ["*.cdn.test"],
                                                   "avoid_actions": ["wipe"]}})
    assert scope["fqdn_deny_list"] == ["*.cdn.test"]
    assert scope["avoid_action_list"] == ["wipe"]


def test_login_block_comes_from_config_not_the_model():
    other = {**CONFIG, "auth": {**CONFIG["auth"],
                                "login_url": "/signin",
                                "selectors": {"email": "#user", "password": "#pw", "submit": ".go"}}}
    plan = journey_from_trace(TRACE, other)
    assert plan["login"]["url"] == "/signin"
    assert plan["login"]["email_selector"] == "#user"


def test_rendered_flow_uses_only_this_apps_banners():
    src = render_flow(PLAN, {**CONFIG, "ui": {"dismiss_selectors": [".my-cookie-bar"]}})
    assert ".my-cookie-bar" in src
    assert "Close Welcome Banner" not in src


def test_rendered_flow_for_an_app_with_no_banners_has_an_empty_tuple():
    src = render_flow(PLAN, {**CONFIG, "ui": {"dismiss_selectors": []}})
    assert "for sel in ():" in src


def test_rendered_flow_uses_the_configured_proof():
    src = render_flow(PLAN, {**CONFIG,
                             "auth": {**CONFIG["auth"], "proof": {"js": "window.APP.isLoggedIn"}}})
    assert "window.APP.isLoggedIn" in src
    assert "localStorage" not in src


def test_committed_pilot_config_still_renders_the_pilot_flow():
    # End-to-end on the real file: the app dir is the only place naming the pilot.
    src = render_flow(PLAN, load_app_config("juice-shop"))
    assert "Close Welcome Banner" in src and "#loginButton" in src


def test_manifest_and_lock_are_json_serializable():
    manifest = emit_manifest(TRACE)
    lock = emit_lock()
    assert json.loads(json.dumps(manifest))["app_id"] == "juice-shop"
    assert "playwright_version" in json.loads(json.dumps(lock))
