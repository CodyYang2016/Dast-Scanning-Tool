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
    scope = emit_scope(TRACE)
    Draft202012Validator(json.loads(SCOPE_SCHEMA.read_text())).validate(scope)
    assert "juice" in scope["fqdn_allow_list"]
    assert scope["environment_class"] != "prod"


# ---- FR-G4 + safety: deterministic render of a validated plan ----------------------------

def test_journey_from_trace_is_schema_valid():
    plan = journey_from_trace(TRACE)
    Draft202012Validator(json.loads(JOURNEY_SCHEMA.read_text())).validate(plan)


def test_render_flow_is_deterministic():
    assert render_flow(PLAN) == render_flow(PLAN)


def test_rendered_flow_compiles_and_defines_run():
    src = render_flow(PLAN)
    tree = ast.parse(src)  # raises SyntaxError if not valid Python
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "run" in funcs


def test_rendered_flow_has_no_hardcoded_secrets():
    # Creds must come from env (auth.json), never baked into generated code (NFR-3).
    src = render_flow(PLAN)
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


def test_manifest_and_lock_are_json_serializable():
    manifest = emit_manifest(TRACE)
    lock = emit_lock()
    assert json.loads(json.dumps(manifest))["app_id"] == "juice-shop"
    assert "playwright_version" in json.loads(json.dumps(lock))
