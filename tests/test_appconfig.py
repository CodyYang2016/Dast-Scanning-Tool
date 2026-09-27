"""Objective tests for the per-app config loader (W2-5).

The config is what makes onboarding a code-free operation, so its contract matters as much as
the schemas it sits beside. Oracles: the committed contracts/app.schema.json (third-party
validator) and hand-built configs with known-correct answers. No browser, no network.
"""

import json

import jsonschema
import pytest
import yaml

from authoring import appconfig

MINIMAL = {
    "app_id": "example",
    "environment_class": "dev",
    "base_url": "http://example:8080",
    "scope": {"allow": ["example"]},
    "auth": {
        "mode": "form",
        "login_url": "/login",
        "selectors": {"email": "#u", "password": "#p", "submit": "#go"},
        "proof": {"js": "window.sessionStorage.getItem('t')"},
    },
}


def _write(tmp_path, cfg, name="app.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


# ---- loading + validation (fail loudly, never silently) ---------------------------------

def test_loads_a_valid_config(tmp_path):
    cfg = appconfig.load_app_config(_write(tmp_path, MINIMAL))
    assert cfg["app_id"] == "example"


def test_unknown_key_is_rejected(tmp_path):
    bad = {**MINIMAL, "scann": {"policy": {}}}      # typo for "scan"
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, bad))


def test_missing_environment_class_is_rejected(tmp_path):
    bad = {k: v for k, v in MINIMAL.items() if k != "environment_class"}
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, bad))


def test_prod_environment_class_is_rejected_by_the_schema(tmp_path):
    # Defence in depth: preflight refuses prod too (D3), but it must not even be expressible.
    bad = {**MINIMAL, "environment_class": "prod"}
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, bad))


def test_auth_without_proof_is_rejected(tmp_path):
    bad = json.loads(json.dumps(MINIMAL))
    del bad["auth"]["proof"]
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, bad))


def test_unparseable_yaml_raises_value_error(tmp_path):
    p = tmp_path / "app.yaml"
    p.write_text("app_id: [unclosed\n")
    with pytest.raises(ValueError):
        appconfig.load_app_config(str(p))


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        appconfig.load_app_config(str(tmp_path / "nope.yaml"))


# ---- app-id resolution: the committed pilot config is found and valid -------------------

def test_bare_app_id_resolves_to_the_committed_config():
    cfg = appconfig.load_app_config("juice-shop")
    assert cfg["app_id"] == "juice-shop"
    assert cfg["environment_class"] in ("dev", "test", "staging")


# ---- accessors: defaults live in exactly one place --------------------------------------

def test_login_block_and_proof():
    cfg = MINIMAL
    assert appconfig.login(cfg) == {"url": "/login", "email": "#u", "password": "#p", "submit": "#go"}
    assert appconfig.proof_js(cfg) == "window.sessionStorage.getItem('t')"


def test_unsupported_proof_mode_fails_closed():
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["proof"] = {"route": "/account"}     # lands with W2-11
    with pytest.raises(ValueError):
        appconfig.proof_js(cfg)


def test_new_app_inherits_no_banners_and_no_routes():
    assert appconfig.dismiss_selectors(MINIMAL) == []
    assert appconfig.authenticated_routes(MINIMAL) == []


def test_identity_defaults_to_provisioned_so_no_account_is_created():
    assert appconfig.self_registers(MINIMAL) is False
    assert appconfig.bootstrap(MINIMAL) is None


def test_bootstrap_only_returned_for_self_registering_apps():
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["bootstrap"] = {"method": "POST", "path": "/api/Users/"}
    assert appconfig.bootstrap(cfg) is None          # identity still provisioned
    cfg["auth"]["identity"] = "self-register"
    assert appconfig.bootstrap(cfg)["path"] == "/api/Users/"


def test_credentials_come_from_the_named_env_vars(monkeypatch):
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["credentials"] = {"email_env": "APP_USER", "password_env": "APP_PASS"}
    monkeypatch.setenv("APP_USER", "u@example.test")
    monkeypatch.setenv("APP_PASS", "s3cret")
    assert appconfig.credentials(cfg) == ("u@example.test", "s3cret")


def test_missing_credentials_raise_rather_than_logging_in_blank(monkeypatch):
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["credentials"] = {"email_env": "APP_USER", "password_env": "APP_PASS"}
    monkeypatch.delenv("APP_USER", raising=False)
    monkeypatch.delenv("APP_PASS", raising=False)
    with pytest.raises(ValueError):
        appconfig.credentials(cfg)


# ---- W2-10: login steps — the shorthand and the general form are one code path ----------
# Onboarding an app whose login is a username field, or two pages, or needs a keypress, must
# not need a code change. The three-selector shorthand normalizes into the same step list the
# general form produces, so record/seed/generate only ever consume steps.

def test_shorthand_normalizes_to_fill_fill_click():
    assert appconfig.login_steps(MINIMAL) == [
        {"action": "fill", "selector": "#u", "value": "identifier"},
        {"action": "fill", "selector": "#p", "value": "secret"},
        {"action": "click", "selector": "#go"},
    ]


def test_explicit_steps_are_returned_as_written():
    cfg = json.loads(json.dumps(MINIMAL))
    del cfg["auth"]["selectors"]
    cfg["auth"]["steps"] = [
        {"action": "fill", "selector": "input[name=username]", "value": "identifier"},
        {"action": "click", "selector": "#next"},
        {"action": "wait_for", "selector": "input[name=password]"},
        {"action": "fill", "selector": "input[name=password]", "value": "secret"},
        {"action": "press", "selector": "input[name=password]", "key": "Enter"},
    ]
    steps = appconfig.login_steps(cfg)
    assert [s["action"] for s in steps] == ["fill", "click", "wait_for", "fill", "press"]
    assert steps[0]["selector"] == "input[name=username]"


def test_auth_with_neither_selectors_nor_steps_is_rejected(tmp_path):
    bad = json.loads(json.dumps(MINIMAL))
    del bad["auth"]["selectors"]
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, bad))


def test_a_username_and_cookie_session_app_is_expressible(tmp_path):
    """The DVWA shape: username field, PHPSESSID cookie, no self-registration."""
    cfg = {
        "app_id": "dvwa",
        "environment_class": "dev",
        "base_url": "http://dvwa",
        "scope": {"allow": ["dvwa"]},
        "auth": {
            "mode": "form",
            "login_url": "/login.php",
            "steps": [
                {"action": "fill", "selector": "input[name=username]", "value": "identifier"},
                {"action": "fill", "selector": "input[name=password]", "value": "secret"},
                {"action": "click", "selector": "input[type=submit]"},
            ],
            "proof": {"route": {"path": "/index.php", "forbid_redirect_to": "login.php"}},
        },
    }
    loaded = appconfig.load_app_config(_write(tmp_path, cfg))
    assert appconfig.self_registers(loaded) is False          # no account creation
    assert appconfig.proof_mode(loaded) == "route"            # no JS token anywhere


# ---- W2-11: proof modes ------------------------------------------------------------------

def test_proof_mode_reports_which_mode_is_configured():
    assert appconfig.proof_mode(MINIMAL) == "js"
    sel = json.loads(json.dumps(MINIMAL))
    sel["auth"]["proof"] = {"selector": "nav .logout"}
    assert appconfig.proof_mode(sel) == "selector"


def test_route_proof_is_accepted_by_the_schema(tmp_path):
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["proof"] = {"route": {"path": "/account", "expect_status": 200,
                                      "forbid_redirect_to": "/login"}}
    assert appconfig.proof_mode(appconfig.load_app_config(_write(tmp_path, cfg))) == "route"


def test_two_proof_modes_at_once_are_rejected(tmp_path):
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["proof"] = {"js": "x", "selector": ".y"}
    with pytest.raises(jsonschema.ValidationError):
        appconfig.load_app_config(_write(tmp_path, cfg))


def test_proof_js_still_raises_for_non_js_modes():
    cfg = json.loads(json.dumps(MINIMAL))
    cfg["auth"]["proof"] = {"selector": ".logout"}
    with pytest.raises(ValueError):
        appconfig.proof_js(cfg)
