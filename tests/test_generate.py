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
    submit_steps,
    validate_plan,
    with_submit_steps,
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

# App config the deterministic transforms read (tests are exempt from the no-app-specifics
# guard; core modules take all app specifics from a config exactly like this).
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
    "api": {"patterns": ["/rest/", "/api/"]},
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


def test_journey_from_trace_leaves_out_a_document_the_crawl_walked_into():
    """A goto step for a download cannot be replayed at all -- Chromium aborts the navigation."""
    trace = dict(TRACE, index=["/#/basket", "/docs/DVWA_v1.3.pdf"])
    targets = [s["target"] for s in journey_from_trace(trace, CONFIG)["journey"]]
    assert "/#/basket" in targets and "/docs/DVWA_v1.3.pdf" not in targets


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
    assert emit_zap_policy(CONFIG)["intensity"] in ("low", "medium", "high")


def test_manifest_and_lock_are_json_serializable():
    manifest = emit_manifest(TRACE)
    lock = emit_lock()
    assert json.loads(json.dumps(manifest))["app_id"] == "juice-shop"
    assert "playwright_version" in json.loads(json.dumps(lock))


# ---- the model asked for must match the selected provider --------------------------------
# A hardcoded default sent Anthropic's model name to the copilot CLI, which rejected it and
# dropped every run to plan_source=fallback while looking like a model-availability problem.

def test_make_plan_asks_the_provider_for_its_own_default_model(monkeypatch):
    from authoring import generate as generate_mod

    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    asked = {}

    def fake_plan_from_llm(trace, model, api_key, config=None):
        asked["model"] = model
        return dict(PLAN)

    monkeypatch.setattr(generate_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(generate_mod, "plan_from_llm", fake_plan_from_llm)

    _, source = generate_mod.make_plan(TRACE, CONFIG, use_llm=True)

    assert source == "llm" and asked["model"] == "gpt-5.5"


# ---- --require-llm: a broken provider must not masquerade as a deliberate fallback --------

def test_make_plan_requires_llm_raises_when_the_llm_plan_fails(monkeypatch):
    import pytest
    from authoring import generate as generate_mod
    from authoring.llm_backend import LLMRequiredError

    monkeypatch.setattr(generate_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(generate_mod, "plan_from_llm",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("model unavailable")))
    with pytest.raises(LLMRequiredError):
        generate_mod.make_plan(TRACE, CONFIG, use_llm=True, require_llm=True)


def test_make_plan_requires_llm_raises_when_no_provider_is_available(monkeypatch):
    import pytest
    from authoring import generate as generate_mod
    from authoring.llm_backend import LLMRequiredError

    monkeypatch.setattr(generate_mod.llm_backend, "available", lambda api_key=None: False)
    with pytest.raises(LLMRequiredError):
        generate_mod.make_plan(TRACE, CONFIG, use_llm=True, require_llm=True)


def test_make_plan_requires_llm_rejects_the_contradictory_no_llm_combination():
    import pytest
    from authoring import generate as generate_mod
    from authoring.llm_backend import LLMRequiredError

    with pytest.raises(LLMRequiredError):
        generate_mod.make_plan(TRACE, CONFIG, use_llm=False, require_llm=True)


def test_make_plan_without_require_llm_still_falls_back(monkeypatch):
    from authoring import generate as generate_mod

    monkeypatch.setattr(generate_mod.llm_backend, "available", lambda api_key=None: False)
    _plan, source = generate_mod.make_plan(TRACE, CONFIG, use_llm=True)
    assert source == "fallback"


# ---- controlled mutation: a submitted form replays as fill + submit ----------------------

SUBMIT_TRACE = dict(
    TRACE,
    interactions=TRACE["interactions"] + [
        {"type": "goto", "url": "http://juice:3000/#/search"},
        {"type": "submit", "url": "http://juice:3000/#/search",
         "selector": "form >> nth=0", "fields": ["q"]},
    ],
)
SUBMIT_CONFIG = dict(CONFIG, explore={"test_data": {"q": "dast-test"}})


def test_a_submitted_form_becomes_a_goto_then_a_submit_step():
    plan = journey_from_trace(SUBMIT_TRACE, SUBMIT_CONFIG)
    Draft202012Validator(json.loads(JOURNEY_SCHEMA.read_text())).validate(plan)
    assert plan["journey"][-2:] == [
        {"action": "goto", "target": "/#/search"},
        {"action": "submit_form", "target": "form >> nth=0", "fields": ["q"]},
    ]


def test_a_plan_carries_field_names_but_never_values():
    plan = journey_from_trace(SUBMIT_TRACE, SUBMIT_CONFIG)
    assert "dast-test" not in json.dumps(plan)


def test_rendered_submit_fills_approved_values_and_submits_through_the_page():
    src = render_flow(journey_from_trace(SUBMIT_TRACE, SUBMIT_CONFIG), SUBMIT_CONFIG)
    ast.parse(src)
    assert 'page.fill("form >> nth=0 >> [name=\\"q\\"]", "dast-test")' in src
    # requestSubmit, so an app that intercepts its own forms in JS still sees the submit
    assert "requestSubmit" in src


def test_rendered_submit_leaves_out_a_field_with_no_approved_value():
    trace = dict(SUBMIT_TRACE, interactions=TRACE["interactions"] + [
        {"type": "goto", "url": "http://juice:3000/#/search"},
        {"type": "submit", "url": "http://juice:3000/#/search",
         "selector": "form >> nth=0", "fields": ["q", "unapproved"]},
    ])
    src = render_flow(journey_from_trace(trace, SUBMIT_CONFIG), SUBMIT_CONFIG)
    assert "unapproved" not in src and "dast-test" in src


def test_rendered_submit_escapes_a_quote_in_a_test_value():
    """Values are json.dumps'd, so a quote cannot close the literal and break the flow."""
    config = dict(CONFIG, explore={"test_data": {"q": 'he said "hi"'}})
    src = render_flow(journey_from_trace(SUBMIT_TRACE, config), config)
    ast.parse(src)
    assert '"he said \\"hi\\""' in src


# ---- an LLM-authored plan may not quietly drop (or invent) a form submission -------------

def test_an_llm_plan_keeps_the_submit_the_walk_performed():
    """The walk's submit is evidence: a plan that omits it would scan less than was reached."""
    from authoring.generate import with_submit_steps

    journey = with_submit_steps([{"action": "goto", "target": "/#/about"}],
                                SUBMIT_TRACE, "http://juice:3000")
    assert journey == [
        {"action": "goto", "target": "/#/about"},
        {"action": "goto", "target": "/#/search"},
        {"action": "submit_form", "target": "form >> nth=0", "fields": ["q"]},
    ]


def test_an_llm_planned_submit_is_not_duplicated_and_gets_its_page():
    from authoring.generate import with_submit_steps

    journey = with_submit_steps([{"action": "submit_form", "target": "form >> nth=0"}],
                                SUBMIT_TRACE, "http://juice:3000")
    assert journey == [
        {"action": "goto", "target": "/#/search"},
        {"action": "submit_form", "target": "form >> nth=0", "fields": ["q"]},
    ]


def test_an_llm_planned_submit_of_a_form_the_walk_never_posted_is_dropped():
    """The only evidence a form is allow-listed with approved data is that the gate let it post."""
    from authoring.generate import with_submit_steps

    journey = with_submit_steps([{"action": "submit_form", "target": "#invented"}],
                                dict(SUBMIT_TRACE, interactions=TRACE["interactions"]),
                                "http://juice:3000")
    assert journey == []


def test_an_llm_planned_submit_carries_the_fields_the_walk_filled_not_the_plans():
    from authoring.generate import with_submit_steps

    journey = with_submit_steps(
        [{"action": "submit_form", "target": "form >> nth=0", "fields": ["q", "invented"]}],
        SUBMIT_TRACE, "http://juice:3000")
    assert journey[-1]["fields"] == ["q"]


def test_a_plan_with_no_journey_at_all_still_gets_the_walks_submits():
    from authoring.generate import with_submit_steps

    assert with_submit_steps(None, SUBMIT_TRACE, "http://juice:3000") == [
        {"action": "goto", "target": "/#/search"},
        {"action": "submit_form", "target": "form >> nth=0", "fields": ["q"]},
    ]


def test_the_llm_plan_prompt_asks_for_the_submits(monkeypatch):
    from authoring import generate as generate_mod

    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["user"] = user
        return json.dumps({"app_id": "juice", "base_url": "http://juice:3000",
                           "login": {"url": "/#/login"}, "journey": []})

    monkeypatch.setattr(generate_mod.llm_backend, "complete", fake_complete)
    plan = generate_mod.plan_from_llm(SUBMIT_TRACE, "m", "k", config=SUBMIT_CONFIG)
    # Naming the action is not enough: a model that is not told how to build one emits a
    # selector with no page, or fields it invented.
    assert "submit_form" in seen["user"]
    assert "`goto` of the page it was made on" in seen["user"]
    assert "whose `fields` are its field names" in seen["user"]
    assert "Field names only" in seen["user"]
    # and the submit survives a plan that left it out
    assert plan["journey"][-1]["action"] == "submit_form"


# ---- a submit that answered a challenge is not replayable -------------------------------

INFERRED_TRACE = dict(
    TRACE,
    interactions=TRACE["interactions"] + [
        {"type": "submit", "url": "http://juice:3000/#/search",
         "selector": "form >> nth=0", "fields": ["q"], "inferred": []},
        {"type": "submit", "url": "http://juice:3000/#/gate",
         "selector": "form >> nth=1", "fields": ["answer", "note"], "inferred": ["answer"]},
    ],
)


def test_a_submit_whose_value_was_inferred_is_left_out_of_the_bundle():
    """Its answer was reasoned from what the page said then; posting it again is refused, so a
    replay step would look like coverage and deliver none."""
    steps = submit_steps(INFERRED_TRACE, "http://juice:3000")
    assert [s["target"] for s in steps] == ["/#/search", "form >> nth=0"]


def test_a_plan_cannot_reinstate_an_inferred_submit():
    journey = [{"action": "submit_form", "target": "form >> nth=1"}]
    steps = with_submit_steps(journey, INFERRED_TRACE, "http://juice:3000")
    assert all(s["target"] != "form >> nth=1" for s in steps)
