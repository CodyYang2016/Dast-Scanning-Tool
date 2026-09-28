"""Objective tests for auto-authoring the auth block (dast onboard --discover).

Writing the auth block by hand was the largest remaining human task in onboarding: when
WebGoat was onboarded, finding a usable authenticated-only marker took a throwaway script
that tried nine candidate selectors. That is mechanical work with a crisp oracle — you either
log in or you do not — which makes it exactly the kind of judgement a model can offer and
code can check.

The contract these tests pin: the model proposes, and nothing is accepted because it sounds
right. A proof must be observed to hold when logged in AND to fail when logged out; the
second half is what a "sounds plausible" answer cannot fake. Oracles: the committed schema,
and hand-built observation pairs with known-correct answers. No browser, no network.
"""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from authoring import discover

ROOT = Path(__file__).resolve().parent.parent

PROPOSAL = {
    "steps": [
        {"action": "fill", "selector": "input[name=username]", "value": "identifier"},
        {"action": "fill", "selector": "input[name=password]", "value": "secret"},
        {"action": "click", "selector": "input[name=Login]"},
    ],
    "proof_candidates": [
        {"js": "window.localStorage.getItem('token')"},
        {"selector": "a[href*='logout']"},
        {"route": {"path": "/index.php", "forbid_redirect_to": "login"}},
    ],
}


# ---- the model's reply is data, and it is validated ------------------------------------

def test_a_well_formed_proposal_parses():
    assert discover.parse_proposal(json.dumps(PROPOSAL))["steps"][0]["selector"] == \
        "input[name=username]"


def test_prose_and_code_fences_around_the_json_are_tolerated():
    text = "Here is the login:\n```json\n" + json.dumps(PROPOSAL) + "\n```\nHope that helps."
    assert discover.parse_proposal(text)["proof_candidates"][0] == {"js": "window.localStorage.getItem('token')"}


def test_a_proposal_with_no_proof_candidates_is_rejected():
    bad = {**PROPOSAL, "proof_candidates": []}
    with pytest.raises(jsonschema.ValidationError):
        discover.parse_proposal(json.dumps(bad))


def test_a_proposal_that_invents_an_action_is_rejected():
    bad = {**PROPOSAL, "steps": [{"action": "exfiltrate", "selector": "#x"}]}
    with pytest.raises(jsonschema.ValidationError):
        discover.parse_proposal(json.dumps(bad))


def test_a_proposal_carrying_a_literal_credential_is_rejected():
    # `value` names which credential to type; it is not a place to put one.
    bad = {**PROPOSAL, "steps": [{"action": "fill", "selector": "#u", "value": "hunter2"}]}
    with pytest.raises(jsonschema.ValidationError):
        discover.parse_proposal(json.dumps(bad))


def test_garbage_raises_rather_than_returning_something_empty():
    with pytest.raises(ValueError):
        discover.parse_proposal("I could not determine the login form.")


# ---- verification: a proof must DISCRIMINATE, not merely be present --------------------

def test_a_proof_that_holds_only_when_logged_in_is_accepted():
    assert discover.discriminates(logged_out=False, logged_in=True)


def test_a_proof_present_on_the_login_page_too_is_rejected():
    # The failure mode that matters: WebGoat answers 200 on /login?error, so a status check
    # would call a FAILED login authenticated.
    assert not discover.discriminates(logged_out=True, logged_in=True)


def test_a_proof_that_never_holds_is_rejected():
    assert not discover.discriminates(logged_out=False, logged_in=False)


def test_the_first_discriminating_candidate_wins_and_the_rest_are_discarded():
    results = {0: (True, True), 1: (False, True), 2: (False, True)}   # index -> (out, in)
    chosen = discover.choose_proof(PROPOSAL["proof_candidates"],
                                   lambda i, c: results[i])
    assert chosen == {"selector": "a[href*='logout']"}


def test_no_candidate_surviving_is_an_explicit_failure_not_a_guess():
    with pytest.raises(discover.DiscoveryFailed) as exc:
        discover.choose_proof(PROPOSAL["proof_candidates"], lambda i, c: (True, True))
    assert "none of the" in str(exc.value).lower()


def test_a_candidate_that_throws_is_skipped_rather_than_crashing_the_run():
    def flaky(i, c):
        if i == 0:
            raise RuntimeError("selector engine blew up")
        return (False, True)
    assert discover.choose_proof(PROPOSAL["proof_candidates"], flaky) == \
        {"selector": "a[href*='logout']"}


# ---- the config it writes is a real config ---------------------------------------------

def test_the_written_config_satisfies_the_app_contract(tmp_path):
    text = discover.render_config(
        app_id="newapp", base_url="http://newapp:8080", login_url="/login",
        steps=PROPOSAL["steps"], proof={"selector": "a[href*='logout']"},
        authenticated_routes=["/home"])
    cfg = yaml.safe_load(text)
    schema = json.loads((ROOT / "contracts" / "app.schema.json").read_text())
    jsonschema.validate(cfg, schema)
    assert cfg["auth"]["steps"] == PROPOSAL["steps"]
    assert cfg["auth"]["proof"] == {"selector": "a[href*='logout']"}


def test_the_written_config_names_credentials_and_never_holds_them():
    text = discover.render_config(app_id="my-app", base_url="http://x", login_url="/login",
                                  steps=PROPOSAL["steps"], proof={"js": "window.t"},
                                  authenticated_routes=[])
    cfg = yaml.safe_load(text)
    assert cfg["auth"]["credentials"] == {"email_env": "MY_APP_USER",
                                          "password_env": "MY_APP_PASS"}


def test_the_written_config_defaults_to_a_provisioned_identity_and_no_writes():
    cfg = yaml.safe_load(discover.render_config(
        app_id="x", base_url="http://x", login_url="/login", steps=PROPOSAL["steps"],
        proof={"js": "window.t"}, authenticated_routes=[]))
    assert cfg["auth"]["identity"] == "provisioned"
    assert cfg.get("data_policy", "durable") == "durable"        # writes off until attested
    assert cfg["explore"]["safe_forms"] == []


def test_the_written_config_records_that_a_model_authored_it():
    text = discover.render_config(app_id="x", base_url="http://x", login_url="/login",
                                  steps=PROPOSAL["steps"], proof={"js": "window.t"},
                                  authenticated_routes=[], model="claude-opus-4-8")
    assert "claude-opus-4-8" in text and "verified" in text.lower()


# ---- the verifier must not break the thing it is verifying ------------------------------
# Observed live on DVWA: the model's first proof candidate was a route proof on /logout.php.
# Evaluating it navigated there, ended the session, and every later candidate was then
# measured against a logged-out browser — so nothing survived and a working login looked
# undiscoverable. The harness has to obey the same rule it enforces everywhere else, and one
# candidate must not be able to spoil the next.

def test_a_session_ending_proof_is_refused_before_it_is_ever_evaluated():
    evaluated = []

    def observe(i, c):
        evaluated.append(c)
        return (False, True)

    candidates = [{"route": {"path": "/logout.php"}}, {"selector": "nav .user"}]
    chosen = discover.choose_proof(candidates, observe)
    assert chosen == {"selector": "nav .user"}
    assert {"route": {"path": "/logout.php"}} not in evaluated     # never even tried


def test_other_session_enders_are_refused_too():
    for path in ("/signout", "/account/delete-account", "/change-password"):
        with pytest.raises(discover.DiscoveryFailed):
            discover.choose_proof([{"route": {"path": path}}], lambda i, c: (False, True))


def test_a_selector_naming_logout_is_still_fine_because_it_only_reads():
    # Looking for a logout LINK is the classic logged-in marker; following one is not.
    chosen = discover.choose_proof([{"selector": "a[href*='logout']"}], lambda i, c: (False, True))
    assert chosen == {"selector": "a[href*='logout']"}
