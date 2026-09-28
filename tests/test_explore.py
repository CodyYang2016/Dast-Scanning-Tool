"""Objective tests for the exploration loop's pure decision logic (Phase B).

The browser loop itself is validated by running it (fallback live; LLM path with a key). Here we
pin the parts that decide WHAT runs: schema+policy validation of a proposal, the deterministic
fallback proposer, and next_action's fallback when no LLM key is present. Oracle: hand-built
observations/actions with known-correct answers.
"""

from authoring.explore import next_action, propose_fallback, validate_proposal

SCOPE = {"app_id": "juice-shop", "fqdn_allow_list": ["juice"],
         "avoid_action_list": ["logout", "delete-account"]}


# ---- validate_proposal: schema + policy (fail-closed) -----------------------------------

def test_valid_get_action_passes():
    ok, _ = validate_proposal(
        {"action": "follow_link", "target": {"method": "GET", "path": "/#/basket"}}, SCOPE)
    assert ok


def test_off_schema_action_rejected():
    ok, reason = validate_proposal({"action": "hack_everything"}, SCOPE)
    assert not ok and "schema" in reason


def test_destructive_action_rejected_by_policy():
    ok, reason = validate_proposal(
        {"action": "visit_api", "target": {"method": "DELETE", "path": "/rest/basket"}}, SCOPE)
    assert not ok and "state-changing" in reason


def test_deny_listed_action_rejected():
    scope = {"app_id": "x", "fqdn_allow_list": ["juice"], "avoid_action_list": ["purchase"]}
    ok, reason = validate_proposal(
        {"action": "follow_link", "target": {"path": "/#/purchase"}}, scope)
    assert not ok and "deny-list" in reason


def test_a_session_ending_action_is_rejected_even_if_the_app_forgot_to_list_it():
    ok, reason = validate_proposal(
        {"action": "follow_link", "target": {"path": "/#/logout"}},
        {"app_id": "x", "fqdn_allow_list": ["juice"]})
    assert not ok and "session" in reason


def test_stop_is_valid():
    ok, _ = validate_proposal({"action": "stop"}, SCOPE)
    assert ok


# ---- propose_fallback: deterministic next-action ----------------------------------------

def test_fallback_picks_first_unvisited_in_scope_link():
    obs = {"url": "/#/", "links": ["/#/basket", "/#/profile"], "forms": [], "api": []}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["action"] == "follow_link" and action["target"]["path"] == "/#/basket"


def test_fallback_skips_visited_links():
    obs = {"url": "/#/", "links": ["/#/basket", "/#/profile"], "forms": [], "api": []}
    action = propose_fallback(obs, visited={"/#/basket"}, scope=SCOPE)
    assert action["target"]["path"] == "/#/profile"


def test_fallback_skips_deny_listed_links():
    obs = {"url": "/#/", "links": ["/#/logout", "/#/basket"], "forms": [], "api": []}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["target"]["path"] == "/#/basket"  # logout skipped


def test_fallback_skips_out_of_scope_absolute_links():
    obs = {"url": "/#/", "links": ["https://evil.example.com/x", "/#/basket"], "forms": [], "api": []}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["target"]["path"] == "/#/basket"


def test_fallback_falls_through_to_api_get():
    obs = {"url": "/#/", "links": [], "forms": [],
           "api": [{"method": "GET", "url": "/rest/user/whoami"}]}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["action"] == "visit_api" and action["target"]["path"] == "/rest/user/whoami"


def test_fallback_stops_when_nothing_left():
    obs = {"url": "/#/", "links": ["/#/logout"], "forms": [], "api": []}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["action"] == "stop"


# ---- next_action: no key -> deterministic fallback --------------------------------------

def test_next_action_uses_fallback_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    obs = {"url": "/#/", "links": ["/#/basket"], "forms": [], "api": []}
    action, source = next_action(obs, visited=set(), scope=SCOPE, use_llm=True, api_key=None)
    assert source == "fallback" and action["target"]["path"] == "/#/basket"


def test_next_action_no_llm_flag_forces_fallback():
    obs = {"url": "/#/", "links": ["/#/basket"], "forms": [], "api": []}
    action, source = next_action(obs, visited=set(), scope=SCOPE, use_llm=False,
                                 api_key="sk-test-would-not-be-used")
    assert source == "fallback"


# ---- href normalization: what the SPA emits vs. what the trace/flow must contain --------
# Angular emits hrefs like "#/contact" and "./redirect?to=..."; appended to base_url verbatim
# they become "http://juice:3000#/contact" (works by accident) and "http://juice:3000./redirect"
# (an invalid URL that crashed the generated flow's replay). Normalize before proposing/recording.

from authoring.explore import normalize_href


def test_normalize_hash_route_gets_leading_slash():
    assert normalize_href("#/contact") == "/#/contact"


def test_normalize_dot_relative_becomes_root_relative():
    assert normalize_href("./redirect?to=x") == "/redirect?to=x"


def test_normalize_leaves_root_relative_and_absolute_alone():
    assert normalize_href("/#/basket") == "/#/basket"
    assert normalize_href("http://juice:3000/#/basket") == "http://juice:3000/#/basket"


def test_normalize_drops_non_navigable_hrefs():
    assert normalize_href("javascript:void(0)") is None
    assert normalize_href("mailto:a@b.c") is None
    assert normalize_href("") is None


def test_fallback_skips_open_redirect_link():
    obs = {"url": "/#/", "links": ["/redirect?to=https://github.com/x", "/#/about"],
           "forms": [], "api": []}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["target"]["path"] == "/#/about"


# ---- LLM proposals get the same normalization as scraped links ---------------------------
# The model may answer with "#/about" or "rest/languages" (no leading slash). Appended to
# base_url those form invalid URLs ("http://juice:3000#/about", "http://juice:3000rest/...") and
# one of them crashed a live run. Normalize before validating/executing.

def test_next_action_normalizes_llm_path(monkeypatch):
    monkeypatch.setattr("authoring.explore.propose_llm",
                        lambda obs, model, api_key: {"action": "follow_link",
                                                     "target": {"method": "GET", "path": "#/about"}})
    action, src = next_action({"url": "/#/", "links": [], "forms": [], "api": []}, set(), SCOPE,
                              api_key="k")
    assert src == "llm" and action["target"]["path"] == "/#/about"


def test_next_action_rejects_non_navigable_llm_path(monkeypatch):
    monkeypatch.setattr("authoring.explore.propose_llm",
                        lambda obs, model, api_key: {"action": "follow_link",
                                                     "target": {"path": "javascript:void(0)"}})
    action, src = next_action({"url": "/#/", "links": [], "forms": [], "api": []}, set(), SCOPE,
                              api_key="k")
    assert src == "fallback"   # rejected -> deterministic fallback (here: stop)


# ---- dispatch: path actions navigate, selector actions click ------------------------------
# expand_nav / submit_form carry a CSS selector (per action.schema.json). A live LLM run
# proposed expand_nav selectors and the loop navigated to base_url + "<selector>" 12 times.

from authoring.explore import dispatch


def test_dispatch_follow_link_and_visit_api_navigate():
    assert dispatch({"action": "follow_link", "target": {"path": "/#/about"}}) == ("goto", "/#/about")
    assert dispatch({"action": "visit_api", "target": {"method": "GET", "path": "/rest/languages"}}) \
        == ("goto", "/rest/languages")


def test_dispatch_expand_nav_and_submit_form_click_selector():
    assert dispatch({"action": "expand_nav", "target": {"selector": "button#navbarAccount"}}) \
        == ("click", "button#navbarAccount")
    assert dispatch({"action": "submit_form", "target": {"selector": "#searchForm"}}) \
        == ("click", "#searchForm")


def test_dispatch_selector_action_never_navigates_and_path_action_never_clicks():
    # a selector on a navigation action, or a path on a click action, is not executable
    assert dispatch({"action": "expand_nav", "target": {"path": "/#/about"}}) is None
    assert dispatch({"action": "follow_link", "target": {"selector": "nav a"}}) is None
    assert dispatch({"action": "stop"}) is None


# ---- parse_action_text: tolerate prose / fences / trailing text around the JSON ------------
# A live run had the model return a valid object followed by extra text ("Extra data: line 3");
# strict json.loads threw the whole step to the fallback. Mirror generate.parse_plan_text.

from authoring.explore import parse_action_text


def test_parse_action_text_plain():
    assert parse_action_text('{"action": "stop"}') == {"action": "stop"}


def test_parse_action_text_strips_fences_and_trailing_prose():
    text = '```json\n{"action":"follow_link","target":{"path":"/#/about"}}\n```\nI chose this because...'
    assert parse_action_text(text)["target"]["path"] == "/#/about"


def test_parse_action_text_takes_first_object_when_two_are_emitted():
    text = '{"action":"visit_api","target":{"method":"GET","path":"/rest/x"}}\n{"action":"stop"}'
    assert parse_action_text(text)["action"] == "visit_api"


def test_parse_action_text_rejects_no_json():
    import pytest
    with pytest.raises(ValueError):
        parse_action_text("no json here")


# ---- the deterministic proposer reads forms too, once links run out ---------------------

def test_fallback_submits_a_read_only_form_when_no_links_remain():
    obs = {"url": "/search", "links": [], "api": [],
           "forms": [{"selector": "#search-form [type=submit]", "method": "GET", "fields": ["q"]}]}
    action = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert action["action"] == "submit_form"
    assert action["target"] == {"method": "GET", "selector": "#search-form [type=submit]"}


def test_fallback_prefers_an_unvisited_link_over_a_form():
    obs = {"url": "/", "links": ["/#/about"], "api": [],
           "forms": [{"selector": "#f [type=submit]", "method": "GET"}]}
    assert propose_fallback(obs, visited=set(), scope=SCOPE)["action"] == "follow_link"


def test_fallback_does_not_resubmit_a_form_it_already_used():
    obs = {"url": "/search", "links": [], "api": [],
           "forms": [{"selector": "#f [type=submit]", "method": "GET"}]}
    assert propose_fallback(obs, visited={"#f [type=submit]"}, scope=SCOPE)["action"] == "stop"


def test_fallback_respects_an_app_that_forbids_form_submission():
    obs = {"url": "/search", "links": [], "api": [],
           "forms": [{"selector": "#f [type=submit]", "method": "GET"}]}
    action = propose_fallback(obs, visited=set(), scope=SCOPE, submit_get_forms=False)
    assert action["action"] == "stop"


# ---- forms must be described well enough to actually submit -----------------------------
# Observed live: _observe reported every DVWA form as the bare selector "form", so the loop
# clicked the <form> element (which does nothing) nineteen times and discovered no
# parameters. A form is only useful if the observation carries what to click and how it
# submits.

def test_fallback_clicks_the_submit_control_not_the_form_element():
    obs = {"url": "/search", "links": [], "api": [],
           "forms": [{"selector": "form >> nth=0 >> [type=submit]", "method": "GET",
                      "fields": ["id"]}]}
    a = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert a["target"]["selector"] == "form >> nth=0 >> [type=submit]"
    assert a["target"]["method"] == "GET"


def test_fallback_will_not_submit_a_post_form():
    obs = {"url": "/transfer", "links": [], "api": [],
           "forms": [{"selector": "form [type=submit]", "method": "POST", "fields": ["amount"]}]}
    assert propose_fallback(obs, visited=set(), scope=SCOPE)["action"] == "stop"


def test_fallback_skips_a_form_with_no_submit_control():
    obs = {"url": "/x", "links": [], "api": [],
           "forms": [{"selector": None, "method": "GET", "fields": ["q"]}]}
    assert propose_fallback(obs, visited=set(), scope=SCOPE)["action"] == "stop"


# ---- an action that achieves nothing must not be repeated -------------------------------

from authoring.explore import is_progress


def test_navigating_somewhere_new_is_progress():
    assert is_progress("http://app/a", "http://app/b?id=1", before_links=1, after_links=1)


def test_staying_put_with_nothing_new_is_not_progress():
    assert not is_progress("http://app/a", "http://app/a", before_links=3, after_links=3)


def test_staying_put_but_revealing_links_is_progress():
    # expand_nav legitimately does not navigate; it uncovers routes.
    assert is_progress("http://app/a", "http://app/a", before_links=3, after_links=9)


# ---- filling a form with approved data --------------------------------------------------

from authoring.explore import fill_values


def test_only_fields_the_app_provides_data_for_are_filled():
    assert fill_values(["email", "csrf_token", "comment"],
                       {"email": "dast@example.test", "comment": "hello"}) == [
        ("email", "dast@example.test"), ("comment", "hello")]


def test_nothing_is_invented_when_no_test_data_is_configured():
    assert fill_values(["email", "amount"], {}) == []


def test_a_form_with_no_fields_is_handled():
    assert fill_values(None, {"email": "x@y.test"}) == []
