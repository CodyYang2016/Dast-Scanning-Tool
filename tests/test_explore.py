"""Objective tests for the exploration loop's pure decision logic (Phase B).

The browser loop itself is validated by running it (fallback live; LLM path with a key). Here we
pin the parts that decide WHAT runs: schema+policy validation of a proposal, the deterministic
fallback proposer, and next_action's fallback when no LLM key is present. Oracle: hand-built
observations/actions with known-correct answers.
"""

from authoring import explore
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
    # the fields travel with the action so policy can judge what would be submitted
    assert action["target"] == {"method": "GET", "selector": "#search-form [type=submit]",
                                "field_bindings": ["q"]}


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


# ---- a page is not finished until its inputs have been tried ----------------------------
# Measured on DVWA: exploration VISITED /vulnerabilities/brute/ twice and never submitted its
# form, so ?username= was never discovered and two high-severity findings stayed invisible.
# The cause was priority — the fallback only reached for a form once no unvisited link
# remained, and with 29 pages of links that never happened. A human tester lands on a page,
# tries its inputs, and only then moves on.

def test_a_form_on_the_current_page_outranks_a_link_elsewhere():
    obs = {"url": "/brute", "links": ["/#/about", "/#/contact"], "api": [],
           "forms": [{"selector": "#brute [type=submit]", "method": "GET",
                      "fields": ["username", "password"]}]}
    a = propose_fallback(obs, visited=set(), scope=SCOPE)
    assert a["action"] == "submit_form"


def test_links_are_followed_once_the_page_has_no_untried_forms():
    obs = {"url": "/brute", "links": ["/#/about"], "api": [],
           "forms": [{"selector": "#brute [type=submit]", "method": "GET"}]}
    a = propose_fallback(obs, visited={"#brute [type=submit]"}, scope=SCOPE)
    assert a["action"] == "follow_link" and a["target"]["path"] == "/#/about"


def test_a_page_with_no_form_still_follows_links():
    obs = {"url": "/", "links": ["/#/about"], "api": [], "forms": []}
    assert propose_fallback(obs, visited=set(), scope=SCOPE)["action"] == "follow_link"


# ---- relative hrefs must resolve, or the same route is explored twice -------------------
# DVWA's menu links are "../../vulnerabilities/brute/". Prefixing a slash produced
# /../../vulnerabilities/brute/, which a browser normalizes but the trace does not — so the
# same page entered the index twice, burned two steps of budget, and produced two different
# endpoint_patterns for one route, which would split it across a lifecycle diff.

def test_a_dot_dot_href_resolves_against_the_current_page():
    assert normalize_href("../../vulnerabilities/brute/",
                          "http://dvwa/dvwa/includes/x.php") == "/vulnerabilities/brute/"


def test_a_sibling_relative_href_resolves():
    assert normalize_href("about.php", "http://dvwa/docs/index.php") == "/docs/about.php"


def test_an_absolute_path_is_unchanged_by_resolution():
    assert normalize_href("/vulnerabilities/sqli/", "http://dvwa/index.php") == "/vulnerabilities/sqli/"


def test_a_hash_route_is_unchanged_by_resolution():
    assert normalize_href("#/basket", "http://juice:3000/#/") == "/#/basket"


def test_resolution_keeps_an_off_host_url_absolute_so_scope_can_judge_it():
    assert normalize_href("https://evil.test/x", "http://dvwa/index.php") == "https://evil.test/x"


# ---- one exploration run is a sample, not a measurement ---------------------------------
# Measured on DVWA with identical config: one run reached sqli, sqli_blind, xss_r and fi and
# the scan found 7 highs; the next spent its budget on five instructions.php?doc= variants,
# never reached sqli, and found 2. ZAP itself is deterministic (two scans of one bundle were
# byte-identical), so the variance is the model's route choices. Repeating exploration and
# taking the union costs a minute per pass and removes the coin-flip.

from authoring.explore import merge_traces


def test_merging_unions_the_routes_two_runs_found():
    a = {"app_id": "x", "base_url": "http://x", "hosts": ["x"], "index": ["http://x/a"],
         "interactions": [{"type": "goto", "url": "http://x/a"}], "forms": [], "api": []}
    b = {**a, "index": ["http://x/b"], "interactions": [{"type": "goto", "url": "http://x/b"}]}
    merged = merge_traces([a, b])
    assert merged["index"] == ["http://x/a", "http://x/b"]


def test_merging_does_not_duplicate_a_route_both_runs_found():
    a = {"app_id": "x", "base_url": "http://x", "hosts": ["x"], "index": ["http://x/a"],
         "interactions": [{"type": "goto", "url": "http://x/a"}], "forms": [], "api": []}
    assert merge_traces([a, dict(a)])["index"] == ["http://x/a"]


def test_merging_unions_api_calls_and_hosts():
    a = {"app_id": "x", "base_url": "http://x", "hosts": ["x"], "index": [], "interactions": [],
         "forms": [], "api": [{"method": "GET", "url": "http://x/api/1", "params": []}]}
    b = {**a, "api": [{"method": "GET", "url": "http://x/api/2", "params": []}]}
    merged = merge_traces([a, b])
    assert len(merged["api"]) == 2 and merged["hosts"] == ["x"]


def test_merging_one_trace_returns_it_unchanged():
    a = {"app_id": "x", "base_url": "http://x", "hosts": ["x"], "index": ["http://x/a"],
         "interactions": [], "forms": [], "api": []}
    assert merge_traces([a]) == a


def test_a_repeat_pass_starts_from_what_earlier_passes_already_covered(monkeypatch):
    """Without this, repeated passes re-decide the same way and their union adds nothing."""
    import inspect
    from authoring import explore as mod
    assert "already_seen" in inspect.signature(mod.explore).parameters


# ---- mechanical decisions belong in code, not in a prompt -------------------------------
# The prompt told the model to submit an untried form before following a link. Measured: it
# did so 3 times in 28 pages, walking past sqli, brute and exec without touching their
# inputs. "Is there an untried form here?" needs no judgement, so it stops being a request
# and becomes a rule — the deterministic-first principle from the discovery proposal (§5.2):
# code for the common case, the model for what actually needs semantics.

from authoring.explore import form_key, untried_form


def test_an_untried_form_on_this_page_is_taken_without_asking():
    obs = {"forms": [{"selector": "#f [type=submit]", "method": "GET", "fields": ["id"]}]}
    a = untried_form(obs, visited=set(), scope=SCOPE)
    assert a and a["action"] == "submit_form" and a["target"]["selector"] == "#f [type=submit]"


def test_no_untried_form_means_the_model_decides():
    obs = {"url": "http://app/x", "forms": [{"selector": "#f [type=submit]", "method": "GET"}]}
    assert untried_form(obs, visited={form_key("http://app/x", "#f [type=submit]")},
                        scope=SCOPE) is None
    assert untried_form({"forms": []}, visited=set(), scope=SCOPE) is None


def test_a_form_the_policy_refuses_is_not_taken_automatically():
    # Automation must not become a way around the action policy.
    obs = {"forms": [{"selector": "#f [type=submit]", "method": "POST"}]}
    assert untried_form(obs, visited=set(), scope=SCOPE) is None          # writes denied
    assert untried_form(obs, visited=set(), scope=SCOPE, allow_writes=True) is not None


def test_a_form_is_tracked_per_page_not_globally():
    """Every page's first form has the same selector (`form >> nth=0`), so a global
    visited-set marked them all tried after the first submission — which is why only two or
    three forms were ever submitted per run no matter how the budget was raised."""
    obs = {"url": "http://app/b", "forms": [{"selector": "form >> nth=0", "method": "GET"}]}
    already = {form_key("http://app/a", "form >> nth=0")}      # submitted on a DIFFERENT page
    assert untried_form(obs, visited=already, scope=SCOPE) is not None


def test_the_same_form_on_the_same_page_is_not_resubmitted():
    obs = {"url": "http://app/a", "forms": [{"selector": "form >> nth=0", "method": "GET"}]}
    already = {form_key("http://app/a", "form >> nth=0")}
    assert untried_form(obs, visited=already, scope=SCOPE) is None


def test_a_password_change_form_is_never_taken_automatically():
    """The loop submits untried forms without asking; that must not become a way to change
    a credential. DVWA's CSRF lesson is a password-change form whose submit selector looks
    like any other — it emptied the admin password and broke every later login."""
    obs = {"url": "http://dvwa/vulnerabilities/csrf/",
           "forms": [{"selector": "form >> nth=0 >> [type=submit]", "method": "GET",
                      "fields": ["password_new", "password_conf", "Change"]}]}
    assert untried_form(obs, visited=set(), scope=SCOPE) is None


# ---- W6-12: a page we walked past is a parameter we never tested -----------------------

OBS = {"url": "http://app/sqli/",
       "forms": [{"selector": "form >> nth=0 >> [type=submit]", "method": "GET",
                  "fields": ["id", "Submit"]}]}


def test_a_form_we_have_not_submitted_is_remembered():
    assert explore.unsubmitted_forms(OBS, set()) == {
        explore.form_key("http://app/sqli/", "form >> nth=0 >> [type=submit]"): "http://app/sqli/"}


def test_a_form_we_already_submitted_is_not_remembered():
    key = explore.form_key("http://app/sqli/", "form >> nth=0 >> [type=submit]")
    assert explore.unsubmitted_forms(OBS, {key}) == {}


def test_a_form_with_no_selector_is_not_remembered():
    obs = {"url": "http://app/x", "forms": [{"method": "GET", "fields": ["a"]}]}
    assert explore.unsubmitted_forms(obs, set()) == {}


def test_every_seed_route_is_visited_not_only_the_last():
    # The measured bug: seed routes were all walked before the loop, so only the last one was
    # ever observed. DVWA seeds [index, sqli, xss_r]; xss_r got its form submitted and sqli,
    # holding two high-severity findings on ?id=, was walked straight past.
    queue = ["/index.php", "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/"]
    seen = []
    while (dest := explore.next_destination(queue, {}, set())) is not None:
        seen.append(dest)
        queue.pop(0)
    assert seen == ["/index.php", "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/"]


def test_a_page_left_with_an_unsubmitted_form_is_returned_to():
    pending = {"http://app/sqli/::form >> nth=0": "http://app/sqli/"}
    assert explore.next_destination([], pending, set()) == "http://app/sqli/"


def test_seed_routes_come_before_returning_to_a_left_page():
    pending = {"http://app/sqli/::form >> nth=0": "http://app/sqli/"}
    assert explore.next_destination(["/next"], pending, set()) == "/next"


def test_a_pending_form_that_has_since_been_submitted_is_not_returned_to():
    key = "http://app/sqli/::form >> nth=0"
    assert explore.next_destination([], {key: "http://app/sqli/"}, {key}) is None


def test_nothing_queued_and_nothing_pending_means_ask_the_model():
    assert explore.next_destination([], {}, set()) is None


def test_a_queued_destination_is_proposed_in_a_shape_policy_accepts():
    # Regression: the loop synthesized {"target": "/path"} and every proposal was refused as
    # "not of type 'object'", so exploration stopped after one page.
    scope = {"app_id": "a", "environment_class": "dev", "fqdn_allow_list": ["app"],
             "fqdn_deny_list": [], "avoid_action_list": []}
    for dest in ("/vulnerabilities/sqli/", "http://app/vulnerabilities/sqli/"):
        action = explore.queued_action(dest, "queued entry point")
        ok, reason = explore.validate_proposal(action, scope, [], [], True, False,
                                               page_url="http://app/index.php")
        assert ok, f"{dest}: {reason}"
        assert explore.dispatch(action) == ("goto", dest)


def test_a_form_policy_will_never_allow_is_not_remembered():
    # Measured: a POST form under write_mode=deny stayed pending forever and the loop returned
    # to its page 23 times, spending the whole budget and reaching 6 pages instead of 28.
    obs = {"url": "http://app/exec/",
           "forms": [{"selector": "form >> nth=0 >> [type=submit]", "method": "POST",
                      "fields": ["ip", "Submit"]}]}
    assert explore.unsubmitted_forms(obs, set(), allowed=lambda f: False) == {}


def test_a_form_policy_allows_is_still_remembered():
    assert explore.unsubmitted_forms(OBS, set(), allowed=lambda f: True) != {}


def test_no_predicate_remembers_everything_as_before():
    assert explore.unsubmitted_forms(OBS, set()) != {}
