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
    ok, reason = validate_proposal(
        {"action": "follow_link", "target": {"path": "/#/logout"}}, SCOPE)
    assert not ok and "deny-list" in reason


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


def test_normalize_resolves_page_relative_against_the_page_it_was_seen_on():
    # DVWA's file-inclusion module links "./?page=include.php" and "?page=file1.php"; read against
    # the site root those address /index.php and lose the module entirely.
    page = "http://dvwa/vulnerabilities/fi/"
    assert normalize_href("./?page=include.php", page) == "/vulnerabilities/fi/?page=include.php"
    assert normalize_href("?page=file1.php", page) == "/vulnerabilities/fi/?page=file1.php"
    assert normalize_href("index.php", page) == "/vulnerabilities/fi/index.php"
    assert normalize_href("../exec/", page) == "/vulnerabilities/exec/"


def test_normalize_collapses_dot_segments_in_a_root_relative_href():
    assert normalize_href("/../../vulnerabilities/captcha/",
                          "http://dvwa/vulnerabilities/fi/") == "/vulnerabilities/captcha/"


def test_normalize_keeps_a_hash_route_origin_relative_even_on_a_nested_page():
    assert normalize_href("#/contact", "http://juice:3000/x/y") == "/#/contact"


def test_normalize_keeps_cross_origin_hrefs_absolute_for_the_scope_guard():
    page = "http://dvwa/vulnerabilities/fi/"
    assert normalize_href("//evil.test/x", page) == "http://evil.test/x"
    assert normalize_href("https://evil.test/x", page) == "https://evil.test/x"


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


def test_next_action_normalizes_llm_path_against_the_observed_page(monkeypatch):
    monkeypatch.setattr("authoring.explore.propose_llm",
                        lambda obs, model, api_key: {"action": "follow_link",
                                                     "target": {"method": "GET",
                                                                "path": "./?page=include.php"}})
    obs = {"url": "http://dvwa/vulnerabilities/fi/", "links": [], "forms": [], "api": []}
    action, src = next_action(obs, set(), SCOPE, api_key="k")
    assert src == "llm" and action["target"]["path"] == "/vulnerabilities/fi/?page=include.php"


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


# ---- the model asked for must match the selected provider --------------------------------

def test_next_action_asks_the_provider_for_its_own_default_model(monkeypatch):
    from authoring import explore as explore_mod

    monkeypatch.setenv("LLM_PROVIDER", "copilot")
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    asked = {}

    def fake_propose_llm(observation, model, api_key):
        asked["model"] = model
        return {"action": "follow_link", "target": {"method": "GET", "path": "/#/about"}}

    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(explore_mod, "propose_llm", fake_propose_llm)

    _, source = next_action({"url": "/#/", "links": [], "forms": [], "api": []}, set(), SCOPE)

    assert source == "llm" and asked["model"] == "gpt-5.5"


# ---- a failed LLM path must be loud, and a refused target must not be re-proposed ---------
# Without --require-llm a wrong model id, an expired token or a missing CLI is indistinguishable
# from a deliberate --no-llm run, so a broken provider can scan unnoticed for weeks.

def test_strict_tolerates_a_flaky_reply_but_aborts_a_dead_provider(monkeypatch):
    import pytest
    from authoring import explore as explore_mod
    from authoring.llm_backend import LLMRequiredError, StrictLLM

    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(explore_mod, "propose_llm",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("no JSON object")))
    obs = {"url": "/#/", "links": ["/#/about"], "forms": [], "api": []}
    strict = StrictLLM(max_consecutive=3)

    for _ in range(2):  # a prose answer costs the step, not the run
        action, source = next_action(obs, set(), SCOPE, strict=strict)
        assert source == "fallback" and action["target"]["path"] == "/#/about"
    with pytest.raises(LLMRequiredError):
        next_action(obs, set(), SCOPE, strict=strict)


def test_strict_forgets_failures_once_the_model_answers(monkeypatch):
    from authoring import explore as explore_mod
    from authoring.llm_backend import StrictLLM

    good = {"action": "follow_link", "target": {"method": "GET", "path": "/#/about"}}
    replies = [RuntimeError("no JSON object"), RuntimeError("no JSON object"), good]
    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: True)

    def flaky(*_a, **_k):
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(explore_mod, "propose_llm", flaky)
    obs = {"url": "/#/", "links": ["/#/about"], "forms": [], "api": []}
    strict = StrictLLM(max_consecutive=3)
    for _ in range(3):
        next_action(obs, set(), SCOPE, strict=strict)
    assert strict.consecutive == 0 and strict.successes == 1
    strict.finish()  # the model drove a step: not a broken provider


def test_strict_finish_raises_when_the_model_never_drove_a_step():
    import pytest
    from authoring.llm_backend import LLMRequiredError, StrictLLM

    strict = StrictLLM(max_consecutive=99)
    strict.failure(RuntimeError("no JSON object"))
    with pytest.raises(LLMRequiredError):
        strict.finish()


def test_strict_finish_is_silent_on_a_clean_run():
    from authoring.llm_backend import StrictLLM

    StrictLLM().finish()  # nothing attempted, nothing failed


def test_strict_raises_immediately_when_the_provider_is_not_available(monkeypatch):
    import pytest
    from authoring import explore as explore_mod
    from authoring.llm_backend import LLMRequiredError, StrictLLM

    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: False)
    with pytest.raises(LLMRequiredError):
        next_action({"url": "/#/", "links": [], "forms": [], "api": []}, set(), SCOPE,
                    strict=StrictLLM())


def test_strict_still_falls_back_on_a_policy_rejection(monkeypatch):
    # A refused action is the safety layer working, not a broken provider: keep exploring.
    from authoring import explore as explore_mod
    from authoring.llm_backend import StrictLLM

    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(explore_mod, "propose_llm",
                        lambda *_a, **_k: {"action": "follow_link", "target": {"path": "/#/logout"}})
    obs = {"url": "/#/", "links": ["/#/about"], "forms": [], "api": []}
    strict = StrictLLM()
    action, source = next_action(obs, set(), SCOPE, strict=strict)
    assert source == "fallback" and action["target"]["path"] == "/#/about"
    strict.finish()


def test_rejected_targets_are_collected_for_the_next_prompt(monkeypatch):
    from authoring import explore as explore_mod

    monkeypatch.setattr(explore_mod.llm_backend, "available", lambda api_key=None: True)
    monkeypatch.setattr(explore_mod, "propose_llm",
                        lambda *_a, **_k: {"action": "follow_link", "target": {"path": "/#/logout"}})
    rejected: set[str] = set()
    next_action({"url": "/#/", "links": [], "forms": [], "api": []}, set(), SCOPE,
                rejected=rejected)
    assert rejected == {"/#/logout"}


def test_propose_llm_tells_the_model_what_policy_forbids(monkeypatch):
    from authoring import explore as explore_mod

    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["system"], seen["user"] = system, user
        return '{"action":"stop"}'

    monkeypatch.setattr(explore_mod.llm_backend, "complete", fake_complete)
    explore_mod.propose_llm({"url": "/", "forbidden": ["logout"], "rejected": ["/#/logout"]},
                            "m", "k")
    assert "forbidden" in seen["system"] and "rejected" in seen["system"]
    assert "/#/logout" in seen["user"]
