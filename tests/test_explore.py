"""Objective tests for the exploration loop's pure decision logic (Phase B).

The browser loop itself is validated by running it (fallback live; LLM path with a key). Here we
pin the parts that decide WHAT runs: schema+policy validation of a proposal, the deterministic
fallback proposer, and next_action's fallback when no LLM key is present. Oracle: hand-built
observations/actions with known-correct answers.
"""

import sys
import types

from authoring.explore import (
    field_selector,
    form_fill_plan,
    next_action,
    propose_fallback,
    validate_proposal,
)

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


def test_dispatch_expand_nav_clicks_and_submit_form_submits():
    assert dispatch({"action": "expand_nav", "target": {"selector": "button#navbarAccount"}}) \
        == ("click", "button#navbarAccount")
    # a form is filled and submitted, not clicked: clicking a <form> does nothing
    assert dispatch({"action": "submit_form", "target": {"selector": "#searchForm"}}) \
        == ("submit", "#searchForm")


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


def test_an_unparseable_reply_reports_what_the_model_actually_said():
    import pytest
    from authoring.explore import parse_action_text

    with pytest.raises(ValueError, match="I cannot help with that"):
        parse_action_text("I cannot help with that request.")


# ---- controlled mutation: approved test data turns an allow-listed form into a submit ----

LESSON = {
    "url": "http://webgoat:8083/WebGoat/SqlInjection.lesson",
    "links": [],
    "api": [],
    "forms": [
        {"selector": "form >> nth=0", "path": "/WebGoat/SqlInjection/attack2",
         "method": "POST", "fields": ["query"]},
    ],
}
WG_SCOPE = {"app_id": "webgoat", "fqdn_allow_list": ["webgoat"],
            "avoid_action_list": ["logout", "reset", "delete"]}


def test_form_fill_plan_takes_only_fields_the_operator_approved():
    form = {"fields": ["query", "secret_token"]}
    assert form_fill_plan(form, {"query": "x"}) == [("query", "x")]


def test_field_selector_chains_so_a_positional_form_selector_survives():
    assert field_selector("form >> nth=2", "query") == 'form >> nth=2 >> [name="query"]'


def test_fallback_submits_an_allow_listed_form_once_it_has_test_data():
    action = propose_fallback(LESSON, set(), WG_SCOPE,
                              safe_forms=["/WebGoat/SqlInjection/attack2"],
                              test_data={"query": "SELECT 1"})
    assert action["action"] == "submit_form"
    assert action["target"]["path"] == "/WebGoat/SqlInjection/attack2"
    assert action["target"]["selector"] == "form >> nth=0"


def test_fallback_will_not_submit_a_form_that_is_not_allow_listed():
    action = propose_fallback(LESSON, set(), WG_SCOPE, safe_forms=[],
                              test_data={"query": "SELECT 1"})
    assert action["action"] == "stop"


def test_fallback_will_not_submit_an_allow_listed_form_with_no_approved_data():
    """The allow-list says where a write may go; test data says what it may carry. Both or none."""
    action = propose_fallback(LESSON, set(), WG_SCOPE,
                              safe_forms=["/WebGoat/SqlInjection/attack2"], test_data={})
    assert action["action"] == "stop"


def test_fallback_reads_before_it_writes():
    obs = dict(LESSON, links=["/WebGoat/start.mvc"])
    action = propose_fallback(obs, set(), WG_SCOPE,
                              safe_forms=["/WebGoat/SqlInjection/attack2"],
                              test_data={"query": "SELECT 1"})
    assert action["action"] == "follow_link"


# ---- the allow-list has to be visible to the proposer that is asked to respect it --------

from authoring import explore as explore_mod


class _FakePage:
    """The slice of the Playwright page _observe uses: a url and evaluate()."""

    def __init__(self, url: str, forms: list[dict]):
        self.url = url
        self._forms = forms

    def evaluate(self, expr: str):
        return list(self._forms) if "querySelectorAll('form')" in expr else []


def test_an_observed_form_says_whether_it_may_be_submitted():
    """A model told to obey an allow-list it cannot see complies by never submitting."""
    page = _FakePage("http://webgoat:8083/WebGoat/SqlInjection.lesson", [
        {"selector": "form >> nth=0", "path": "/WebGoat/SqlInjection/attack2",
         "method": "POST", "fields": ["query"]},
        {"selector": "form >> nth=1", "path": "/WebGoat/SqlInjection/attack3",
         "method": "POST", "fields": ["query"]},
    ])
    obs = explore_mod._observe(page, "http://webgoat:8083", [], {"query": "SELECT 1"},
                               safe_forms=["/WebGoat/SqlInjection/attack2"])
    assert [f["submittable"] for f in obs["forms"]] == [True, False]


def test_an_allow_listed_form_with_no_approved_data_is_not_submittable():
    page = _FakePage("http://webgoat:8083/WebGoat/SqlInjection.lesson", [
        {"selector": "form >> nth=0", "path": "/WebGoat/SqlInjection/attack2",
         "method": "POST", "fields": ["query"]},
    ])
    obs = explore_mod._observe(page, "http://webgoat:8083", [], {},
                               safe_forms=["/WebGoat/SqlInjection/attack2"])
    assert obs["forms"][0]["submittable"] is False


def test_propose_llm_tells_the_model_a_submittable_form_is_not_a_reason_to_stop(monkeypatch):
    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["system"] = system
        return '{"action":"stop"}'

    monkeypatch.setattr(explore_mod.llm_backend, "complete", fake_complete)
    explore_mod.propose_llm({"url": "/", "forms": [], "forbidden": [], "rejected": []}, "m", "k")
    assert "submittable" in seen["system"]
    assert "Do not stop while one remains" in seen["system"]


def test_a_walk_takes_the_allow_list_from_the_app_config():
    """dast author passes no allow-list: taken from the config, or every approved form is refused."""
    config = {"explore": {"safe_forms": ["/WebGoat/SqlInjection/attack2"]}}
    assert explore_mod.effective_safe_forms(None, config) == ["/WebGoat/SqlInjection/attack2"]


def test_an_explicit_empty_allow_list_is_honoured_over_the_config():
    config = {"explore": {"safe_forms": ["/WebGoat/SqlInjection/attack2"]}}
    assert explore_mod.effective_safe_forms([], config) == []
    assert explore_mod.effective_safe_forms(None, None) == []


def test_a_submittable_form_is_remembered_against_the_page_it_was_seen_on():
    """Reading comes first and navigates away: without this the forms are never reachable."""
    obs = {"url": "http://webgoat:8083/WebGoat/SqlInjection.lesson",
           "forms": [{"path": "/WebGoat/SqlInjection/attack2", "submittable": True},
                     {"path": "/WebGoat/SqlInjection/attack3", "submittable": True},
                     {"path": "/WebGoat/other", "submittable": False}]}
    here = explore_mod.page_path(obs["url"], "http://webgoat:8083")
    assert here == "/WebGoat/SqlInjection.lesson"
    pending = explore_mod.deferred_submits([], obs, here, set(), set())
    assert pending == [(here, "/WebGoat/SqlInjection/attack2"),
                       (here, "/WebGoat/SqlInjection/attack3")]


def test_a_posted_or_already_revisited_form_is_not_queued_again():
    obs = {"url": "http://webgoat:8083/WebGoat/SqlInjection.lesson",
           "forms": [{"path": "/WebGoat/SqlInjection/attack2", "submittable": True},
                     {"path": "/WebGoat/SqlInjection/attack3", "submittable": True}]}
    here = "/WebGoat/SqlInjection.lesson"
    pending = explore_mod.deferred_submits(
        [], obs, here,
        submitted={"/WebGoat/SqlInjection/attack2"},
        offered={(here, "/WebGoat/SqlInjection/attack3")})
    assert pending == []


def test_a_second_form_on_an_already_revisited_page_is_still_queued():
    """`offered` is per (page, endpoint): one refused form must not strand its neighbours."""
    here = "/WebGoat/SqlInjection.lesson"
    obs = {"url": "http://webgoat:8083" + here,
           "forms": [{"path": "/WebGoat/SqlInjection/attack2", "submittable": True},
                     {"path": "/WebGoat/SqlInjection/attack3", "submittable": True}]}
    pending = explore_mod.deferred_submits(
        [], obs, here, submitted=set(),
        offered={(here, "/WebGoat/SqlInjection/attack2")})
    assert pending == [(here, "/WebGoat/SqlInjection/attack3")]


# ---- the revisit, through the loop ------------------------------------------------------

class _LoopPage:
    """Enough of a Playwright page to drive explore(): two pages, forms on only one of them."""

    PAGES = {
        "/lesson": {"links": ["/data.json"],
                    "forms": [{"selector": "form >> nth=0", "path": "/lesson/attack",
                               "method": "POST", "fields": ["query"]}]},
        "/data.json": {"links": [], "forms": []},
    }

    def __init__(self, base: str):
        self._base = base
        self.url = base + "/lesson"
        self.filled: list[tuple[str, str]] = []
        self.submitted: list[str] = []

    def _here(self):
        return self.PAGES.get(self.url[len(self._base):], {"links": [], "forms": []})

    def route(self, *a, **k): pass

    def on(self, *a, **k): pass

    def goto(self, url, **k): self.url = url

    def evaluate(self, expr):
        here = self._here()
        return [dict(f) for f in here["forms"]] if "querySelectorAll('form')" in expr \
            else list(here["links"])

    def fill(self, selector, value, **k): self.filled.append((selector, value))

    def eval_on_selector(self, selector, _script): self.submitted.append(selector)

    def wait_for_load_state(self, *a, **k): pass

    def click(self, *a, **k): pass


def _fake_playwright(page):
    """A sync_playwright() stand-in handing explore() the one page above."""
    context = types.SimpleNamespace(new_page=lambda: page, close=lambda: None)
    browser = types.SimpleNamespace(new_context=lambda **k: context, close=lambda: None)
    pw = types.SimpleNamespace(chromium=types.SimpleNamespace(launch=lambda **k: browser))


    class _Manager:
        def __enter__(self): return pw

        def __exit__(self, *exc): return False

    return _Manager


def test_the_walk_returns_to_the_form_it_read_its_way_past(monkeypatch):
    """The whole point: reading leaves /lesson, and the submit still happens."""
    base = "http://app:8080"
    page = _LoopPage(base)
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore_mod, "prove_auth_live",
                        lambda *a, **k: {"alive": True, "reason": "ok"})

    trace, _guard = explore_mod.explore(
        "app", base, {}, ["/lesson"], {"app_id": "app", "fqdn_allow_list": ["app"]},
        use_llm=False, max_pages=10,
        config={"base_url": base, "auth": {"proof": {"selector": "#ok"}},
                "explore": {"safe_forms": ["/lesson/attack"],
                            "test_data": {"query": "SELECT 1"}}})

    submits = [ev for ev in trace["interactions"] if ev.get("type") == "submit"]
    assert [ev["selector"] for ev in submits] == ["form >> nth=0"]
    assert submits[0]["fields"] == ["query"]
    assert page.filled == [('form >> nth=0 >> [name="query"]', "SELECT 1")]
    # and it happened after the walk had already left the page the form was on
    assert page.url.endswith("/lesson")


# ---- inferred fields: the planner supplies content, the operator permission ---------------

INFERRED = {"answer": {"pattern": "^[0-9]{1,3}$", "max_length": 3}}
GATE_SCOPE = {"app_id": "app", "fqdn_allow_list": ["app"], "avoid_action_list": ["logout"]}


def test_a_value_for_an_operator_inferable_field_is_permitted():
    assert explore_mod.vet_values({"answer": "13"}, INFERRED)[0] is True


def test_a_value_for_a_field_nobody_declared_is_refused():
    ok, reason = explore_mod.vet_values({"token": "9:4:abc"}, INFERRED)
    assert not ok and "not operator-inferable" in reason


def test_a_value_outside_the_operators_shape_is_refused():
    assert not explore_mod.vet_values({"answer": "' OR 1=1 --"}, INFERRED)[0]
    assert not explore_mod.vet_values({"answer": "1234"}, INFERRED)[0]
    assert not explore_mod.vet_values({"answer": 13}, INFERRED)[0]


def test_a_submit_carrying_an_approved_shape_passes_validation():
    action = {"action": "submit_form",
              "target": {"method": "POST", "path": "/gate", "selector": "form >> nth=0",
                         "values": {"answer": "13"}}}
    ok, _reason = explore_mod.validate_proposal(action, GATE_SCOPE, safe_forms=["/gate"],
                                                allow_writes=True, inferred=INFERRED)
    assert ok


def test_a_submit_carrying_an_unpermitted_value_is_refused_before_it_runs():
    action = {"action": "submit_form",
              "target": {"method": "POST", "path": "/gate", "selector": "form >> nth=0",
                         "values": {"answer": "nil"}}}
    ok, reason = explore_mod.validate_proposal(action, GATE_SCOPE, safe_forms=["/gate"],
                                               allow_writes=True, inferred=INFERRED)
    assert not ok and "approved shape" in reason


def test_values_on_a_read_action_are_refused():
    action = {"action": "follow_link", "target": {"method": "GET", "path": "/home",
                                                  "values": {"answer": "13"}}}
    assert not explore_mod.validate_proposal(action, GATE_SCOPE, inferred=INFERRED)[0]


def test_an_inferred_value_fills_the_field_the_operator_left_open():
    form = {"fields": ["token", "answer", "note"]}
    plan = form_fill_plan(form, {"note": "dast-test"}, {"answer": "13"}, INFERRED)
    assert plan == [("answer", "13"), ("note", "dast-test")]
    assert explore_mod.inferred_fields_of(plan, {"note": "dast-test"}) == ["answer"]


def test_operator_data_wins_over_an_inferred_value_for_the_same_field():
    form = {"fields": ["answer"]}
    assert form_fill_plan(form, {"answer": "7"}, {"answer": "13"}, INFERRED) == [("answer", "7")]


def test_an_unpermitted_value_fills_nothing_at_all():
    """Fail closed: a plan cannot smuggle a payload in beside a legitimate value."""
    form = {"fields": ["answer", "note"]}
    plan = form_fill_plan(form, {"note": "dast-test"},
                          {"answer": "13", "note": "' OR 1=1 --"}, INFERRED)
    assert plan == [("note", "dast-test")]


def test_a_form_with_only_an_inferable_field_is_submittable():
    """The gate case: nothing in test_data, so without this the model is told not to try."""
    page = _FakePage("http://app:8080/gate", [
        {"selector": "form >> nth=0", "path": "/gate", "method": "POST",
         "fields": ["token", "answer"]},
    ])
    obs = explore_mod._observe(page, "http://app:8080", [], {}, safe_forms=["/gate"],
                               inferred=INFERRED)
    form = obs["forms"][0]
    assert form["fillable"] is False
    assert form["submittable"] is True
    assert list(form["inferable"]) == ["answer"]


def test_a_form_off_the_allow_list_is_not_submittable_however_inferable():
    page = _FakePage("http://app:8080/gate", [
        {"selector": "form >> nth=0", "path": "/elsewhere", "method": "POST",
         "fields": ["answer"]},
    ])
    obs = explore_mod._observe(page, "http://app:8080", [], {}, safe_forms=["/gate"],
                               inferred=INFERRED)
    assert obs["forms"][0]["submittable"] is False


def test_the_deterministic_proposer_does_not_invent_a_value_for_an_inferable_field():
    """It has no way to read the question, and guessing would make the comparison dishonest."""
    observation = {"url": "http://app:8080/gate", "links": [], "api": [],
                   "forms": [{"selector": "form >> nth=0", "path": "/gate", "method": "POST",
                              "fields": ["answer"], "submittable": True,
                              "inferable": INFERRED}]}
    assert propose_fallback(observation, set(), GATE_SCOPE,
                            safe_forms=["/gate"], test_data={})["action"] == "stop"


def test_the_model_is_told_what_an_inferable_field_is_and_what_bounds_it(monkeypatch):
    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["system"] = system
        return '{"action":"stop"}'

    monkeypatch.setattr(explore_mod.llm_backend, "complete", fake_complete)
    explore_mod.propose_llm({"url": "/", "forms": [], "forbidden": [], "rejected": []}, "m", "k")
    assert "inferable" in seen["system"]
    assert "target.values" in seen["system"]
    assert "never guess at a field that is not inferable" in seen["system"]


# ---- the frontier: a link is not forgotten when the walk moves on -------------------------

def test_a_link_seen_earlier_stays_proposable():
    obs = {"url": "http://app:8080/profile", "links": ["/home"], "forms": []}
    frontier = explore_mod.remaining_links(["/gate"], obs, {"/home", "/profile"}, GATE_SCOPE)
    assert frontier == ["/gate"]


def test_the_frontier_drops_what_has_since_been_visited_and_keeps_order():
    obs = {"url": "http://app:8080/home", "links": ["/profile", "/gate", "/home"], "forms": []}
    frontier = explore_mod.remaining_links([], obs, {"/home"}, GATE_SCOPE)
    assert frontier == ["/profile", "/gate"]
    obs2 = {"url": "http://app:8080/profile", "links": [], "forms": []}
    assert explore_mod.remaining_links(frontier, obs2, {"/home", "/profile"},
                                       GATE_SCOPE) == ["/gate"]


def test_the_fallback_follows_a_remembered_link_rather_than_stopping():
    obs = {"url": "http://app:8080/profile", "links": [], "forms": [],
           "unvisited": ["/gate"]}
    action = explore_mod.propose_fallback(obs, {"/home", "/profile"}, GATE_SCOPE)
    assert action["action"] == "follow_link"
    assert action["target"]["path"] == "/gate"


def test_the_llm_is_told_the_frontier_is_proposable(monkeypatch):
    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["system"] = system
        return '{"action": "stop"}'

    monkeypatch.setattr(explore_mod.llm_backend, "complete", fake_complete)
    explore_mod.propose_llm({"url": "u", "links": [], "forms": [], "unvisited": ["/gate"]}, "m")
    assert "`unvisited`" in seen["system"]


class _BranchPage(_LoopPage):
    """Two links off the landing page, and the second one is where the form is."""

    PAGES = {
        "/home": {"links": ["/profile", "/gate"], "forms": []},
        "/profile": {"links": ["/home"], "forms": []},
        "/gate": {"links": [], "forms": [{"selector": "form >> nth=0", "path": "/gate",
                                          "method": "POST", "fields": ["token", "answer"]}]},
    }


def test_the_walk_follows_the_second_branch_instead_of_stopping_on_a_dead_end(monkeypatch):
    """The semgate failure: /profile is a dead end, and /gate was never read at all."""
    base = "http://app:8080"
    page = _BranchPage(base)
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore_mod, "prove_auth_live",
                        lambda *a, **k: {"alive": True, "reason": "ok"})

    trace, _guard = explore_mod.explore(
        "app", base, {}, ["/home"], {"app_id": "app", "fqdn_allow_list": ["app"]},
        use_llm=False, max_pages=10,
        config={"base_url": base, "auth": {"proof": {"selector": "#ok"}},
                "explore": {"safe_forms": ["/gate"], "write_mode": "allow",
                            "test_data": {"note": "dast-test"},
                            "inferred_fields": {"answer": {"pattern": "^[0-9]{1,3}$"}}}})

    assert "/gate" in [ev.get("url", "")[len(base):] for ev in trace["interactions"]
                       if ev.get("type") == "goto"]
    # the deterministic arm reaches the gate and does not invent an answer for it
    assert [ev for ev in trace["interactions"]
            if ev.get("type") == "submit" and ev.get("inferred")] == []


def test_a_link_on_several_pages_is_remembered_once():
    """The frontier carries forward, so a link seen again is already in it, not appended twice."""
    nav = {"links": ["/gate", "/profile"], "forms": []}
    frontier = explore_mod.remaining_links([], dict(nav, url="http://app:8080/home"),
                                           {"/home"}, GATE_SCOPE)
    frontier = explore_mod.remaining_links(frontier, dict(nav, url="http://app:8080/profile"),
                                           {"/home", "/profile"}, GATE_SCOPE)
    assert frontier == ["/gate"]


def test_a_queued_link_reached_another_way_leaves_the_frontier():
    frontier = ["/gate", "/profile"]
    obs = {"url": "http://app:8080/gate", "links": [], "forms": []}
    assert explore_mod.remaining_links(frontier, obs, {"/home", "/gate"},
                                       GATE_SCOPE) == ["/profile"]


# ---- was the submit actually accepted ---------------------------------------------------

def test_the_status_of_the_response_a_submit_caused_is_reported():
    responses = [{"method": "GET", "url": "http://app:8080/gate", "status": 200},
                 {"method": "POST", "url": "http://app:8080/gate", "status": 200}]
    assert explore_mod.submit_outcome(responses, "/gate") == {"status": 200, "accepted": True}


def test_a_refused_submit_is_not_counted_as_accepted():
    responses = [{"method": "POST", "url": "http://app:8080/gate", "status": 400}]
    assert explore_mod.submit_outcome(responses, "/gate") == {"status": 400, "accepted": False}


def test_the_latest_response_to_the_path_wins_and_reads_are_ignored():
    responses = [{"method": "POST", "url": "http://app:8080/gate", "status": 400},
                 {"method": "POST", "url": "http://app:8080/gate", "status": 200},
                 {"method": "GET", "url": "http://app:8080/gate", "status": 500}]
    assert explore_mod.submit_outcome(responses, "/gate")["accepted"] is True


def test_an_unobserved_submit_claims_nothing():
    """No response seen is reported as unknown, not as success."""
    assert explore_mod.submit_outcome([], "/gate") == {}
    assert explore_mod.submit_outcome(
        [{"method": "POST", "url": "http://app:8080/other", "status": 200}], "/gate") == {}


class _RefusingPage(_LoopPage):
    """Accepts the post, then answers 400 -- the shape of a validating form told no."""

    def __init__(self, base: str):
        super().__init__(base)
        self._handlers: dict[str, object] = {}

    def on(self, event, handler):
        self._handlers[event] = handler

    def eval_on_selector(self, selector, script):
        super().eval_on_selector(selector, script)
        handler = self._handlers.get("response")
        if handler:
            handler(types.SimpleNamespace(
                url=self._base + "/lesson/attack", status=400,
                request=types.SimpleNamespace(method="POST")))


def test_a_submit_the_app_refused_is_recorded_as_refused(monkeypatch):
    base = "http://app:8080"
    page = _RefusingPage(base)
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore_mod, "prove_auth_live",
                        lambda *a, **k: {"alive": True, "reason": "ok"})

    trace, _guard = explore_mod.explore(
        "app", base, {}, ["/lesson"], {"app_id": "app", "fqdn_allow_list": ["app"]},
        use_llm=False, max_pages=10,
        config={"base_url": base, "auth": {"proof": {"selector": "#ok"}},
                "explore": {"safe_forms": ["/lesson/attack"],
                            "test_data": {"query": "SELECT 1"}}})

    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert submit["status"] == 400
    assert submit["accepted"] is False


def test_a_redirect_after_a_post_is_acceptance_and_a_forbidden_is_not():
    """3xx took the submission; 4xx of any flavour means the walk did not get past the form."""
    assert explore_mod.submit_outcome(
        [{"method": "POST", "url": "http://app:8080/gate", "status": 303}],
        "/gate") == {"status": 303, "accepted": True}
    for status in (403, 422, 429):
        assert explore_mod.submit_outcome(
            [{"method": "POST", "url": "http://app:8080/gate", "status": status}],
            "/gate") == {"status": status, "accepted": False}


def test_a_query_string_does_not_hide_the_response():
    """Forms are allow-listed by path, so the path is what the response is matched on."""
    assert explore_mod.submit_outcome(
        [{"method": "POST", "url": "http://app:8080/gate?step=2", "status": 200}],
        "/gate")["accepted"] is True
    assert explore_mod.submit_outcome(
        [{"method": "POST", "url": "http://app:8080/gate", "status": 200}],
        "/gate?step=2")["accepted"] is True


def test_an_unreadable_status_is_reported_as_unknown_and_said_out_loud(capsys):
    assert explore_mod.submit_outcome(
        [{"method": "POST", "url": "http://app:8080/gate", "status": None}], "/gate") == {}
    assert "non-integer status" in capsys.readouterr().err


def test_a_response_that_cannot_be_read_does_not_break_the_walk(monkeypatch, capsys):
    """The handler is an event callback: raising out of it would end the run, not a step."""
    base = "http://app:8080"

    class _Broken(_RefusingPage):
        def eval_on_selector(self, selector, script):
            _LoopPage.eval_on_selector(self, selector, script)
            boom = types.SimpleNamespace()  # no .request/.url/.status
            self._handlers["response"](boom)

    page = _Broken(base)
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore_mod, "prove_auth_live",
                        lambda *a, **k: {"alive": True, "reason": "ok"})

    trace, _guard = explore_mod.explore(
        "app", base, {}, ["/lesson"], {"app_id": "app", "fqdn_allow_list": ["app"]},
        use_llm=False, max_pages=10,
        config={"base_url": base, "auth": {"proof": {"selector": "#ok"}},
                "explore": {"safe_forms": ["/lesson/attack"],
                            "test_data": {"query": "SELECT 1"}}})

    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert "accepted" not in submit          # unknown, not assumed
    assert "could not record a response" in capsys.readouterr().err


# ---- the response is waited for around the submit, not after it -------------------------

class _GatePage(_LoopPage):
    """A gate that only reveals what is behind it in the response to the submit itself.

    `expect_response` is the whole point: the submit navigates asynchronously, so a page that
    only updates once the response lands is invisible to anything checked before it.
    """

    PAGES = {
        "/gate": {"links": [], "forms": [{"selector": "form >> nth=0", "path": "/gate/check",
                                          "method": "POST", "fields": ["answer"]}]},
        "/vault": {"links": [], "forms": []},
    }

    def __init__(self, base: str, status: int = 200):
        super().__init__(base)
        self.url = base + "/gate"
        self._status = status
        self._opened = False

    def expect_response(self, predicate, timeout=None):
        page = self

        class _Info:
            @property
            def value(self):
                return types.SimpleNamespace(
                    url=page._base + "/gate/check", status=page._status,
                    request=types.SimpleNamespace(method="POST"))

        class _Manager:
            def __enter__(self):
                return _Info()

            def __exit__(self, *exc):
                # The response lands only now: this is what the old code never waited for.
                if page._status < 400:
                    page.PAGES = dict(page.PAGES,
                                      **{"/gate": dict(page.PAGES["/gate"], links=["/vault"])})
                    page._opened = True
                return False

        return _Manager()


def _run_gate(monkeypatch, page):
    base = page._base
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore_mod, "prove_auth_live",
                        lambda *a, **k: {"alive": True, "reason": "ok"})
    trace, _guard = explore_mod.explore(
        "app", base, {}, ["/gate"], {"app_id": "app", "fqdn_allow_list": ["app"]},
        use_llm=False, max_pages=10,
        config={"base_url": base, "auth": {"proof": {"selector": "#ok"}},
                "explore": {"safe_forms": ["/gate/check"], "test_data": {"answer": "7"}}})
    return trace


def test_the_submit_waits_for_the_response_it_caused(monkeypatch):
    trace = _run_gate(monkeypatch, _GatePage("http://app:8080"))
    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert submit["status"] == 200
    assert submit["accepted"] is True
    # and what the response revealed is then walked, instead of the pre-submit page
    assert "/vault" in [ev.get("url", "")[len("http://app:8080"):]
                        for ev in trace["interactions"] if ev.get("type") == "goto"]


def test_a_gate_that_says_no_is_recorded_as_refused_and_opens_nothing(monkeypatch):
    page = _GatePage("http://app:8080", status=400)
    trace = _run_gate(monkeypatch, page)
    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert (submit["status"], submit["accepted"]) == (400, False)
    assert page._opened is False


class _SilentGatePage(_GatePage):
    """A gate that takes the submit and never answers it."""

    def expect_response(self, predicate, timeout=None):
        page = self

        class _Manager:
            def __enter__(self):
                return types.SimpleNamespace()

            def __exit__(self, *exc):
                page.settled = False
                raise TimeoutError(f"waiting for response failed: timeout {timeout}ms exceeded")

        return _Manager()

    def wait_for_load_state(self, *a, **k):
        self.settled = True


def test_a_submit_that_is_never_answered_is_unknown_and_still_settles(monkeypatch, capsys):
    """A timeout costs the outcome, not the step: the walk must go on, and say why it can't tell."""
    page = _SilentGatePage("http://app:8080")
    trace = _run_gate(monkeypatch, page)
    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert "accepted" not in submit and "status" not in submit
    assert "did not complete" in capsys.readouterr().err
    assert page.settled is True        # the load-state wait is not skipped by the timeout
    assert page.submitted == ["form >> nth=0"]


class _ChattyGatePage(_GatePage):
    """Background traffic in flight while the submit's own response is waited for."""

    OTHERS = [("GET", "/gate/check"),        # a read of the same path
              ("POST", "/telemetry"),        # a write somewhere else
              (None, None)]                  # a response that cannot be read at all

    def expect_response(self, predicate, timeout=None):
        page = self
        page.offered = []

        class _Info:
            @property
            def value(self):
                for method, path in page.OTHERS:
                    if method is None:
                        candidate = types.SimpleNamespace()   # no .request/.url
                    else:
                        candidate = types.SimpleNamespace(
                            url=page._base + path, status=500,
                            request=types.SimpleNamespace(method=method))
                    page.offered.append(predicate(candidate))
                mine = types.SimpleNamespace(
                    url=page._base + "/gate/check", status=200,
                    request=types.SimpleNamespace(method="POST"))
                page.offered.append(predicate(mine))
                return mine

        class _Manager:
            def __enter__(self): return _Info()

            def __exit__(self, *exc): return False

        return _Manager()


def test_only_the_submit_s_own_response_is_accepted_as_its_outcome(monkeypatch, capsys):
    page = _ChattyGatePage("http://app:8080")
    trace = _run_gate(monkeypatch, page)
    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert submit["status"] == 200            # not the 500s in flight alongside it
    assert page.offered == [False, False, False, True]
    assert "unreadable response" in capsys.readouterr().err


def test_a_form_with_no_action_path_falls_back_to_the_listener(monkeypatch):
    """Nothing to match a response on, so the walk submits and reports no outcome rather than
    waiting 10s for a response it cannot identify."""
    page = _GatePage("http://app:8080")
    events: list[dict] = []
    assert explore_mod._submit(page, "form >> nth=0", [("answer", "7")], events, path=None) == {}
    assert page.submitted == ["form >> nth=0"]      # the submit still happened
    assert "status" not in events[-1]
    assert page._opened is False                    # expect_response was never entered
