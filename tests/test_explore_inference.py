"""Inferred form fields, the link frontier and submit outcomes in the exploration loop.

Inference is the one place the planner supplies content rather than a choice, so its bounds are
pinned here: a value is used only for a field the operator declared inferable, only in the
declared shape, and never by the deterministic proposer. The frontier and submit outcomes are
what make the difference measurable: a walk that reaches the form, and a record of whether the
application accepted what was sent. Oracle: hand-built observations, and a fake browser whose
gate accepts exactly one answer.
"""

import sys
import types
from urllib.parse import urlsplit

from authoring import explore

INFERRED = {"answer": {"pattern": "^[0-9]{1,3}$", "max_length": 3}}
SCOPE = {"app_id": "app", "fqdn_allow_list": ["app"], "avoid_action_list": ["logout"]}
GATE_FORM = {"selector": "form >> nth=0 >> [type=submit]", "method": "POST",
             "endpoint": "/gate", "fields": ["token", "answer", "note"],
             "inferable": INFERRED, "prompt": "What is 4 plus 7?"}


def _submit(values):
    return {"action": "submit_form",
            "target": {"method": "POST", "selector": GATE_FORM["selector"], "values": values}}


# ---- the operator's bounds ------------------------------------------------------------------

def test_a_value_for_an_operator_inferable_field_is_permitted():
    assert explore.vet_values({"answer": "13"}, INFERRED)[0] is True


def test_a_value_for_a_field_nobody_declared_is_refused():
    ok, reason = explore.vet_values({"token": "9:4:abc"}, INFERRED)
    assert not ok and "not operator-inferable" in reason


def test_a_value_outside_the_operators_shape_is_refused():
    assert not explore.vet_values({"answer": "' OR 1=1 --"}, INFERRED)[0]
    assert not explore.vet_values({"answer": "1234"}, INFERRED)[0]
    assert not explore.vet_values({"answer": 13}, INFERRED)[0]
    assert not explore.vet_values(["answer"], INFERRED)[0]


def test_with_no_inferred_fields_configured_every_value_is_refused():
    assert not explore.vet_values({"answer": "13"}, None)[0]


def test_a_submit_carrying_an_approved_shape_passes_validation():
    ok, _ = explore.validate_proposal(_submit({"answer": "13"}), SCOPE, allow_writes=True,
                                      inferred=INFERRED)
    assert ok


def test_a_submit_carrying_an_unpermitted_value_is_refused_before_it_runs():
    ok, reason = explore.validate_proposal(_submit({"answer": "nil"}), SCOPE,
                                           allow_writes=True, inferred=INFERRED)
    assert not ok and "approved shape" in reason


def test_values_are_refused_when_the_app_declares_no_inferred_fields():
    ok, reason = explore.validate_proposal(_submit({"answer": "13"}), SCOPE, allow_writes=True)
    assert not ok and "not operator-inferable" in reason


def test_values_on_a_read_action_are_refused():
    action = {"action": "follow_link",
              "target": {"method": "GET", "path": "/home", "values": {"answer": "13"}}}
    ok, reason = explore.validate_proposal(action, SCOPE, inferred=INFERRED)
    assert not ok and "only accepted on submit_form" in reason


def test_values_do_not_bypass_the_write_policy():
    ok, _ = explore.validate_proposal(_submit({"answer": "13"}), SCOPE, inferred=INFERRED)
    assert not ok


def test_an_inferred_value_fills_the_field_the_operator_left_open():
    plan = explore.fill_values(["token", "answer", "note"], {"note": "dast-test"},
                               {"answer": "13"}, INFERRED)
    assert plan == [("answer", "13"), ("note", "dast-test")]


def test_operator_data_wins_over_an_inferred_value_for_the_same_field():
    assert explore.fill_values(["answer"], {"answer": "7"}, {"answer": "13"},
                               INFERRED) == [("answer", "7")]


def test_an_out_of_shape_or_undeclared_value_fills_nothing():
    plan = explore.fill_values(["answer", "token"], {}, {"answer": "abcd", "token": "x"},
                               INFERRED)
    assert plan == []


def test_fill_values_without_inference_is_unchanged():
    assert explore.fill_values(["email", "csrf"], {"email": "a@b.test"}) == [("email", "a@b.test")]


def test_only_fields_outside_test_data_are_inferable():
    assert explore.inferable_fields(["token", "answer", "note"], {"answer": "1"}, INFERRED) == []
    assert explore.inferable_fields(["token", "answer"], {}, INFERRED) == ["answer"]
    assert explore.inferable_fields(["answer"], {}, None) == []


# ---- the deterministic proposer never answers ---------------------------------------------

def test_the_page_local_form_rule_leaves_an_inferable_form_to_the_model():
    obs = {"url": "http://app/gate", "links": [], "api": [], "forms": [GATE_FORM]}
    assert explore.untried_form(obs, set(), SCOPE, allow_writes=True) is None


def test_the_fallback_does_not_invent_a_value_for_an_inferable_field():
    obs = {"url": "http://app/gate", "links": [], "api": [], "forms": [GATE_FORM]}
    assert explore.propose_fallback(obs, set(), SCOPE, allow_writes=True)["action"] == "stop"


def test_a_form_without_inferable_fields_is_still_submitted_deterministically():
    form = {k: v for k, v in GATE_FORM.items() if k not in ("inferable", "prompt")}
    obs = {"url": "http://app/gate", "links": [], "api": [], "forms": [form]}
    assert explore.untried_form(obs, set(), SCOPE, allow_writes=True) is not None


# ---- the model is told, and only when it matters --------------------------------------------

def _capture_system(monkeypatch):
    seen = {}

    def fake_complete(system, user, model, **kwargs):
        seen["system"] = system
        return '{"action": "stop"}'

    monkeypatch.setattr(explore.llm_backend, "complete", fake_complete)
    return seen


def test_the_model_is_told_what_an_inferable_field_is_and_what_bounds_it(monkeypatch):
    seen = _capture_system(monkeypatch)
    explore.propose_llm({"url": "/gate", "forms": [GATE_FORM], "links": []}, "m")
    assert "target.values" in seen["system"] and "`pattern`" in seen["system"]


def test_an_app_without_inferred_fields_gets_the_same_prompt_as_before(monkeypatch):
    seen = _capture_system(monkeypatch)
    explore.propose_llm({"url": "/", "forms": [{"selector": "#f", "fields": ["q"]}],
                         "links": []}, "m")
    assert "submit_form and target.values" not in seen["system"]
    assert "`unvisited` lists" not in seen["system"]


def test_the_model_is_told_the_frontier_is_proposable(monkeypatch):
    seen = _capture_system(monkeypatch)
    explore.propose_llm({"url": "/", "forms": [], "links": [], "unvisited": ["/gate"]}, "m")
    assert "`unvisited`" in seen["system"]


def test_a_model_answer_in_shape_is_taken(monkeypatch):
    monkeypatch.setattr(explore.llm_backend, "available", lambda *a, **k: True)
    monkeypatch.setattr(explore, "propose_llm", lambda *a, **k: _submit({"answer": "11"}))
    obs = {"url": "http://app/gate", "links": [], "api": [], "forms": [GATE_FORM]}
    action, src = explore.next_action(obs, set(), SCOPE, allow_writes=True, inferred=INFERRED)
    assert src == "llm" and action["target"]["values"] == {"answer": "11"}


def test_a_model_answer_out_of_shape_is_rejected_and_falls_back(monkeypatch):
    monkeypatch.setattr(explore.llm_backend, "available", lambda *a, **k: True)
    monkeypatch.setattr(explore, "propose_llm",
                        lambda *a, **k: _submit({"answer": "1; DROP TABLE"}))
    obs = {"url": "http://app/gate", "links": [], "api": [], "forms": [GATE_FORM]}
    rejected: set[str] = set()
    action, src = explore.next_action(obs, set(), SCOPE, allow_writes=True, inferred=INFERRED,
                                      rejected=rejected)
    assert src == "fallback" and action["action"] == "stop"
    assert GATE_FORM["selector"] in rejected


# ---- what the observation carries -----------------------------------------------------------

class _ObservedPage:
    def __init__(self, url, forms):
        self.url, self._forms = url, forms

    def evaluate(self, expr):
        return [] if "a[href]" in expr else [dict(f) for f in self._forms]


RAW_GATE = {"selector": "form >> nth=0 >> [type=submit]", "method": "POST", "action": "/gate",
            "prompt": "What is 4 plus 7?", "labels": {"answer": "What is 4 plus 7?", "note": ""},
            "fields": ["token", "answer", "note"]}


def test_an_inferable_form_carries_its_bounds_prompt_and_labels():
    obs = explore._observe(_ObservedPage("http://app/gate", [RAW_GATE]), "http://app", [],
                           {"note": "dast-test"}, INFERRED)
    form = obs["forms"][0]
    assert form["inferable"] == INFERRED
    assert form["prompt"] == "What is 4 plus 7?"
    assert form["labels"] == {"answer": "What is 4 plus 7?"}
    assert form["endpoint"] == "/gate"


def test_a_form_with_nothing_to_infer_carries_no_prompt():
    obs = explore._observe(_ObservedPage("http://app/gate", [RAW_GATE]), "http://app", [],
                           {"note": "dast-test", "answer": "1"}, INFERRED)
    assert set(obs["forms"][0]) == {"selector", "method", "fields", "endpoint"}


def test_a_script_handled_form_has_no_endpoint_to_wait_for():
    raw = dict(RAW_GATE, action=None, method="GET")
    obs = explore._observe(_ObservedPage("http://app/#/search", [raw]), "http://app", [])
    assert "endpoint" not in obs["forms"][0]


def test_a_form_endpoint_resolves_against_its_page():
    assert explore.form_endpoint("../save", "POST", "http://app/a/b/page") == "/a/save"
    assert explore.form_endpoint("", "POST", "http://app/gate?x=1") == "/gate"
    assert explore.form_endpoint("#", "GET", "http://app/sqli/") == "/sqli/"
    assert explore.form_endpoint(None, "GET", "http://app/") is None


# ---- the frontier ---------------------------------------------------------------------------

def test_a_link_seen_earlier_stays_proposable_in_order():
    obs = {"url": "http://app/profile", "links": ["/home"]}
    assert explore.remaining_links(["/profile", "/gate", "/x"], obs, {"/home", "/profile"},
                                   SCOPE) == ["/gate", "/x"]


def test_the_frontier_leaves_out_the_current_pages_links_and_off_scope_ones():
    obs = {"url": "http://app/home", "links": ["/gate"]}
    assert explore.remaining_links(["/gate", "https://evil.test/x"], obs, set(), SCOPE) == []


def test_the_fallback_follows_a_remembered_link_rather_than_stopping():
    obs = {"url": "http://app/profile", "links": [], "forms": [], "api": [],
           "unvisited": ["/gate"]}
    action = explore.propose_fallback(obs, {"/home", "/profile"}, SCOPE)
    assert action["action"] == "follow_link" and action["target"]["path"] == "/gate"


def test_the_current_pages_links_still_come_before_the_frontier():
    obs = {"url": "http://app/home", "links": ["/here"], "forms": [], "api": [],
           "unvisited": ["/earlier"]}
    assert explore.propose_fallback(obs, set(), SCOPE)["target"]["path"] == "/here"


# ---- submit outcomes ------------------------------------------------------------------------

def test_a_response_is_matched_to_its_forms_method_and_path():
    assert explore.is_submit_response("POST", "http://app/gate?x=1", "POST", "/gate")
    assert not explore.is_submit_response("GET", "http://app/gate", "POST", "/gate")
    assert not explore.is_submit_response("POST", "http://app/other", "POST", "/gate")


def test_status_decides_accepted_and_unknown_claims_nothing():
    assert explore.response_outcome(302) == {"status": 302, "accepted": True}
    assert explore.response_outcome(400) == {"status": 400, "accepted": False}
    assert explore.response_outcome(None) == {"status": None, "accepted": None}


def test_submit_counts():
    trace = {"interactions": [
        {"type": "submit", "inferred": ["answer"], "accepted": True},
        {"type": "submit", "inferred": [], "accepted": False},
        {"type": "submit", "inferred": [], "accepted": None},
        {"type": "click"}]}
    assert explore.submit_counts(trace) == {"submits": 3, "inferred_submits": 1,
                                            "accepted_submits": 1, "refused_submits": 1}


# ---- the loop, end to end, against a gate that accepts one answer ---------------------------

VAULT = ["/vault/policy", "/vault/claims", "/vault/billing"]
PAGES = {"/home": ["/profile", "/gate"], "/profile": ["/home"], "/gate": []}


class _Response:
    def __init__(self, url, method, status):
        self.url, self.status = url, status
        self.request = types.SimpleNamespace(method=method)


class _Expect:
    def __init__(self, page, predicate):
        self.page, self.predicate = page, predicate

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            return False
        resp = self.page.last_response
        if resp is None or not self.predicate(resp):
            raise TimeoutError("no matching response")
        self.value = resp
        return False


class _GatePage:
    """/home -> /profile (dead end) and /gate; /gate's form accepts only "11"."""

    def __init__(self, base):
        self.base, self.url = base, base + "/home"
        self.filled, self.unlocked, self.answered = {}, False, False
        self.last_response = None
        self.context = types.SimpleNamespace(on=lambda *a, **k: None)

    def route(self, *a, **k):
        pass

    def on(self, *a, **k):
        pass

    def _path(self):
        return urlsplit(self.url).path

    def goto(self, url, wait_until=None):
        self.url, self.answered, self.filled = url, False, {}

    def evaluate(self, expr):
        path = self._path()
        if "a[href]" in expr:
            if path == "/gate" and self.answered and self.unlocked:
                return list(VAULT)
            if path in VAULT:
                return [p for p in VAULT if p != path] if self.unlocked else []
            return list(PAGES.get(path, []))
        if path == "/gate" and not self.answered:
            return [dict(RAW_GATE)]
        return []

    def fill(self, selector, value, timeout=None):
        self.filled[selector] = value

    def expect_response(self, predicate, timeout=None):
        self.last_response = None
        return _Expect(self, predicate)

    def click(self, selector, timeout=None):
        self.answered = True
        ok = self.filled.get("[name=answer]") == "11"
        self.unlocked = self.unlocked or ok
        self.last_response = _Response(self.url, "POST", 200 if ok else 400)

    def wait_for_load_state(self, *a, **k):
        pass


def _fake_playwright(page):
    browser = types.SimpleNamespace(
        new_context=lambda **k: types.SimpleNamespace(new_page=lambda: page,
                                                      close=lambda: None),
        close=lambda: None)
    pw = types.SimpleNamespace(chromium=types.SimpleNamespace(launch=lambda **k: browser))

    class _Ctx:
        def __enter__(self):
            return pw

        def __exit__(self, *a):
            return False

    return lambda: _Ctx()


CONFIG = {"base_url": "http://app", "data_policy": "disposable",
          "auth": {"proof": {"selector": "#whoami"}},
          "explore": {"write_mode": "allow", "test_data": {"note": "dast-test"},
                      "inferred_fields": INFERRED}}


def _run(monkeypatch, *, use_llm, config=CONFIG):
    page = _GatePage("http://app")
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = _fake_playwright(page)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(explore, "prove_auth_live", lambda *a, **k: {"alive": True, "reason": "ok"})
    stats: dict = {}
    trace, _ = explore.explore("app", "http://app", "state.json", ["/home"], SCOPE,
                               config=config, max_pages=15, use_llm=use_llm, stats=stats,
                               require_llm=use_llm)
    return trace, stats


def _reasoning_model(observation, model, api_key=None):
    """Stands in for the provider: answers the stated question, otherwise walks somewhere new."""
    for form in observation.get("forms", []):
        if form.get("inferable"):
            left, right = form["prompt"].replace("What is ", "").rstrip("?").split(" plus ")
            return {"action": "submit_form",
                    "target": {"method": form["method"], "selector": form["selector"],
                               "values": {"answer": str(int(left) + int(right))}}}
    for href in observation.get("links", []) + observation.get("unvisited", []):
        if href not in observation.get("visited", []):
            return {"action": "follow_link", "target": {"method": "GET", "path": href}}
    return {"action": "stop"}


def _visited_paths(trace):
    return {urlsplit(u).path for u in trace["index"]}


def test_the_deterministic_arm_reaches_the_gate_and_stops_there(monkeypatch):
    trace, stats = _run(monkeypatch, use_llm=False)
    assert "/gate" in _visited_paths(trace)
    assert not _visited_paths(trace) & set(VAULT)
    assert explore.submit_counts(trace)["submits"] == 0
    assert "llm" not in stats


def test_the_model_answers_the_gate_and_reaches_the_pages_behind_it(monkeypatch):
    monkeypatch.setattr(explore.llm_backend, "available", lambda *a, **k: True)
    monkeypatch.setattr(explore, "propose_llm", _reasoning_model)
    trace, stats = _run(monkeypatch, use_llm=True)
    assert set(VAULT) <= _visited_paths(trace)
    submit = next(ev for ev in trace["interactions"] if ev.get("type") == "submit")
    assert submit["inferred"] == ["answer"] and submit["accepted"] is True
    assert submit["status"] == 200 and "11" not in str(submit)
    assert explore.submit_counts(trace) == {"submits": 1, "inferred_submits": 1,
                                            "accepted_submits": 1, "refused_submits": 0}
    assert stats["llm"] >= 1


def test_a_wrong_answer_is_recorded_as_refused(monkeypatch):
    def wrong(observation, model, api_key=None):
        action = _reasoning_model(observation, model, api_key)
        if action.get("action") == "submit_form":
            action["target"]["values"] = {"answer": "12"}
        return action

    monkeypatch.setattr(explore.llm_backend, "available", lambda *a, **k: True)
    monkeypatch.setattr(explore, "propose_llm", wrong)
    trace, _ = _run(monkeypatch, use_llm=True)
    counts = explore.submit_counts(trace)
    assert counts["refused_submits"] >= 1 and counts["accepted_submits"] == 0
    assert not _visited_paths(trace) & set(VAULT)


def test_without_inferred_fields_the_model_cannot_supply_a_value(monkeypatch):
    monkeypatch.setattr(explore.llm_backend, "available", lambda *a, **k: True)
    monkeypatch.setattr(explore, "propose_llm", _reasoning_model)
    config = {**CONFIG, "explore": {k: v for k, v in CONFIG["explore"].items()
                                    if k != "inferred_fields"}}
    trace, _ = _run(monkeypatch, use_llm=True, config=config)
    assert not _visited_paths(trace) & set(VAULT)
    assert explore.submit_counts(trace)["inferred_submits"] == 0
