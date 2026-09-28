"""Objective tests for the deterministic action policy (Phase B safety, open question 1).

Oracle: hand-built actions with known-correct allow/deny answers. The policy must NEVER trust an
action's own label — a state-changing verb is denied unless explicitly allow-listed, and deny-list
terms are rejected regardless of what the action claims.
"""

from runner.action_policy import action_verb, is_denied, validate_action

SCOPE = {"fqdn_allow_list": ["juice"], "avoid_action_list": ["logout", "delete-account"]}


def _a(kind, path="", method=None, selector=None):
    target = {}
    if path:
        target["path"] = path
    if method:
        target["method"] = method
    if selector:
        target["selector"] = selector
    return {"action": kind, "target": target}


def test_get_navigation_allowed():
    assert validate_action(_a("follow_link", "/account/orders"), SCOPE).allowed


def test_visit_api_get_allowed():
    assert validate_action(_a("visit_api", "/rest/user/whoami", method="GET"), SCOPE).allowed


def test_state_changing_verb_denied_by_default():
    d = validate_action(_a("visit_api", "/rest/basket", method="DELETE"), SCOPE)
    assert not d.allowed and "state-changing" in d.reason


def test_submit_form_defaults_to_post_denied():
    # submit_form with no explicit GET method is treated as POST -> denied unless allow-listed
    assert action_verb(_a("submit_form", selector="#search")) == "POST"
    assert not validate_action(_a("submit_form", path="#search"), SCOPE).allowed


def test_state_changing_allowed_when_on_safe_form_list():
    d = validate_action(_a("submit_form", path="/#/search", method="POST"), SCOPE,
                        safe_forms={"/#/search"})
    assert d.allowed


def test_deny_list_blocks_logout_even_as_get():
    d = validate_action(_a("follow_link", "/#/logout"), SCOPE)
    assert not d.allowed and "deny-list" in d.reason


def test_deny_list_matches_action_name():
    # deny term can match the action kind text too (defense in depth)
    d = validate_action({"action": "submit_form", "target": {"path": "/account/delete-account"}},
                        SCOPE)
    assert not d.allowed


def test_out_of_scope_absolute_host_denied():
    d = validate_action(_a("follow_link", "https://evil.example.com/x"), SCOPE)
    assert not d.allowed and "host" in d.reason


def test_relative_path_is_in_scope_by_construction():
    assert validate_action(_a("follow_link", "/#/basket"), SCOPE).allowed


def test_is_denied_is_case_insensitive():
    assert is_denied(_a("follow_link", "/#/LOGOUT"), ["logout"])
    assert not is_denied(_a("follow_link", "/#/basket"), ["logout"])


def test_deny_actions_defaults_to_scope_avoid_list():
    # no explicit deny_actions -> uses scope.avoid_action_list
    assert not validate_action(_a("follow_link", "/#/logout"), SCOPE).allowed


# ---- embedded off-scope URLs (open-redirect style targets) ------------------------------
# An in-scope *path* can still carry the browser off-scope when it embeds an absolute URL the
# app redirects to (Juice Shop's /redirect?to=...). The action layer must reject that up front,
# not rely on the request-boundary guard to catch the follow-up request mid-scan.

def test_embedded_off_scope_url_rejected():
    d = validate_action({"action": "follow_link", "target": {
        "path": "/redirect?to=https://github.com/juice-shop/juice-shop"}}, SCOPE)
    assert not d.allowed and "embedded" in d.reason


def test_embedded_in_scope_url_allowed():
    d = validate_action({"action": "follow_link", "target": {
        "path": "/redirect?to=http://juice:3000/#/basket"}}, SCOPE)
    assert d.allowed


def test_embedded_url_check_is_case_insensitive_and_query_encoded():
    d = validate_action({"action": "follow_link", "target": {
        "path": "/go?next=HTTPS://Evil.Example.com/x&x=1"}}, SCOPE)
    assert not d.allowed


# ---- reading a form is not writing to one -----------------------------------------------
# Every submit_form was treated as a POST, even one the model explicitly marked GET, so the
# exploration loop could never submit a search or filter form. That is where the interesting
# parameters live: measured on DVWA, discovery found /vulnerabilities/sqli/ but never
# ?id=1&Submit=Submit, and four high-severity findings went with it. A GET form submission is
# a read; the write-path guarantee is about state-changing verbs, and it is untouched here.

def test_an_explicit_get_form_submit_is_a_read():
    d = validate_action({"action": "submit_form",
                         "target": {"method": "GET", "selector": "#search"}}, SCOPE)
    assert d.allowed


def test_a_form_submit_with_no_stated_method_is_still_assumed_to_write():
    # Unstated means unknown, and unknown must fail closed.
    d = validate_action({"action": "submit_form", "target": {"selector": "#search"}}, SCOPE)
    assert not d.allowed and "state-changing" in d.reason


def test_a_post_form_still_needs_the_safe_form_allow_list():
    action = {"action": "submit_form", "target": {"method": "POST", "selector": "#transfer"}}
    assert not validate_action(action, SCOPE).allowed
    assert validate_action(action, SCOPE, safe_forms=["#transfer"]).allowed


def test_a_get_form_on_the_deny_list_is_still_refused():
    # Plenty of applications mutate on GET; the deny-list is what protects those.
    d = validate_action({"action": "submit_form",
                         "target": {"method": "GET", "selector": "#logout-form"}}, SCOPE)
    assert not d.allowed and "deny-list" in d.reason


def test_an_app_can_switch_get_form_submission_off_entirely():
    action = {"action": "submit_form", "target": {"method": "GET", "selector": "#search"}}
    assert validate_action(action, SCOPE).allowed
    assert not validate_action(action, SCOPE, submit_get_forms=False).allowed


def test_get_verb_is_reported_for_an_explicit_get_form():
    assert action_verb({"action": "submit_form", "target": {"method": "GET"}}) == "GET"
    assert action_verb({"action": "submit_form", "target": {}}) == "POST"
