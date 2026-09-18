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
