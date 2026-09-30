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


# ---- deny_terms: what the explorer tells the model up front -------------------------------

def test_deny_terms_merges_the_configured_list_with_the_never_allowed_terms():
    from runner.action_policy import deny_terms

    terms = deny_terms({"avoid_action_list": ["captcha", " Purchase "]})
    assert "captcha" in terms and "purchase" in terms and "logout" in terms
    assert terms == sorted(set(terms))


def test_deny_terms_prefers_an_explicit_deny_list_over_the_scope():
    from runner.action_policy import deny_terms

    terms = deny_terms({"avoid_action_list": ["captcha"]}, deny_actions=["upload"])
    assert "upload" in terms and "captcha" not in terms


# ---- downloads are not pages ------------------------------------------------------------
# A crawl picks up documentation and export links like any other href, but Chromium aborts a
# navigation to one with "Download is starting". Observed on DVWA: the deterministic proposer
# followed /docs/DVWA_v1.3.pdf, which put that step in the journey and made the generated flow
# unreplayable -- the scan died on it. Judged here so it never reaches a trace.

def test_download_link_is_not_a_navigable_target():
    d = validate_action(_a("follow_link", "/docs/DVWA_v1.3.pdf"), SCOPE)
    assert not d.allowed and "download" in d.reason


def test_download_detection_ignores_the_query_string():
    assert not validate_action(_a("follow_link", "/export/report.csv?range=30d"), SCOPE).allowed


def test_download_detection_is_case_insensitive():
    assert not validate_action(_a("goto", "/files/Handbook.PDF"), SCOPE).allowed


def test_a_page_whose_query_merely_names_a_document_is_still_a_page():
    """The extension has to be the path's: /vulnerabilities/fi/?page=include.php is a page."""
    assert validate_action(_a("follow_link", "/download?file=report.pdf"), SCOPE).allowed


def test_an_api_get_of_a_download_is_allowed():
    """api_get is fetched beside the page (page.request.get), so no navigation can abort."""
    assert validate_action(_a("visit_api", "/rest/export.csv", method="GET"), SCOPE).allowed
