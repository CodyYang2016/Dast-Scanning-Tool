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


def test_deny_list_blocks_a_denied_route_even_as_get():
    # A per-app deny term, not a session-ender: this exercises the deny-list rule itself.
    scope = {"fqdn_allow_list": ["juice"], "avoid_action_list": ["purchase"]}
    d = validate_action(_a("follow_link", "/#/checkout/purchase"), scope)
    assert not d.allowed and "deny-list" in d.reason


def test_logout_is_refused_by_the_stronger_session_rule():
    # Denied whether or not the app remembered to list it: losing auth invalidates the scan.
    d = validate_action(_a("follow_link", "/#/logout"), {"fqdn_allow_list": ["juice"]})
    assert not d.allowed and "session" in d.reason


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
    scope = {"fqdn_allow_list": ["juice"], "avoid_action_list": ["purchase"]}
    d = validate_action({"action": "submit_form",
                         "target": {"method": "GET", "selector": "#purchase-form"}}, scope)
    assert not d.allowed and "deny-list" in d.reason


def test_an_app_can_switch_get_form_submission_off_entirely():
    action = {"action": "submit_form", "target": {"method": "GET", "selector": "#search"}}
    assert validate_action(action, SCOPE).allowed
    assert not validate_action(action, SCOPE, submit_get_forms=False).allowed


def test_get_verb_is_reported_for_an_explicit_get_form():
    assert action_verb({"action": "submit_form", "target": {"method": "GET"}}) == "GET"
    assert action_verb({"action": "submit_form", "target": {}}) == "POST"


# ---- write mode: posture is a choice, but some actions never are ------------------------
# Whole vulnerability classes live behind writes — stored XSS, POST-body injection, mass
# assignment, IDOR on update endpoints, upload flaws — and refusing every write makes the
# tool look weaker than a commercial scanner when the real difference is posture (SP-1). So
# writes become an ENVIRONMENT-level opt-in rather than a per-form allow-list a human has to
# maintain forever. Two things stay non-negotiable: the deny-list, and anything that ends the
# session or the credential, because losing authentication mid-scan silently invalidates
# everything after it (W5-1) and we cannot yet detect it.

WRITE = {"action": "submit_form", "target": {"method": "POST", "selector": "#comment"}}


def test_a_write_is_refused_by_default():
    assert not validate_action(WRITE, SCOPE).allowed


def test_a_write_is_permitted_when_the_environment_opts_in():
    d = validate_action(WRITE, SCOPE, allow_writes=True)
    assert d.allowed


def test_the_deny_list_still_wins_over_write_mode():
    scope = {"fqdn_allow_list": ["juice"], "avoid_action_list": ["purchase"]}
    action = {"action": "submit_form", "target": {"method": "POST", "selector": "#purchase-form"}}
    assert not validate_action(action, scope, allow_writes=True).allowed


def test_session_ending_actions_are_refused_even_in_write_mode():
    # Not posture — correctness. These are denied whatever the app's config says.
    for target in ("/account/delete-account", "#change-password", "/auth/logout",
                   "/profile/deactivate", "/reset-password"):
        d = validate_action({"action": "submit_form",
                             "target": {"method": "POST", "selector": target}},
                            {"fqdn_allow_list": ["app"], "avoid_action_list": []},
                            allow_writes=True)
        assert not d.allowed, target
        assert "session" in d.reason or "deny" in d.reason


def test_a_delete_verb_is_still_refused_in_write_mode_unless_explicitly_safe():
    # DELETE is the one verb where "it is a test environment" is least comforting.
    action = {"action": "visit_api", "target": {"method": "DELETE", "path": "/api/orders/1"}}
    assert not validate_action(action, SCOPE, allow_writes=True).allowed
    assert validate_action(action, SCOPE, allow_writes=True,
                           safe_forms=["/api/orders/1"]).allowed


def test_write_mode_does_not_loosen_scope():
    action = {"action": "submit_form",
              "target": {"method": "POST", "selector": "http://evil.test/x"}}
    assert not validate_action(action, SCOPE, allow_writes=True).allowed


# ---- judge an action by its context, not just its selector ------------------------------
# The autonomous loop destroyed its own credential and the session guard did not fire. It
# submitted DVWA's CSRF lesson — a password-change form — and the only thing the guard saw
# was the selector "form >> nth=0 >> [type=submit]", which says nothing. The page URL
# (/vulnerabilities/csrf/) and the field names (password_new, password_conf) both said
# exactly what the form did. An action has to be judged by where it is and what it carries.

def _form(selector="form >> nth=0 >> [type=submit]", method="GET", fields=None):
    t = {"method": method, "selector": selector}
    if fields:
        t["field_bindings"] = fields
    return {"action": "submit_form", "target": t}


def test_a_password_change_form_is_refused_by_its_field_names():
    d = validate_action(_form(fields=["password_new", "password_conf", "Change"]), SCOPE)
    assert not d.allowed and "credential" in d.reason


def test_the_variants_applications_actually_use_are_covered():
    for fields in (["new_password", "confirm_password"], ["current_password", "password1"],
                   ["oldPassword", "newPassword"], ["passwordConfirm"]):
        assert not validate_action(_form(fields=fields), SCOPE).allowed, fields


def test_a_form_on_a_password_change_page_is_refused_by_its_url():
    d = validate_action(_form(), SCOPE, page_url="http://app/account/change-password")
    assert not d.allowed and ("session" in d.reason or "credential" in d.reason)


def test_the_login_form_itself_is_not_mistaken_for_a_credential_change():
    # Logging in is the whole point; only CHANGING a credential is refused.
    d = validate_action(_form(fields=["username", "password", "Login"]), SCOPE,
                        page_url="http://app/login.php")
    assert d.allowed


def test_an_ordinary_search_form_is_unaffected():
    assert validate_action(_form(fields=["id", "Submit"]), SCOPE,
                           page_url="http://app/vulnerabilities/sqli/").allowed


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


# ---- deny_terms ----

def test_deny_terms_merges_the_configured_list_with_the_never_allowed_terms():
    from runner.action_policy import deny_terms

    terms = deny_terms({"avoid_action_list": ["captcha", " Purchase "]})
    assert "captcha" in terms and "purchase" in terms and "logout" in terms
    assert terms == sorted(set(terms))


def test_deny_terms_prefers_an_explicit_deny_list_over_the_scope():
    from runner.action_policy import deny_terms

    terms = deny_terms({"avoid_action_list": ["captcha"]}, deny_actions=["upload"])
    assert "upload" in terms and "captcha" not in terms
