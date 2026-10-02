"""Deterministic action policy (Phase B safety — open question 1).

The LLM only *suggests* actions; whether an action is safe to execute is decided here, by code —
never by the model's own "non-destructive" label. Three independent rules, all fail-closed:

  1. Deny-list: if the action's target matches any `avoid_action_list` / `deny_actions` term
     (logout, delete, purchase, admin-mutation, ...), reject it.
  2. Default-deny state-changing verbs: any POST/PUT/PATCH/DELETE is rejected unless its target is
     on an explicit safe-form allow-list, or the environment has been declared disposable and
     write mode enabled (app.yaml `data_policy` + `explore.write_mode`) — DELETE always needs
     the explicit allow-list. GET-like navigation (follow_link/goto/expand_nav) is allowed
     subject to scope, as is a form submit that explicitly states GET: reading a form is how
     parameters are discovered. A submit with no stated method is assumed to write.
  4. Never, at any posture: actions that end the session or the credential (logout, delete
     account, change/reset password). Losing auth mid-scan silently invalidates the results.
  3. Embedded off-scope URLs: an in-scope *path* whose query embeds an absolute URL to a host
     outside the allow-list (open-redirect style, e.g. `/redirect?to=https://github.com/...`) is
     rejected — following it would carry the browser off-scope on the app's 302.

Scope (host allow-list) is still enforced independently at the request boundary by ScopeGuard
(D2/D6) — this module is the *action* layer, kept separate so both must pass. See
docs/junior_engineer/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from runner.scope_guard import host_of, in_scope, path_excluded

_EMBEDDED_URL = re.compile(r"https?://[^\s&\"'<>]+", re.IGNORECASE)

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Refused whatever the application's posture says. These end the session or the credential,
# and losing authentication mid-scan does not merely risk damage — it silently invalidates
# every result after it, which we cannot yet detect (W5-1). Not posture; correctness.
_NEVER = ("logout", "log-out", "signout", "sign-out", "delete-account", "delete_account",
          "deleteaccount", "close-account", "deactivate", "change-password", "changepassword",
          "reset-password", "resetpassword")

# Even in write mode, DELETE needs an explicit per-target opt-in: "it is a test environment"
# is least comforting for the one verb whose whole purpose is destruction.
_ALWAYS_EXPLICIT = {"DELETE"}

# A form that carries these fields changes a credential, whatever its selector looks like.
# The selector of a submit button ("form >> nth=0 >> [type=submit]") says nothing at all, so
# the fields and the page are the only honest evidence of what a submission does.
_CREDENTIAL_FIELDS = ("password_new", "password_conf", "new_password", "newpassword",
                      "confirm_password", "passwordconfirm", "password_confirm",
                      "current_password", "currentpassword", "old_password", "oldpassword",
                      "password1", "password2")

# Navigation actions are read-only by nature; visit_api/submit_form carry an explicit method.
_GET_ACTIONS = {"follow_link", "goto", "expand_nav"}


@dataclass
class ActionDecision:
    allowed: bool
    reason: str


def action_verb(action: dict) -> str:
    """Effective HTTP verb an action would issue (upper-case).

    A form submit with no stated method is assumed to POST: unknown must fail closed. One that
    explicitly states GET is a read — submitting a search or filter form is how an endpoint's
    parameters become visible at all, and refusing it costs real findings rather than buying
    safety (measured on DVWA: four high-severity findings unreachable without it).
    """
    kind = action.get("action")
    stated = action.get("target", {}).get("method")
    if kind in _GET_ACTIONS:
        return "GET"
    if kind == "submit_form":
        return stated.upper() if stated else "POST"
    return (stated or "GET").upper()  # visit_api and anything else use the stated method


def _target_str(action: dict) -> str:
    t = action.get("target", {})
    return t.get("path") or t.get("selector") or ""


def is_denied(action: dict, deny_actions) -> bool:
    """True if the action (kind + target) matches any deny term (case-insensitive substring)."""
    hay = f"{action.get('action', '')} {_target_str(action)}".lower()
    return any(term.strip().lower() in hay for term in (deny_actions or []) if term.strip())


def changes_a_credential(action: dict) -> bool:
    """True when a form's own fields show it sets or confirms a password.

    Two password-ish fields, or any explicit new/confirm/current naming, means the submission
    changes a credential. A login form (one password field alongside a username) does not
    qualify — logging in is the point.
    """
    fields = [str(f).lower() for f in action.get("target", {}).get("field_bindings", [])]
    if any(f in _CREDENTIAL_FIELDS for f in fields):
        return True
    return sum(1 for f in fields if "password" in f or "passwd" in f) > 1


def never_allowed(action: dict, page_url: str | None = None) -> bool:
    """True for an action that ends the session or the credential, at any posture.

    Judged on everything available: the action kind, its target, the page it is on, and the
    fields it would submit. Looking at the target alone let an autonomous run submit a
    password-change form whose selector was an anonymous "[type=submit]", which destroyed the
    credential the scan depended on.
    """
    hay = f"{action.get('action', '')} {_target_str(action)} {page_url or ''}".lower()
    if any(term in hay for term in _NEVER):
        return True
    return changes_a_credential(action)


def validate_action(action: dict, scope: dict, deny_actions=None, safe_forms=None,
                    submit_get_forms: bool = True, allow_writes: bool = False,
                    page_url: str | None = None) -> ActionDecision:
    """Decide whether a proposed LLM action may execute. Fail-closed on every rule.

    `deny_actions` defaults to the scope's `avoid_action_list`. `safe_forms` is the explicit
    allow-list of targets for which a state-changing submit is permitted. `submit_get_forms`
    lets an application opt out of read-form submission entirely, for the case where GET is
    known to mutate.
    """
    deny_actions = deny_actions if deny_actions is not None else scope.get("avoid_action_list", [])
    safe_forms = set(safe_forms or [])
    target = _target_str(action)

    if changes_a_credential(action):
        return ActionDecision(False, "submits a credential change; refused at any posture")
    if never_allowed(action, page_url):
        return ActionDecision(False, "ends the session or the credential; refused at any posture")

    if is_denied(action, deny_actions):
        return ActionDecision(False, "matches deny-list (avoid_action_list)")
    if target.startswith(("/", "http://", "https://")) and \
            path_excluded(target, scope.get("exclude_paths")):
        return ActionDecision(False, "path is excluded for this application (scope.exclude)")

    verb = action_verb(action)
    if verb in STATE_CHANGING and target not in safe_forms:
        # A write is permitted only where the environment has been declared disposable
        # (app.yaml data_policy + explore.write_mode), and never for DELETE.
        if not allow_writes or verb in _ALWAYS_EXPLICIT:
            return ActionDecision(False, f"state-changing {verb} not on the safe-form allow-list")
    if action.get("action") == "submit_form" and verb == "GET" and not submit_get_forms:
        return ActionDecision(False, "this application does not permit form submission")

    # A login-only host (scope.traverse) is reached only by the login itself, never explored.
    if target.startswith(("http://", "https://")) and in_scope(target, scope.get("traverse_list")):
        return ActionDecision(False, "login-only host (scope.traverse): never explored or attacked")

    # Absolute targets must be in scope; relative paths inherit the (in-scope) base origin.
    allow = scope.get("fqdn_allow_list", [])
    if target.startswith("http://") or target.startswith("https://"):
        if not in_scope(target, allow):
            return ActionDecision(False, "target host not in allow-list")

    # Any absolute URL embedded in the target (query/fragment, possibly percent-encoded) must be
    # in-scope too — otherwise the app can redirect the browser off-scope.
    for embedded in _EMBEDDED_URL.findall(unquote(target)):
        if not in_scope(embedded, allow):
            return ActionDecision(False, f"embedded off-scope URL in target: {host_of(embedded)}")

    return ActionDecision(True, "allowed")
