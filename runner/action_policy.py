"""Deterministic action policy (Phase B safety — open question 1).

The LLM only *suggests* actions; whether an action is safe to execute is decided here, by code —
never by the model's own "non-destructive" label. Three independent rules, all fail-closed:

  1. Deny-list: if the action's target matches any `avoid_action_list` / `deny_actions` term
     (logout, delete, purchase, admin-mutation, ...), reject it.
  2. Default-deny state-changing verbs: any POST/PUT/PATCH/DELETE is rejected unless its target is
     on an explicit safe-form allow-list. GET-like navigation (follow_link/goto/expand_nav) is
     allowed subject to scope.
  3. Embedded off-scope URLs: an in-scope *path* whose query embeds an absolute URL to a host
     outside the allow-list (open-redirect style, e.g. `/redirect?to=https://github.com/...`) is
     rejected — following it would carry the browser off-scope on the app's 302.
  4. Downloads: a page navigation to a file the browser saves instead of rendering is rejected.
     Not a posture rule but a correctness one — see `is_download`.

Scope (host allow-list) is still enforced independently at the request boundary by ScopeGuard
(D2/D6) — this module is the *action* layer, kept separate so both must pass. See
docs/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from runner.scope_guard import host_of

_EMBEDDED_URL = re.compile(r"https?://[^\s&\"'<>]+", re.IGNORECASE)

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Navigation actions are read-only by nature; visit_api/submit_form carry an explicit method.
_GET_ACTIONS = {"follow_link", "goto", "expand_nav"}

# Actions that drive the page itself, rather than issuing a request beside it.
_NAVIGATES = {"follow_link", "goto"}

# Suffixes whose response a browser saves rather than renders. Chromium aborts a navigation to
# one with "Download is starting", which is an exception, not a page -- so a documentation link
# picked up from a crawl takes the whole journey down with it when the flow is replayed.
_DOWNLOAD_SUFFIXES = (
    ".pdf", ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".iso", ".jar", ".war",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods",
    ".csv", ".mp3", ".mp4", ".avi", ".mov", ".wav",
)


def is_download(target: str) -> bool:
    """True when a target names a file the browser downloads instead of rendering as a page.

    Judged on the path only, so a query string or fragment does not hide the extension.
    """
    return urlsplit(target or "").path.lower().endswith(_DOWNLOAD_SUFFIXES)


@dataclass
class ActionDecision:
    allowed: bool
    reason: str


def action_verb(action: dict) -> str:
    """Effective HTTP verb an action would issue (upper-case)."""
    kind = action.get("action")
    method = (action.get("target", {}).get("method") or "GET").upper()
    if kind in _GET_ACTIONS:
        return "GET"
    if kind == "submit_form":
        return method if method != "GET" else "POST"  # a form submit defaults to POST
    return method  # visit_api and anything else use the stated method


def _target_str(action: dict) -> str:
    t = action.get("target", {})
    return t.get("path") or t.get("selector") or ""


def is_denied(action: dict, deny_actions) -> bool:
    """True if the action (kind + target) matches any deny term (case-insensitive substring)."""
    hay = f"{action.get('action', '')} {_target_str(action)}".lower()
    return any(term.strip().lower() in hay for term in (deny_actions or []) if term.strip())


# Terms that end the session or the credential at any posture — losing authentication mid-run
# silently invalidates every result after it (correctness, not posture).
_NEVER = ("logout", "log-out", "signout", "sign-out", "delete-account", "delete_account",
          "deleteaccount", "close-account", "deactivate", "change-password", "changepassword",
          "reset-password", "resetpassword")

# A form carrying these fields changes a credential, whatever its submit selector looks like.
_CREDENTIAL_FIELDS = ("password_new", "password_conf", "new_password", "newpassword",
                      "confirm_password", "passwordconfirm", "password_confirm",
                      "current_password", "currentpassword", "old_password", "oldpassword",
                      "password1", "password2")


def deny_terms(scope: dict, deny_actions=None) -> list[str]:
    """The terms an action's target must not contain, as this module will judge it.

    Exposed so the explorer can tell the model what will be refused up front: a model that isn't
    told spends a round trip per rejection re-proposing the same denied path.
    """
    configured = deny_actions if deny_actions is not None else scope.get("avoid_action_list", [])
    terms = [t.strip().lower() for t in configured if str(t).strip()]
    return sorted(set(terms) | set(_NEVER))


def changes_a_credential(action: dict) -> bool:
    """True when a form's own fields show it sets or confirms a password (not a plain login)."""
    fields = [str(f).lower() for f in action.get("target", {}).get("field_bindings", [])]
    if any(f in _CREDENTIAL_FIELDS for f in fields):
        return True
    return sum(1 for f in fields if "password" in f or "passwd" in f) > 1


def never_allowed(action: dict, page_url: str | None = None) -> bool:
    """True for an action that ends the session or the credential, at any posture.

    Judged on the action kind, its target, the page it is on, and the fields it would submit —
    used by discovery to refuse a proof whose evaluation would itself log us out.
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
    allow-list of targets for which a state-changing submit is permitted.
    """
    deny_actions = deny_actions if deny_actions is not None else scope.get("avoid_action_list", [])
    safe_forms = set(safe_forms or [])
    target = _target_str(action)

    if is_denied(action, deny_actions):
        return ActionDecision(False, "matches deny-list (avoid_action_list)")

    if never_allowed(action, page_url):
        return ActionDecision(False, "ends the session or credential; refused at any posture")

    verb = action_verb(action)
    if verb in STATE_CHANGING and target not in safe_forms:
        if not allow_writes or verb == "DELETE":
            return ActionDecision(False, f"state-changing {verb} not on the safe-form allow-list")
    if action.get("action") == "submit_form" and verb == "GET" and not submit_get_forms:
        return ActionDecision(False, "GET form submission is disabled for this application")

    # A download is a dead end that also aborts the navigation: skip it here so it never enters
    # a trace, rather than discovering at replay time that the journey cannot be executed. The
    # bytes are still reachable to the scanner's own spider, which does not drive a browser.
    if action.get("action") in _NAVIGATES and is_download(target):
        return ActionDecision(False, "target is a file download, not a page")

    # Absolute targets must be in-scope by host; relative paths inherit the (in-scope) base host.
    allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
    if target.startswith("http://") or target.startswith("https://"):
        if host_of(target) not in allow:
            return ActionDecision(False, "target host not in allow-list")

    # Any absolute URL embedded in the target (query/fragment, possibly percent-encoded) must be
    # in-scope too — otherwise the app can redirect the browser off-scope.
    for embedded in _EMBEDDED_URL.findall(unquote(target)):
        if host_of(embedded) not in allow:
            return ActionDecision(False, f"embedded off-scope URL in target: {host_of(embedded)}")

    return ActionDecision(True, "allowed")
