"""Deterministic action policy (Phase B safety — open question 1).

The LLM only *suggests* actions; whether an action is safe to execute is decided here, by code —
never by the model's own "non-destructive" label. Two independent rules, both fail-closed:

  1. Deny-list: if the action's target matches any `avoid_action_list` / `deny_actions` term
     (logout, delete, purchase, admin-mutation, ...), reject it.
  2. Default-deny state-changing verbs: any POST/PUT/PATCH/DELETE is rejected unless its target is
     on an explicit safe-form allow-list. GET-like navigation (follow_link/goto/expand_nav) is
     allowed subject to scope.

Scope (host allow-list) is still enforced independently at the request boundary by ScopeGuard
(D2/D6) — this module is the *action* layer, kept separate so both must pass. See
docs/junior_engineer/seeded_session_exploration_design.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from runner.scope_guard import host_of

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Navigation actions are read-only by nature; visit_api/submit_form carry an explicit method.
_GET_ACTIONS = {"follow_link", "goto", "expand_nav"}


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


def validate_action(action: dict, scope: dict, deny_actions=None, safe_forms=None) -> ActionDecision:
    """Decide whether a proposed LLM action may execute. Fail-closed on every rule.

    `deny_actions` defaults to the scope's `avoid_action_list`. `safe_forms` is the explicit
    allow-list of targets for which a state-changing submit is permitted.
    """
    deny_actions = deny_actions if deny_actions is not None else scope.get("avoid_action_list", [])
    safe_forms = set(safe_forms or [])
    target = _target_str(action)

    if is_denied(action, deny_actions):
        return ActionDecision(False, "matches deny-list (avoid_action_list)")

    verb = action_verb(action)
    if verb in STATE_CHANGING and target not in safe_forms:
        return ActionDecision(False, f"state-changing {verb} not on the safe-form allow-list")

    # Absolute targets must be in-scope by host; relative paths inherit the (in-scope) base host.
    if target.startswith("http://") or target.startswith("https://"):
        allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
        if host_of(target) not in allow:
            return ActionDecision(False, "target host not in allow-list")

    return ActionDecision(True, "allowed")
