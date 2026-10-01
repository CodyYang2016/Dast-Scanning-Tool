"""Per-application configuration: the one file you add to onboard an application.

Everything app-specific — login selectors, how authentication is proven, cookie banners to
dismiss, which URLs count as API calls, scope, budgets — lives in
`security/dast/<app_id>/app.yaml` and is validated against `contracts/app.schema.json`.
Nothing under `authoring/` or `runner/` may name an application (enforced by
tests/test_no_app_specifics.py), so onboarding is a config change, never a code change.

This is an INPUT. `generate` still emits the frozen artifacts (scope.json, auth.json,
zap-policy.yaml, manifest.json, lock) from it, so the contracts, preflight and the runner are
unchanged. Credentials appear here only as environment variable NAMES; values come from the
environment at run time (NFR-3).

`load_app_config` mirrors `authoring.seed.load_seed`: read, parse, schema-validate, return a
plain dict. Pure and unit-tested; no browser, no network.
"""

from __future__ import annotations

import os
from pathlib import Path

import jsonschema
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_APP_SCHEMA = _ROOT / "contracts" / "app.schema.json"
_APPS_DIR = _ROOT / "security" / "dast"

_CONFIG_FILENAME = "app.yaml"


def app_config_path(app_id: str) -> Path:
    """Conventional location of an application's config."""
    return _APPS_DIR / app_id / _CONFIG_FILENAME


def load_app_config(path_or_app_id: str) -> dict:
    """Load + schema-validate an app config. Accepts a path or a bare app id.

    Raises FileNotFoundError if it does not exist, ValueError if the YAML is unparseable, and
    jsonschema.ValidationError if it is off-contract (including an unknown key — a typo must
    fail loudly rather than be silently ignored).
    """
    path = Path(path_or_app_id)
    if not path.suffix:  # a bare app id, e.g. "juice-shop"
        path = app_config_path(path_or_app_id)
    if not path.is_file():
        raise FileNotFoundError(f"no app config at {path}")
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"app config {path} is not valid YAML: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ValueError(f"app config {path} must be a mapping, got {type(cfg).__name__}")

    import json  # local: only needed to read the committed schema
    jsonschema.validate(cfg, json.loads(_APP_SCHEMA.read_text(encoding="utf-8")))
    return cfg


def scope_from_config(cfg: dict) -> dict:
    """Derive the runner scope from the single app configuration."""
    from runner.scope_guard import host_of
    target = host_of(cfg["base_url"])
    if not target:
        raise ValueError(f"cannot determine target host from base_url {cfg['base_url']!r}")
    scope = cfg.get("scope", {})
    return {
        "app_id": cfg["app_id"],
        "environment_class": cfg["environment_class"],
        "target_fqdn": target,
        "fqdn_allow_list": sorted(set(scope.get("allow", [])) | {target}),
        "fqdn_deny_list": list(scope.get("deny", [])),
        "avoid_action_list": list(scope.get("avoid_actions", [])),
    }


def seed_from_config(cfg: dict) -> dict:
    """Derive the seeded exploration input from app.yaml."""
    state = storage_state(cfg)
    if not state:
        raise ValueError("no auth.storage_state in app config; seed a session first")
    return {
        "target": {"base_url": cfg["base_url"]},
        "session": {"storage_state": state},
        "seed_routes": seed_routes(cfg) or ["/"],
        "deny_actions": avoid_actions(cfg),
    }


# ---- accessors: one place for every default, so callers never invent one -----------------

def base_url(cfg: dict) -> str:
    return cfg["base_url"]


def login(cfg: dict) -> dict:
    """The login block: url + the three shorthand selectors.

    Only valid for applications configured with the shorthand; anything else must use
    `login_steps`, which covers both shapes.
    """
    auth = cfg["auth"]
    if "selectors" not in auth:
        raise ValueError("this application's login is a step list; use login_steps()")
    return {"url": auth["login_url"], **auth["selectors"]}


def login_url(cfg: dict) -> str:
    return cfg["auth"]["login_url"]


def uses_shorthand_login(cfg: dict) -> bool:
    return "selectors" in cfg["auth"]


_CREDENTIAL_ALIASES = {"email": "identifier", "password": "secret"}


def login_steps(cfg: dict) -> list[dict]:
    """The login as an ordered list of browser actions.

    The three-selector shorthand normalizes into the same shape as an explicit `steps` list, so
    every consumer (record, seed, the flow renderer) has one code path whether the app has an
    email field, a username field, two pages or a keypress. `value` names which credential to
    type; the value itself never appears in config (NFR-3).
    """
    auth = cfg["auth"]
    if "steps" in auth:
        out = []
        for step in auth["steps"]:
            step = dict(step)
            if "value" in step:
                step["value"] = _CREDENTIAL_ALIASES.get(step["value"], step["value"])
            out.append(step)
        return out
    sel = auth["selectors"]
    return [
        {"action": "fill", "selector": sel["email"], "value": "identifier"},
        {"action": "fill", "selector": sel["password"], "value": "secret"},
        {"action": "click", "selector": sel["submit"]},
    ]


def proof(cfg: dict) -> dict:
    """The configured proof of authentication, exactly one mode (schema-enforced)."""
    return cfg["auth"]["proof"]


def proof_mode(cfg: dict) -> str:
    """'js' | 'route' | 'selector' — which proof this application uses."""
    return next(iter(cfg["auth"]["proof"]))


def proof_js(cfg: dict) -> str:
    """The JS expression proving authentication.

    Raises ValueError for any other mode: a caller that can only evaluate JavaScript must fail
    rather than silently treat an unproven session as authenticated.
    """
    p = cfg["auth"]["proof"]
    if "js" in p:
        return p["js"]
    raise ValueError(f"auth.proof mode '{proof_mode(cfg)}' is not a JS expression")


def dismiss_selectors(cfg: dict) -> list[str]:
    """Cookie banners / modals to click away. Empty unless the app says otherwise."""
    return list(cfg.get("ui", {}).get("dismiss_selectors", []))


def api_patterns(cfg: dict) -> tuple[str, ...]:
    """URL substrings that mark a request as an API call worth recording."""
    return tuple(cfg.get("api", {}).get("patterns", ["/api/"]))


def authenticated_routes(cfg: dict) -> list[str]:
    """Routes the recorded walk visits after login."""
    return list(cfg.get("record", {}).get("authenticated_routes", []))


def seed_routes(cfg: dict) -> list[str]:
    return list(cfg.get("explore", {}).get("seed_routes", []))


def safe_forms(cfg: dict) -> list[str]:
    return list(cfg.get("explore", {}).get("safe_forms", []))


def submit_get_forms(cfg: dict) -> bool:
    return bool(cfg.get("explore", {}).get("submit_get_forms", True))


def writes_allowed(cfg: dict) -> bool:
    return (cfg.get("data_policy") == "disposable"
            and cfg.get("explore", {}).get("write_mode") == "allow")


def test_data(cfg: dict) -> dict:
    return dict(cfg.get("explore", {}).get("test_data", {}))


def inferred_fields(cfg: dict) -> dict:
    """Fields the operator permits the planner to supply a value for, with the shape required.

    Separate from test_data because the two answer different questions: test_data is a value the
    operator chose, this is permission to choose one, bounded by a pattern and a length. A field
    in neither is never filled.
    """
    return dict(cfg.get("explore", {}).get("inferred_fields", {}))


def avoid_actions(cfg: dict) -> list[str]:
    return list(cfg.get("scope", {}).get("avoid_actions", []))


def scope_allow(cfg: dict) -> list[str]:
    """Hosts this application may be reached AND attacked on."""
    return list(cfg.get("scope", {}).get("allow", []))


def scope_deny(cfg: dict) -> list[str]:
    """Host patterns that must never be contacted, even if otherwise allowed."""
    return list(cfg.get("scope", {}).get("deny", []))


def scan_cookies(cfg: dict) -> dict:
    return dict(cfg.get("auth", {}).get("cookies", {}))


def state_probes(cfg: dict) -> list[str]:
    return list(cfg.get("scan", {}).get("state_probes", []))


def storage_state(cfg: dict) -> str | None:
    return cfg["auth"].get("storage_state")


def max_pages(cfg: dict, default: int = 50) -> int:
    return int(cfg.get("explore", {}).get("budgets", {}).get("max_pages", default))


_DEFAULT_POLICY = {"attack_strength": "medium", "alert_threshold": "medium",
                   "disabled_rules": ["40026"]}   # DOM-XSS is browser-driven and slow
_DEFAULT_BUDGETS = {"max_scan_min": 4, "max_rule_min": 1}


def scan_policy(cfg: dict) -> dict:
    """Attack strength, alert threshold and disabled rules for this application (W2-4).

    Defaults to the historical posture so nothing changes for an app that says nothing — but
    every value here is a deliberate choice, and each disabled rule is a detection gap to
    disclose when results are compared with another tool (SP-3).
    """
    return {**_DEFAULT_POLICY, **cfg.get("scan", {}).get("policy", {})}


def scan_budgets(cfg: dict) -> dict:
    """Wall-clock bounds for the active scan. A truncated scan is not a clean bill of health."""
    return {**_DEFAULT_BUDGETS, **cfg.get("scan", {}).get("budgets", {})}


def self_registers(cfg: dict) -> bool:
    """True only when the application permits the tool to create its own account."""
    return cfg["auth"].get("identity", "provisioned") == "self-register"


def bootstrap(cfg: dict) -> dict | None:
    """The account-creation request, or None when the identity is provisioned."""
    return cfg["auth"].get("bootstrap") if self_registers(cfg) else None


def credential_env_names(cfg: dict) -> tuple[str, str]:
    """The environment variable names holding (identifier, secret) — never the values."""
    creds = cfg["auth"].get("credentials", {})
    return creds.get("email_env", "AUTH_EMAIL"), creds.get("password_env", "AUTH_PASSWORD")


def credentials(cfg: dict) -> tuple[str, str]:
    """(email, password) read from the environment variables the config NAMES (NFR-3).

    Raises ValueError when either variable is unset — an empty credential would fail at the
    login form with a far less obvious error.
    """
    creds = cfg["auth"].get("credentials", {})
    email_env = creds.get("email_env", "AUTH_EMAIL")
    password_env = creds.get("password_env", "AUTH_PASSWORD")
    email, password = os.environ.get(email_env), os.environ.get(password_env)
    missing = [n for n, v in ((email_env, email), (password_env, password)) if not v]
    if missing:
        raise ValueError(f"credentials not in the environment: {', '.join(missing)}")
    return email, password


def output_dir(cfg: dict) -> str | None:
    return cfg.get("output", {}).get("dir")


def github_publish(cfg: dict) -> dict:
    return dict(cfg.get("publish", {}).get("github", {}))
