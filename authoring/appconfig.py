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
        cfg = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"app config {path} is not valid YAML: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ValueError(f"app config {path} must be a mapping, got {type(cfg).__name__}")

    import json  # local: only needed to read the committed schema
    jsonschema.validate(cfg, json.loads(_APP_SCHEMA.read_text()))
    return cfg


# ---- accessors: one place for every default, so callers never invent one -----------------

def base_url(cfg: dict) -> str:
    return cfg["base_url"]


def login(cfg: dict) -> dict:
    """The login block: url + email/password/submit selectors."""
    auth = cfg["auth"]
    return {"url": auth["login_url"], **auth["selectors"]}


def proof_js(cfg: dict) -> str:
    """The JS expression proving authentication.

    Raises ValueError for a proof mode this build cannot evaluate (route/selector arrive with
    W2-11). Fail closed: never fall back to "assume authenticated".
    """
    proof = cfg["auth"]["proof"]
    if "js" in proof:
        return proof["js"]
    mode = next(iter(proof), "none")
    raise ValueError(f"auth.proof mode '{mode}' is not supported yet (W2-11); use proof.js")


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


def avoid_actions(cfg: dict) -> list[str]:
    return list(cfg.get("scope", {}).get("avoid_actions", []))


def storage_state(cfg: dict) -> str | None:
    return cfg["auth"].get("storage_state")


def max_pages(cfg: dict, default: int = 50) -> int:
    return int(cfg.get("explore", {}).get("budgets", {}).get("max_pages", default))


def self_registers(cfg: dict) -> bool:
    """True only when the application permits the tool to create its own account."""
    return cfg["auth"].get("identity", "provisioned") == "self-register"


def bootstrap(cfg: dict) -> dict | None:
    """The account-creation request, or None when the identity is provisioned."""
    return cfg["auth"].get("bootstrap") if self_registers(cfg) else None


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
