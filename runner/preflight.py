"""Preflight safety gate for the DAST runner (FR-S3, NFR-2).

Refuses to scan an unsafe configuration BEFORE any network traffic is sent. This is the
single most important guardrail: never scan production, never scan an unbounded target.
Conforms to the frozen spec in docs/junior_engineer/runner_design.md §7 and the test-first
suite tests/test_preflight.py.

Fails closed: any doubt raises PreflightError (CLI: non-zero exit), which a scan wrapper
must treat as "do not proceed".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

_DEFAULT_SCHEMA = str(Path(__file__).resolve().parent.parent / "contracts" / "scope.schema.json")

# Explicit, case-insensitive production denylist — defense-in-depth beyond the schema enum, so
# loosening scope.schema.json can never silently re-enable production scanning.
_PROD_VALUES = {"prod", "production"}


class PreflightError(Exception):
    """Raised when a scope is unsafe/invalid to scan. Callers MUST abort (send no traffic)."""


def check_scope(scope: dict) -> None:
    """Safety checks on an in-memory scope. Raise PreflightError if unsafe. Pure; no I/O.

    Rejects: missing environment_class; production (any case); missing/empty fqdn_allow_list.
    """
    env = scope.get("environment_class")
    if env is None:
        raise PreflightError("scope has no 'environment_class' — refusing to scan (NFR-2).")
    if str(env).strip().lower() in _PROD_VALUES:
        raise PreflightError(
            f"environment_class={env!r} is production — refusing to scan (NFR-2)."
        )
    if not scope.get("fqdn_allow_list"):  # None or empty list
        raise PreflightError(
            "scope has no non-empty 'fqdn_allow_list' — refusing to scan an unbounded "
            "target (NFR-2)."
        )


def preflight(scope_path: str, schema_path: str = _DEFAULT_SCHEMA) -> dict:
    """Load scope.json, run check_scope(), then full JSON-Schema validation.

    Returns the validated scope dict, or raises PreflightError (missing file, bad JSON,
    unsafe config, or schema violation). Never performs network I/O.
    """
    if not os.path.exists(scope_path):
        raise PreflightError(f"scope file not found: {scope_path}")
    try:
        with open(scope_path) as fh:
            scope = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise PreflightError(f"could not read scope.json: {exc}") from exc
    if not isinstance(scope, dict):
        raise PreflightError("scope.json must be a JSON object.")

    # Explicit safety checks first (clear, safety-specific messages) ...
    check_scope(scope)

    # ... then full structural validation against the contract schema.
    try:
        with open(schema_path) as fh:
            schema = json.load(fh)
    except OSError as exc:
        raise PreflightError(f"could not read scope schema: {exc}") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(scope), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(e.message for e in errors[:3])
        raise PreflightError(f"scope.json failed schema validation: {detail}")

    return scope


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Preflight safety gate for the DAST runner (FR-S3/NFR-2)."
    )
    p.add_argument("--scope", required=True, help="Path to scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA, help="Path to scope.schema.json")
    args = p.parse_args(argv)

    try:
        scope = preflight(args.scope, args.schema)
    except PreflightError as exc:
        print(f"PREFLIGHT ABORT: {exc}", file=sys.stderr)
        return 2  # non-zero: a scan wrapper MUST NOT proceed
    print(
        f"preflight OK: app_id={scope['app_id']} "
        f"environment_class={scope['environment_class']} "
        f"allow_list={scope['fqdn_allow_list']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
