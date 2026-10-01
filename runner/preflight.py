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
_SHARED = {"test", "staging"}


class PreflightError(Exception):
    """Raised when a scope is unsafe/invalid to scan. Callers MUST abort (send no traffic)."""


def check_scope(scope: dict, registry=None) -> None:
    """Safety checks on an in-memory scope. Raise PreflightError if unsafe. Pure; no I/O.

    Rejects: missing environment_class; production (any case); missing/empty fqdn_allow_list;
    and, given an environment `registry` (runner/env_registry.py), production-looking hosts,
    hosts registered as another class, and unregistered shared hosts (W4-6).
    """
    env = scope.get("environment_class")
    if env is None:
        raise PreflightError("scope has no 'environment_class' — refusing to scan (NFR-2).")
    if str(env).strip().lower() in _PROD_VALUES:
        raise PreflightError(
            f"environment_class={env!r} is production — refusing to scan (NFR-2)."
        )
    # Shared environments must name exact origins (W4-2). A bare host admits every scheme and
    # port on that machine — an admin port, another service, a plaintext listener — which is
    # harmless on a disposable dev container and not acceptable on a shared test/staging host.
    if str(env).strip().lower() in _SHARED and scope.get("fqdn_allow_list"):
        from runner.scope_guard import is_origin
        bare = [h for h in scope["fqdn_allow_list"] if not is_origin(h)]
        if bare:
            examples = ", ".join(f"https://{h}" for h in bare[:3])
            raise PreflightError(
                f"environment_class={env!r} is a shared environment, so scope must name exact "
                f"origins, not bare hosts: {bare} admit every scheme and port on those machines. "
                f"Write them as origins, e.g. {examples} (add :port when it is not the default).")
    if not scope.get("fqdn_allow_list"):  # None or empty list
        raise PreflightError(
            "scope has no non-empty 'fqdn_allow_list' — refusing to scan an unbounded "
            "target (NFR-2)."
        )
    if registry is not None:
        check_registry(scope, registry)


def check_registry(scope: dict, registry) -> None:
    """The declared environment, verified (W4-6). One typed word is not a safety story."""
    from runner.scope_guard import host_of, is_origin
    env = str(scope["environment_class"]).strip().lower()
    for entry in scope["fqdn_allow_list"]:
        host = host_of(entry) if is_origin(entry) else str(entry).strip().lower()
        if registry.is_production(host):
            raise PreflightError(
                f"{host!r} matches a production hostname pattern — refusing to scan it whatever "
                f"environment_class says (W4-6). If it is not production, change the pattern "
                f"in the environment registry, not this scope.")
        registered = registry.lookup(host)
        if registered is not None and registered != env:
            raise PreflightError(
                f"{host!r} is registered as {registered!r} but this scope declares "
                f"environment_class={env!r} — refusing to scan until they agree (W4-6).")
        if registered is None and env in _SHARED:
            raise PreflightError(
                f"{host!r} is not registered, and a {env} environment must be: add "
                f"`{host}: {env}` under `hosts:` in the environment registry "
                f"(security/dast/environments.yaml or $DAST_ENV_REGISTRY) (W4-6).")


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
    from runner import env_registry
    try:
        registry = env_registry.load()
    except Exception as exc:
        raise PreflightError(f"could not read the environment registry: {exc}") from exc
    check_scope(scope, registry=registry)

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
