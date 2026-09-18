"""Authenticated flow replay through the ZAP proxy (FR-S1, FR-R2).

Launches Chromium with its proxy pointed at the ZAP daemon and runs a hand-authored flow, so
ZAP observes the authenticated traffic it could never reach on its own. Both safety layers are
active: preflight (FR-S3) runs before the browser launches, and the scope guard (FR-S4) is
attached as a page.route interceptor so any out-of-allow-list request is blocked and fails the
scan. See docs/junior_engineer/runner_design.md.

Topology note: the browser is proxied through ZAP, so ZAP (not the browser) resolves the
target host. With the containerized ZAP, the reachable target is http://juice:3000, so the
scope's allow-list must contain that host (see security/dast/juice-shop/scope.json).
"""

from __future__ import annotations

import argparse
import inspect
import importlib.util
import json
import os
import sys
from pathlib import Path

from runner.preflight import preflight
from runner.scope_guard import ScopeGuard

_DEFAULT_SCHEMA = str(Path(__file__).resolve().parent.parent / "contracts" / "scope.schema.json")


_LOGIN_MARKERS = ("/login", "/#/login", "/signin")


class SessionDeadError(Exception):
    """Raised when a seeded session is not authenticated (expired/invalid). Fail closed: the
    caller must fall back to a login flow, never scan an unauthenticated surface (Phase A)."""


def prove_auth_live(page, base_url: str, seed_route: str, token_check: str | None = None) -> dict:
    """Visit a seed route and decide whether the (seeded) session is authenticated.

    Dead if the app redirects to a login route, the response is 401/403, or `token_check` (a JS
    truthy expression) is falsy. Pure w.r.t. the page object (takes any page-like) so the decision
    logic is unit-testable with a fake page. Returns {"alive": bool, "reason": str, "url": str}.
    """
    resp = page.goto(base_url + seed_route, wait_until="networkidle")
    status = getattr(resp, "status", None)
    if callable(status):  # some fakes/clients expose status() as a method
        status = status()
    current = page.url
    if any(m in current for m in _LOGIN_MARKERS):
        return {"alive": False, "reason": f"redirected to login: {current}", "url": current}
    if status in (401, 403):
        return {"alive": False, "reason": f"seed route returned {status}", "url": current}
    if token_check and not page.evaluate(f"() => !!({token_check})"):
        return {"alive": False, "reason": "auth token missing (session not established)", "url": current}
    return {"alive": True, "reason": "session authenticated", "url": current}


def load_flow(flow_path: str):
    """Load a hand-authored flow module from a file path (the app dir has a hyphen, so it is
    not importable as a package)."""
    spec = importlib.util.spec_from_file_location("dast_flow", flow_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        raise RuntimeError(f"flow {flow_path} has no run(page, base_url) function")
    return module


def replay(scope: dict, flow_module, base_url: str, zap_proxy: str, headless: bool = True,
           evidence_dir: str | None = None):
    """Run the flow in Chromium proxied through ZAP, enforcing the scope guard. Returns
    (result, guard). Raises ScopeViolation if any out-of-scope request occurred.

    If evidence_dir is given, a HAR (active-scan.har) and a screenshot (screenshot.png) are
    captured there (FR-E1). The HAR is UNREDACTED at this point — the caller must redact it
    before it is published (see runner/evidence.py)."""
    from playwright.sync_api import sync_playwright  # imported lazily so tests don't need it

    # In a container Chromium runs as root and with a small /dev/shm; both need flags. Gated by
    # an env var so local (non-root) runs are unaffected. Compose sets RUNNER_CHROMIUM_NO_SANDBOX=1.
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []

    guard = ScopeGuard(scope)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, proxy={"server": zap_proxy}, args=launch_args)
        ctx_kwargs = {"ignore_https_errors": True}
        if evidence_dir:
            Path(evidence_dir).mkdir(parents=True, exist_ok=True)
            ctx_kwargs["record_har_path"] = str(Path(evidence_dir) / "active-scan.har")
        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()
        # Safety layer 2: every browser request passes the scope guard before the proxy.
        page.route("**/*", lambda route: guard.route_handler(route))
        try:
            run_params = inspect.signature(flow_module.run).parameters
            if evidence_dir and "evidence_dir" in run_params:
                result = flow_module.run(page, base_url, evidence_dir=evidence_dir)
            else:
                result = flow_module.run(page, base_url)
        finally:
            if evidence_dir and "evidence_dir" not in inspect.signature(flow_module.run).parameters:
                page.screenshot(path=str(Path(evidence_dir) / "screenshot.png"), full_page=True)
            context.close()  # writes the HAR
            browser.close()

    guard.raise_if_violated()  # FR-S4: fail the scan if the boundary was crossed
    return result, guard


def replay_seeded(scope: dict, base_url: str, zap_proxy: str, storage_state: str,
                  seed_routes: list[str], headless: bool = True, evidence_dir: str | None = None,
                  token_check: str | None = None):
    """Replay a SEEDED session through ZAP: start already authenticated from `storage_state` (no
    login flow), prove the session is live, then visit the seed routes so ZAP observes the
    authenticated traffic. Returns (result, guard).

    Raises SessionDeadError if the seeded session is not authenticated (caller falls back to a
    login flow — never scan unauthenticated). Both safety layers stay active: preflight (caller)
    and the scope guard (page.route). HAR is unredacted here; the caller redacts before publishing.
    """
    from playwright.sync_api import sync_playwright  # lazy, as in replay()

    if not seed_routes:
        raise ValueError("replay_seeded requires at least one seed route")
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []

    guard = ScopeGuard(scope)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, proxy={"server": zap_proxy}, args=launch_args)
        ctx_kwargs = {"ignore_https_errors": True, "storage_state": storage_state}
        if evidence_dir:
            Path(evidence_dir).mkdir(parents=True, exist_ok=True)
            ctx_kwargs["record_har_path"] = str(Path(evidence_dir) / "active-scan.har")
        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()
        page.route("**/*", lambda route: guard.route_handler(route))  # safety layer 2
        try:
            liveness = prove_auth_live(page, base_url, seed_routes[0], token_check)
            if not liveness["alive"]:
                raise SessionDeadError(liveness["reason"])
            for route in seed_routes:
                page.goto(base_url + route, wait_until="networkidle")
        finally:
            if evidence_dir:
                page.screenshot(path=str(Path(evidence_dir) / "screenshot.png"), full_page=True)
            context.close()  # writes the HAR
            browser.close()

    guard.raise_if_violated()  # FR-S4
    return {"authenticated": True, "seeded": True, "routes_visited": len(seed_routes)}, guard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Replay an authenticated flow through ZAP (FR-S1/R2).")
    p.add_argument("--scope", required=True, help="Path to the app scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--flow", required=True, help="Path to the hand-authored flow.py")
    p.add_argument("--base-url", default="http://juice:3000", help="Target as ZAP resolves it")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--evidence-dir", default=None,
                   help="Optional directory for replay HAR and screenshot evidence")
    p.add_argument("--headed", action="store_true", help="Run with a visible browser")
    args = p.parse_args(argv)

    # Safety layer 1: preflight before we launch anything.
    scope = preflight(args.scope, args.schema)
    flow = load_flow(args.flow)

    try:
        result, guard = replay(scope, flow, args.base_url, args.zap_proxy,
                               headless=not args.headed, evidence_dir=args.evidence_dir)
    except Exception as exc:
        print(f"REPLAY FAILED: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "result": result,
        "requests_seen": len(guard.decisions),
        "blocked": len(guard.violations),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
