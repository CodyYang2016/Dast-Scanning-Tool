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
import importlib.util
import json
import sys
from pathlib import Path

from runner.preflight import preflight
from runner.scope_guard import ScopeGuard

_DEFAULT_SCHEMA = str(Path(__file__).resolve().parent.parent / "contracts" / "scope.schema.json")


def load_flow(flow_path: str):
    """Load a hand-authored flow module from a file path (the app dir has a hyphen, so it is
    not importable as a package)."""
    spec = importlib.util.spec_from_file_location("dast_flow", flow_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        raise RuntimeError(f"flow {flow_path} has no run(page, base_url) function")
    return module


def replay(scope: dict, flow_module, base_url: str, zap_proxy: str, headless: bool = True):
    """Run the flow in Chromium proxied through ZAP, enforcing the scope guard. Returns
    (result, guard). Raises ScopeViolation if any out-of-scope request occurred."""
    from playwright.sync_api import sync_playwright  # imported lazily so tests don't need it

    guard = ScopeGuard(scope)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, proxy={"server": zap_proxy})
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        # Safety layer 2: every browser request passes the scope guard before the proxy.
        page.route("**/*", lambda route: guard.route_handler(route))
        try:
            result = flow_module.run(page, base_url)
        finally:
            context.close()
            browser.close()

    guard.raise_if_violated()  # FR-S4: fail the scan if the boundary was crossed
    return result, guard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Replay an authenticated flow through ZAP (FR-S1/R2).")
    p.add_argument("--scope", required=True, help="Path to the app scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--flow", required=True, help="Path to the hand-authored flow.py")
    p.add_argument("--base-url", default="http://juice:3000", help="Target as ZAP resolves it")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--headed", action="store_true", help="Run with a visible browser")
    args = p.parse_args(argv)

    # Safety layer 1: preflight before we launch anything.
    scope = preflight(args.scope, args.schema)
    flow = load_flow(args.flow)

    try:
        result, guard = replay(scope, flow, args.base_url, args.zap_proxy, headless=not args.headed)
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
