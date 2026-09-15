"""validate CLI (FR-V1/V2/V3): check a generated bundle before it drives a scan.

- FR-V2 (pure): every host the journey plan would contact is covered by scope.json's allow-list.
- FR-V1 (live): replay the generated flow.py against the pilot app and confirm auth succeeds.
- FR-V3: write validation-report.json (per-check pass/fail) and return non-zero on any failure.

The allow-list check and the report/exit contract are pure and unit-tested; the auth replay is
verified by running it. Reuses runner/scope_guard.py and runner/replay.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from runner.scope_guard import ScopeGuard, host_of

_DEFAULT_SCHEMA = str(Path(__file__).resolve().parent.parent / "contracts" / "scope.schema.json")


def plan_hosts(plan: dict) -> set[str]:
    """Hosts the plan would contact: the base_url host plus any absolute-URL journey targets."""
    hosts: set[str] = set()
    base = host_of(plan.get("base_url", ""))
    if base:
        hosts.add(base)
    for step in plan.get("journey", []):
        target = step.get("target", "")
        if "://" in target:
            h = host_of(target)
            if h:
                hosts.add(h)
    return hosts


def check_allowlist(plan: dict, scope: dict) -> list[str]:
    """Return the hosts the plan would contact that scope does NOT allow (empty = in scope)."""
    guard = ScopeGuard(scope)
    return [h for h in sorted(plan_hosts(plan)) if not guard.check(f"http://{h}/").allowed]


def build_report(checks: dict) -> dict:
    """checks: {name: (passed, detail)} -> {"checks":[...], "passed": all}."""
    items = [{"name": n, "passed": bool(p), "detail": d} for n, (p, d) in checks.items()]
    return {"checks": items, "passed": all(c["passed"] for c in items)}


def _replay_auth(plan_path: str, flow_path: str, scope: dict, base_url: str, zap_proxy: str):
    """Live FR-V1: replay the generated flow and confirm auth. Returns (passed, detail)."""
    from runner.replay import load_flow, replay
    try:
        result, _guard = replay(scope, load_flow(flow_path), base_url, zap_proxy)
        ok = bool(result.get("authenticated"))
        return ok, f"authenticated={result.get('authenticated')}"
    except Exception as exc:
        return False, f"replay failed: {exc}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate a generated bundle (FR-V1/V2/V3).")
    p.add_argument("--plan", required=True, help="journey.json from generate")
    p.add_argument("--scope", required=True, help="scope.json from generate")
    p.add_argument("--flow", default=None, help="generated flow.py (needed unless --no-replay)")
    p.add_argument("--base-url", default="http://juice:3000")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--no-replay", action="store_true", help="Skip the live auth replay (FR-V2/V3 only)")
    p.add_argument("--report", default="validation-report.json")
    args = p.parse_args(argv)

    plan = json.loads(Path(args.plan).read_text())
    scope = json.loads(Path(args.scope).read_text())

    checks: dict = {}
    violations = check_allowlist(plan, scope)
    checks["allowlist"] = (not violations,
                           "all hosts in allow-list" if not violations
                           else f"out-of-scope hosts: {violations}")

    if not args.no_replay:
        if not args.flow:
            checks["auth"] = (False, "no --flow provided for replay")
        else:
            checks["auth"] = _replay_auth(args.plan, args.flow, scope, args.base_url, args.zap_proxy)

    report = build_report(checks)
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 2  # FR-V3: non-zero exit on any failing check


if __name__ == "__main__":
    sys.exit(main())
