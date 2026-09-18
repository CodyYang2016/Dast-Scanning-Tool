"""End-to-end runner — the Phase 1 "minimum viable scanner" gate.

Chains the whole safe-scan loop into one command:

    preflight (FR-S3/NFR-2) -> fresh ZAP session -> authenticated replay through the ZAP
    proxy (FR-S1/R2) with the scope guard active (FR-S4/NFR-4) -> bounded active scan
    (FR-S1/S2) -> normalize into detection records (FR-N1).

Exit code is the gate: 0 only if the scan authenticated, stayed in scope, and produced at
least one high/medium detection. See docs/junior_engineer/runner_design.md and the demo
plan's Phase 1 gate.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from detections.normalizer import normalize, write_json_array
from runner import coverage as coverage_capture
from runner import evidence
from runner.preflight import PreflightError, preflight
from runner.replay import load_flow, replay
from runner.scan import ScanScopeError, new_session, scan
from runner.scope_guard import ScopeViolation

_DEFAULT_SCHEMA = "contracts/scope.schema.json"


def _scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _reachable(url: str, timeout: float = 3.0) -> bool:
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except Exception:
        return False


def _zap_can_reach(zap_api: str, target: str, timeout: float = 10.0) -> bool:
    """True if ZAP can fetch the target (checked THROUGH ZAP via accessUrl).

    The runner reaches the target only via ZAP (ZAP resolves the host, e.g. `juice` on the
    docker network), so readiness must be checked from ZAP's perspective — not by the runner
    polling the target directly, which fails on the host where `juice` doesn't resolve.
    """
    q = urllib.parse.urlencode({"url": target, "followRedirects": "true"})
    url = zap_api.rstrip("/") + "/JSON/core/action/accessUrl/?" + q
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return bool(json.loads(resp.read()).get("accessUrl"))
    except Exception:
        return False


def wait_ready(zap_api: str, base_url: str, timeout: float = 120.0, interval: float = 2.0) -> None:
    """Poll until the ZAP API is up AND ZAP can reach the target (robust start ordering).

    Works on the host and in compose alike, because both reach ZAP and it's ZAP that resolves
    the target host. Returns immediately when ready; raises after `timeout`.
    """
    zap_version = zap_api.rstrip("/") + "/JSON/core/view/version/"
    end = time.monotonic() + timeout
    while True:
        if _reachable(zap_version) and _zap_can_reach(zap_api, base_url):
            return
        if time.monotonic() >= end:
            raise RuntimeError(f"services not ready within {timeout:.0f}s (zap={zap_api}, target={base_url})")
        time.sleep(interval)


def evaluate_gate(authenticated: bool, scope_ok: bool, records: list[dict]) -> dict:
    """Phase 1 gate: authenticated + in-scope + >=1 high/medium detection. Pure/testable."""
    has_high_or_medium = any(r["severity"] in ("critical", "high", "medium") for r in records)
    return {
        "authenticated": bool(authenticated),
        "scope_ok": bool(scope_ok),
        "has_high_or_medium": has_high_or_medium,
        "detections": len(records),
        "passed": bool(authenticated) and bool(scope_ok) and has_high_or_medium,
    }


def run(scope_path, schema, flow_path, base_url, zap_api, zap_proxy,
        fresh=True, do_spider=True, max_scan_min=4, wait=True):
    """Execute the full loop. Returns (scope, replay_result, guard, records, scan_id, coverage).

    `coverage` is the (route x rule) surface this scan exercised (R2), for the lifecycle diff."""
    scope = preflight(scope_path, schema)              # safety layer 1 (offline; fail fast)
    if wait:
        wait_ready(zap_api, base_url)                  # tolerate container startup ordering
    scan_id = _scan_id()
    app_dir = str(Path(scope_path).resolve().parent)   # evidence lives under the app dir
    ev_dir = evidence.evidence_dir(app_dir, scan_id)    # FR-E1

    if fresh:
        new_session(zap_api)                           # clean per-scan session
    flow = load_flow(flow_path)
    result, guard = replay(scope, flow, base_url, zap_proxy, evidence_dir=str(ev_dir))

    # Redact the HAR immediately after capture — before it can be published (hard requirement).
    har = ev_dir / "active-scan.har"
    if har.exists():
        evidence.redact_har_file(str(har))

    report = scan(zap_api, base_url, scope["fqdn_allow_list"],
                  do_spider=do_spider, max_scan_min=max_scan_min)
    records = list(normalize(report["alerts"], scope["app_id"], scan_id))
    # Reference the scan's evidence from each record (FR-E1).
    relpath = evidence.evidence_relpath(scan_id)
    for r in records:
        r["evidence_path"] = relpath
    # Capture the (route x rule) surface this scan exercised, for the coverage-aware diff (R2).
    coverage = coverage_capture.capture(zap_api, base_url)
    return scope, result, guard, records, scan_id, coverage


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="End-to-end DAST runner (Phase 1 gate).")
    p.add_argument("--scope", required=True, help="App scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--flow", required=True, help="Hand-authored flow.py")
    p.add_argument("--base-url", default="http://juice:3000", help="Target as ZAP resolves it")
    p.add_argument("--zap-api", default="http://localhost:8080")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--records-out", default=None, help="Write detection records here")
    p.add_argument("--coverage-out", default=None,
                   help="Write this scan's (route x rule) coverage here for the lifecycle diff (R2)")
    p.add_argument("--no-spider", action="store_true")
    p.add_argument("--no-fresh", action="store_true", help="Do not reset the ZAP session first")
    p.add_argument("--no-wait", action="store_true", help="Do not wait for ZAP/target readiness")
    p.add_argument("--max-scan-min", type=int, default=4)
    args = p.parse_args(argv)

    try:
        scope, result, guard, records, scan_id, coverage = run(
            args.scope, args.schema, args.flow, args.base_url, args.zap_api, args.zap_proxy,
            fresh=not args.no_fresh, do_spider=not args.no_spider, max_scan_min=args.max_scan_min,
            wait=not args.no_wait,
        )
    except (PreflightError, ScanScopeError, ScopeViolation) as exc:
        print(f"RUNNER ABORT: {exc}", file=sys.stderr)
        return 2

    gate = evaluate_gate(result.get("authenticated"), guard.ok, records)
    if args.records_out:
        with open(args.records_out, "w") as fh:
            write_json_array(records, fh)
    if args.coverage_out:
        with open(args.coverage_out, "w") as fh:
            json.dump(coverage, fh, indent=2)

    print(json.dumps({
        "scan_id": scan_id,
        "app_id": scope["app_id"],
        "requests_seen": len(guard.decisions),
        "blocked": len(guard.violations),
        "gate": gate,
    }, indent=2))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
