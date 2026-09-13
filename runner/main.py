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
from datetime import datetime, timezone
from pathlib import Path

from detections.normalizer import normalize, write_json_array
from runner import evidence
from runner.preflight import PreflightError, preflight
from runner.replay import load_flow, replay
from runner.scan import ScanScopeError, new_session, scan
from runner.scope_guard import ScopeViolation

_DEFAULT_SCHEMA = "contracts/scope.schema.json"


def _scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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
        fresh=True, do_spider=True, max_scan_min=4):
    """Execute the full loop. Returns (scope, replay_result, guard, records, scan_id)."""
    scope = preflight(scope_path, schema)              # safety layer 1
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
    return scope, result, guard, records, scan_id


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="End-to-end DAST runner (Phase 1 gate).")
    p.add_argument("--scope", required=True, help="App scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--flow", required=True, help="Hand-authored flow.py")
    p.add_argument("--base-url", default="http://juice:3000", help="Target as ZAP resolves it")
    p.add_argument("--zap-api", default="http://localhost:8080")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--records-out", default=None, help="Write detection records here")
    p.add_argument("--no-spider", action="store_true")
    p.add_argument("--no-fresh", action="store_true", help="Do not reset the ZAP session first")
    p.add_argument("--max-scan-min", type=int, default=4)
    args = p.parse_args(argv)

    try:
        scope, result, guard, records, scan_id = run(
            args.scope, args.schema, args.flow, args.base_url, args.zap_api, args.zap_proxy,
            fresh=not args.no_fresh, do_spider=not args.no_spider, max_scan_min=args.max_scan_min,
        )
    except (PreflightError, ScanScopeError, ScopeViolation) as exc:
        print(f"RUNNER ABORT: {exc}", file=sys.stderr)
        return 2

    gate = evaluate_gate(result.get("authenticated"), guard.ok, records)
    if args.records_out:
        with open(args.records_out, "w") as fh:
            write_json_array(records, fh)

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
