"""Normalize raw ZAP output into detection records (FR-N1).

Input:  ZAP alerts JSON (contracts/sample_zap_output.json shape: {"alerts": [...]}).
Output: records matching contracts/detection.schema.json.

Pure functions — no I/O in the core, so this is trivially unit-testable against the fixture.
A thin CLI at the bottom is provided for pipeline use.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from detections.fingerprint import endpoint_pattern, fingerprint, payload_family

# ZAP risk -> normalized severity enum (contracts/detection.schema.json).
_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# ZAP uses "-1" (and occasionally "0") to mean "no CWE".
_NO_CWE = {"", "-1", "0", None}


def _cwe_id(raw) -> str | None:
    """ZAP cweid -> 'CWE-<n>' or None when absent (FR-N1 'CWE where available')."""
    if raw in _NO_CWE:
        return None
    return f"CWE-{raw}"


def normalize_alert(alert: dict, app_id: str, scan_id: str) -> dict:
    """Map a single ZAP alert to a detection record (contracts/detection.schema.json)."""
    rule_id = str(alert.get("pluginId", ""))
    endpoint = endpoint_pattern(alert.get("url", ""))
    parameter = alert.get("param") or None  # empty string -> null in the record
    family = payload_family(rule_id)

    return {
        "app_id": app_id,
        "scan_id": scan_id,
        "fingerprint": fingerprint(rule_id, endpoint, parameter or "", family),
        "rule_id": rule_id,
        "title": alert.get("alert") or alert.get("name") or "",
        "severity": _SEVERITY.get(alert.get("risk"), "info"),
        "cwe_id": _cwe_id(alert.get("cweid")),
        "endpoint": endpoint,
        "parameter": parameter,
        "status": "open",  # lifecycle diff (FR-L2) reassigns new/open/resolved
        "evidence_path": None,  # wired in by the runner's evidence capture (FR-E1)
    }


def normalize(zap_report: dict, app_id: str, scan_id: str) -> list[dict]:
    """Normalize a full ZAP report ({"alerts": [...]}) into detection records."""
    return [normalize_alert(a, app_id, scan_id) for a in zap_report.get("alerts", [])]


def _new_scan_id() -> str:
    """UTC scan id matching detection.schema.json pattern ^[0-9]{8}T[0-9]{6}Z$."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Normalize ZAP output into detection records.")
    p.add_argument("zap_json", help="Path to ZAP alerts JSON (e.g. contracts/sample_zap_output.json)")
    p.add_argument("--app-id", required=True, help="Application id (must match scope.app_id)")
    p.add_argument("--scan-id", default=None, help="Scan id (default: current UTC timestamp)")
    p.add_argument("-o", "--out", default="-", help="Output path, or - for stdout (default)")
    args = p.parse_args(argv)

    with open(args.zap_json) as fh:
        report = json.load(fh)
    records = normalize(report, args.app_id, args.scan_id or _new_scan_id())

    out = json.dumps(records, indent=2)
    if args.out == "-":
        print(out)
    else:
        with open(args.out, "w") as fh:
            fh.write(out + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
