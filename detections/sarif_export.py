"""Export normalized detection records as a SARIF 2.1.0 log (FR-X1).

Pure format translation: detection records in (contracts/detection.schema.json) → one SARIF
2.1.0 document out, which GitHub's Security tab ingests natively. Our stable fingerprint is
carried in `partialFingerprints` so GitHub tracks a finding across scans in agreement with our
lifecycle diff (FR-L2). See docs/junior_engineer/sarif_exporter_design.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from typing import TextIO

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
FINGERPRINT_KEY = "dastFingerprint/v1"

DRIVER_NAME = "OWASP ZAP (ssd-dast-poc)"
DRIVER_URI = "https://www.zaproxy.org/"

# severity -> SARIF result.level (enum: error | warning | note | none)
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# severity -> GitHub "security-severity" numeric band (>=9 critical, 7-8.9 high, 4-6.9 medium,
# 0.1-3.9 low). Without this, GitHub renders every alert as a plain warning.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}


def _rule_tags(cwe_id: str | None) -> list[str]:
    tags = ["security"]
    if cwe_id:
        # "CWE-89" -> "external/cwe/cwe-89" (GitHub's CWE tagging convention)
        tags.append("external/cwe/" + cwe_id.lower())
    return tags


def _rule_for(rec: dict) -> dict:
    return {
        "id": rec["rule_id"],
        "name": (rec.get("title") or rec["rule_id"]).replace(" ", ""),
        "shortDescription": {"text": rec.get("title") or rec["rule_id"]},
        "properties": {
            "tags": _rule_tags(rec.get("cwe_id")),
            "security-severity": _SECURITY_SEVERITY.get(rec["severity"], "0.0"),
        },
    }


def _result_for(rec: dict, rule_index: int) -> dict:
    result = {
        "ruleId": rec["rule_id"],
        "ruleIndex": rule_index,
        "level": _LEVEL.get(rec["severity"], "note"),
        "message": {"text": rec.get("title") or rec["rule_id"]},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": rec["endpoint"]}}}
        ],
        "partialFingerprints": {FINGERPRINT_KEY: rec["fingerprint"]},
        "properties": {
            "severity": rec["severity"],
            "parameter": rec.get("parameter"),
            "cwe_id": rec.get("cwe_id"),
            "scan_id": rec.get("scan_id"),
        },
    }
    # Reference the (redacted) evidence for this scan from the result (FR-E1).
    evidence = rec.get("evidence_path")
    if evidence:
        result["attachments"] = [
            {"artifactLocation": {"uri": evidence}, "description": {"text": "HAR + screenshot"}}
        ]
    return result


def to_sarif(records: Iterable[dict], driver_version: str | None = None) -> dict:
    """Build one SARIF 2.1.0 log from detection records (single pass over the input).

    A deduped `rules` array is assembled as results stream by, keeping ruleId <-> ruleIndex
    referential integrity. This holds the results in memory by necessity (SARIF is one
    document; GitHub uploads it whole) — the accepted D1 carve-out.
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for rec in records:
        # Coverage-aware publishing (R2): GitHub auto-closes any alert absent from the newest
        # upload. Only a `resolved` record (its route x rule was exercised and the finding is
        # gone) may be omitted; `not_scanned` is carried forward so a route this scan did not
        # reach never shows as "fixed". Raw normalizer records carry status "open" and pass.
        if rec.get("status") == "resolved":
            continue
        rid = rec["rule_id"]
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(_rule_for(rec))
        results.append(_result_for(rec, rule_index[rid]))

    driver = {"name": DRIVER_NAME, "informationUri": DRIVER_URI, "rules": rules}
    if driver_version:
        driver["version"] = driver_version

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def write_sarif(records: Iterable[dict], fh: TextIO, driver_version: str | None = None) -> None:
    json.dump(to_sarif(records, driver_version), fh, indent=2)
    fh.write("\n")


def _read_records(source: str | TextIO) -> list[dict]:
    """Read detection records from a JSON array or NDJSON file/stream."""
    fh = source if hasattr(source, "read") else open(source)
    try:
        text = fh.read()
    finally:
        if fh is not source:
            fh.close()
    text = text.strip()
    if not text:
        return []
    if text[0] == "[":  # JSON array
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]  # NDJSON


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export detection records as a SARIF 2.1.0 log.")
    p.add_argument("records", nargs="?", default="-",
                   help="Detection records (JSON array or NDJSON); - for stdin (default)")
    p.add_argument("--app-id", default=None, help="Application id (informational)")
    p.add_argument("--driver-version", default=None, help="Scanner version, e.g. ZAP 2.17.0")
    p.add_argument("-o", "--out", default="-", help="Output path, or - for stdout (default)")
    args = p.parse_args(argv)

    records = _read_records(sys.stdin if args.records == "-" else args.records)
    if args.out == "-":
        write_sarif(records, sys.stdout, args.driver_version)
    else:
        with open(args.out, "w") as fh:
            write_sarif(records, fh, args.driver_version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
