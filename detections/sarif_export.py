"""Export normalized detection records as a SARIF 2.1.0 log (FR-X1).

Pure format translation: detection records in (contracts/detection.schema.json) → one SARIF
2.1.0 document out, which GitHub's Security tab ingests natively. Our stable fingerprint is
carried in `partialFingerprints` so GitHub tracks a finding across scans in agreement with our
lifecycle diff (FR-L2). See docs/junior_engineer/sarif_exporter_design.md.
"""

from __future__ import annotations

import argparse
import json
import re
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


def _help(rec: dict) -> dict | None:
    """The remediation panel GitHub shows on an alert: how to fix it, then what to read.

    Rule-level. ZAP's description and solution describe the plugin rather than the instance, so
    the first record of a rule speaks for all of them (pinned by a test, so a source that varies
    them per finding fails loudly instead of showing one finding's text on another).
    """
    solution, refs = rec.get("solution"), rec.get("references") or []
    if not (solution or refs):
        return None
    text_parts, md_parts = [], []
    if solution:
        text_parts.append(solution)
        # ZAP writes one instruction per line; markdown would join them into a single
        # paragraph, so each line ends in a hard break.
        md_parts.append("**How to fix**\n\n" + "  \n".join(solution.splitlines()))
    if refs:
        text_parts.append("References:\n" + "\n".join(refs))
        md_parts.append("**References**\n\n" + "\n".join(f"- <{u}>" for u in refs))
    return {"text": "\n\n".join(text_parts), "markdown": "\n\n".join(md_parts)}


def _rule_for(rec: dict) -> dict:
    rule = {
        "id": rec["rule_id"],
        "name": (rec.get("title") or rec["rule_id"]).replace(" ", ""),
        "shortDescription": {"text": rec.get("title") or rec["rule_id"]},
        "properties": {
            "tags": _rule_tags(rec.get("cwe_id")),
            "security-severity": _SECURITY_SEVERITY.get(rec["severity"], "0.0"),
        },
    }
    # Only when the source had them: an empty help panel reads as "there is no advice", which is
    # a different statement from "the scanner gave none".
    if rec.get("description"):
        rule["fullDescription"] = {"text": rec["description"]}
    help_ = _help(rec)
    if help_:
        rule["help"] = help_
    if rec.get("references"):
        rule["helpUri"] = rec["references"][0]
    return rule


def _code(value: str, markdown: bool) -> str:
    """Wrap a value as inline code.

    In markdown the value may be hostile: evidence is lifted from the TARGET's response, and a
    backtick inside it would close a naive span and let the rest render as live markdown — a
    link in the Security tab authored by whoever controls the scanned application. CommonMark
    closes a code span only on a run of EXACTLY the opening length, so the delimiter is one
    longer than the longest backtick run inside, padded so a leading/trailing backtick is safe.
    """
    if not markdown:
        return f"`{value}`"
    longest = max((len(r) for r in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {value} {fence}" if longest else f"{fence}{value}{fence}"


def _message(rec: dict, markdown: bool = False) -> str:
    """What a reviewer reads under the location on the alert page.

    GitHub renders a result's message and its rule's help — NOT `properties`. That is why the
    parameter was invisible in the Security tab while sitting in properties.parameter all along.
    So where the finding is, what proved it, and how sure the scanner is all belong here. Each
    clause appears only when its field does, so a header finding reads as a plain sentence.
    """
    msg = rec.get("title") or rec["rule_id"]
    if rec.get("parameter"):
        msg += f" in parameter {_code(rec['parameter'], markdown)}"
    attack, evidence = rec.get("attack"), rec.get("evidence_excerpt")
    if attack and evidence:
        msg += (f" — ZAP sent {_code(attack, markdown)} and the server answered "
                f"{_code(evidence, markdown)}")
    elif attack:
        msg += f" — ZAP sent {_code(attack, markdown)}"
    elif evidence:
        msg += f" — evidence: {_code(evidence, markdown)}"
    msg += "."
    if rec.get("confidence"):
        msg += f" Confidence: {rec['confidence'].capitalize()}."
    # How to replay it (W1-3). The request line carries the attack payload, so it is fenced like
    # any other target-shaped text; the full redacted exchange sits at exchange_path.
    if rec.get("request_line"):
        msg += f" Reproduce: {_code(rec['request_line'], markdown)}"
        if rec.get("response_status") is not None:
            msg += f" → {rec['response_status']}"
        msg += "."
    return msg


def _result_for(rec: dict, rule_index: int) -> dict:
    result = {
        "ruleId": rec["rule_id"],
        "ruleIndex": rule_index,
        "level": _LEVEL.get(rec["severity"], "note"),
        "message": {"text": _message(rec), "markdown": _message(rec, markdown=True)},
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
    # A suppressed finding (W1-5) stays in the upload — dropping it is how GitHub would decide it
    # was "fixed" — and carries SARIF's own suppression marker with the recorded justification.
    # GitHub IGNORES this marker (verified 2026-10-01: alert #1501, uploaded suppressed, stayed
    # open). It is kept because it is valid SARIF that other consumers honour; on GitHub, dismiss
    # in the UI and `dast triage --from-github` brings that decision back here.
    sup = rec.get("suppression") or {}
    if rec.get("status") == "suppressed" and not sup.get("expired"):
        result["suppressions"] = [{"kind": "external", "status": "accepted",
                                   "justification": sup.get("justification", "")}]
    # Also machine-readable, for API consumers and filtering — but never the ONLY place a value
    # a person needs lives, since the alert page does not show properties.
    for field in ("confidence", "attack"):
        if rec.get(field):
            result["properties"][field] = rec[field]
    # Reference the (redacted) evidence for this scan from the result (FR-E1).
    evidence = rec.get("evidence_path")
    if evidence:
        result["attachments"] = [
            {"artifactLocation": {"uri": evidence}, "description": {"text": "HAR + screenshot"}}
        ]
    return result


def to_sarif(records: Iterable[dict], driver_version: str | None = None,
             category: str | None = None) -> dict:
    """Build one SARIF 2.1.0 log from detection records (single pass over the input).

    A deduped `rules` array is assembled as results stream by, keeping ruleId <-> ruleIndex
    referential integrity. This holds the results in memory by necessity (SARIF is one
    document; GitHub uploads it whole) — the accepted D1 carve-out.
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    scan_ids: set[str] = set()

    for rec in records:
        if rec.get("scan_id"):
            scan_ids.add(rec["scan_id"])
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

    run = {"tool": {"driver": driver}, "results": results}
    # GitHub keys a code-scanning analysis by (tool name, category, ref). Every application
    # exports under the same driver name, so without a category the second app uploaded to a
    # repository REPLACES the first one's alerts. The category travels in the document — the
    # REST API has no field for it — as runs[].automationDetails.id, which is exactly what the
    # CodeQL action's `category` input sets.
    if category:
        # GitHub splits this id at its LAST "/": before is the category, after is a run id. So the
        # category must be followed by one — "dast/juice-shop" alone was read as category "dast"
        # and run "juice-shop", giving every app the same category (measured on an upload). The
        # scan id is the natural run id; with no records the id still ends in "/".
        # Carried-forward records keep their older scan ids; the newest is this scan.
        run_id = max(scan_ids) if scan_ids else ""
        run["automationDetails"] = {"id": f"{category.rstrip('/')}/{run_id}"}

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def write_sarif(records: Iterable[dict], fh: TextIO, driver_version: str | None = None,
                category: str | None = None) -> None:
    json.dump(to_sarif(records, driver_version, category), fh, indent=2)
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
    p.add_argument("--category", default=None,
                   help="Automation category, e.g. dast/<app>. Separates this application's "
                        "analysis from another's in the GitHub Security tab; without one they "
                        "share a slot and the newer upload replaces the older one's alerts")
    p.add_argument("-o", "--out", default="-", help="Output path, or - for stdout (default)")
    args = p.parse_args(argv)

    records = _read_records(sys.stdin if args.records == "-" else args.records)
    if args.out == "-":
        write_sarif(records, sys.stdout, args.driver_version, args.category)
    else:
        with open(args.out, "w") as fh:
            write_sarif(records, fh, args.driver_version, args.category)
    return 0


if __name__ == "__main__":
    sys.exit(main())
