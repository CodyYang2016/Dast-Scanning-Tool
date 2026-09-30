"""Normalize raw ZAP output into detection records (FR-N1).

Input:  ZAP alerts (contracts/sample_zap_output.json shape: {"alerts": [...]}).
Output: records matching contracts/detection.schema.json.

Scalability convention (project-wide): **stream by default.** The core `normalize()` takes an
iterable of alerts and *yields* records, so no stage needs the whole set in memory. The only
place that currently reads a whole file is `iter_alerts()`, deliberately isolated so it can be
swapped for an incremental parser (e.g. ijson) without touching anything downstream. See
docs/junior_engineer/decisions_and_known_issues.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import TextIO

from detections.fingerprint import endpoint_pattern, fingerprint, payload_family
from runner.redact import redact_text

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


# Per-finding strings are capped so one noisy scan cannot push the SARIF past GitHub's 10 MB
# upload limit; per-rule text is not, because it is carried once per rule rather than per finding.
_MAX_EXCERPT = 500
_TRUNCATED = " [truncated]"

_CONFIDENCE = {"High": "high", "Medium": "medium", "Low": "low", "Confirmed": "high"}


def _text(raw) -> str | None:
    value = str(raw or "").strip()
    return value or None


def _excerpt(raw) -> str | None:
    """A per-finding string safe to store and publish: redacted first, then capped.

    Evidence and attack are lifted from the target's responses and the scanner's payloads, so
    they can carry session tokens or injected content. Redacting HERE means no downstream stage
    — records, state, SARIF, GitHub — ever holds the raw value. The redactor knows JWTs, bearer
    tokens, secret-named fields and emails; an opaque session id with no telling key name would
    still pass through, which the cap limits but does not close.
    """
    value = _text(raw)
    if value is None:
        return None
    # Bound the input BEFORE redacting: redact_text's email pattern is quadratic in input length
    # (measured: 200 KB takes ~44 s), and this string comes from the target, so its length is not
    # ours to choose. Pre-capping at 4x the output cap keeps redaction cheap while a secret that
    # starts inside the kept 500 characters is still seen whole — unless it is over 1,500
    # characters long, in which case its unredacted prefix could survive. Stated, not hidden.
    value = redact_text(value[:_MAX_EXCERPT * 4])
    if len(value) > _MAX_EXCERPT:
        value = value[:_MAX_EXCERPT] + _TRUNCATED
    return value


def _references(raw) -> list[str] | None:
    """ZAP packs several URLs into one newline-separated string; split them."""
    refs = [line.strip() for line in str(raw or "").splitlines() if line.strip()]
    return refs or None


def _remediation(alert: dict) -> dict:
    """What a developer needs to act on the finding (W1-1). Only fields that are present:
    an empty value is omitted rather than written as "", as `parameter` already is."""
    fields = {
        "description": _text(alert.get("description")),
        "solution": _text(alert.get("solution")),
        "references": _references(alert.get("reference")),
        "confidence": _CONFIDENCE.get(str(alert.get("confidence", "")).strip()),
        "evidence_excerpt": _excerpt(alert.get("evidence")),
        "attack": _excerpt(alert.get("attack")),
    }
    return {k: v for k, v in fields.items() if v}


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
        # None of these feed the fingerprint above: they describe a finding, they do not
        # identify it, so adding them leaves every lifecycle history and GitHub alert intact.
        **_remediation(alert),
    }


def normalize(alerts: Iterable[dict], app_id: str, scan_id: str) -> Iterator[dict]:
    """Stream detection records from an iterable of raw ZAP alerts.

    Yields one record at a time — the caller decides whether to materialize (``list(...)``)
    or keep streaming. Accepts any iterable: a list in tests, or the lazy iterator from
    ``iter_alerts()`` in the pipeline.
    """
    for alert in alerts:
        yield normalize_alert(alert, app_id, scan_id)


def iter_alerts(source: str | TextIO) -> Iterator[dict]:
    """Yield raw ZAP alerts from a report file path or open stream.

    THE SWAP POINT: this is the single place that reads the whole report into memory
    (``json.load``). For very large ZAP outputs, replace this body with an incremental parser
    — e.g. ``yield from ijson.items(fh, "alerts.item")`` — and nothing else in the pipeline
    changes, because ``normalize()`` already consumes a lazy iterable.
    """
    if hasattr(source, "read"):
        report = json.load(source)
    else:
        with open(source) as fh:
            report = json.load(fh)
    yield from report.get("alerts", [])


def write_json_array(records: Iterable[dict], fh: TextIO) -> None:
    """Write records as a JSON array, streamed — never holds the full list in memory."""
    fh.write("[")
    first = True
    for rec in records:
        fh.write("\n" if first else ",\n")
        fh.write(json.dumps(rec, indent=2))
        first = False
    fh.write("\n]\n" if not first else "]\n")


def write_ndjson(records: Iterable[dict], fh: TextIO) -> None:
    """Write records as newline-delimited JSON — the most stream-friendly interchange."""
    for rec in records:
        fh.write(json.dumps(rec) + "\n")


def _new_scan_id() -> str:
    """UTC scan id matching detection.schema.json pattern ^[0-9]{8}T[0-9]{6}Z$."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Normalize ZAP output into detection records.")
    p.add_argument("zap_json", help="Path to ZAP alerts JSON (e.g. contracts/sample_zap_output.json)")
    p.add_argument("--app-id", required=True, help="Application id (must match scope.app_id)")
    p.add_argument("--scan-id", default=None, help="Scan id (default: current UTC timestamp)")
    p.add_argument("-o", "--out", default="-", help="Output path, or - for stdout (default)")
    p.add_argument("--format", choices=["json", "ndjson"], default="json",
                   help="Output format: json array (default) or newline-delimited json")
    args = p.parse_args(argv)

    scan_id = args.scan_id or _new_scan_id()
    records = normalize(iter_alerts(args.zap_json), args.app_id, scan_id)  # fully lazy
    writer = write_ndjson if args.format == "ndjson" else write_json_array

    if args.out == "-":
        writer(records, sys.stdout)
    else:
        with open(args.out, "w") as fh:
            writer(records, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
