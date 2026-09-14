"""Lifecycle diff across scans (FR-L1/L2).

Given this scan's detection records and the previous scan's, label each new / open / resolved
by comparing fingerprints, and persist state so the next scan can diff against this one.

Conforms to the frozen spec in docs/junior_engineer/lifecycle_diff_design.md and the
test-first suite tests/test_lifecycle_diff.py. Identity is the fingerprint:
  new      = fingerprint in current only
  open     = fingerprint in both
  resolved = fingerprint in previous only (emitted from previous context)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable

from detections.normalizer import write_json_array


def diff(current_records: Iterable[dict], previous_records: Iterable[dict]) -> list[dict]:
    """Label current records new/open, then append resolved records from the previous scan.

    Returns copies (inputs are never mutated). Order: labeled current records in input order,
    then resolved records in previous order. Accepts one-shot iterators for either argument.
    """
    current = list(current_records)
    previous = list(previous_records)
    current_fps = {r["fingerprint"] for r in current}
    previous_fps = {r["fingerprint"] for r in previous}

    out: list[dict] = []
    for r in current:
        status = "open" if r["fingerprint"] in previous_fps else "new"
        out.append({**r, "status": status})
    for r in previous:
        if r["fingerprint"] not in current_fps:
            out.append({**r, "status": "resolved"})
    return out


def _load_state(state_path: str) -> dict:
    if not os.path.exists(state_path):
        return {}
    with open(state_path) as fh:
        return json.load(fh)


def save_state(state_path: str, app_id: str, records: Iterable[dict]) -> None:
    """Persist this scan's records under app_id, MERGING into any existing file (FR-L1)."""
    records = list(records)
    state = _load_state(state_path)
    state[app_id] = {
        "scan_id": records[0]["scan_id"] if records else None,
        "records": records,
    }
    with open(state_path, "w") as fh:
        json.dump(state, fh, indent=2)


def load_previous(state_path: str, app_id: str) -> list[dict]:
    """Return the previous scan's records for app_id, or [] if the file/app is absent."""
    entry = _load_state(state_path).get(app_id)
    if not entry:
        return []
    return entry.get("records", [])


def _read_records(source: str | object) -> list[dict]:
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
    if text[0] == "[":
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lifecycle diff: label detections new/open/resolved.")
    p.add_argument("records", nargs="?", default="-",
                   help="Current detection records (JSON array or NDJSON); - for stdin")
    p.add_argument("--app-id", required=True, help="Application id (state is keyed by this)")
    p.add_argument("--state", required=True, help="Path to the lifecycle state file")
    p.add_argument("-o", "--out", default="-", help="Output path for labeled records, or -")
    p.add_argument("--no-save", action="store_true",
                   help="Diff only; do not update the state file with this scan")
    args = p.parse_args(argv)

    current = _read_records(sys.stdin if args.records == "-" else args.records)
    previous = load_previous(args.state, args.app_id)
    labeled = diff(current, previous)

    if args.out == "-":
        write_json_array(labeled, sys.stdout)
    else:
        with open(args.out, "w") as fh:
            write_json_array(labeled, fh)

    if not args.no_save:
        save_state(args.state, args.app_id, current)
    return 0


if __name__ == "__main__":
    sys.exit(main())
