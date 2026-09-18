"""Lifecycle diff across scans (FR-L1/L2).

Given this scan's detection records and the previous scan's, label each new / open / resolved
by comparing fingerprints, and persist state so the next scan can diff against this one.

Conforms to the frozen spec in docs/junior_engineer/lifecycle_diff_design.md and the
test-first suite tests/test_lifecycle_diff.py. Identity is the fingerprint:
  new         = fingerprint in current only
  open        = fingerprint in both
  resolved    = fingerprint in previous only AND its (route x rule) pair was exercised this scan
  not_scanned = fingerprint in previous only but its (route x rule) pair was NOT exercised

The resolved/not_scanned split is coverage-aware (R2): a finding that vanished only counts as a
real fix if this scan actually exercised its route with its rule enabled. `covered` describes what
the current scan exercised; when it is None the diff is coverage-blind and every previous-only
finding is `resolved` (legacy behavior, preserved for existing callers). See R2 in
docs/junior_engineer/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable

from detections.normalizer import write_json_array


def _coverage_check(covered):
    """Return a predicate (route, rule) -> bool for whether this scan exercised that pair.

    `covered` may be:
      - None                             -> coverage-blind; everything counts as covered (legacy)
      - {"routes": [...], "rules": [...]} -> exercised iff route in routes AND rule in rules
      - an iterable of (route, rule) pairs -> exercised iff the exact pair is present
    """
    if covered is None:
        return lambda route, rule: True
    if isinstance(covered, dict):
        routes = set(covered.get("routes", []))
        rules = set(covered.get("rules", []))
        return lambda route, rule: route in routes and rule in rules
    pairs = {tuple(p) for p in covered}
    return lambda route, rule: (route, rule) in pairs


def diff(current_records: Iterable[dict], previous_records: Iterable[dict],
         covered=None) -> list[dict]:
    """Label current records new/open, then append resolved/not_scanned records from the previous
    scan (coverage-aware, R2).

    Returns copies (inputs are never mutated). Order: labeled current records in input order,
    then previous-only records in previous order. Accepts one-shot iterators for either record
    argument. `covered` (see _coverage_check) decides resolved vs not_scanned; None keeps the
    legacy coverage-blind behavior (all previous-only -> resolved).
    """
    current = list(current_records)
    previous = list(previous_records)
    current_fps = {r["fingerprint"] for r in current}
    previous_fps = {r["fingerprint"] for r in previous}
    is_covered = _coverage_check(covered)

    out: list[dict] = []
    for r in current:
        status = "open" if r["fingerprint"] in previous_fps else "new"
        out.append({**r, "status": status})
    for r in previous:
        if r["fingerprint"] not in current_fps:
            status = "resolved" if is_covered(r.get("endpoint"), r.get("rule_id")) else "not_scanned"
            out.append({**r, "status": status})
    return out


def _load_state(state_path: str) -> dict:
    if not os.path.exists(state_path):
        return {}
    with open(state_path) as fh:
        return json.load(fh)


def save_state(state_path: str, app_id: str, records: Iterable[dict], coverage=None) -> None:
    """Persist this scan's records (and its coverage, R2) under app_id, MERGING into any existing
    file (FR-L1). `coverage` is stored for auditing/reproducibility; the diff itself consumes the
    *current* scan's coverage, passed to diff()."""
    records = list(records)
    state = _load_state(state_path)
    entry = {
        "scan_id": records[0]["scan_id"] if records else None,
        "records": records,
    }
    if coverage is not None:
        entry["coverage"] = coverage
    state[app_id] = entry
    with open(state_path, "w") as fh:
        json.dump(state, fh, indent=2)


def load_previous(state_path: str, app_id: str) -> list[dict]:
    """Return the previous scan's records for app_id, or [] if the file/app is absent."""
    entry = _load_state(state_path).get(app_id)
    if not entry:
        return []
    return entry.get("records", [])


def load_coverage(state_path: str, app_id: str):
    """Return the previous scan's stored coverage for app_id, or None if absent."""
    entry = _load_state(state_path).get(app_id)
    if not entry:
        return None
    return entry.get("coverage")


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
    p.add_argument("--coverage", default=None,
                   help="This scan's coverage JSON ({\"routes\":[...],\"rules\":[...]}) from the "
                        "runner (R2). If omitted, the diff is coverage-blind and previous-only "
                        "findings are all 'resolved'.")
    p.add_argument("-o", "--out", default="-", help="Output path for labeled records, or -")
    p.add_argument("--no-save", action="store_true",
                   help="Diff only; do not update the state file with this scan")
    args = p.parse_args(argv)

    current = _read_records(sys.stdin if args.records == "-" else args.records)
    previous = load_previous(args.state, args.app_id)
    coverage = json.loads(open(args.coverage).read()) if args.coverage else None
    labeled = diff(current, previous, coverage)

    if args.out == "-":
        write_json_array(labeled, sys.stdout)
    else:
        with open(args.out, "w") as fh:
            write_json_array(labeled, fh)

    if not args.no_save:
        save_state(args.state, args.app_id, current, coverage)
    return 0


if __name__ == "__main__":
    sys.exit(main())
