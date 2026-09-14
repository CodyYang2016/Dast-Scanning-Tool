"""Objective, TEST-FIRST suite for the lifecycle diff (FR-L1/L2).

Written and frozen BEFORE detections/lifecycle_diff.py exists, so the implementation must
conform to these — not the other way around. Oracle: hand-built fingerprint sets with
known-correct labels (set theory), plus round-trip state persistence.

See docs/junior_engineer/lifecycle_diff_design.md for the frozen API and criteria.
"""

import json

import pytest

# Import target does not exist yet (test-first). Until it's implemented this whole module is
# "red" at collection — which is the point: the tests predate the code.
from detections.lifecycle_diff import diff, load_previous, save_state


def rec(fp, **kw):
    """Build a minimal detection record with a given fingerprint."""
    base = {
        "app_id": "juice-shop",
        "scan_id": "20260101T000000Z",
        "fingerprint": fp,
        "rule_id": "1",
        "title": "Example",
        "severity": "low",
        "cwe_id": None,
        "endpoint": "/x",
        "parameter": None,
        "status": "open",
        "evidence_path": None,
    }
    base.update(kw)
    return base


def _by_status(result):
    out = {"new": set(), "open": set(), "resolved": set()}
    for r in result:
        out[r["status"]].add(r["fingerprint"])
    return out


# ---- Pure diff logic (oracle: hand-built sets + known answers) ---------------------------

def test_first_scan_all_new():
    current = [rec("A"), rec("B")]
    s = _by_status(diff(current, []))
    assert s["new"] == {"A", "B"} and not s["open"] and not s["resolved"]


def test_unchanged_scan_all_open():
    prev = [rec("A"), rec("B")]
    current = [rec("A"), rec("B")]  # same fingerprints, fresh objects
    s = _by_status(diff(current, prev))
    assert s["open"] == {"A", "B"} and not s["new"] and not s["resolved"]


def test_fixed_finding_becomes_resolved():
    prev = [rec("A"), rec("B")]
    current = [rec("A")]  # B was fixed
    s = _by_status(diff(current, prev))
    assert s["open"] == {"A"}
    assert s["resolved"] == {"B"}
    assert not s["new"]


def test_new_finding_labeled_new():
    prev = [rec("A")]
    current = [rec("A"), rec("C")]
    s = _by_status(diff(current, prev))
    assert s["open"] == {"A"} and s["new"] == {"C"} and not s["resolved"]


def test_all_fixed_all_resolved():
    prev = [rec("A"), rec("B")]
    s = _by_status(diff([], prev))
    assert s["resolved"] == {"A", "B"} and not s["new"] and not s["open"]


def test_resolved_carries_previous_context():
    prev = [rec("B", title="SQL Injection", endpoint="/rest/products/search")]
    resolved = [r for r in diff([], prev) if r["status"] == "resolved"]
    assert len(resolved) == 1
    assert resolved[0]["title"] == "SQL Injection"
    assert resolved[0]["endpoint"] == "/rest/products/search"
    assert resolved[0]["fingerprint"] == "B"


def test_counts_conserved():
    prev = [rec("A"), rec("B"), rec("C")]
    current = [rec("A"), rec("D")]
    result = diff(current, prev)
    prev_fps = {"A", "B", "C"}
    cur_fps = {"A", "D"}
    assert len(result) == len(current) + len(prev_fps - cur_fps)


def test_labels_are_valid_enum():
    result = diff([rec("A"), rec("C")], [rec("A"), rec("B")])
    assert all(r["status"] in {"open", "new", "resolved"} for r in result)


def test_partition_no_double_labeling():
    s = _by_status(diff([rec("A"), rec("C")], [rec("A"), rec("B")]))
    assert not (s["new"] & s["resolved"])
    assert not (s["new"] & s["open"])
    assert not (s["open"] & s["resolved"])


def test_inputs_not_mutated():
    current = [rec("A")]
    prev = [rec("B")]
    before_cur = json.dumps(current, sort_keys=True)
    before_prev = json.dumps(prev, sort_keys=True)
    diff(current, prev)
    assert json.dumps(current, sort_keys=True) == before_cur
    assert json.dumps(prev, sort_keys=True) == before_prev


# ---- State persistence (FR-L1) ----------------------------------------------------------

def test_save_then_load_roundtrips_fingerprints(tmp_path):
    state = tmp_path / "state.json"
    records = [rec("A"), rec("B")]
    save_state(str(state), "juice-shop", records)
    loaded = load_previous(str(state), "juice-shop")
    assert {r["fingerprint"] for r in loaded} == {"A", "B"}


def test_state_is_keyed_by_app_id(tmp_path):
    state = tmp_path / "state.json"
    save_state(str(state), "app-a", [rec("A")])
    save_state(str(state), "app-b", [rec("B")])  # must not clobber app-a
    assert {r["fingerprint"] for r in load_previous(str(state), "app-a")} == {"A"}
    assert {r["fingerprint"] for r in load_previous(str(state), "app-b")} == {"B"}


def test_load_missing_returns_empty(tmp_path):
    assert load_previous(str(tmp_path / "nope.json"), "juice-shop") == []
    state = tmp_path / "state.json"
    save_state(str(state), "app-a", [rec("A")])
    assert load_previous(str(state), "unknown-app") == []


# ---- Two-scan integration (FR-L2 demo, proof point #4) ----------------------------------

def test_two_scans_fix_one(tmp_path):
    state = tmp_path / "state.json"
    scan1 = [rec("X"), rec("keep1"), rec("keep2")]
    save_state(str(state), "juice-shop", scan1)

    scan2 = [rec("keep1"), rec("keep2"), rec("Y")]  # X fixed, Y newly found
    result = diff(scan2, load_previous(str(state), "juice-shop"))
    s = _by_status(result)
    assert s["resolved"] == {"X"}
    assert s["new"] == {"Y"}
    assert s["open"] == {"keep1", "keep2"}


# ---- Scalability (D1) -------------------------------------------------------------------

def test_diff_accepts_iterators():
    result = diff(iter([rec("A"), rec("C")]), iter([rec("A"), rec("B")]))
    s = _by_status(result)
    assert s["open"] == {"A"} and s["new"] == {"C"} and s["resolved"] == {"B"}
