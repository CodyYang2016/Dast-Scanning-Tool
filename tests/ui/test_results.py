"""RES-1..RES-4 — results agree with the run's own files and the tool's own summary."""
from __future__ import annotations

import json
import re
from collections import Counter

from tests.ui.harness import COMPLETE_RUN, LATER_RUN


def _labeled(ws, scan):
    return json.loads((ws.run_dir("juice-shop", scan) / "labeled.json").read_text())


def _run(api, scan):
    r = api.get(f"/api/apps/juice-shop/runs/{scan}")
    assert r.status_code == 200, r.text
    return r.json()


# ── RES-1: counts computed here, from labeled.json ────────────────────────────────────────

def test_res1_counts_match_labeled(api, ws):
    for scan in (COMPLETE_RUN, LATER_RUN):
        records = _labeled(ws, scan)
        sev = Counter(r["severity"] for r in records)
        life = Counter(r["status"] for r in records)
        run = _run(api, scan)
        assert run["counts"] == {s: sev.get(s, 0) for s in ("high", "medium", "low", "info")}
        assert run["lifecycle"] == {s: life.get(s, 0)
                                    for s in ("new", "open", "resolved", "not_scanned", "suppressed")}


# ── RES-2: coverage agrees with coverage.json and summary.md ──────────────────────────────

def test_res2_coverage_matches_tool_summary(api, ws):
    run_dir = ws.run_dir("juice-shop", COMPLETE_RUN)
    cov = json.loads((run_dir / "coverage.json").read_text())
    summary = (run_dir / "summary.md").read_text()
    m = re.search(r"Tested \*\*(\d+) routes?\*\* with \*\*(\d+) rules?\*\*", summary)
    assert m, "the tool's summary no longer states routes and rules"
    got = _run(api, COMPLETE_RUN)["coverage"]
    assert got["routes_tested"] == int(m.group(1)) == len(cov["routes"])
    assert got["rules"] == int(m.group(2)) == len(cov["rules"])
    assert got["truncated_rules"] == cov["truncated_rules"]
    assert got["excluded"] == cov["excluded"]


# ── RES-3: not_scanned stays visible ──────────────────────────────────────────────────────

def test_res3_not_scanned_listed(api, ws):
    expected = {r["fingerprint"] for r in _labeled(ws, LATER_RUN) if r["status"] == "not_scanned"}
    assert len(expected) == 3
    listed = api.get(f"/api/apps/juice-shop/runs/{LATER_RUN}/findings").json()
    assert {f["fingerprint"] for f in listed if f["status"] == "not_scanned"} == expected
    assert len(listed) == len(_labeled(ws, LATER_RUN))


# ── RES-4: a finding's detail is the record's own data ────────────────────────────────────

def test_res4_finding_detail_from_record(api, ws):
    rec = next(r for r in _labeled(ws, COMPLETE_RUN) if r["severity"] == "high")
    r = api.get(f"/api/apps/juice-shop/runs/{COMPLETE_RUN}/findings/{rec['fingerprint']}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["parameter"] == rec["parameter"]
    assert d["solution"] == rec["solution"]
    assert d["references"] == rec.get("references")
    assert d["request_line"] == rec["request_line"]
    assert d["endpoint"] == rec["endpoint"] and d["rule_id"] == rec["rule_id"]
    assert d["attack"] == rec.get("attack")
    assert d["evidence"] == rec.get("evidence_excerpt")
    assert d["replay"] and rec["endpoint"].split("?")[0] in d["replay"]
