"""Regression tests for the issues manual QA run 1 found (docs/ui-docs/ui_qa_findings.md).

Back-end half: QA-3, QA-4, QA-9, QA-10, QA-11. The page-level half is in
webui/frontend/tests/qa_run1.test.tsx and e2e/qa_run1.spec.ts.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil

import pytest
import yaml

from detections import lifecycle_diff, triage
from runner.session_store import POSIX_PERMISSIONS
from tests.ui.harness import ABORTED_RUN, COMPLETE_RUN, LATER_RUN

posix_only = pytest.mark.skipif(not POSIX_PERMISSIONS, reason="Windows has no POSIX mode bits")

FRESH_RUN = "20261022T120000Z"
LIFECYCLE = ("new", "open", "resolved", "not_scanned", "suppressed")


def _settings(api, app):
    r = api.get(f"/api/apps/{app}/settings")
    assert r.status_code == 200, r.text
    return r.json()


def _fields(api, app):
    return {f["path"]: f for f in _settings(api, app)["fields"]}


# ── QA-9: a save keeps the file's permissions ─────────────────────────────────────────────

def _save_budget(api, value):
    s = _settings(api, "orders-portal")
    r = api.put("/api/apps/orders-portal/settings",
                json={"etag": s["etag"], "changes": {"scan.budgets.max_scan_min": value}})
    assert r.status_code == 200, r.text


@posix_only
def test_qa9_save_keeps_mode_0644(api, ws):
    target = ws.app_yaml("orders-portal")
    target.chmod(0o644)
    _save_budget(api, 12)
    assert oct(target.stat().st_mode & 0o777) == oct(0o644)


@posix_only
def test_qa9_save_keeps_mode_0640(api, ws):
    target = ws.app_yaml("orders-portal")
    target.chmod(0o640)
    _save_budget(api, 13)
    assert oct(target.stat().st_mode & 0o777) == oct(0o640)


# ── QA-3: a required setting that isn't in app.yaml is still shown, and can be filled in ──

def test_qa3_missing_required_setting_is_listed(api):
    fields = _fields(api, "juice-shop")          # durable data, no scope.exclude in the file
    f = fields.get("scope.exclude")
    assert f is not None, "scope.exclude is required for juice-shop but isn't listed"
    assert f["tier"] == "A" and f["editable"] is True
    assert f["missing"] is True
    assert f["value"] == []


def test_qa3_present_settings_are_not_marked_missing(api):
    fields = _fields(api, "orders-portal")
    assert fields["scope.exclude"].get("missing", False) is False
    assert not [p for p, f in fields.items() if f.get("missing") and f["tier"] != "A"]


def test_qa3_missing_setting_can_be_saved(api, ws):
    target = ws.app_yaml("juice-shop")
    before = target.read_text()
    s = _settings(api, "juice-shop")
    r = api.put("/api/apps/juice-shop/settings",
                json={"etag": s["etag"], "changes": {"scope.exclude": ["/api/notify"]}})
    assert r.status_code == 200, r.text
    after = target.read_text()
    assert yaml.safe_load(after)["scope"]["exclude"] == ["/api/notify"]
    # Only lines were added: every original line, comments included, is still there in order.
    kept = iter(after.splitlines())
    assert all(any(line == k for k in kept) for line in before.splitlines())
    assert _fields(api, "juice-shop")["scope.exclude"].get("missing", False) is False


# ── QA-4: a refused value names the setting it belongs to ─────────────────────────────────

def test_qa4_invalid_value_names_its_setting(api):
    s = _settings(api, "orders-portal")
    r = api.post("/api/apps/orders-portal/settings/preview",
                 json={"etag": s["etag"], "changes": {"scan.budgets.max_scan_min": "ten"}})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["field"] == "scan.budgets.max_scan_min"
    assert detail["message"]


# ── QA-11: a cut-short rule is named ──────────────────────────────────────────────────────

def test_qa11_cut_short_rules_have_names(api, ws):
    cov = json.loads((ws.run_dir("juice-shop", COMPLETE_RUN) / "coverage.json").read_text())
    got = api.get(f"/api/apps/juice-shop/runs/{COMPLETE_RUN}").json()["coverage"]
    assert got["truncated_rules"] == cov["truncated_rules"]          # RES-2's field, unchanged
    assert got["truncated"] == [{"id": rid, "name": cov["rule_outcomes"][rid]["name"]}
                                for rid in cov["truncated_rules"]]
    assert got["truncated"][0]["name"] == "User Agent Fuzzer"


# ── QA-10: a run not yet reported is compared with the last report, without writing ──────

def _fresh_run(ws):
    """A new latest run beside a reported one: one finding gone, one new, the rest the same."""
    previous = json.loads((ws.run_dir("juice-shop", LATER_RUN) / "labeled.json").read_text())
    previous = [{**r, "status": "open"} for r in previous if r["status"] == "open"]
    state = ws.out_dir / "juice-shop" / "state.json"
    state.write_text(json.dumps({"juice-shop": {"scan_id": LATER_RUN, "records": previous}}))
    gone = previous[0]
    new = {**previous[1], "fingerprint": "f" * 64, "title": "A finding not seen before",
           "endpoint": "/brand-new", "scan_id": FRESH_RUN}
    current = [{**r, "scan_id": FRESH_RUN} for r in previous[1:]] + [new]
    d = ws.run_dir("juice-shop", FRESH_RUN)
    d.mkdir(parents=True)
    (d / "records.json").write_text(json.dumps(current))
    shutil.copy(ws.run_dir("juice-shop", LATER_RUN) / "coverage.json", d / "coverage.json")
    return d, state, current, previous, gone


def _digest(paths):
    out = {}
    for p in paths:
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
        for f in files:
            out[str(f)] = (hashlib.sha256(f.read_bytes()).hexdigest(), os.stat(f).st_mtime_ns)
    return out


def test_qa10_unreported_run_is_compared(api, ws):
    d, state, current, previous, gone = _fresh_run(ws)
    covered = json.loads((d / "coverage.json").read_text())
    supps = triage.load(ws.suppressions("juice-shop")) if ws.suppressions("juice-shop").exists() else []
    expected = triage.apply(lifecycle_diff.diff(current, previous, covered=covered), supps, dt.date.today())
    want = {s: sum(1 for r in expected if r["status"] == s) for s in LIFECYCLE}
    assert want["new"] == 1

    run = api.get(f"/api/apps/juice-shop/runs/{FRESH_RUN}").json()
    assert run["compared"] == "preview"
    assert run["lifecycle"] == want
    listed = {f["fingerprint"]: f["status"] for f in
              api.get(f"/api/apps/juice-shop/runs/{FRESH_RUN}/findings").json()}
    assert listed["f" * 64] == "new"
    assert listed[gone["fingerprint"]] in ("resolved", "not_scanned")


def test_qa10_viewing_writes_nothing(api, ws):
    d, state, *_ = _fresh_run(ws)
    before = _digest([d, state])
    api.get(f"/api/apps/juice-shop/runs/{FRESH_RUN}")
    api.get(f"/api/apps/juice-shop/runs/{FRESH_RUN}/findings")
    assert _digest([d, state]) == before
    assert not (d / "labeled.json").exists()


def test_qa10_reported_and_older_runs(api, ws):
    _fresh_run(ws)
    assert api.get(f"/api/apps/juice-shop/runs/{LATER_RUN}").json()["compared"] == "recorded"
    assert api.get(f"/api/apps/juice-shop/runs/{COMPLETE_RUN}").json()["compared"] == "recorded"
    assert api.get(f"/api/apps/juice-shop/runs/{ABORTED_RUN}").json()["compared"] == "none"
