"""CORE-1..4, TRI-3, TRI-6, TRI-7 — the small core changes the UI depends on.

These exercise the existing public modules and the real `dast` command line, not the UI.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from collections import Counter

import jsonschema
import pytest
import yaml

from tests.ui.harness import COMPLETE_RUN, ROOT

TODAY = dt.date(2026, 10, 21)


def _dast(args, env_extra, cwd=ROOT):
    env = {**os.environ, **env_extra}
    return subprocess.run([sys.executable, "-m", "dast", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


def _labeled(ws):
    return json.loads((ws.run_dir("juice-shop", COMPLETE_RUN) / "labeled.json").read_text())


# ── CORE-1: DAST_APPS_DIR relocates app configs ──────────────────────────────────────────

def test_core1_apps_dir_moves_config_paths(ws, monkeypatch):
    from authoring import appconfig
    monkeypatch.setenv("DAST_APPS_DIR", str(ws.apps_dir))
    assert appconfig.app_config_path("orders-portal") == ws.app_yaml("orders-portal")
    assert appconfig.suppressions_path("orders-portal") == ws.suppressions("orders-portal")
    cfg = appconfig.load_app_config("orders-portal")
    assert cfg["base_url"] == "https://orders.test.example.internal"


def test_core1_unset_keeps_repo_default(monkeypatch):
    from authoring import appconfig
    monkeypatch.delenv("DAST_APPS_DIR", raising=False)
    assert appconfig.app_config_path("juice-shop") == ROOT / "security" / "dast" / "juice-shop" / "app.yaml"


def test_core1_cli_reads_from_apps_dir(ws):
    # juice-shop exists in both the repo and the fixture apps dir, so `onboard` refuses (exit 2)
    # either way and never writes; the path in its refusal says which directory it read.
    r = _dast(["onboard", "juice-shop", "--base-url", "http://juice:3000"],
              {"DAST_APPS_DIR": str(ws.apps_dir)})
    assert r.returncode == 2
    assert str(ws.app_yaml("juice-shop")) in r.stderr


# ── CORE-2: onboard --config-out ─────────────────────────────────────────────────────────

def test_core2_config_out_writes_only_there(ws, tmp_path):
    staged = tmp_path / "staging" / "newapp.yaml"
    r = _dast(["onboard", "newapp", "--base-url", "http://newapp.local", "--config-out", str(staged)],
              {"DAST_APPS_DIR": str(ws.apps_dir)})
    assert r.returncode == 0, r.stderr
    assert staged.is_file()
    assert yaml.safe_load(staged.read_text())["app_id"] == "newapp"
    assert not (ws.apps_dir / "newapp" / "app.yaml").exists()


# ── CORE-3: validate_app_config ──────────────────────────────────────────────────────────

def test_core3_validate_accepts_valid_and_rejects_invalid(ws):
    from authoring import appconfig
    good = yaml.safe_load(ws.app_yaml("orders-portal").read_text())
    appconfig.validate_app_config(good)                       # does not raise
    bad = dict(good, environment_class="production")
    schema = json.loads((ROOT / "contracts" / "app.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)                      # the oracle agrees it is invalid
    with pytest.raises(Exception):
        appconfig.validate_app_config(bad)


# ── CORE-4: DAST_ACTOR stamps every event ────────────────────────────────────────────────

def test_core4_actor_on_every_event(tmp_path, monkeypatch):
    from runner import events
    monkeypatch.setenv("DAST_ACTOR", "alice")
    log = events.start(app_id="orders-portal", scan_id="20261021T000000Z")
    log.emit("preflight", outcome="ok")                       # before the run dir exists
    log.attach(tmp_path / "events.jsonl")
    log.emit("auth", outcome="ok")
    lines = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert len(lines) == 2
    assert all(line["actor"] == "alice" for line in lines)
    events.reset()


# ── TRI-3 / TRI-6: proposals are not decisions; legacy entries still apply ───────────────

def _one(ws):
    rec = next(r for r in _labeled(ws) if r["status"] == "new")
    return rec


def test_tri3_proposed_entries_change_nothing(ws):
    from detections import triage
    records = _labeled(ws)
    target = _one(ws)
    proposal = {"fingerprint": target["fingerprint"], "reason": "false_positive",
                "justification": "proposed only", "status": "proposed", "proposed_by": "dev"}
    out = triage.apply(records, [proposal], TODAY)
    assert Counter(r["status"] for r in out) == Counter(r["status"] for r in records)


def test_tri6_entry_without_status_is_applied(ws):
    from detections import triage
    target = _one(ws)
    legacy = {"fingerprint": target["fingerprint"], "reason": "false_positive",
              "justification": "decided before statuses existed"}
    out = triage.apply(_labeled(ws), [legacy], TODAY)
    hit = next(r for r in out if r["fingerprint"] == target["fingerprint"])
    assert hit["status"] == "suppressed"


def test_tri_schema_accepts_status_fields():
    schema = json.loads((ROOT / "contracts" / "suppressions.schema.json").read_text())
    doc = {"suppressions": [{"fingerprint": "abc", "reason": "accepted_risk", "justification": "x",
                             "expires": "2026-12-31", "status": "approved", "proposed_by": "dev",
                             "approved_by": "sec", "decided_at": "2026-10-21T10:00:00Z"}]}
    jsonschema.validate(doc, schema)
    doc["suppressions"][0]["status"] = "maybe"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)


# ── TRI-7: imports from GitHub become proposals ──────────────────────────────────────────

def test_tri7_from_github_writes_proposals(ws):
    from detections import triage
    records = _labeled(ws)
    pairs = Counter((str(r["rule_id"]), r["endpoint"]) for r in records)
    rec = next(r for r in records if pairs[(str(r["rule_id"]), r["endpoint"])] == 1)
    alert = {"state": "dismissed", "number": 5, "rule": {"id": str(rec["rule_id"])},
             "most_recent_instance": {"location": {"path": rec["endpoint"]},
                                      "message": {"text": "no parameter named"}},
             "dismissed_reason": "false positive", "dismissed_by": {"login": "dev1"}}
    out = triage.from_github([alert], records, [], TODAY)
    assert out["proposed"], out
    assert all(e["status"] == "proposed" for e in out["proposed"])
