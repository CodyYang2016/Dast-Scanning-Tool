"""TRI-1, TRI-2, TRI-4, TRI-5, PUB-1..PUB-3 — triage in the UI, publishing through `dast report`."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import jsonschema
import pytest
import yaml

from tests.ui.harness import ACTOR, LATER_RUN, ROOT, wait_job

SUPP_SCHEMA = json.loads((ROOT / "contracts" / "suppressions.schema.json").read_text())
SHA = "5658473cf8814459bf89000ce373b20ed0b4eb37"


def _open_record(ws):
    labeled = json.loads((ws.run_dir("juice-shop", LATER_RUN) / "labeled.json").read_text())
    return next(r for r in labeled if r["status"] == "open")


# ── TRI-1: a proposal needs its reasons ────────────────────────────────────────────────────

@pytest.mark.parametrize("body", [
    {"reason": "false_positive"},                                         # no justification
    {"justification": "because"},                                         # no reason
    {"reason": "accepted_risk", "justification": "training target"},      # accepted risk, no expiry
])
def test_tri1_incomplete_proposal_refused(api, ws, body):
    body = {"fingerprint": _open_record(ws)["fingerprint"], **body}
    r = api.post("/api/apps/juice-shop/suppressions", json=body)
    assert r.status_code == 422
    assert not ws.suppressions("juice-shop").exists()


# ── TRI-2: a proposal is written, valid, and marked as a proposal ─────────────────────────

def test_tri2_proposal_written_and_valid(api, ws):
    fp = _open_record(ws)["fingerprint"]
    r = api.post("/api/apps/juice-shop/suppressions",
                 json={"fingerprint": fp, "reason": "accepted_risk",
                       "justification": "training target", "expires": "2026-12-31"})
    assert r.status_code == 201, r.text
    doc = yaml.safe_load(ws.suppressions("juice-shop").read_text())
    jsonschema.validate(doc, SUPP_SCHEMA)
    entry = next(e for e in doc["suppressions"] if e["fingerprint"] == fp)
    assert entry["status"] == "proposed"
    assert entry["proposed_by"] == ACTOR


# ── TRI-4: approval is what the real `dast report` honours ────────────────────────────────

def test_tri4_approval_reaches_dast_report(api, ws):
    fp = _open_record(ws)["fingerprint"]
    assert api.post("/api/apps/juice-shop/suppressions",
                    json={"fingerprint": fp, "reason": "false_positive",
                          "justification": "scanner misread the response"}).status_code == 201
    r = api.post(f"/api/apps/juice-shop/suppressions/{fp}/approve")
    assert r.status_code == 200, r.text
    entry = r.json()
    assert entry["status"] == "approved" and entry["approved_by"] == ACTOR and entry["decided_at"]
    jsonschema.validate(yaml.safe_load(ws.suppressions("juice-shop").read_text()), SUPP_SCHEMA)
    env = {**os.environ, "DAST_APPS_DIR": str(ws.apps_dir), "DAST_OUT": str(ws.out_dir),
           "DAST_ENV_REGISTRY": str(ws.registry)}
    rep = subprocess.run([sys.executable, "-m", "dast", "report", "juice-shop", "--fail-on", "none"],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert rep.returncode == 0, rep.stderr
    labeled = json.loads((ws.run_dir("juice-shop", LATER_RUN) / "labeled.json").read_text())
    assert next(x for x in labeled if x["fingerprint"] == fp)["status"] == "suppressed"


# ── TRI-5: expired is shown as expired ────────────────────────────────────────────────────

def test_tri5_expired_suppression_reported(api, ws):
    fp = _open_record(ws)["fingerprint"]
    ws.suppressions("juice-shop").write_text(yaml.safe_dump({"suppressions": [
        {"fingerprint": fp, "reason": "accepted_risk", "justification": "until the fix ships",
         "expires": "2026-01-31", "status": "approved", "approved_by": "sec"}]}), encoding="utf-8")
    listed = api.get("/api/apps/juice-shop/suppressions").json()
    assert next(e for e in listed if e["fingerprint"] == fp)["expired"] is True


# ── PUB-1..3: publishing is `dast report`, with the token kept out of sight ───────────────

TOKEN = "ghp_SENTINELsentinel0000000000000000000"


def _pub(**over):
    body = {"destination": "code-scanning", "owner": "example-org", "repo": "juice-shop",
            "ref": "refs/heads/deployed/v20.2.0", "commit": SHA, "token_env": "UI_TEST_GH_TOKEN"}
    body.update(over)
    return body


def _pairs(argv):
    return {argv[i]: argv[i + 1] for i in range(len(argv) - 1)
            if argv[i].startswith("--") and not argv[i + 1].startswith("--")}


@pytest.mark.parametrize("over,unset", [({"commit": ""}, False), ({}, True)])
def test_pub1_missing_commit_or_token_refused(api, ws, monkeypatch, over, unset):
    if unset:
        monkeypatch.delenv("UI_TEST_GH_TOKEN", raising=False)
    else:
        monkeypatch.setenv("UI_TEST_GH_TOKEN", TOKEN)
    r = api.post("/api/apps/juice-shop/publish", json=_pub(**over))
    assert r.status_code == 422
    assert ws.invocations() == []


def test_pub2_preview_matches_report(api, ws, monkeypatch):
    monkeypatch.setenv("UI_TEST_GH_TOKEN", TOKEN)
    labeled = json.loads((ws.run_dir("juice-shop", LATER_RUN) / "labeled.json").read_text())
    r = api.post("/api/apps/juice-shop/publish/preview", json=_pub())
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["count"] == len(labeled)
    assert p["category"] == "dast/juice-shop"
    assert p["scan_id"] == LATER_RUN
    assert TOKEN not in r.text


@pytest.mark.parametrize("destination,flag", [("code-scanning", "--upload"), ("issues", "--issues")])
def test_pub3_publish_runs_report_with_token_in_env_only(api, ws, monkeypatch, destination, flag):
    monkeypatch.setenv("UI_TEST_GH_TOKEN", TOKEN)
    monkeypatch.setenv("FAKE_DAST_PRINT_ENV", "GITHUB_TOKEN")      # the job echoes it
    r = api.post("/api/apps/juice-shop/publish", json=_pub(destination=destination))
    assert r.status_code == 201, r.text
    job = r.json()
    wait_job(api, job["job_id"])
    inv = [i for i in ws.invocations() if i["argv"][:1] == ["report"]]
    assert len(inv) == 1
    argv = inv[0]["argv"]
    assert argv[:2] == ["report", "juice-shop"] and flag in argv
    assert _pairs(argv) == {"--owner": "example-org", "--repo": "juice-shop",
                            "--ref": "refs/heads/deployed/v20.2.0", "--commit": SHA}
    assert TOKEN not in " ".join(argv)
    assert inv[0]["env"]["GITHUB_TOKEN"] == TOKEN
    for body in (api.get(f"/api/jobs/{job['job_id']}").text,
                 api.get(f"/api/jobs/{job['job_id']}/log").text, r.text):
        assert TOKEN not in body
