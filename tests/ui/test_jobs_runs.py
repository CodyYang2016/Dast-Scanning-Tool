"""RUN-1..RUN-7, RES-5 — starting, watching and stopping `dast` jobs."""
from __future__ import annotations

import json
import threading
import time

from tests.ui.harness import (ABORTED_RUN, ACTOR, COMPLETE_RUN, LATER_RUN, wait_for, wait_job)


def _start(c, app, command="scan", **options):
    return c.post(f"/api/apps/{app}/jobs", json={"command": command, "options": options})


# ── RUN-1: exactly the CLI command, with who started it ───────────────────────────────────

def test_run1_scan_runs_exact_cli_command(api_zap, ws):
    r = _start(api_zap, "orders-portal")
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["command"] == "python -m dast scan orders-portal"
    wait_job(api_zap, job["job_id"])
    scans = [i for i in ws.invocations() if i["argv"][:1] == ["scan"]]
    assert len(scans) == 1
    assert scans[0]["argv"] == ["scan", "orders-portal"]
    assert scans[0]["env"]["DAST_ACTOR"] == ACTOR
    assert scans[0]["env"]["DAST_APPS_DIR"] == str(ws.apps_dir)
    assert scans[0]["env"]["DAST_OUT"] == str(ws.out_dir)


# ── RUN-2: one job per app ─────────────────────────────────────────────────────────────────

def test_run2_second_job_for_same_app_refused(api_zap, monkeypatch):
    monkeypatch.setenv("FAKE_DAST_SCAN", "slow")
    first = _start(api_zap, "orders-portal")
    assert first.status_code == 201, first.text
    try:
        assert _start(api_zap, "orders-portal").status_code == 409
    finally:
        api_zap.post(f"/api/jobs/{first.json()['job_id']}/stop")


# ── RUN-3: the live stream follows events.jsonl ───────────────────────────────────────────

def test_run3_events_stream_in_order(api, ws):
    run = ws.run_dir("orders-portal", "20261021T120000Z")
    run.mkdir(parents=True)
    events = run / "events.jsonl"
    events.write_text(json.dumps({"event": "preflight", "n": 0}) + "\n")
    lines = [{"event": "scan_progress", "n": i} for i in range(1, 4)]

    def append():
        for line in lines:
            time.sleep(0.3)
            with open(events, "a") as fh:
                fh.write(json.dumps(line) + "\n")

    threading.Thread(target=append, daemon=True).start()
    seen, started = [], time.monotonic()
    with api.stream("GET", "/api/apps/orders-portal/runs/20261021T120000Z/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for raw in r.iter_lines():
            if raw.startswith("data:"):
                seen.append(json.loads(raw[5:].strip())["n"])
            if len(seen) == 4:
                break
            assert time.monotonic() - started < 5
    assert seen == [0, 1, 2, 3]
    assert time.monotonic() - started < 0.3 * 3 + 2


# ── RUN-4: stop is a stop, not a failure ──────────────────────────────────────────────────

def test_run4_stop_ends_process_and_records_stopped(api_zap, ws, monkeypatch):
    monkeypatch.setenv("FAKE_DAST_SCAN", "slow")
    monkeypatch.setenv("FAKE_DAST_SCAN_ID", "20261021T130000Z")
    job = _start(api_zap, "orders-portal").json()
    wait_for(lambda: ws.run_dir("orders-portal", "20261021T130000Z").joinpath("events.jsonl").exists())
    r = api_zap.post(f"/api/jobs/{job['job_id']}/stop")
    assert r.status_code == 200 and r.json()["status"] == "stopped"
    done = wait_job(api_zap, job["job_id"])
    assert done["status"] == "stopped"
    assert any(i["argv"][:2] == ["stop", "orders-portal"] for i in ws.invocations())
    runs = {x["scan_id"]: x for x in api_zap.get("/api/apps/orders-portal/runs").json()}
    assert runs["20261021T130000Z"]["status"] == "stopped"
    assert any(e.get("event") in ("job.stop", "stop") and e.get("actor") == ACTOR for e in ws.audit())


# ── RUN-5: a refusal reads as a sentence, never a traceback ───────────────────────────────

def test_run5_abort_becomes_plain_refusal(api_zap, monkeypatch):
    monkeypatch.setenv("FAKE_DAST_SCAN", "abort")
    job = _start(api_zap, "orders-portal").json()
    done = wait_job(api_zap, job["job_id"])
    assert done["status"] == "failed"
    refusal = done["refusal"]
    assert refusal["kind"] == "PreflightError"
    assert "billing.test.example.internal" in refusal["message"]
    assert refusal["fix"]
    for body in (api_zap.get(f"/api/jobs/{job['job_id']}").text,
                 api_zap.get(f"/api/jobs/{job['job_id']}/log").text):
        assert "Traceback" not in body


# ── RUN-6: newest first; aborted runs stay visible ────────────────────────────────────────

def test_run6_runs_newest_first_with_aborted(api):
    runs = api.get("/api/apps/juice-shop/runs").json()
    ids = [r["scan_id"] for r in runs]
    assert ids == sorted([COMPLETE_RUN, ABORTED_RUN, LATER_RUN], reverse=True)
    status = {r["scan_id"]: r["status"] for r in runs}
    assert status[ABORTED_RUN] == "aborted"
    assert status[COMPLETE_RUN] == "complete"


# ── RUN-7: no ZAP, no job ─────────────────────────────────────────────────────────────────

def test_run7_zap_down_refuses_without_starting(api, ws):
    for command in ("scan", "author"):
        r = _start(api, "orders-portal", command)
        assert r.status_code == 422
        assert "ZAP" in r.json()["detail"]["message"]
    assert ws.invocations() == []


# ── RES-5: AI step counts come from the author command's own output ───────────────────────

def test_res5_author_job_reports_steps_by_source(api_zap):
    job = _start(api_zap, "orders-portal", "author", explore=True).json()
    done = wait_job(api_zap, job["job_id"])
    assert done["status"] == "succeeded"
    assert done["summary"]["steps_by_source"] == {"llm": 7}
