"""Refusals beyond the frozen spec (UI-8), found while running the live tests:

- a scan or authoring run for a host the registry wouldn't allow is refused before anything
  starts, in the same words onboarding uses;
- a command that stops without an `abort` event (no bundle yet, say) is still explained, in its
  own words, with the next step as the fix.
"""
from __future__ import annotations

import stat
import sys

import yaml

from tests.ui.harness import logged_in, make_app, wait_job


def test_unregistered_host_refused_before_starting(ws, zap_up):
    app = ws.apps_dir / "billing"
    app.mkdir()
    cfg = yaml.safe_load(ws.app_yaml("orders-portal").read_text())
    cfg.update(app_id="billing", base_url="https://billing.test.example.internal")
    cfg["scope"]["allow"] = ["billing.test.example.internal"]
    (app / "app.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    c = logged_in(make_app(ws, zap_api=zap_up))
    for command in ("scan", "author"):
        r = c.post("/api/apps/billing/jobs", json={"command": command, "options": {}})
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert "billing.test.example.internal" in detail["message"] and "registry" in detail["fix"]
    assert ws.invocations() == []


def test_failure_without_abort_event_is_explained(ws, zap_up):
    script = ws.root / "no-bundle-python"
    script.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "print('no bundle at out/orders-portal/authoring/bundle — run: dast author orders-portal',"
        " file=sys.stderr)\nsys.exit(2)\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    c = logged_in(make_app(ws, zap_api=zap_up, python=str(script)))
    job = c.post("/api/apps/orders-portal/jobs", json={"command": "scan", "options": {}}).json()
    done = wait_job(c, job["job_id"])
    assert done["status"] == "failed"
    refusal = done["refusal"]
    assert refusal["message"].startswith("No bundle at out/orders-portal/authoring/bundle")
    assert refusal["fix"] == "Run `python -m dast author orders-portal` first."
