"""QA-14: onboarding discovery reaches the app the way the scan will, through ZAP, whenever ZAP is
answering (docs/ui-docs/ui_qa_findings.md). Without it, an app only the scanner can reach (one on
ZAP's network, such as http://dvwa) can't be discovered from the UI.
"""
from __future__ import annotations

from tests.ui.harness import wait_job

NEW = {"app_id": "billing", "base_url": "http://billing.dev.local", "environment_class": "dev",
       "auth": "form", "login_url": "/signin", "user_env": "BILLING_LOGIN", "pass_env": "BILLING_SECRET"}


def _onboard_argv(c, ws, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")      # an AI provider is available
    r = c.post("/api/onboard", json=NEW)
    assert r.status_code == 201, r.text
    assert r.json()["mode"] == "discover"
    wait_job(c, r.json()["job_id"])
    return next(i["argv"] for i in ws.invocations() if i["argv"][:1] == ["onboard"])


def test_qa14_discovery_goes_through_zap_when_it_answers(api_zap, ws, zap_up, monkeypatch):
    argv = _onboard_argv(api_zap, ws, monkeypatch)
    assert "--discover" in argv
    assert "--zap-proxy" in argv, argv
    assert argv[argv.index("--zap-proxy") + 1] == zap_up


def test_qa14_discovery_still_runs_directly_when_zap_is_down(api, ws, monkeypatch):
    argv = _onboard_argv(api, ws, monkeypatch)
    assert "--discover" in argv
    assert "--zap-proxy" not in argv
