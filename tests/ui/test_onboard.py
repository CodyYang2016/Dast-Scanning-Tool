"""ONB-2..ONB-6, ONB-9 — onboarding through the UI is `dast onboard`, staged until confirmed."""
from __future__ import annotations

import yaml

from tests.ui.harness import wait_job

NEW = {"app_id": "billing", "base_url": "http://billing.dev.local", "environment_class": "dev",
       "auth": "form", "login_url": "/signin", "user_env": "BILLING_LOGIN", "pass_env": "BILLING_SECRET"}


def _pairs(argv):
    return {argv[i]: argv[i + 1] for i in range(len(argv) - 1)
            if argv[i].startswith("--") and not argv[i + 1].startswith("--")}


# ── ONB-2 / ONB-3: the registry decides before anything runs ──────────────────────────────

def test_onb2_unregistered_test_host_refused(api, ws):
    r = api.post("/api/onboard/check", json={"app_id": "billing",
                                             "base_url": "https://billing.test.example.internal",
                                             "environment_class": "test"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "billing.test.example.internal" in detail["message"] and detail["fix"]
    assert ws.invocations() == []


def test_onb2_registered_test_host_accepted(api):
    r = api.post("/api/onboard/check", json={"app_id": "orders-two",
                                             "base_url": "https://orders.test.example.internal",
                                             "environment_class": "test"})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_onb3_prod_like_host_refused_whatever_the_class(api):
    for cls in ("dev", "test", "staging"):
        r = api.post("/api/onboard/check", json={"app_id": "orders-live",
                                                 "base_url": "https://orders.prod.example.internal",
                                                 "environment_class": cls})
        assert r.status_code == 422, cls


# ── ONB-6: no silent overwrite ─────────────────────────────────────────────────────────────

def test_onb6_existing_app_needs_overwrite(api, ws, monkeypatch):
    monkeypatch.setenv("ORDERS_PORTAL_USER", "u")
    monkeypatch.setenv("ORDERS_PORTAL_PASS", "p")
    check = api.post("/api/onboard/check", json={"app_id": "orders-portal",
                                                 "base_url": "https://orders.test.example.internal",
                                                 "environment_class": "test"})
    assert check.status_code == 409
    body = {**NEW, "app_id": "orders-portal", "base_url": "https://orders.test.example.internal",
            "environment_class": "test", "user_env": "ORDERS_PORTAL_USER",
            "pass_env": "ORDERS_PORTAL_PASS"}
    assert api.post("/api/onboard", json=body).status_code == 409
    assert api.post("/api/onboard", json={**body, "overwrite": True}).status_code == 201


# ── ONB-4: discovery is `dast onboard --discover`, staged until the proof is confirmed ────

def test_onb4_discover_staged_then_confirmed(api, ws, monkeypatch):
    from authoring import appconfig
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")      # an AI provider is available
    monkeypatch.setenv("BILLING_LOGIN", "dast-user")
    monkeypatch.setenv("BILLING_SECRET", "dast-pass")
    r = api.post("/api/onboard", json=NEW)
    assert r.status_code == 201, r.text
    assert r.json()["mode"] == "discover"
    wait_job(api, r.json()["job_id"])
    inv = [i for i in ws.invocations() if i["argv"][:1] == ["onboard"]]
    assert len(inv) == 1
    argv = inv[0]["argv"]
    assert argv[1] == "billing" and "--discover" in argv
    pairs = _pairs(argv)
    assert pairs["--base-url"] == NEW["base_url"]
    assert pairs["--environment-class"] == "dev"
    assert pairs["--auth"] == "form"
    assert pairs["--login-url"] == "/signin"
    final = ws.apps_dir / "billing" / "app.yaml"
    assert pairs["--config-out"] != str(final)
    assert not final.exists()                                          # not before confirmation
    proposal = api.get("/api/onboard/billing/proposal").json()
    assert proposal["steps"] and proposal["proof"]
    assert not final.exists()
    assert api.post("/api/onboard/billing/confirm", json={"proof_confirmed": False}).status_code == 422
    assert not final.exists()
    done = api.post("/api/onboard/billing/confirm", json={"proof_confirmed": True})
    assert done.status_code == 201, done.text
    monkeypatch.setenv("DAST_APPS_DIR", str(ws.apps_dir))
    cfg = appconfig.load_app_config("billing")                         # validates
    assert cfg["auth"]["credentials"] == {"email_env": "BILLING_LOGIN", "password_env": "BILLING_SECRET"}


# ── ONB-5: no AI, no discovery — and the UI says so ───────────────────────────────────────

def test_onb5_without_ai_falls_back_to_skeleton(api, ws, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    r = api.post("/api/onboard", json=NEW)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["mode"] == "skeleton"
    assert "by hand" in body["message"]
    wait_job(api, body["job_id"])
    argv = next(i["argv"] for i in ws.invocations() if i["argv"][:1] == ["onboard"])
    assert "--discover" not in argv and "--config-out" in argv


# ── ONB-9: SSO sign-in is a headed `dast author --explore` ────────────────────────────────

def test_onb9_sso_sign_in_job(api_zap, ws):
    r = api_zap.post("/api/onboard/intranet-sso/sign-in")
    assert r.status_code == 201, r.text
    wait_job(api_zap, r.json()["job_id"])
    argv = next(i["argv"] for i in ws.invocations() if i["argv"][:1] == ["author"])
    assert argv[:2] == ["author", "intranet-sso"]
    assert "--explore" in argv and "--headed" in argv
    assert yaml.safe_load(ws.app_yaml("intranet-sso").read_text())["auth"]["mode"] == "seeded"
