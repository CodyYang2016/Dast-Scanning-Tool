"""SEC-2..SEC-9 — the local UI controls an attack tool, so it must hold up against the browser."""
from __future__ import annotations

import re

import pytest

from tests.ui.harness import (COMPLETE_RUN, LAUNCH_TOKEN, PORT, client_for, logged_in, make_app,
                              wait_job)

API_GETS = ["/api/session", "/api/system", "/api/apps", "/api/apps/juice-shop/settings",
            "/api/apps/juice-shop/runs", f"/api/apps/juice-shop/runs/{COMPLETE_RUN}",
            f"/api/apps/juice-shop/runs/{COMPLETE_RUN}/findings", "/api/apps/juice-shop/suppressions",
            "/api/governance", "/api/apps/juice-shop/workflow"]

WRITES = [("put", "/api/apps/orders-portal/settings", {"etag": "x", "changes": {}}),
          ("post", "/api/apps/orders-portal/settings/preview", {"etag": "x", "changes": {}}),
          ("post", "/api/apps/juice-shop/jobs", {"command": "scan", "options": {}}),
          ("post", "/api/apps/juice-shop/suppressions",
           {"fingerprint": "x", "reason": "false_positive", "justification": "x"}),
          ("post", "/api/onboard/check",
           {"app_id": "x", "base_url": "http://x", "environment_class": "dev"})]


# ── SEC-2: no session, no API ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", API_GETS)
def test_sec2_api_needs_session(ws, path):
    c = client_for(make_app(ws))
    assert c.get(path).status_code == 401


# ── SEC-3: the launch token works once, and only at /auth ─────────────────────────────────

def test_sec3_launch_token_single_use(ws):
    c = client_for(make_app(ws))
    first = c.get(f"/auth?token={LAUNCH_TOKEN}", follow_redirects=False)
    assert first.status_code == 303 and first.headers["location"] == "/"
    other = client_for(c.app)
    assert other.get(f"/auth?token={LAUNCH_TOKEN}", follow_redirects=False).status_code == 401


def test_sec3_wrong_token_refused(ws):
    c = client_for(make_app(ws))
    assert c.get("/auth?token=" + "x" * 43, follow_redirects=False).status_code == 401


def test_sec3_launch_token_is_not_an_api_credential(ws):
    c = client_for(make_app(ws))
    assert c.get(f"/api/apps?token={LAUNCH_TOKEN}").status_code == 401
    assert c.get("/api/apps", headers={"Authorization": f"Bearer {LAUNCH_TOKEN}"}).status_code == 401


# ── SEC-4: Host header pinned (DNS rebinding) ─────────────────────────────────────────────

@pytest.mark.parametrize("host", ["evil.example", f"evil.example:{PORT}", f"127.0.0.1:{PORT + 1}",
                                  f"192.168.1.20:{PORT}", "localhost"])
def test_sec4_foreign_host_refused_even_with_session(ws, host):
    c = logged_in(make_app(ws))
    assert c.get("/api/apps", headers={"Host": host}).status_code == 400


@pytest.mark.parametrize("host", [f"127.0.0.1:{PORT}", f"localhost:{PORT}"])
def test_sec4_own_host_accepted(ws, host):
    c = logged_in(make_app(ws))
    assert c.get("/api/apps", headers={"Host": host}).status_code == 200


# ── SEC-5: CSRF on every write ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("method,path,body", WRITES)
def test_sec5_write_without_csrf_refused(ws, method, path, body):
    c = logged_in(make_app(ws))
    del c.headers["X-CSRF-Token"]
    assert getattr(c, method)(path, json=body).status_code == 403


@pytest.mark.parametrize("method,path,body", WRITES)
def test_sec5_write_with_wrong_csrf_refused(ws, method, path, body):
    c = logged_in(make_app(ws))
    c.headers["X-CSRF-Token"] = "not-the-token"
    assert getattr(c, method)(path, json=body).status_code == 403


# ── SEC-6: no CORS, ever ───────────────────────────────────────────────────────────────────

def test_sec6_no_cors_headers(ws):
    c = logged_in(make_app(ws))
    responses = [c.get(p, headers={"Origin": "https://evil.example"}) for p in API_GETS]
    responses.append(c.options("/api/apps", headers={"Origin": "https://evil.example",
                                                     "Access-Control-Request-Method": "POST"}))
    for r in responses:
        assert not [h for h in r.headers if h.lower().startswith("access-control-allow")], r.headers


# ── SEC-7: strict CSP on every page ────────────────────────────────────────────────────────

@pytest.mark.parametrize("page", ["/", "/onboard", "/apps/juice-shop/settings", "/governance"])
def test_sec7_csp_on_pages(ws, page):
    c = logged_in(make_app(ws))
    r = c.get(page)
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    csp = r.headers.get("content-security-policy", "")
    directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";") if d.strip()}
    for name in ("script-src", "style-src"):
        value = directives.get(name) or directives.get("default-src", "")
        assert value, csp
        assert "unsafe-inline" not in value and "unsafe-eval" not in value, csp
    assert directives.get("frame-ancestors") == "frame-ancestors 'none'", csp


# ── SEC-8: secret values never leave the server ───────────────────────────────────────────

SENTINEL = "s3ntinel-VALUE-9f2c"


def test_sec8_secret_values_never_returned(ws, monkeypatch, zap_up):
    for name in ("AUTH_EMAIL", "AUTH_PASSWORD", "ORDERS_PORTAL_USER", "ORDERS_PORTAL_PASS",
                 "DVWA_USER", "DVWA_PASS"):
        monkeypatch.setenv(name, SENTINEL)
    monkeypatch.setenv("FAKE_DAST_PRINT_ENV", "ORDERS_PORTAL_PASS")   # the job echoes it
    c = logged_in(make_app(ws, zap_api=zap_up))
    bodies = [c.get(p).text for p in API_GETS]
    bodies += [c.get(f"/api/apps/{a}/settings").text for a in ("orders-portal", "dvwa")]
    job = c.post("/api/apps/orders-portal/jobs", json={"command": "scan", "options": {}}).json()
    done = wait_job(c, job["job_id"])
    bodies.append(c.get(f"/api/jobs/{job['job_id']}").text)
    bodies.append(c.get(f"/api/jobs/{job['job_id']}/log").text)
    if done.get("scan_id"):
        events = ws.run_dir("orders-portal", done["scan_id"]) / "events.jsonl"
        bodies.append(events.read_text())
    if ws.audit_log.exists():
        bodies.append(ws.audit_log.read_text())
    for body in bodies:
        assert SENTINEL not in body
    settings = c.get("/api/apps/orders-portal/settings").json()
    secrets = [f["secret"] for f in settings["fields"] if f.get("secret")]
    assert {s["name"] for s in secrets} >= {"ORDERS_PORTAL_USER", "ORDERS_PORTAL_PASS"}
    assert all(set(s) == {"name", "set"} and s["set"] is True for s in secrets)


# ── SEC-9: cookie flags ────────────────────────────────────────────────────────────────────

def test_sec9_session_cookie_flags(ws):
    c = client_for(make_app(ws))
    r = c.get(f"/auth?token={LAUNCH_TOKEN}", follow_redirects=False)
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("dast_session=")
    assert re.search(r"(?i)\bhttponly\b", cookie)
    assert re.search(r"(?i)\bsamesite=strict\b", cookie)
    assert re.search(r"(?i)\bpath=/(;|$)", cookie)
