"""Hand-authored authenticated flow for OWASP Juice Shop (FR-R2).

Drives a real browser through: register a test user -> log in via the UI form -> reach an
authenticated endpoint. Run by runner/replay.py with the browser proxied through the ZAP
daemon, so ZAP observes the authenticated traffic it would never reach on its own.

This is intentionally hand-authored (the Week-1 fallback): in Week 2 the `generate` CLI
produces an equivalent flow from a recording. Keep it robust and boring.

Contract: expose `run(page, base_url) -> dict`. Return a small result dict for the runner to
log/assert on. Raise on failure.
"""

from __future__ import annotations

import json

# A unique-ish test account. Registered fresh each run so we never depend on seed data.
TEST_EMAIL = "dast-poc@juice-sh.op"
TEST_PASSWORD = "Dast-POC-passw0rd!"


def _dismiss_banners(page) -> None:
    """Close the welcome dialog and cookie banner if present (best-effort)."""
    for selector in (
        "button[aria-label='Close Welcome Banner']",
        "a[aria-label='dismiss cookie message']",
        ".cc-btn",
    ):
        try:
            el = page.locator(selector)
            if el.count() and el.first.is_visible():
                el.first.click(timeout=2000)
        except Exception:
            pass


def _register_user(page, base_url: str) -> None:
    """Register the test user via the REST API (idempotent-ish: ignore 'already exists').

    Uses page.request so the call goes through the same context/proxy as the browser, i.e.
    ZAP observes it too.
    """
    resp = page.request.post(
        f"{base_url}/api/Users/",
        data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "passwordRepeat": TEST_PASSWORD,
            "securityQuestion": {"id": 1},
            "securityAnswer": "dast",
        },
    )
    # 201 created, or 4xx if the user already exists from a prior run — both are fine.
    _ = resp.status


def _login_via_form(page, base_url: str) -> None:
    page.goto(f"{base_url}/#/login", wait_until="networkidle")
    _dismiss_banners(page)
    page.fill("#email", TEST_EMAIL)
    page.fill("#password", TEST_PASSWORD)
    page.click("#loginButton")
    # Auth success = a JWT lands in localStorage under 'token'.
    page.wait_for_function("() => !!window.localStorage.getItem('token')", timeout=15000)


def run(page, base_url: str) -> dict:
    """Register -> form login -> hit an authenticated endpoint. Returns a result summary."""
    page.goto(f"{base_url}/#/", wait_until="networkidle")
    _dismiss_banners(page)

    _register_user(page, base_url)
    _login_via_form(page, base_url)

    token = page.evaluate("() => window.localStorage.getItem('token')")
    if not token:
        raise RuntimeError("login did not produce an auth token")

    # Visit an authenticated view so the SPA fires authenticated XHR (Bearer token added by
    # its own interceptor). These go through page.route (the scope guard) AND the ZAP proxy,
    # so ZAP records genuine authenticated in-browser traffic.
    page.goto(f"{base_url}/#/basket", wait_until="networkidle")

    # Authenticated request: /rest/user/whoami echoes the logged-in user when the Bearer
    # token is sent. This is the request we want ZAP to observe as authenticated traffic.
    whoami = page.request.get(
        f"{base_url}/rest/user/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = {}
    try:
        body = whoami.json()
    except Exception:
        pass
    email = (body.get("user") or {}).get("email")

    return {
        "authenticated": True,
        "token_present": bool(token),
        "whoami_status": whoami.status,
        "whoami_email": email,
    }
