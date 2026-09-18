"""Seed step (Phase A): capture a human-authenticated session once, load the seed config.

The unreliable part of DAST automation is login (SSO/MFA/CAPTCHA). We solve it once, by hand:
a human logs in through a real browser and Playwright saves the resulting `storageState`
(cookies + localStorage) to a gitignored file. Scans then start already authenticated by loading
that state — no autonomous login. See docs/junior_engineer/seeded_session_exploration_design.md.

`load_seed` (pure) parses + schema-validates the seed config and is unit-tested. `capture_session`
drives a real browser and is validated by running it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import jsonschema

_ROOT = Path(__file__).resolve().parent.parent
_SEED_SCHEMA = _ROOT / "contracts" / "seed.schema.json"


def load_seed(path: str) -> dict:
    """Load + schema-validate a seed config (JSON, a valid YAML subset). Pure.

    Raises jsonschema.ValidationError if the config is off-contract, or ValueError if the file
    isn't parseable JSON.
    """
    text = Path(path).read_text()
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"seed config {path} is not valid JSON: {exc}") from exc
    jsonschema.validate(cfg, json.loads(_SEED_SCHEMA.read_text()))
    return cfg


def _launch_args() -> list[str]:
    return ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []


def capture_session(base_url: str, storage_state: str, *, email: str | None = None,
                    password: str | None = None, token_check: str | None = None,
                    zap_proxy: str | None = None, headless: bool = False,
                    timeout_ms: int = 180000) -> str:
    """Open a browser at base_url, obtain an authenticated session, and save storageState.

    Two modes:
      - manual (default, headless=False): a human logs in; we wait until `token_check` is truthy
        (the seed for real targets with SSO/MFA/CAPTCHA).
      - assisted (email+password given): auto-fill the Juice Shop login so the pilot can be seeded
        without a human — also how the seeded path is verified.

    Seed through the SAME origin the scan uses: storageState keys localStorage by origin, so if the
    runner scans http://juice:3000 (as ZAP resolves it), seed with base_url=http://juice:3000 and
    zap_proxy set, so the browser reaches juice through ZAP and the saved origin matches (D7).

    The saved file holds live session secrets and MUST be gitignored (see .gitignore .secrets/).
    Returns the storage_state path.
    """
    from playwright.sync_api import sync_playwright

    check = token_check or "window.localStorage.getItem('token')"
    Path(storage_state).parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as pw:
        launch = {"headless": headless, "args": _launch_args()}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        browser = pw.chromium.launch(**launch)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(base_url + "/#/login", wait_until="networkidle")
        if email and password:
            # Assisted login (pilot). Register best-effort so creds are valid, then form-login.
            page.request.post(f"{base_url}/api/Users/", data={
                "email": email, "password": password, "passwordRepeat": password,
                "securityQuestion": {"id": 1}, "securityAnswer": "dast"})
            for sel in ("button[aria-label='Close Welcome Banner']",
                        "a[aria-label='dismiss cookie message']", ".cc-btn"):
                try:
                    el = page.locator(sel)
                    if el.count() and el.first.is_visible():
                        el.first.click(timeout=2000)
                except Exception:
                    pass
            page.fill("#email", email)
            page.fill("#password", password)
            page.click("#loginButton")
        # Wait for auth to be established (human finishes login, or the assisted login lands).
        page.wait_for_function(f"() => !!({check})", timeout=timeout_ms)
        context.storage_state(path=storage_state)
        browser.close()
    return storage_state


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Capture a human-authenticated storageState (Phase A seed).")
    p.add_argument("--base-url", required=True, help="Target base URL, e.g. http://localhost:3000")
    p.add_argument("--storage-state", required=True, help="Output path (gitignored, e.g. .secrets/storageState.json)")
    p.add_argument("--assisted", action="store_true",
                   help="Auto-login with AUTH_EMAIL/AUTH_PASSWORD (pilot); default waits for a human")
    p.add_argument("--zap-proxy", default=None,
                   help="Seed through ZAP so the origin matches the scan (e.g. http://localhost:8080)")
    p.add_argument("--headed", action="store_true", help="Show the browser (default for manual seed)")
    args = p.parse_args(argv)

    email = os.environ.get("AUTH_EMAIL") if args.assisted else None
    password = os.environ.get("AUTH_PASSWORD") if args.assisted else None
    headless = not (args.headed or not args.assisted)  # manual seed is headed so the human can act
    path = capture_session(args.base_url, args.storage_state, email=email, password=password,
                           zap_proxy=args.zap_proxy, headless=headless)
    print(f"seeded session saved -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
