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

from authoring import appconfig
from runner.replay import wait_for_auth

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


def capture_session(config: dict, storage_state: str | None = None, *,
                    base_url: str | None = None, email: str | None = None,
                    password: str | None = None, zap_proxy: str | None = None,
                    headless: bool = False, timeout_ms: int = 180000) -> str:
    """Open a browser at base_url, obtain an authenticated session, and save storageState.

    Two modes:
      - manual (default, headless=False): a human logs in; we wait until `token_check` is truthy
        (the seed for real targets with SSO/MFA/CAPTCHA).
      - assisted (email+password given): auto-fill the Juice Shop login so the pilot can be seeded
        without a human — also how the seeded path is verified.

    Seed through the SAME origin the scan uses: storageState is keyed by origin, so seed with the
    same base_url the runner scans (as ZAP resolves it) and with zap_proxy set, or the saved
    session is invisible to the scan (D7).

    Login selectors, banners, the account-bootstrap request and the proof of authentication all
    come from `config` (app.yaml), so this function names no application.

    The saved file holds live session secrets and MUST be gitignored (see .gitignore .secrets/).
    Returns the storage_state path.
    """
    from playwright.sync_api import sync_playwright

    base_url = base_url or appconfig.base_url(config)
    storage_state = storage_state or appconfig.storage_state(config)
    if not storage_state:
        raise ValueError("no storage_state given and none in the app config (auth.storage_state)")
    proof = appconfig.proof(config)
    login_url = appconfig.login_url(config)
    steps = appconfig.login_steps(config)
    Path(storage_state).parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as pw:
        launch = {"headless": headless, "args": _launch_args()}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        browser = pw.chromium.launch(**launch)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(base_url + login_url, wait_until="networkidle")
        if email and password:
            # Assisted login: create the account first where the application allows it, then
            # drive the form. A human seeding a real target does this part themselves.
            boot = appconfig.bootstrap(config)
            if boot:
                page.request.fetch(
                    f"{base_url}{boot['path']}", method=boot.get("method", "POST"),
                    data={"email": email, "password": password, "passwordRepeat": password,
                          **boot.get("body", {})})
            for sel in appconfig.dismiss_selectors(config):
                try:
                    el = page.locator(sel)
                    if el.count() and el.first.is_visible():
                        el.first.click(timeout=2000)
                except Exception:
                    pass
            values = {"identifier": email, "secret": password}
            for step in steps:
                action, sel = step["action"], step["selector"]
                if action == "fill":
                    page.fill(sel, values[step.get("value", "identifier")])
                elif action == "click":
                    page.click(sel)
                elif action == "press":
                    page.press(sel, step.get("key", "Enter"))
                elif action == "wait_for":
                    page.wait_for_selector(sel, timeout=15000)
        # Wait for auth to be established (human finishes login, or the assisted login lands).
        wait_for_auth(page, base_url, proof, timeout_ms=timeout_ms)
        context.storage_state(path=storage_state)
        browser.close()
    return storage_state


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Capture a human-authenticated storageState (Phase A seed).")
    p.add_argument("--app", required=True, help="App id or path to security/dast/<app>/app.yaml")
    p.add_argument("--base-url", default=None, help="Override the config's base_url")
    p.add_argument("--storage-state", default=None,
                   help="Output path; defaults to the config's auth.storage_state (gitignored)")
    p.add_argument("--assisted", action="store_true",
                   help="Auto-login with AUTH_EMAIL/AUTH_PASSWORD (pilot); default waits for a human")
    p.add_argument("--zap-proxy", default=None,
                   help="Seed through ZAP so the origin matches the scan (e.g. http://localhost:8080)")
    p.add_argument("--headed", action="store_true", help="Show the browser (default for manual seed)")
    args = p.parse_args(argv)

    config = appconfig.load_app_config(args.app)
    email = password = None
    if args.assisted:
        email, password = appconfig.credentials(config)
    headless = not (args.headed or not args.assisted)  # manual seed is headed so the human can act
    path = capture_session(config, args.storage_state, base_url=args.base_url,
                           email=email, password=password,
                           zap_proxy=args.zap_proxy, headless=headless)
    print(f"seeded session saved -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
