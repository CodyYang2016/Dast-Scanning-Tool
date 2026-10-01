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
from runner.replay import AuthProofError, wait_for_auth

_ROOT = Path(__file__).resolve().parent.parent
_SEED_SCHEMA = _ROOT / "contracts" / "seed.schema.json"


class SeedPreflightError(RuntimeError):
    """Raised when the login page is not in a state the declared login steps can run against.

    Its whole purpose is to name the precondition that failed. Without it every environment
    problem -- the target not started, a database not initialised, a redirect to a setup wizard --
    surfaces as a Playwright locator timeout on the first `fill`, which points the operator at the
    config when the config is fine.
    """


def leading_selectors(steps: list[dict]) -> list[str]:
    """The selectors that must already exist on the login page as first loaded.

    Only the `fill` steps before the first click/press/wait_for: anything after one of those is
    reached by the application's own navigation, so its absence up front proves nothing.
    """
    out = []
    for step in steps:
        if step.get("action") != "fill":
            break
        out.append(step["selector"])
    return out


def _absent_errors() -> tuple[type[BaseException], ...]:
    """The timeout types that mean "the selector is not on the page".

    Playwright is imported lazily, as in replay(), so the pure helpers stay usable without it.
    Any other Playwright error -- an invalid selector, a closed page -- is a different fault and
    propagates rather than being reported as a login form that failed to render.
    """
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    except ImportError:
        return (TimeoutError,)
    return (PlaywrightTimeoutError, TimeoutError)


def _selector_present(page, selector: str, timeout_ms: int) -> bool:
    try:
        page.wait_for_selector(selector, state="attached", timeout=timeout_ms)
    except _absent_errors():
        return False
    return True


def preflight_login_page(page, url: str, status: int | None, steps: list[dict], *,
                         timeout_ms: int = 5000) -> None:
    """Check the loaded page can actually be logged in to, or raise SeedPreflightError saying why.

    Runs after the navigation and before any credential is typed, so a missing form costs one
    short selector wait and reports the page we actually landed on (a setup wizard, an error page)
    instead of timing out for the full Playwright default on the first field.
    """
    landed = page.url
    if status is not None and status >= 400:
        raise SeedPreflightError(
            f"login page {url} returned HTTP {status}\n"
            f"  landed on: {landed}\n"
            "  hint: the target is reachable but not serving the login page -- check the app "
            "started cleanly and login_url is right")
    missing = [s for s in leading_selectors(steps) if not _selector_present(page, s, timeout_ms)]
    if missing:
        raise SeedPreflightError(
            f"login page did not render the configured selector(s): {', '.join(missing)}\n"
            f"  requested: {url}\n"
            f"  landed on: {landed}\n"
            f"  page title: {page.title()!r}\n"
            "  hint: if landed-on differs from requested the app redirected (setup/error page); "
            "otherwise auth.steps does not match this login page")


def proof_failure_detail(page, exc: Exception) -> str:
    """The proof failure, plus the page it failed on.

    A wrong credential is not an error in most applications: the login page simply re-renders, so
    the proof times out and the timeout alone cannot distinguish "these credentials are wrong"
    from "auth.proof does not match a logged-in page". The URL landed on separates them.
    """
    return (f"{exc}\n"
            f"  landed on: {page.url}\n"
            f"  page title: {page.title()!r}\n"
            "  hint: still on the login page means the credentials were rejected (the form\n"
            "        re-renders rather than erroring); past it means auth.proof does not match")


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
    from playwright.sync_api import Error as PlaywrightError
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
        url = base_url + login_url
        try:
            response = page.goto(url, wait_until="networkidle")
        except PlaywrightError as exc:
            raise SeedPreflightError(
                f"login page {url} could not be loaded\n"
                f"  playwright: {str(exc).splitlines()[0]}\n"
                "  hint: check the target container is up and published, and that the ZAP proxy "
                "can resolve its hostname") from exc
        if email and password:
            preflight_login_page(page, url, response.status if response else None, steps)
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
        try:
            wait_for_auth(page, base_url, proof, timeout_ms=timeout_ms)
        except AuthProofError as exc:
            raise AuthProofError(proof_failure_detail(page, exc)) from exc
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
        try:
            email, password = appconfig.credentials(config)
        except ValueError as exc:
            print(f"SEED ABORT: {exc}", file=sys.stderr)
            return 2
    headless = not (args.headed or not args.assisted)  # manual seed is headed so the human can act
    # A human needs minutes for SSO/MFA; a submitted login form either lands or does not.
    timeout_ms = 30000 if args.assisted else 180000
    try:
        path = capture_session(config, args.storage_state, base_url=args.base_url,
                               email=email, password=password, timeout_ms=timeout_ms,
                               zap_proxy=args.zap_proxy, headless=headless)
    except (SeedPreflightError, AuthProofError) as exc:
        print(f"SEED ABORT: {exc}", file=sys.stderr)
        return 2
    print(f"seeded session saved -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
