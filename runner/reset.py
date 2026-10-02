"""Put a disposable application back into a known state before a scan (W6-1).

Write-enabled scanning changes the application, so scan N+1 would start wherever scan N left
it: findings appear and vanish with the data, not the code, and the lifecycle diff fills with
noise. `scan.reset` is the application's own reset — DVWA's "Create / Reset Database", a seeded
test tenant's reset page — driven in a browser through ZAP and the scope guard, with the same
step vocabulary as the login. `verify` proves it took effect; a scan that cannot prove its
starting state does not start.

This does NOT make a write-enabled scan able to claim `resolved`: the scan's own writes move the
state DURING the scan, which no reset beforehand can undo.
"""

from __future__ import annotations


class ResetError(RuntimeError):
    """The reset did not run or did not verify. The scan must not start."""


def run_reset(cfg: dict, base_url: str, drive, fetch=None) -> dict:
    """`drive(url, steps)` runs the steps in a browser; `fetch(url) -> (status, body, final)`
    reads the verify page through ZAP. Both injected so this stays testable."""
    url = base_url.rstrip("/") + cfg["url"]
    try:
        drive(url, cfg.get("steps") or [])
    except Exception as exc:
        raise ResetError(f"data reset failed at {cfg['url']}: {exc}") from exc
    verify = cfg.get("verify")
    if not verify:
        return {"ran": True, "verified": None}
    status, body, _final = fetch(base_url.rstrip("/") + verify["path"])
    if verify["contains"] not in (body or ""):
        raise ResetError(
            f"data reset did not verify: {verify['path']} answered {status} without "
            f"{verify['contains']!r}. The application's starting state is unknown, so the scan "
            f"does not start.")
    return {"ran": True, "verified": True}


def browser_driver(scope: dict, zap_proxy: str, identifier: str = "", secret: str = ""):
    """The real `drive`: Chromium through ZAP with the scope guard attached."""
    def drive(url: str, steps) -> None:
        import os
        from playwright.sync_api import sync_playwright
        from authoring.record import _run_login_steps
        from runner.scope_guard import ScopeGuard
        guard = ScopeGuard(scope)
        args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
            "RUNNER_CHROMIUM_NO_SANDBOX") else []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, proxy={"server": zap_proxy}, args=args)
            page = browser.new_context(ignore_https_errors=True).new_page()
            guard.attach(page)
            try:
                page.goto(url, wait_until="networkidle")
                _run_login_steps(page, steps, identifier, secret, [])
                page.wait_for_load_state("networkidle")
            finally:
                browser.close()
        guard.raise_if_violated()
    return drive
