"""record CLI (FR-R1/R2/R3): crawl the pilot app and capture a trace.

`build_trace` is a pure function (raw events -> a trace conforming to trace.schema.json) and is
unit-tested. `crawl` drives a real browser (optionally through the ZAP proxy so recorded hosts
match the runner topology, D7) and is validated by running it. Credentials come from env.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from authoring import appconfig
from runner.replay import wait_for_auth
from runner.scope_guard import host_of


def _is_api(url: str, patterns) -> bool:
    return any(m in url for m in patterns)


def build_trace(app_id: str, base_url: str, events: list[dict]) -> dict:
    """Assemble a trace (trace.schema.json) from raw captured events. Pure."""
    interactions: list[dict] = []
    index: list[str] = []
    forms: list[dict] = []
    api: list[dict] = []
    hosts: set[str] = set()

    def _note_host(url):
        h = host_of(url) if url else None
        if h:
            hosts.add(h)

    for ev in events:
        etype = ev.get("type")
        url = ev.get("url")
        _note_host(url)
        if etype == "goto":
            interactions.append({"type": "goto", "url": url})
            if url and url not in index:
                index.append(url)
        elif etype in ("fill", "click", "login"):
            interactions.append(dict(ev))
        elif etype == "form":
            # `method` decides whether this form's parameters can ever appear in a URL, and
            # so whether coverage can see them at all (W6-12).
            forms.append({"url": url, "method": str(ev.get("method", "GET")).upper(),
                          "fields": list(ev.get("fields", []))})
        elif etype == "request":
            api.append({"method": ev.get("method", "GET"), "url": url,
                        "params": list(ev.get("params", []))})

    _note_host(base_url)
    return {
        "app_id": app_id,
        "base_url": base_url,
        "hosts": sorted(hosts),
        "index": index,
        "interactions": interactions,
        "forms": forms,
        "api": api,
    }


def _launch_args() -> list[str]:
    return ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []


def crawl(config: dict, email: str, password: str, base_url: str | None = None,
          zap_proxy: str | None = None, headless: bool = True, slow_mo: int = 0) -> dict:
    """Drive a real browser through (optional) registration -> login -> an authenticated page,
    recording goto/fill/click/form interactions and API/XHR requests. Returns a build_trace()
    result.

    Everything application-specific — selectors, the login route, whether the tool may create
    its own account, which banners to dismiss, how authentication is proven, which routes to
    visit afterwards and what counts as an API call — comes from `config` (app.yaml), so this
    function names no application.

    slow_mo (ms) delays each Playwright action so a headed run is watchable in a live demo /
    screen recording; 0 (default) is full speed and does not affect the captured trace."""
    from playwright.sync_api import sync_playwright

    app_id = config["app_id"]
    base_url = base_url or appconfig.base_url(config)
    login_url = appconfig.login_url(config)
    steps = appconfig.login_steps(config)
    patterns = appconfig.api_patterns(config)
    banners = appconfig.dismiss_selectors(config)
    proof = appconfig.proof(config)
    events: list[dict] = []
    with sync_playwright() as pw:
        launch = {"headless": headless, "args": _launch_args()}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        if slow_mo:
            launch["slow_mo"] = slow_mo
        browser = pw.chromium.launch(**launch)
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.on("request", lambda r: events.append(
            {"type": "request", "method": r.method, "url": r.url})
            if _is_api(r.url, patterns) else None)

        def goto(route):
            events.append({"type": "goto", "url": base_url + route})
            page.goto(base_url + route, wait_until="networkidle")

        goto("/")
        # Create the account only where the application permits it (auth.identity:
        # self-register). Most real targets use a provisioned test identity instead.
        boot = appconfig.bootstrap(config)
        if boot:
            page.request.fetch(
                f"{base_url}{boot['path']}", method=boot.get("method", "POST"),
                data={"email": email, "password": password, "passwordRepeat": password,
                      **boot.get("body", {})})
        goto(login_url)
        _dismiss(page, banners)
        events.append({"type": "form", "url": base_url + login_url,
                       "fields": [s.get("value") for s in steps if s.get("value")]})
        _run_login_steps(page, steps, email, password, events)
        # Fail closed: nothing downstream runs unless authentication is proven.
        wait_for_auth(page, base_url, proof)
        # Authenticated pages -> the app fires its authenticated XHR, captured above.
        for route in appconfig.authenticated_routes(config):
            goto(route)
        browser.close()

    return build_trace(app_id, base_url, events)


def _run_login_steps(page, steps, identifier: str, secret: str, events: list[dict]) -> None:
    """Drive the configured login and record what was done (never the values typed)."""
    values = {"identifier": identifier, "secret": secret}
    for step in steps:
        action, sel = step["action"], step["selector"]
        if action == "fill":
            field = step.get("value", "identifier")
            events.append({"type": "fill", "selector": sel, "field": field})
            page.fill(sel, values[field])
        elif action == "click":
            events.append({"type": "click", "selector": sel})
            page.click(sel)
        elif action == "press":
            events.append({"type": "click", "selector": sel})
            page.press(sel, step.get("key", "Enter"))
        elif action == "wait_for":
            page.wait_for_selector(sel, timeout=15000)


def _dismiss(page, selectors) -> None:
    """Click away cookie banners / welcome modals that sit over the login form (best-effort)."""
    for sel in selectors:
        try:
            el = page.locator(sel)
            if el.count() and el.first.is_visible():
                el.first.click(timeout=2000)
        except Exception:
            pass


def write_trace(trace: dict, out_dir: str) -> None:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
    (d / "index.json").write_text(json.dumps(trace["index"], indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Record a crawl trace of an application (FR-R1/R2/R3).")
    p.add_argument("--app", required=True,
                   help="App id or path to security/dast/<app>/app.yaml")
    p.add_argument("--base-url", default=None, help="Override the config's base_url")
    p.add_argument("--zap-proxy", default=None, help="Proxy through ZAP so hosts match the runner (D7)")
    p.add_argument("--out-dir", required=True, help="Directory for trace.json + index.json")
    p.add_argument("--headed", action="store_true")
    p.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                   help="Delay each browser action by MS milliseconds (for headed demos/recordings)")
    args = p.parse_args(argv)

    config = appconfig.load_app_config(args.app)
    email, password = appconfig.credentials(config)
    trace = crawl(config, email, password, base_url=args.base_url,
                  zap_proxy=args.zap_proxy, headless=not args.headed, slow_mo=args.slow_mo)
    write_trace(trace, args.out_dir)
    print(f"recorded: {len(trace['interactions'])} interactions, {len(trace['api'])} api calls, "
          f"hosts={trace['hosts']} -> {args.out_dir}/trace.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
