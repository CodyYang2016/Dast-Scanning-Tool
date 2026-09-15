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

from runner.scope_guard import host_of

_API_MARKERS = ("/rest/", "/api/")


def _is_api(url: str) -> bool:
    return any(m in url for m in _API_MARKERS)


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
            forms.append({"url": url, "fields": list(ev.get("fields", []))})
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


def crawl(app_id: str, base_url: str, email: str, password: str,
          zap_proxy: str | None = None, headless: bool = True) -> dict:
    """Drive a real browser through register -> login -> an authenticated page, recording
    goto/fill/click/form interactions and API/XHR requests. Returns a build_trace() result."""
    from playwright.sync_api import sync_playwright

    events: list[dict] = []
    with sync_playwright() as pw:
        launch = {"headless": headless, "args": _launch_args()}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        browser = pw.chromium.launch(**launch)
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.on("request", lambda r: events.append(
            {"type": "request", "method": r.method, "url": r.url}) if _is_api(r.url) else None)

        def goto(route):
            events.append({"type": "goto", "url": base_url + route})
            page.goto(base_url + route, wait_until="networkidle")

        goto("/#/")
        # best-effort register so the login has valid creds
        page.request.post(f"{base_url}/api/Users/", data={
            "email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": 1}, "securityAnswer": "dast"})
        goto("/#/login")
        events.append({"type": "form", "url": base_url + "/#/login",
                       "fields": ["email", "password"]})
        events.append({"type": "fill", "selector": "#email", "field": "email"})
        page.fill("#email", email)
        events.append({"type": "fill", "selector": "#password", "field": "password"})
        page.fill("#password", password)
        events.append({"type": "click", "selector": "#loginButton"})
        page.click("#loginButton")
        page.wait_for_function("() => !!window.localStorage.getItem('token')", timeout=15000)
        goto("/#/basket")  # authenticated page -> SPA fires /rest/* XHR (captured above)
        browser.close()

    return build_trace(app_id, base_url, events)


def write_trace(trace: dict, out_dir: str) -> None:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
    (d / "index.json").write_text(json.dumps(trace["index"], indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Record a crawl trace of the pilot app (FR-R1/R2/R3).")
    p.add_argument("--app-id", required=True)
    p.add_argument("--base-url", default="http://juice:3000")
    p.add_argument("--zap-proxy", default=None, help="Proxy through ZAP so hosts match the runner (D7)")
    p.add_argument("--out-dir", required=True, help="Directory for trace.json + index.json")
    p.add_argument("--headed", action="store_true")
    args = p.parse_args(argv)

    email = os.environ.get("AUTH_EMAIL", "dast-poc@juice-sh.op")
    password = os.environ.get("AUTH_PASSWORD", "Dast-POC-passw0rd!")
    trace = crawl(args.app_id, args.base_url, email, password,
                  zap_proxy=args.zap_proxy, headless=not args.headed)
    write_trace(trace, args.out_dir)
    print(f"recorded: {len(trace['interactions'])} interactions, {len(trace['api'])} api calls, "
          f"hosts={trace['hosts']} -> {args.out_dir}/trace.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
