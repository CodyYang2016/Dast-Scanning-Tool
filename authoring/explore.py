"""explore CLI (Phase B): LLM-driven authenticated exploration -> the same trace `record` emits.

The human seeds a session once (authoring/seed.py); this loop then expands breadth from the seed
routes so the scanned surface is no longer bounded by a human walk (closes KI4). The LLM only
*suggests* a constrained JSON action (contracts/action.schema.json); deterministic code validates it
against scope AND the action deny-list (runner/action_policy.py) and only then executes it — the D8
safety boundary. Observations are redacted (runner/redact.py) before they ever reach the model.

R1: this runs at AUTHORING time. Its output (trace.json/index.json, identical to record's) is
reviewed + committed; monitoring scans replay the committed bundle deterministically. LLM is the
primary path with a deterministic fallback (D9), so the loop is demoable without a key.

Pure pieces (propose_fallback / validate_proposal / next_action) are unit-tested; the browser loop
is validated by running it (fallback path live; LLM path with ANTHROPIC_API_KEY).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import jsonschema

from authoring.record import build_trace, write_trace
from authoring.seed import load_seed
from runner.action_policy import validate_action
from runner.preflight import preflight
from runner.replay import SessionDeadError, prove_auth_live
from runner.redact import redact
from runner.scope_guard import ScopeGuard, host_of

_ROOT = Path(__file__).resolve().parent.parent
_ACTION_SCHEMA = _ROOT / "contracts" / "action.schema.json"
_DEFAULT_MODEL = "claude-opus-4-8"


# ---- validation: schema + scope/deny policy (pure) --------------------------------------

def validate_proposal(action: dict, scope: dict, deny_actions=None, safe_forms=None):
    """Validate a proposed action against the action schema AND the action policy.
    Returns (ok: bool, reason: str). Fail-closed: any schema or policy failure -> not ok."""
    try:
        jsonschema.validate(action, json.loads(_ACTION_SCHEMA.read_text()))
    except jsonschema.ValidationError as exc:
        return False, f"schema: {exc.message}"
    if action.get("action") == "stop":
        return True, "stop"
    decision = validate_action(action, scope, deny_actions=deny_actions, safe_forms=safe_forms)
    return decision.allowed, decision.reason


# ---- deterministic fallback proposer (pure) ---------------------------------------------

def _in_scope_path(path: str, scope: dict) -> bool:
    if path.startswith("http://") or path.startswith("https://"):
        allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
        return host_of(path) in allow
    return path.startswith("/") or path.startswith("#") or path.startswith("./")


def propose_fallback(observation: dict, visited, scope: dict, deny_actions=None,
                     safe_forms=None) -> dict:
    """Pick the next action deterministically: the first unvisited, in-scope, non-destructive link,
    then an unvisited observed API GET; else stop. No LLM. Used as the D9 fallback and in tests."""
    visited = set(visited)
    for href in observation.get("links", []):
        if href and href not in visited and _in_scope_path(href, scope):
            candidate = {"action": "follow_link", "target": {"method": "GET", "path": href},
                         "reason": "unvisited in-scope link", "confidence": 1.0}
            if validate_proposal(candidate, scope, deny_actions, safe_forms)[0]:
                return candidate
    for api in observation.get("api", []):
        path = api.get("url", "")
        if (api.get("method", "GET").upper() == "GET" and path and path not in visited
                and _in_scope_path(path, scope)):
            candidate = {"action": "visit_api", "target": {"method": "GET", "path": path},
                         "reason": "unvisited observed API GET", "confidence": 1.0}
            if validate_proposal(candidate, scope, deny_actions, safe_forms)[0]:
                return candidate
    return {"action": "stop", "reason": "no unvisited in-scope non-destructive targets"}


# ---- LLM proposer (primary) -------------------------------------------------------------

def propose_llm(observation: dict, model: str, api_key: str) -> dict:
    """Ask the LLM for ONE constrained action given the (already redacted) observation. Raises on
    any failure so callers fall back (D9). Mirrors authoring/generate.plan_from_llm."""
    import anthropic  # lazy

    schema = _ACTION_SCHEMA.read_text()
    system = (
        "You drive an authenticated DAST exploration. Given a redacted observation of the current "
        "page (links, forms, observed API calls) you propose exactly ONE next action to widen "
        "coverage of the authenticated surface. Output ONLY a JSON object — no prose, no code "
        "fences — validating against this JSON Schema:\n" + schema +
        "\nNever propose destructive actions (logout, delete, purchase, admin mutations). Prefer "
        "unexplored in-scope authenticated routes. Emit {\"action\":\"stop\"} when nothing useful "
        "remains."
    )
    user = "Redacted observation:\n" + json.dumps(observation, indent=2)
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model, max_tokens=1024, system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(getattr(b, "text", "") for b in msg.content).strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):text.rfind("}") + 1]
    return json.loads(text)


def next_action(observation: dict, visited, scope: dict, *, deny_actions=None, safe_forms=None,
                use_llm: bool = True, model: str = _DEFAULT_MODEL, api_key: str | None = None):
    """Return (action, source). LLM-primary; on any LLM/validation failure, deterministic fallback."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if use_llm and api_key:
        try:
            action = propose_llm(observation, model, api_key)
            ok, reason = validate_proposal(action, scope, deny_actions, safe_forms)
            if ok:
                return action, "llm"
            print(f"explore: LLM action rejected ({reason}); using fallback", file=sys.stderr)
        except Exception as exc:
            print(f"explore: LLM path failed ({exc}); using fallback", file=sys.stderr)
    return propose_fallback(observation, visited, scope, deny_actions, safe_forms), "fallback"


# ---- browser loop -----------------------------------------------------------------------

def _observe(page, base_url: str, api_events: list[dict]) -> dict:
    """Snapshot the current page: url, in-page links, forms (+field names), and API calls seen so
    far. Best-effort; never raises out of the loop."""
    def _safe_eval(expr, default):
        try:
            return page.evaluate(expr)
        except Exception:
            return default

    links = _safe_eval(
        "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))",
        [])
    forms = _safe_eval(
        "() => Array.from(document.querySelectorAll('form')).map(f => ({selector: f.getAttribute('id')"
        " ? '#' + f.getAttribute('id') : 'form', fields: Array.from(f.querySelectorAll('input,select,"
        "textarea')).map(i => i.getAttribute('name')).filter(Boolean)}))",
        [])
    return {"url": page.url, "links": [l for l in links if l],
            "forms": forms, "api": list(api_events)}


def explore(app_id: str, base_url: str, storage_state: str, seed_routes: list[str], scope: dict, *,
            deny_actions=None, safe_forms=None, max_pages: int = 50, use_llm: bool = True,
            model: str = _DEFAULT_MODEL, api_key: str | None = None, zap_proxy: str | None = None,
            headless: bool = True) -> tuple[dict, ScopeGuard]:
    """Run the seeded, LLM-driven exploration loop and return (trace, guard). The trace matches
    record's output (build_trace), so generate/validate/runner consume it unchanged."""
    from playwright.sync_api import sync_playwright

    if not seed_routes:
        raise ValueError("explore requires at least one seed route")
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []
    guard = ScopeGuard(scope, mode="discovery")  # block-and-continue during discovery (KI4)
    events: list[dict] = []
    api_events: list[dict] = []

    with sync_playwright() as pw:
        launch = {"headless": headless, "args": launch_args}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        browser = pw.chromium.launch(**launch)
        context = browser.new_context(ignore_https_errors=True, storage_state=storage_state)
        page = context.new_page()
        page.route("**/*", lambda route: guard.route_handler(route))  # safety layer 2
        page.on("request", lambda r: api_events.append({"type": "request", "method": r.method,
                "url": r.url}) if ("/rest/" in r.url or "/api/" in r.url) else None)

        liveness = prove_auth_live(page, base_url, seed_routes[0],
                                   token_check="window.localStorage.getItem('token')")
        if not liveness["alive"]:
            context.close(); browser.close()
            raise SessionDeadError(liveness["reason"])

        visited: set[str] = set()

        def _goto(path: str):
            url = path if path.startswith("http") else base_url + path
            events.append({"type": "goto", "url": url})
            visited.add(path)
            try:
                page.goto(url, wait_until="networkidle")
            except Exception:
                pass

        for route in seed_routes:
            _goto(route)

        steps = 0
        while steps < max_pages:
            observation = redact(_observe(page, base_url, api_events))  # redact BEFORE the LLM
            action, _src = next_action(observation, visited, scope, deny_actions=deny_actions,
                                       safe_forms=safe_forms, use_llm=use_llm, model=model,
                                       api_key=api_key)
            kind = action.get("action")
            if kind == "stop":
                break
            ok, _reason = validate_proposal(action, scope, deny_actions, safe_forms)
            if not ok:  # fail-closed: never execute an action that didn't pass validation
                break
            target = action.get("target", {})
            path = target.get("path") or target.get("selector") or ""
            if kind in ("follow_link", "visit_api", "expand_nav") and path:
                _goto(path)
            elif kind == "submit_form" and path:
                events.append({"type": "click", "selector": path})
                try:
                    page.click(path, timeout=3000)
                except Exception:
                    pass
                visited.add(path)
            for f in observation.get("forms", []):
                events.append({"type": "form", "url": observation.get("url"),
                               "fields": f.get("fields", [])})
            steps += 1

        context.close()
        browser.close()

    guard.finalize()  # discovery mode: block-and-continue, does not raise
    events.extend(api_events)  # fold observed API calls into the trace
    return build_trace(app_id, base_url, events), guard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="LLM-driven authenticated exploration -> trace (Phase B).")
    p.add_argument("--seed", required=True, help="Seed config (storage_state + seed_routes)")
    p.add_argument("--scope", required=True, help="App scope.json (preflight-validated first)")
    p.add_argument("--schema", default=str(_ROOT / "contracts" / "scope.schema.json"))
    p.add_argument("--base-url", default=None, help="Override the seed's target.base_url")
    p.add_argument("--zap-proxy", default=None, help="Proxy through ZAP so hosts match the runner (D7)")
    p.add_argument("--out-dir", required=True, help="Directory for trace.json + index.json")
    p.add_argument("--app-id", default=None, help="Defaults to scope.app_id")
    p.add_argument("--model", default=_DEFAULT_MODEL)
    p.add_argument("--no-llm", action="store_true", help="Force the deterministic fallback proposer")
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--headed", action="store_true")
    args = p.parse_args(argv)

    scope = preflight(args.scope, args.schema)  # safety layer 1 before any traffic
    seed = load_seed(args.seed)
    base_url = args.base_url or seed["target"]["base_url"]
    app_id = args.app_id or scope["app_id"]
    try:
        trace, guard = explore(
            app_id, base_url, seed["session"]["storage_state"], seed["seed_routes"], scope,
            deny_actions=seed.get("deny_actions"), max_pages=args.max_pages,
            use_llm=not args.no_llm, model=args.model, zap_proxy=args.zap_proxy,
            headless=not args.headed,
        )
    except SessionDeadError as exc:
        print(f"EXPLORE ABORT: seeded session dead ({exc}); re-seed and retry", file=sys.stderr)
        return 2

    write_trace(trace, args.out_dir)
    print(json.dumps({
        "app_id": app_id, "pages": len(trace["index"]), "api_calls": len(trace["api"]),
        "forms": len(trace["forms"]), "hosts": trace["hosts"],
        "requests_seen": len(guard.decisions), "blocked": len(guard.violations),
        "out_dir": args.out_dir,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
