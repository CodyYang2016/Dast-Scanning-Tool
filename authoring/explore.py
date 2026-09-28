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
import re
import sys
from pathlib import Path

import jsonschema

from authoring import appconfig
from authoring.record import build_trace, write_trace
from authoring.seed import load_seed
from runner.action_policy import validate_action
from runner.preflight import check_scope, preflight
from runner.replay import SessionDeadError, prove_auth_live
from runner.redact import redact
from runner.scope_guard import ScopeGuard, host_of

_ROOT = Path(__file__).resolve().parent.parent
_ACTION_SCHEMA = _ROOT / "contracts" / "action.schema.json"
_DEFAULT_MODEL = "claude-opus-4-8"
_MAX_STALLED_STEPS = 3   # consecutive actions that achieve nothing before giving up


# ---- validation: schema + scope/deny policy (pure) --------------------------------------

def validate_proposal(action: dict, scope: dict, deny_actions=None, safe_forms=None,
                      submit_get_forms: bool = True):
    """Validate a proposed action against the action schema AND the action policy.
    Returns (ok: bool, reason: str). Fail-closed: any schema or policy failure -> not ok."""
    try:
        jsonschema.validate(action, json.loads(_ACTION_SCHEMA.read_text()))
    except jsonschema.ValidationError as exc:
        return False, f"schema: {exc.message}"
    if action.get("action") == "stop":
        return True, "stop"
    target = action.get("target") or {}
    if not (target.get("path") or target.get("selector")):
        return False, "no navigable target (empty path/selector)"
    decision = validate_action(action, scope, deny_actions=deny_actions, safe_forms=safe_forms,
                               submit_get_forms=submit_get_forms)
    return decision.allowed, decision.reason


# ---- href normalization (pure) -----------------------------------------------------------

_NON_NAVIGABLE = ("javascript:", "mailto:", "tel:", "data:", "blob:")


def normalize_href(href: str | None) -> str | None:
    """Turn an href as the SPA emits it into a path the trace/flow can append to base_url.

    Angular emits "#/contact" and "./redirect?to=..."; appended verbatim to base_url those become
    "http://juice:3000#/contact" (works by accident) and "http://juice:3000./redirect?..." (an
    invalid URL that crashes the generated flow). Returns None for non-navigable hrefs.
    """
    if not href:
        return None
    h = href.strip()
    if not h or h.lower().startswith(_NON_NAVIGABLE):
        return None
    if h.startswith("http://") or h.startswith("https://") or h.startswith("/"):
        return h
    if h.startswith("./"):
        return "/" + h[2:]
    if h.startswith("#"):
        return "/" + h
    return "/" + h


def _normalize_action(action: dict) -> dict:
    """Apply normalize_href to an LLM-proposed path so it gets the same treatment as scraped
    links. A non-navigable path is blanked so schema validation (minLength) rejects it."""
    if not isinstance(action, dict):
        return action
    target = action.get("target")
    if isinstance(target, dict) and isinstance(target.get("path"), str):
        target = dict(target)
        target["path"] = normalize_href(target["path"]) or ""
        action = dict(action, target=target)
    return action


def is_progress(url_before: str, url_after: str, before_links: int, after_links: int) -> bool:
    """Did an executed action achieve anything?

    Either it moved us somewhere new, or it revealed routes that were not visible before (an
    expanded menu). Neither means the action was useless, and repeating a useless action is
    how a loop burns its whole budget — observed live: the same unclickable form submitted
    nineteen times.
    """
    return url_after != url_before or after_links > before_links


def dispatch(action: dict) -> tuple[str, str] | None:
    """Map a validated action to what the browser does: ("goto", path) for follow_link /
    visit_api, ("click", selector) for expand_nav / submit_form. None = nothing executable
    (e.g. stop, or a selector on a navigation action). Pure."""
    kind = action.get("action")
    target = action.get("target") or {}
    if kind in ("follow_link", "visit_api"):
        return ("goto", target["path"]) if target.get("path") else None
    if kind in ("expand_nav", "submit_form"):
        return ("click", target["selector"]) if target.get("selector") else None
    return None


# ---- deterministic fallback proposer (pure) ---------------------------------------------

def _in_scope_path(path: str, scope: dict) -> bool:
    if path.startswith("http://") or path.startswith("https://"):
        allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
        return host_of(path) in allow
    return path.startswith("/") or path.startswith("#") or path.startswith("./")


def propose_fallback(observation: dict, visited, scope: dict, deny_actions=None,
                     safe_forms=None, submit_get_forms: bool = True) -> dict:
    """Pick the next action deterministically: the first unvisited, in-scope, non-destructive link,
    then an unvisited observed API GET, then an unsubmitted read-only form; else stop. No LLM.
    Used as the D9 fallback and in tests."""
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
    # Nothing left to navigate to: submitting a read-only form is what reveals an endpoint's
    # parameters, and those are what the scanner can actually test.
    for form in observation.get("forms", []):
        sel = form.get("selector")
        if sel and sel not in visited:
            candidate = {"action": "submit_form",
                         "target": {"method": form.get("method", "POST"), "selector": sel},
                         "reason": "unsubmitted read-only form; reveals its parameters",
                         "confidence": 1.0}
            if validate_proposal(candidate, scope, deny_actions, safe_forms, submit_get_forms)[0]:
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
        "follow_link / visit_api on paths that appear in the observation's `links` / `api` and are "
        "NOT in `visited`. When a page has a search or filter form, submit_form with "
        "target.method GET is valuable and permitted: it reveals the endpoint's query "
        "parameters, which is what makes them testable. A submit_form without method GET is "
        "treated as a write and will be refused. Use expand_nav when a menu hides routes. Emit "
        "{\"action\":\"stop\"} when nothing useful remains."
    )
    user = "Redacted observation:\n" + json.dumps(observation, indent=2)
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model, max_tokens=1024, system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(getattr(b, "text", "") for b in msg.content)
    return parse_action_text(text)


def parse_action_text(text: str) -> dict:
    """Extract the first JSON object from raw LLM text (strips ``` fences, ignores trailing
    prose or a second object). Raises ValueError. Mirrors generate.parse_plan_text."""
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    start = t.find("{")
    if start == -1:
        raise ValueError("no JSON object found in text")
    try:
        obj, _end = json.JSONDecoder().raw_decode(t[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("JSON is not an object")
    return obj


def next_action(observation: dict, visited, scope: dict, *, deny_actions=None, safe_forms=None,
                submit_get_forms: bool = True, use_llm: bool = True,
                model: str = _DEFAULT_MODEL, api_key: str | None = None):
    """Return (action, source). LLM-primary; on any LLM/validation failure, deterministic fallback."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if use_llm and api_key:
        try:
            action = _normalize_action(propose_llm(observation, model, api_key))
            ok, reason = validate_proposal(action, scope, deny_actions, safe_forms, submit_get_forms)
            if ok:
                return action, "llm"
            t = action.get("target") or {}
            print(f"explore: LLM action rejected ({reason}): {action.get('action')} "
                  f"{t.get('method', '')} {t.get('path') or t.get('selector') or ''}; using fallback",
                  file=sys.stderr)
        except Exception as exc:
            print(f"explore: LLM path failed ({exc}); using fallback", file=sys.stderr)
    return propose_fallback(observation, visited, scope, deny_actions, safe_forms,
                            submit_get_forms), "fallback"


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
    # A form is only actionable if we know what to click and how it submits. Report an
    # addressable selector, its submit control, its method and its field names — reporting
    # the bare tag made every form on a page look identical and unclickable.
    forms = _safe_eval(
        "() => Array.from(document.querySelectorAll('form')).map((f, i) => {"
        # f.id is NOT the id attribute when the form has a control named "id": a form's named
        # controls shadow its properties, so f.id returns that element. getAttribute is immune.
        "  const fid = f.getAttribute('id');"
        "  const base = fid ? '#' + CSS.escape(fid) : 'form >> nth=' + i;"
        "  const btn = f.querySelector('[type=submit], button');"
        # One selector per form, and it is the CLICKABLE one. Reporting both the container
        # and its submit control invited the model to copy the container, which submits
        # nothing — an ambiguity the prompt should not have to resolve.
        "  return {selector: btn ? base + ' >> ' + (btn.getAttribute('type') === 'submit'"
        "                  ? '[type=submit]' : 'button') : null,"
        "          method: (f.getAttribute('method') || 'GET').toUpperCase(),"
        "          fields: Array.from(f.querySelectorAll('input,select,textarea'))"
        "                   .map(i2 => i2.getAttribute('name')).filter(Boolean)};"
        "})",
        [])
    seen: set[str] = set()
    clean: list[str] = []
    for l in links:
        n = normalize_href(l)
        if n and n not in seen:
            seen.add(n)
            clean.append(n)
    return {"url": page.url, "links": clean, "forms": forms, "api": list(api_events)}


def explore(app_id: str, base_url: str, storage_state: str, seed_routes: list[str], scope: dict, *,
            config: dict | None = None,
            deny_actions=None, safe_forms=None, max_pages: int = 50, use_llm: bool = True,
            model: str = _DEFAULT_MODEL, api_key: str | None = None, zap_proxy: str | None = None,
            headless: bool = True, slow_mo: int = 0) -> tuple[dict, ScopeGuard]:
    """Run the seeded, LLM-driven exploration loop and return (trace, guard). The trace matches
    record's output (build_trace), so generate/validate/runner consume it unchanged.

    slow_mo (ms) delays each Playwright action so a headed run is watchable in a live demo (same
    knob as record); 0 (default) is full speed and does not affect the captured trace."""
    from playwright.sync_api import sync_playwright

    if not seed_routes:
        raise ValueError("explore requires at least one seed route")
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []
    # App-specific knowledge (how auth is proven, what counts as an API call) comes from the
    # app config; the loop itself names no application.
    api_patterns = appconfig.api_patterns(config) if config else ("/rest/", "/api/")
    allow_get_forms = appconfig.submit_get_forms(config) if config else True
    proof = appconfig.proof(config) if config else None
    guard = ScopeGuard(scope, mode="discovery")  # block-and-continue during discovery (KI4)
    events: list[dict] = []
    api_events: list[dict] = []

    with sync_playwright() as pw:
        launch = {"headless": headless, "args": launch_args}
        if zap_proxy:
            launch["proxy"] = {"server": zap_proxy}
        if slow_mo:
            launch["slow_mo"] = slow_mo
        browser = pw.chromium.launch(**launch)
        context = browser.new_context(ignore_https_errors=True, storage_state=storage_state)
        page = context.new_page()
        page.route("**/*", lambda route: guard.route_handler(route))  # safety layer 2
        page.on("request", lambda r: api_events.append({"type": "request", "method": r.method,
                "url": r.url}) if any(m in r.url for m in api_patterns) else None)

        liveness = prove_auth_live(page, base_url, seed_routes[0], proof=proof)
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

        steps = stalled = 0
        while steps < max_pages:
            observation = redact(_observe(page, base_url, api_events))  # redact BEFORE the LLM
            observation["visited"] = sorted(visited)  # coverage so far, so the model doesn't repeat
            action, _src = next_action(observation, visited, scope, deny_actions=deny_actions,
                                       safe_forms=safe_forms, submit_get_forms=allow_get_forms,
                                       use_llm=use_llm, model=model,
                                       api_key=api_key)
            if action.get("action") == "stop":
                break
            ok, _reason = validate_proposal(action, scope, deny_actions, safe_forms,
                                            allow_get_forms)
            if not ok:  # fail-closed: never execute an action that didn't pass validation
                break
            todo = dispatch(action)
            if todo is None:
                break  # nothing executable (fail closed rather than guess)
            op, arg = todo
            url_before, links_before = page.url, len(observation.get("links", []))
            if op == "goto":
                _goto(arg)
            else:  # click a selector (expand_nav / submit_form)
                events.append({"type": "click", "selector": arg})
                try:
                    page.click(arg, timeout=3000)
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                visited.add(arg)
                # A submitted form navigates, usually to the same path carrying the query
                # parameters it just revealed. Record where we landed: an URL the trace never
                # saw is an endpoint the scanner will never test.
                landed = page.url
                if landed != url_before:
                    events.append({"type": "goto", "url": landed})
                    visited.add(landed)

            # Refuse to keep paying for actions that change nothing (observed: the same
            # unclickable form submitted nineteen times, burning the whole budget).
            after_links = len(_observe(page, base_url, api_events).get("links", []))
            if not is_progress(url_before, page.url, links_before, after_links):
                stalled += 1
                if stalled >= _MAX_STALLED_STEPS:
                    break
            else:
                stalled = 0
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
    p.add_argument("--app", default=None,
                   help="App id or path to security/dast/<app>/app.yaml — supplies the scope, "
                        "the seeded session and the entry points, so --seed/--scope are only "
                        "needed for a hand-written legacy bundle")
    p.add_argument("--seed", default=None, help="Override: seed config (storage_state + routes)")
    p.add_argument("--scope", default=None, help="Override: a scope.json file")
    p.add_argument("--schema", default=str(_ROOT / "contracts" / "scope.schema.json"))
    p.add_argument("--base-url", default=None, help="Override the seed's target.base_url")
    p.add_argument("--zap-proxy", default=None, help="Proxy through ZAP so hosts match the runner (D7)")
    p.add_argument("--out-dir", required=True, help="Directory for trace.json + index.json")
    p.add_argument("--app-id", default=None, help="Defaults to scope.app_id")
    p.add_argument("--model", default=_DEFAULT_MODEL)
    p.add_argument("--no-llm", action="store_true", help="Force the deterministic fallback proposer")
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--headed", action="store_true")
    p.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                   help="Delay each browser action by MS milliseconds (for headed demos/recordings)")
    args = p.parse_args(argv)

    if not (args.app or (args.seed and args.scope)):
        p.error("give --app, or both --seed and --scope for a hand-written bundle")
    config = appconfig.load_app_config(args.app) if args.app else None

    # Safety layer 1 runs either way: a scope derived from app.yaml goes through the same
    # fail-closed check as one read from disk (D2/NFR-2).
    if args.scope:
        scope = preflight(args.scope, args.schema)
    else:
        scope = appconfig.scope_from_config(config)
        check_scope(scope)

    seed = load_seed(args.seed) if args.seed else appconfig.seed_from_config(config)
    base_url = args.base_url or seed["target"]["base_url"]
    app_id = args.app_id or scope["app_id"]
    try:
        trace, guard = explore(
            app_id, base_url, seed["session"]["storage_state"], seed["seed_routes"], scope,
            config=config, deny_actions=seed.get("deny_actions"), max_pages=args.max_pages,
            use_llm=not args.no_llm, model=args.model, zap_proxy=args.zap_proxy,
            headless=not args.headed, slow_mo=args.slow_mo,
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
