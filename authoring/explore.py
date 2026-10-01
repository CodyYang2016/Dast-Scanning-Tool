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
from urllib.parse import urljoin, urlsplit

import jsonschema

from authoring import appconfig, llm_backend
from authoring.record import build_trace, write_trace
from authoring.seed import load_seed
from runner.action_policy import deny_terms, validate_action
from runner.preflight import preflight
from runner.replay import SessionDeadError, prove_auth_live
from runner.redact import redact
from runner.scope_guard import ScopeGuard, host_of

_ROOT = Path(__file__).resolve().parent.parent
_ACTION_SCHEMA = _ROOT / "contracts" / "action.schema.json"


# ---- validation: schema + scope/deny policy (pure) --------------------------------------

def validate_proposal(action: dict, scope: dict, deny_actions=None, safe_forms=None,
                      submit_get_forms: bool = True, allow_writes: bool = False):
    """Validate a proposed action against the action schema AND the action policy.
    Returns (ok: bool, reason: str). Fail-closed: any schema or policy failure -> not ok."""
    try:
        jsonschema.validate(action, json.loads(_ACTION_SCHEMA.read_text(encoding="utf-8")))
    except jsonschema.ValidationError as exc:
        return False, f"schema: {exc.message}"
    if action.get("action") == "stop":
        return True, "stop"
    target = action.get("target") or {}
    if not (target.get("path") or target.get("selector")):
        return False, "no navigable target (empty path/selector)"
    decision = validate_action(action, scope, deny_actions=deny_actions, safe_forms=safe_forms,
                               submit_get_forms=submit_get_forms, allow_writes=allow_writes)
    return decision.allowed, decision.reason


# ---- href normalization (pure) -----------------------------------------------------------

_NON_NAVIGABLE = ("javascript:", "mailto:", "tel:", "data:", "blob:")


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _origin_relative(url: str) -> str:
    """An absolute URL reduced to the path(+query/fragment) the trace/flow appends to base_url."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.fragment:
        path += "#" + parts.fragment
    return path


def normalize_href(href: str | None, page_url: str | None = None) -> str | None:
    """Turn an href as the page emits it into a path the trace/flow can append to base_url.

    Angular emits "#/contact" and "./redirect?to=..."; appended verbatim to base_url those become
    "http://juice:3000#/contact" (works by accident) and "http://juice:3000./redirect?..." (an
    invalid URL that crashes the generated flow). Returns None for non-navigable hrefs.

    page_url resolves a page-relative href against the page it was seen on, which is the only
    correct reading of one: "./?page=include.php" on /vulnerabilities/fi/ addresses that module,
    not the site root, and "/../../x" needs its dot segments collapsed. Without it a relative
    href is assumed to be root-relative, which is the historical behaviour.
    """
    if not href:
        return None
    h = href.strip()
    if not h or h.lower().startswith(_NON_NAVIGABLE):
        return None
    if h.startswith("#"):
        return "/" + h  # SPA route: always read against the origin, never the current path
    if h.startswith("http://") or h.startswith("https://"):
        return h  # left absolute so the scope guard judges it by host
    if page_url:
        resolved = urljoin(page_url, h)
        # A cross-origin resolution ("//evil/x") stays absolute for the same reason.
        return _origin_relative(resolved) if _same_origin(resolved, page_url) else resolved
    if h.startswith("/"):
        return h
    if h.startswith("./"):
        return "/" + h[2:]
    return "/" + h


def _normalize_action(action: dict, page_url: str | None = None) -> dict:
    """Apply normalize_href to an LLM-proposed path so it gets the same treatment as scraped
    links. A non-navigable path is blanked so schema validation (minLength) rejects it."""
    if not isinstance(action, dict):
        return action
    target = action.get("target")
    if isinstance(target, dict) and isinstance(target.get("path"), str):
        target = dict(target)
        target["path"] = normalize_href(target["path"], page_url) or ""
        action = dict(action, target=target)
    return action


def dispatch(action: dict) -> tuple[str, str] | None:
    """Map a validated action to what the browser does: ("goto", path) for follow_link /
    visit_api, ("click", selector) for expand_nav / submit_form. None = nothing executable
    (e.g. stop, or a selector on a navigation action). Pure."""
    kind = action.get("action")
    target = action.get("target") or {}
    if kind in ("follow_link", "visit_api"):
        return ("goto", target["path"]) if target.get("path") else None
    if kind == "submit_form":
        return ("submit", target["selector"]) if target.get("selector") else None
    if kind == "expand_nav":
        return ("click", target["selector"]) if target.get("selector") else None
    return None


def field_selector(form_selector: str, field: str) -> str:
    """A named field inside a form, as a Playwright chained selector. Pure.

    Chained (`>>`) rather than a CSS descendant because a positional form selector
    (`form >> nth=2`) is not CSS and cannot be concatenated into one.
    """
    return f'{form_selector} >> [name="{field}"]'


def form_fill_plan(form: dict, test_data: dict) -> list[tuple[str, str]]:
    """The (field, approved value) pairs to type into a form, in declaration order. Pure.

    Only fields the operator supplied data for in `explore.test_data`. A field with no approved
    value is left empty rather than guessed at: the values that reach a write path are the
    operator's decision, not the planner's, so a form nobody has supplied data for yields an
    empty plan and is not submitted.
    """
    return [(name, test_data[name]) for name in form.get("fields", []) if name in test_data]


# ---- deterministic fallback proposer (pure) ---------------------------------------------

def _in_scope_path(path: str, scope: dict) -> bool:
    if path.startswith("http://") or path.startswith("https://"):
        allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
        return host_of(path) in allow
    return path.startswith("/") or path.startswith("#") or path.startswith("./")


def propose_fallback(observation: dict, visited, scope: dict, deny_actions=None,
                     safe_forms=None, test_data=None) -> dict:
    """Pick the next action deterministically: the first unvisited, in-scope, non-destructive link,
    then an unvisited observed API GET, then an allow-listed form we hold test data for; else stop.
    No LLM. Used as the D9 fallback and in tests.

    Forms come last because a submit is the only step with a side effect: everything readable is
    read first, so a write happens only when it is the sole way to widen coverage.
    """
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
    for form in observation.get("forms", []):
        path, selector = form.get("path"), form.get("selector")
        if not path or not selector or path in visited:
            continue
        if not form_fill_plan(form, dict(test_data or {})):
            continue
        candidate = {"action": "submit_form",
                     "target": {"method": form.get("method", "POST"), "path": path,
                                "selector": selector,
                                "field_bindings": [f for f in form.get("fields", [])]},
                     "reason": "allow-listed form with approved test data", "confidence": 1.0}
        if validate_proposal(candidate, scope, deny_actions, safe_forms)[0]:
            return candidate
    return {"action": "stop", "reason": "no unvisited in-scope non-destructive targets"}


# ---- LLM proposer (primary) -------------------------------------------------------------

def propose_llm(observation: dict, model: str, api_key: str | None = None) -> dict:
    """Ask the configured LLM backend for ONE constrained action given the (already redacted)
    observation. Raises on any failure so callers fall back (D9). Mirrors generate.plan_from_llm."""
    schema = _ACTION_SCHEMA.read_text(encoding="utf-8")
    system = (
        "You drive an authenticated DAST exploration. Given a redacted observation of the current "
        "page (links, forms, observed API calls) you propose exactly ONE next action to widen "
        "coverage of the authenticated surface. Output ONLY a JSON object — no prose, no code "
        "fences — validating against this JSON Schema:\n" + schema +
        "\nNever propose destructive actions (logout, delete, purchase, admin mutations). Prefer "
        "follow_link / visit_api on paths that appear in the observation's `links` / `api` and are "
        "NOT in `visited`. Use expand_nav / submit_form (with a CSS `selector`) only when no "
        "unvisited link or API path remains. Emit {\"action\":\"stop\"} when nothing useful "
        "remains.\n"
        "A form may be submitted only if its `fillable` is true and its `path` is on the "
        "operator's allow-list; propose it with BOTH that `path` and its `selector`, and never "
        "invent field values -- approved test data is filled in for you.\n"
        "The observation's `forbidden` lists path fragments the operator's policy refuses, and "
        "`rejected` lists targets already refused on this run: proposing either wastes the step, "
        "so never propose a path containing a `forbidden` fragment or appearing in `rejected`."
    )
    user = "Redacted observation:\n" + json.dumps(observation, indent=2)
    text = llm_backend.complete(system, user, model, api_key=api_key, max_tokens=1024)
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
        raise ValueError(f"no JSON object found in text: {llm_backend.snippet(t)}")
    try:
        obj, _end = json.JSONDecoder().raw_decode(t[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("JSON is not an object")
    return obj


def target_key(action: dict) -> str | None:
    """The path or selector an action addresses — what identifies it as already-rejected."""
    target = action.get("target") or {}
    return target.get("path") or target.get("selector") or None


def next_action(observation: dict, visited, scope: dict, *, deny_actions=None, safe_forms=None,
                test_data=None, use_llm: bool = True, model: str | None = None,
                api_key: str | None = None, strict: llm_backend.StrictLLM | None = None,
                rejected: set[str] | None = None):
    """Return (action, source). LLM-primary; on any LLM/validation failure, deterministic fallback.

    A rejected target is recorded in `rejected` (when given) so the next observation can tell the
    model not to propose it again.

    strict is the --require-llm budget: an unavailable provider is fatal immediately (nothing about
    the run can improve), while a failed call is reported to it and only becomes fatal once enough
    of them accumulate to mean the provider is dead rather than flaky. A policy rejection is the
    safety layer working, so it is not a failure at all and still falls back.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    model = model or llm_backend.default_model()
    if use_llm and llm_backend.available(api_key):
        try:
            action = _normalize_action(propose_llm(observation, model, api_key),
                                       observation.get("url"))
            ok, reason = validate_proposal(action, scope, deny_actions, safe_forms)
            if ok:
                if strict is not None:
                    strict.success()
                return action, "llm"
            t = action.get("target") or {}
            if rejected is not None and target_key(action):
                rejected.add(target_key(action))
            print(f"explore: LLM action rejected ({reason}): {action.get('action')} "
                  f"{t.get('method', '')} {t.get('path') or t.get('selector') or ''}; using fallback",
                  file=sys.stderr)
        except Exception as exc:
            print(f"explore: LLM path failed ({exc}); using fallback", file=sys.stderr)
            if strict is not None:
                strict.failure(exc)
    elif strict is not None:
        raise llm_backend.LLMRequiredError(
            f"provider {llm_backend.provider()} is not available "
            "(is the CLI installed / the token or key set?)")
    return propose_fallback(observation, visited, scope, deny_actions, safe_forms,
                            test_data), "fallback"


# ---- browser loop -----------------------------------------------------------------------

def _observe(page, base_url: str, api_events: list[dict], test_data: dict) -> dict:
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
    # The form's own action/method, not just its fields: a submit is allow-listed by the endpoint
    # it posts to, so the policy needs the path. The positional `form >> nth=i` keeps forms
    # addressable on pages like WebGoat's lessons, where every form is id-less and a bare `form`
    # would always select the first one.
    forms = _safe_eval(
        "() => Array.from(document.querySelectorAll('form')).map((f, i) => ({selector:"
        " f.getAttribute('id') ? '#' + f.getAttribute('id') : 'form >> nth=' + i,"
        " path: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'GET')"
        ".toUpperCase(), fields: Array.from(f.querySelectorAll('input,select,textarea'))"
        ".map(i => i.getAttribute('name')).filter(Boolean)}))",
        [])
    for form in forms:
        form["path"] = normalize_href(form.get("path", ""), page.url) or ""
        form["fillable"] = bool(form_fill_plan(form, test_data))
    seen: set[str] = set()
    clean: list[str] = []
    for l in links:
        n = normalize_href(l, page.url)
        if n and n not in seen:
            seen.add(n)
            clean.append(n)
    return {"url": page.url, "links": clean, "forms": forms, "api": list(api_events)}


def _submit(page, selector: str, plan: list[tuple[str, str]], events: list[dict]) -> None:
    """Fill a form with approved values and submit it through the page's own handlers.

    requestSubmit(), not submit(): an application that intercepts its forms in JavaScript (as
    WebGoat's lessons do) never sees a raw form.submit(), so the request under test would never
    be issued. Best-effort, like the rest of the loop -- a form that refuses to submit costs a
    step, not the run.
    """
    events.append({"type": "submit", "url": page.url, "selector": selector,
                   "fields": [name for name, _ in plan]})
    try:
        for name, value in plan:
            page.fill(field_selector(selector, name), value, timeout=3000)
        page.eval_on_selector(selector, "f => f.requestSubmit ? f.requestSubmit() : f.submit()")
        # Wait for the response the submit caused, not for a guessed interval: what we are
        # measuring is whether the request reached the application through the proxy.
        page.wait_for_load_state("networkidle", timeout=10000)
    except Exception as exc:
        print(f"explore: form submit on {selector} did not complete ({exc})", file=sys.stderr)


def explore(app_id: str, base_url: str, storage_state: str, seed_routes: list[str], scope: dict, *,
            config: dict | None = None,
            deny_actions=None, safe_forms=None, max_pages: int = 50, use_llm: bool = True,
            model: str | None = None, api_key: str | None = None, zap_proxy: str | None = None,
            headless: bool = True, slow_mo: int = 0, require_llm: bool = False,
            stats: dict | None = None) -> tuple[dict, ScopeGuard]:
    """Run the seeded, LLM-driven exploration loop and return (trace, guard). The trace matches
    record's output (build_trace), so generate/validate/runner consume it unchanged.

    slow_mo (ms) delays each Playwright action so a headed run is watchable in a live demo (same
    knob as record); 0 (default) is full speed and does not affect the captured trace.

    stats, when given, is filled with the per-step action source counts ({"llm": n,
    "fallback": n}) so a caller can report how much of the walk the model actually drove."""
    from playwright.sync_api import sync_playwright

    if not seed_routes:
        raise ValueError("explore requires at least one seed route")
    if require_llm and not use_llm:
        raise llm_backend.LLMRequiredError("require_llm contradicts use_llm=False (--no-llm)")
    strict = llm_backend.StrictLLM() if require_llm else None
    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"] if os.environ.get(
        "RUNNER_CHROMIUM_NO_SANDBOX") else []
    # App-specific knowledge (how auth is proven, what counts as an API call) comes from the
    # app config; the loop itself names no application.
    api_patterns = appconfig.api_patterns(config) if config else ("/rest/", "/api/")
    submit_get_forms = appconfig.submit_get_forms(config) if config else True
    allow_writes = appconfig.writes_allowed(config) if config else False
    test_data = appconfig.test_data(config) if config else {}
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

        steps = 0
        rejected: set[str] = set()
        forbidden = deny_terms(scope, deny_actions)
        while steps < max_pages:
            observation = redact(_observe(page, base_url, api_events, test_data))  # before the LLM
            observation["visited"] = sorted(visited)  # coverage so far, so the model doesn't repeat
            observation["forbidden"] = forbidden      # what policy will refuse, said up front
            observation["rejected"] = sorted(rejected)
            action, src = next_action(observation, visited, scope, deny_actions=deny_actions,
                                      safe_forms=safe_forms, test_data=test_data,
                                      use_llm=use_llm, model=model,
                                      api_key=api_key, strict=strict,
                                      rejected=rejected)
            if stats is not None:
                stats[src] = stats.get(src, 0) + 1
            if action.get("action") == "stop":
                break
            ok, _reason = validate_proposal(action, scope, deny_actions, safe_forms,
                                            submit_get_forms, allow_writes)
            if not ok:  # fail-closed: never execute an action that didn't pass validation
                break
            todo = dispatch(action)
            if todo is None:
                break  # nothing executable (fail closed rather than guess)
            op, arg = todo
            if op == "goto":
                _goto(arg)
            elif op == "submit":
                form = next((f for f in observation.get("forms", [])
                             if f.get("selector") == arg), {})
                plan = form_fill_plan(form, test_data)
                if not plan:
                    break  # no approved value for any field: fail closed rather than post blanks
                _submit(page, arg, plan, events)
                visited.add(action["target"]["path"])
            else:  # click a selector (expand_nav); never a navigation
                events.append({"type": "click", "selector": arg})
                try:
                    page.click(arg, timeout=3000)
                except Exception:
                    pass
                visited.add(arg)
            for f in observation.get("forms", []):
                events.append({"type": "form", "url": observation.get("url"),
                               "fields": f.get("fields", [])})
            steps += 1

        context.close()
        browser.close()

    guard.finalize()  # discovery mode: block-and-continue, does not raise
    if strict is not None:
        strict.finish()  # a walk the model never drove is a broken provider, not a fallback run
    events.extend(api_events)  # fold observed API calls into the trace
    return build_trace(app_id, base_url, events), guard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="LLM-driven authenticated exploration -> trace (Phase B).")
    p.add_argument("--app", default=None, help="App id or path to security/dast/<app>/app.yaml")
    p.add_argument("--seed", required=True, help="Seed config (storage_state + seed_routes)")
    p.add_argument("--scope", required=True, help="App scope.json (preflight-validated first)")
    p.add_argument("--schema", default=str(_ROOT / "contracts" / "scope.schema.json"))
    p.add_argument("--base-url", default=None, help="Override the seed's target.base_url")
    p.add_argument("--zap-proxy", default=None, help="Proxy through ZAP so hosts match the runner (D7)")
    p.add_argument("--out-dir", required=True, help="Directory for trace.json + index.json")
    p.add_argument("--app-id", default=None, help="Defaults to scope.app_id")
    p.add_argument("--model", default=None,
                   help="LLM model id; defaults to the LLM_PROVIDER's default (Anthropic or Copilot)")
    p.add_argument("--no-llm", action="store_true", help="Force the deterministic fallback proposer")
    p.add_argument("--require-llm", action="store_true",
                   help="Fail instead of falling back when the LLM path cannot be taken")
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--headed", action="store_true")
    p.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                   help="Delay each browser action by MS milliseconds (for headed demos/recordings)")
    args = p.parse_args(argv)
    if args.require_llm and args.no_llm:  # caught here so it costs no session seed and no traffic
        p.error("--require-llm contradicts --no-llm")

    scope = preflight(args.scope, args.schema)  # safety layer 1 before any traffic
    seed = load_seed(args.seed)
    base_url = args.base_url or seed["target"]["base_url"]
    app_id = args.app_id or scope["app_id"]
    model = args.model or llm_backend.default_model()
    try:
        config = appconfig.load_app_config(args.app or app_id)
    except Exception:
        config = None   # exploration can still run on a raw seed+scope without an app.yaml
    stats: dict[str, int] = {}
    try:
        trace, guard = explore(
            app_id, base_url, seed["session"]["storage_state"], seed["seed_routes"], scope,
            config=config,
            deny_actions=seed.get("deny_actions"), max_pages=args.max_pages,
            use_llm=not args.no_llm, model=model, zap_proxy=args.zap_proxy,
            headless=not args.headed, slow_mo=args.slow_mo, require_llm=args.require_llm,
            stats=stats,
        )
    except SessionDeadError as exc:
        print(f"EXPLORE ABORT: seeded session dead ({exc}); re-seed and retry", file=sys.stderr)
        return 2
    except llm_backend.LLMRequiredError as exc:
        print(f"EXPLORE ABORT: {exc}", file=sys.stderr)
        return 3

    write_trace(trace, args.out_dir)
    print(json.dumps({
        "app_id": app_id, "pages": len(trace["index"]), "api_calls": len(trace["api"]),
        "forms": len(trace["forms"]), "hosts": trace["hosts"],
        "requests_seen": len(guard.decisions), "blocked": len(guard.violations),
        # How much of the walk the model actually drove: all-fallback steps with the LLM enabled
        # mean the provider is misconfigured, not that the tool chose to be deterministic.
        "steps_by_source": stats,
        "out_dir": args.out_dir,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
