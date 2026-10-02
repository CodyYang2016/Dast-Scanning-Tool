"""generate CLI (FR-G1-G4): trace -> journey plan -> flow.py + scan config.

The LLM emits a constrained JSON journey plan (validated against journey.schema.json);
deterministic code renders it into flow.py — the LLM never authors executable code (safety).
LLM is the primary path (Anthropic SDK, ANTHROPIC_API_KEY); a deterministic trace->plan
fallback is used only if the key is absent or the model output can't be repaired.

Deterministic transforms (emit_scope / render_flow / emit_*) are pure and unit-tested; the
live LLM call is verified by running it with a key.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path

import jsonschema

from authoring import appconfig
from runner.scope_guard import host_of

_ROOT = Path(__file__).resolve().parent.parent
_JOURNEY_SCHEMA = _ROOT / "contracts" / "journey.schema.json"
_SCOPE_SCHEMA = _ROOT / "contracts" / "scope.schema.json"
_VERSIONS_LOCK = _ROOT / "versions.lock"

_DEFAULT_MODEL = "claude-opus-4-8"


def _is_absolute(target: str) -> bool:
    return target.startswith(("http://", "https://"))


def _relpath(url: str, base_url: str) -> str:
    if url.startswith(base_url):
        return url[len(base_url):] or "/"
    return url if url.startswith("/") else ""


# ---- FR-G2: scope emission --------------------------------------------------------------

def emit_scope(trace: dict, config: dict) -> dict:
    """Seed the allow-list from hosts actually seen in the trace, everything else from config.

    `environment_class` has no default on purpose: it is what preflight refuses prod on, so a
    missing value must fail here rather than quietly become "dev".
    """
    hosts = list(trace.get("hosts") or [])
    target = host_of(trace["base_url"]) or (hosts[0] if hosts else None)
    if target is None:
        raise ValueError("cannot determine target host from the trace")
    scope_cfg = config.get("scope", {})
    if str(config["environment_class"]).strip().lower() in ("test", "staging"):
        # Shared environment: the configured origins plus the target's own ORIGIN. Hosts merely
        # observed while recording are not adopted — seeing a host does not put it in scope.
        from runner.scope_guard import origin_of
        allow = sorted(set(scope_cfg.get("allow", [])) | {origin_of(trace["base_url"])})
    else:
        allow = sorted(set(hosts) | set(scope_cfg.get("allow", [])) | {target})
    return {
        "app_id": trace["app_id"],
        "environment_class": config["environment_class"],
        "target_fqdn": target,
        "fqdn_allow_list": allow,
        "fqdn_deny_list": list(scope_cfg.get("deny", [])),
        "avoid_action_list": appconfig.avoid_actions(config),
        "exclude_paths": appconfig.exclude_paths(config),
        "traverse_list": list(config.get("scope", {}).get("traverse", [])),
    }


# ---- journey plan: deterministic fallback + validation ----------------------------------

def _allowed_writes(trace: dict, config: dict) -> list[dict]:
    """Writes the app's JavaScript made during the walk, replayed so ZAP can attack them (W6-1).

    ZAP's spider submits HTML forms itself; what it never sees are API writes made from script.
    Each is replayed only if the action policy that governs exploration allows it under this
    application's posture — the same decision, made the same way, so a write the walk could not
    make is never made by the scan: writes need `data_policy: disposable` + `write_mode: allow`,
    DELETE needs `safe_forms`, `scope.exclude` and the deny list win, and a credential change is
    refused at any posture. A read-only app gets exactly the plan it got before.
    """
    if not appconfig.writes_allowed(config):
        return []
    from runner.action_policy import validate_action
    scope = appconfig.scope_from_config(config)
    out = []
    for a in trace.get("api", []):
        method = a.get("method", "GET").upper()
        path = _relpath(a.get("url", ""), trace["base_url"])
        if method == "GET" or not path or "body_omitted" in a:
            continue
        try:
            fields = list(json.loads(a.get("body") or "{}").keys())
        except (ValueError, AttributeError):
            fields = [kv.split("=", 1)[0] for kv in (a.get("body") or "").split("&") if kv]
        action = {"action": "visit_api",
                  "target": {"path": path, "method": method, "field_bindings": fields}}
        if not validate_action(action, scope, safe_forms=appconfig.safe_forms(config),
                               allow_writes=True).allowed:
            continue
        step = {"action": "api_send", "target": path, "method": method}
        if a.get("body") is not None:
            step["body"] = a["body"]
        if a.get("content_type"):
            step["content_type"] = a["content_type"]
        out.append(step)
    return out


def journey_from_trace(trace: dict, config: dict) -> dict:
    base = trace["base_url"]
    login = login_block(config)
    journey: list[dict] = []
    for route in trace.get("index", []):
        path = _relpath(route, base)
        if path and "/login" not in path and path not in ("/#/", "/"):
            journey.append({"action": "goto", "target": path})
    for a in trace.get("api", []):
        if a.get("method", "GET").upper() == "GET":
            path = _relpath(a["url"], base)
            if path:
                journey.append({"action": "api_get", "target": path})
    journey.extend(_allowed_writes(trace, config))
    if not journey:
        journey = [{"action": "goto", "target": "/#/"}]
    seen, dedup = set(), []
    for s in journey:
        key = (s["action"], s["target"], s.get("method"))
        if key not in seen:
            seen.add(key)
            dedup.append(s)
    return {"app_id": trace["app_id"], "base_url": base, "login": login, "journey": dedup}


def login_block(config: dict) -> dict:
    """The plan's login block, built from operator config.

    Deliberately NOT something the LLM authors: how to log in and how authentication is proven
    are safety-relevant and knowable, so they come from app.yaml. The model contributes the
    journey only. `generate` injects this block into every plan before validation, so a model
    that omits it (or invents one) cannot change how we authenticate.
    """
    block: dict = {"url": appconfig.login_url(config)}
    if appconfig.uses_shorthand_login(config):
        cfg_login = appconfig.login(config)
        block["email_selector"] = cfg_login["email"]
        block["password_selector"] = cfg_login["password"]
        block["submit_selector"] = cfg_login["submit"]
    else:
        block["steps"] = appconfig.login_steps(config)
    if appconfig.proof_mode(config) == "js":
        block["token_check"] = appconfig.proof_js(config)
    return block


def validate_plan(plan: dict) -> None:
    """Raise jsonschema.ValidationError if the plan is not a valid journey."""
    jsonschema.validate(plan, json.loads(_JOURNEY_SCHEMA.read_text()))


def parse_plan_text(text: str) -> dict:
    """Extract a JSON object from raw LLM text (strips ``` fences). Raises ValueError."""
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in text")
    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


# ---- Step B: deterministic render (LLM safety boundary) ----------------------------------

def _render_login_steps(config: dict, w) -> None:
    """Emit the login itself. The shorthand and a step list normalize to one code path."""
    for step in appconfig.login_steps(config):
        action, sel = step["action"], json.dumps(step["selector"])
        if action == "fill":
            var = "identifier" if step.get("value", "identifier") == "identifier" else "secret"
            w(f"    page.fill({sel}, {var})")
        elif action == "click":
            w(f"    page.click({sel})")
        elif action == "press":
            w(f"    page.press({sel}, {json.dumps(step.get('key', 'Enter'))})")
        elif action == "wait_for":
            w(f"    page.wait_for_selector({sel}, timeout=15000)")


def _render_auth_proof(config: dict, w) -> bool:
    """Emit the proof that we are authenticated. Returns True when a bearer token is available.

    Every mode ends in a raise if the proof fails: a flow that cannot prove authentication must
    stop, never hand an unauthenticated session to the scanner.
    """
    mode = appconfig.proof_mode(config)
    spec = appconfig.proof(config)[mode]
    if mode == "js":
        w(f'    page.wait_for_function({json.dumps("() => !!(" + spec + ")")}, timeout=15000)')
        w(f'    token = page.evaluate({json.dumps("() => " + spec)})')
        w("    if not token:")
        w('        raise RuntimeError("login did not produce an auth token")')
        return True
    if mode == "selector":
        # state="attached" matches runner.replay.wait_for_auth: presence proves the session,
        # and an authenticated-only marker is often hidden inside a nav menu.
        w(f'    page.wait_for_selector({json.dumps(spec)}, timeout=15000, state="attached")')
        w(f"    if not page.locator({json.dumps(spec)}).count():")
        w('        raise RuntimeError("login did not reveal the authenticated marker")')
        return False
    # route: an authenticated page must answer, and must not bounce us back to the login form
    w(f'    _resp = page.goto(base_url + {json.dumps(spec["path"])}, wait_until="networkidle")')
    w("    _status = _resp.status if _resp else None")
    if "expect_status" in spec:
        w(f"    if _status != {spec['expect_status']}:")
    else:
        w("    if _status is None or not (200 <= _status < 400):")
    w('        raise RuntimeError(f"auth check returned {_status}")')
    if spec.get("forbid_redirect_to"):
        w(f"    if {json.dumps(spec['forbid_redirect_to'])} in page.url:")
        w('        raise RuntimeError(f"auth check redirected to {page.url}")')
    return False


# The in-page request an api_send step makes: through the browser, so the scope guard and ZAP
# both see it, with the page's cookies and an optional bearer token.
_FETCH_JS = ("([url, method, body, ctype, bearer]) => fetch(url, {method, body, "
             "credentials: 'include', headers: Object.assign(ctype ? {'Content-Type': ctype} : {}, "
             "bearer ? {'Authorization': 'Bearer ' + bearer} : {})}).then(r => r.status)")


def render_flow(plan: dict, config: dict) -> str:
    """Render a validated journey plan into flow.py source. Deterministic (FR-G4); no secrets
    (creds from env, NFR-3). String literals are json.dumps-quoted for safety.

    The banner selectors and the authentication proof come from `config`, not from the plan —
    they are the application's, and no app's UI quirks are inherited by another's flow.
    """
    banners = appconfig.dismiss_selectors(config)
    # Render as a tuple literal; a single selector needs the trailing comma or the generated
    # loop would iterate over the characters of a string.
    banners_src = "(" + ", ".join(json.dumps(b) for b in banners) + ("," if len(banners) == 1 else "") + ")"
    out: list[str] = []
    w = out.append
    w('"""Generated by authoring/generate.py from a journey plan. Do not edit by hand."""')
    w("from __future__ import annotations")
    w("")
    w("import os")
    w("")
    w("")
    w("def _dismiss_banners(page):")
    w(f"    for sel in {banners_src}:")
    w("        try:")
    w("            el = page.locator(sel)")
    w("            if el.count() and el.first.is_visible():")
    w("                el.first.click(timeout=2000)")
    w("        except Exception:")
    w("            pass")
    w("")
    w("")
    creds = appconfig.credential_env_names(config)
    w("def run(page, base_url, evidence_dir=None):")
    w(f'    identifier = os.environ.get({json.dumps(creds[0])}, "")')
    w(f'    secret = os.environ.get({json.dumps(creds[1])}, "")')
    w(f'    page.goto(base_url + {json.dumps(appconfig.login_url(config))}, '
      'wait_until="networkidle")')
    w("    _dismiss_banners(page)")
    _render_login_steps(config, w)
    has_token = _render_auth_proof(config, w)
    for step in plan["journey"]:
        action, target = step["action"], step["target"]
        # A target may be absolute or relative: a plan derived from a trace naturally carries
        # absolute URLs, and an LLM asked for routes from that trace will answer in kind.
        # Gluing base_url onto an absolute URL produces nonsense, so only relative paths are
        # joined. An absolute target pointing off-host is caught by validate's allow-list
        # check, which is where a scope decision belongs.
        url = json.dumps(target) if _is_absolute(target) else f"base_url + {json.dumps(target)}"
        if action == "goto":
            w(f'    page.goto({url}, wait_until="networkidle")')
        elif action == "click":
            w(f'    page.click({json.dumps(target)})')
        elif action == "api_send":
            # From the page, not page.request: the request passes the browser's scope guard
            # as well as ZAP. The session rides on the page's cookies; an app that also wants
            # a bearer token names the cookie that holds it (auth.bearer_from_cookie).
            bearer = appconfig.bearer_from_cookie(config)
            if bearer:
                w(f'    _bearer = next((c["value"] for c in page.context.cookies() '
                  f'if c["name"] == {json.dumps(bearer)}), None)')
            else:
                w('    _bearer = None')
            w(f'    page.evaluate({json.dumps(_FETCH_JS)}, '
              f'[{url}, {json.dumps(step.get("method", "POST"))}, {json.dumps(step.get("body"))}, '
              f'{json.dumps(step.get("content_type"))}, _bearer])')
        elif action == "api_get":
            if has_token:
                w(f'    page.request.get({url}, '
                  'headers={"Authorization": f"Bearer {token}"})')
            else:
                # No bearer token: the session rides on the context's cookies.
                w(f'    page.request.get({url})')
    if has_token:
        w('    return {"authenticated": True, "token_present": bool(token)}')
    else:
        w('    return {"authenticated": True, "token_present": False}')
    w("")
    return "\n".join(out)


# ---- FR-G3: policy / manifest / lock / auth ---------------------------------------------

def emit_zap_policy(config: dict | None = None, intensity: str = "medium") -> dict:
    """The scan posture the runner will apply, taken from the application's config (W2-4).

    Emitted into the bundle so the policy that produced a set of findings is committed
    alongside them, and read back by runner/scan.py — it is no longer a file nobody consumes.
    """
    if config is None:  # legacy callers: the historical posture
        return {"intensity": intensity, "attack_strength": intensity,
                "alert_threshold": "medium", "disabled_scanners": ["40026"]}
    policy = appconfig.scan_policy(config)
    budgets = appconfig.scan_budgets(config)
    return {
        # Recorded so the scan's coverage artifact, and therefore the lifecycle diff, knows
        # whether the application was changed while it was being explored.
        "write_mode": "allow" if appconfig.writes_allowed(config) else "deny",
        "intensity": policy["attack_strength"],
        "attack_strength": policy["attack_strength"],
        "alert_threshold": policy["alert_threshold"],
        "disabled_scanners": list(policy["disabled_rules"]),
        "max_scan_min": budgets["max_scan_min"],
        "max_rule_min": budgets["max_rule_min"],
    }


def emit_manifest(trace: dict, plan_source: str = "unknown", model: str | None = None) -> dict:
    """The bundle's provenance: what produced this plan, from which trace.

    `plan_source` is the load-bearing field. The safety argument for this project is that the
    LLM emits only a schema-validated journey plan, which deterministic code renders — so a
    reviewer looking at a committed bundle must be able to tell whether a model was involved,
    and which one, without rerunning anything or reading terminal scrollback. `model` is
    present only when one actually authored the plan (W2-14).
    """
    manifest = {
        "app_id": trace["app_id"],
        "base_url": trace["base_url"],
        "generated_by": "authoring/generate.py",
        "plan_source": plan_source,
        "trace_app_id": trace["app_id"],
        "artifacts": ["flow.py", "scope.json", "auth.json", "zap-policy.yaml",
                      "manifest.json", "lock"],
    }
    if plan_source == "llm" and model:
        manifest["model"] = model
    return manifest


def emit_lock() -> dict:
    lock: dict[str, str] = {}
    if _VERSIONS_LOCK.exists():
        for line in _VERSIONS_LOCK.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            lock[k.strip()] = v.strip()
    lock.setdefault("playwright_version", "1.62.0")
    return lock


def emit_auth(config: dict) -> dict:
    """auth.json references env var names for creds — never the secrets themselves (NFR-3)."""
    creds = config["auth"].get("credentials", {})
    return {"email_env": creds.get("email_env", "AUTH_EMAIL"),
            "password_env": creds.get("password_env", "AUTH_PASSWORD")}


# ---- Step A (primary): LLM plan ---------------------------------------------------------

def plan_from_llm(trace: dict, model: str, api_key: str, config: dict | None = None) -> dict:
    """Ask the LLM for a journey plan. Raises on any failure so callers can fall back.

    The model's job is the JOURNEY — which authenticated routes are worth visiting, in what
    order. How to log in is operator config, so the login block is replaced with the
    config-derived one *before* validation: the model cannot influence authentication, and an
    irrelevant field in its reply cannot fail the call. (It could: asked for a plan against a
    schema documenting both login forms, the model returned both at once, and `oneOf` rejected
    the combination — killing the LLM path over a block that was about to be discarded.)

    anthropic is imported lazily so the fallback and the tests don't need it.
    """
    import anthropic  # lazy

    schema = _JOURNEY_SCHEMA.read_text()
    system = (
        "You convert a web-app crawl trace into a STRICT JSON 'journey plan' for an "
        "authenticated DAST scan. Output ONLY the JSON object — no prose, no code fences. "
        "It must validate against this JSON Schema:\n" + schema
    )
    user = (
        "Crawl trace (no secrets):\n" + json.dumps(trace, indent=2) +
        "\n\nProduce the journey plan. Only the `journey` matters: the authenticated routes "
        "worth visiting (`goto`) and authenticated GET endpoints worth calling (`api_get`), "
        "in a sensible order, drawn from the trace. Emit `login` as {\"url\": \"/\"} — the "
        "real login block is supplied from the application's configuration and whatever you "
        "put there is discarded. Never include credentials."
    )
    client = anthropic.Anthropic(api_key=api_key)
    # Latest models (Opus 4.8, Sonnet 5, ...) reject temperature/top_p/top_k; omit them.
    msg = client.messages.create(
        model=model, max_tokens=4096,
        system=system, messages=[{"role": "user", "content": user}],
    )
    text = "".join(getattr(b, "text", "") for b in msg.content)
    plan = parse_plan_text(text)
    if config is not None:
        plan["login"] = login_block(config)   # operator config wins, before validation
    validate_plan(plan)  # raise if the model's JOURNEY is off-contract
    return plan


def make_plan(trace: dict, config: dict, use_llm: bool = True, model: str = _DEFAULT_MODEL,
              api_key: str | None = None) -> tuple[dict, str]:
    """Return (plan, source) where source is 'llm' or 'fallback'.

    Whatever the plan's origin, the login block is overwritten with the config-derived one: the
    model chooses routes, never how we authenticate.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if use_llm and api_key:
        try:
            plan = plan_from_llm(trace, model, api_key, config=config)
            plan["login"] = login_block(config)   # belt and braces for any other caller
            validate_plan(plan)
            return plan, "llm"
        except Exception as exc:  # network/parse/validation — fall back deterministically
            print(f"generate: LLM path failed ({exc}); using deterministic fallback",
                  file=sys.stderr)
    plan = journey_from_trace(trace, config)
    validate_plan(plan)
    return plan, "fallback"


def generate(trace: dict, out_dir: str, config: dict, use_llm: bool = True,
             model: str = _DEFAULT_MODEL, api_key: str | None = None) -> dict:
    """Produce all authoring artifacts from a trace. Returns a summary dict."""
    plan, source = make_plan(trace, config, use_llm=use_llm, model=model, api_key=api_key)
    # Record which path produced the plan, so the committed bundle is self-describing.
    flow_src = render_flow(plan, config)
    ast.parse(flow_src)  # guarantee the generated code compiles (FR-G1 pre-check)

    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "journey.json").write_text(json.dumps(plan, indent=2) + "\n")
    (d / "flow.py").write_text(flow_src)
    (d / "scope.json").write_text(json.dumps(emit_scope(trace, config), indent=2) + "\n")
    (d / "auth.json").write_text(json.dumps(emit_auth(config), indent=2) + "\n")
    # json.dumps is valid YAML, so no PyYAML dependency is needed for the .yaml file.
    (d / "zap-policy.yaml").write_text(json.dumps(emit_zap_policy(config), indent=2) + "\n")
    (d / "manifest.json").write_text(
        json.dumps(emit_manifest(trace, plan_source=source, model=model), indent=2) + "\n")
    (d / "lock").write_text(json.dumps(emit_lock(), indent=2) + "\n")
    return {"plan_source": source, "journey_steps": len(plan["journey"]), "out_dir": str(d)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate flow.py + scan config from a trace (FR-G1-4).")
    p.add_argument("--app", required=True,
                   help="App id or path to security/dast/<app>/app.yaml")
    p.add_argument("--trace", required=True, help="Path to trace.json from record")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--model", default=_DEFAULT_MODEL)
    p.add_argument("--no-llm", action="store_true", help="Force the deterministic fallback plan")
    args = p.parse_args(argv)

    config = appconfig.load_app_config(args.app)
    trace = json.loads(Path(args.trace).read_text())
    summary = generate(trace, args.out_dir, config, use_llm=not args.no_llm, model=args.model)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
