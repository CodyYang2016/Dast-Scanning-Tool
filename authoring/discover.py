"""Auto-author an application's auth block (`dast onboard --discover`).

Writing `auth:` by hand was the largest remaining human task in onboarding. It is also the
most automatable: the model reads a login page and proposes how to log in and how to prove it
worked, and — crucially — the proposal has a crisp oracle. You either log in or you do not.

So the model proposes DATA (contracts/auth_discovery.schema.json) and deterministic code
VERIFIES it by executing it against the running application. A proof is accepted only when it
is observed to hold while logged in AND to fail while logged out. That second half is the
part a plausible-sounding answer cannot fake, and it is what makes accepting a model's
suggestion here safe: nothing is believed, everything is checked.

Same D8 boundary as the rest of the project — the model never emits code, and its confidence
is never the reason anything is accepted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema

from authoring import llm_backend
from runner.action_policy import never_allowed

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA = _ROOT / "contracts" / "auth_discovery.schema.json"


class DiscoveryFailed(Exception):
    """Raised when no proposed way of proving authentication survived verification.

    Deliberately an error rather than a best guess: an unverified proof would be written into
    a config, and every later scan would trust it.
    """


# ---- the model's reply is data, and it is validated -------------------------------------

def parse_proposal(text: str) -> dict:
    """Extract and schema-validate a proposal from raw model output.

    Raises ValueError when there is no JSON object, jsonschema.ValidationError when the
    object is off-contract — including a step carrying a literal credential, since `value`
    names which credential to type and is an enum.
    """
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError(
            f"no JSON object found in the model's reply: {llm_backend.snippet(t)}")
    try:
        proposal = json.loads(t[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in the model's reply: {exc}") from exc
    jsonschema.validate(proposal, json.loads(_SCHEMA.read_text()))
    return proposal


# ---- verification (pure decision logic; the observing is done by the caller) -------------

def discriminates(logged_out: bool, logged_in: bool) -> bool:
    """Is this proof actually evidence of a session?

    It must hold when logged in and fail when logged out. Requiring the second is what
    catches the common trap: an application that answers 200 on its own failed-login page
    would satisfy a naive status check whether or not anyone had logged in.
    """
    return bool(logged_in) and not bool(logged_out)


def _would_end_the_session(candidate: dict) -> bool:
    """True for a proof whose evaluation would itself log us out.

    Only navigation is dangerous: a `route` proof is visited, so /logout.php ends the very
    session being proven. A `selector` looking for a logout LINK is the classic logged-in
    marker and only reads the page.
    """
    route = candidate.get("route")
    return bool(route and never_allowed({"action": "goto",
                                         "target": {"path": route.get("path", "")}}))


def choose_proof(candidates: list[dict], observe) -> dict:
    """Return the first candidate that discriminates, else raise.

    `observe(index, candidate) -> (holds_logged_out, holds_logged_in)` does the live work. A
    candidate whose observation raises is skipped rather than allowed to end the run: a
    selector the browser cannot parse says nothing about the others.
    """
    tried = []
    for i, candidate in enumerate(candidates):
        if _would_end_the_session(candidate):
            # Refused before evaluation, not after: visiting it is what does the damage.
            tried.append(f"{candidate} (refused: navigating there would end the session)")
            continue
        try:
            out, inn = observe(i, candidate)
        except Exception as exc:                       # noqa: BLE001 — any failure disqualifies
            tried.append(f"{candidate} (error: {exc})")
            continue
        if discriminates(out, inn):
            return candidate
        tried.append(f"{candidate} (logged_out={out}, logged_in={inn})")
    raise DiscoveryFailed(
        "none of the proposed proofs distinguished a logged-in session from a logged-out one; "
        "tried: " + "; ".join(tried))


# ---- what gets written -------------------------------------------------------------------

_TEMPLATE = """\
# {app_id} — discovered by `dast onboard --discover`{provenance}
#
# The login steps and the proof below were proposed by a model reading the login page and
# then VERIFIED by executing them: the proof was observed to hold while logged in and to fail
# while logged out. Review them anyway — they are a starting point, not an authority.
#
# TODOs are the decisions a model cannot make for you.

app_id: {app_id}
environment_class: dev            # dev | test | staging — never prod (preflight refuses it)
base_url: {base_url}

scope:
  allow: [{host}]
  deny: []
  avoid_actions: [logout, delete, purchase, change-password]

auth:
  mode: form
  login_url: {login_url}
  steps:
{steps}
  proof:
{proof}
  identity: provisioned           # the tool does not create accounts unless told to
  credentials:                    # environment variable NAMES; values never live here
    email_env: {env_prefix}_USER
    password_env: {env_prefix}_PASS
  storage_state: .secrets/{app_id}-storageState.json

ui:
  dismiss_selectors: []           # TODO cookie banners or modals covering the login form

record:
  authenticated_routes:{routes}

# api:
#   patterns: ["/api/", "/rest/"]   # TODO what counts as an API call; omit if server-rendered

explore:
  seed_routes: [{seed}]
  safe_forms: []                  # read-only until someone decides otherwise
  budgets:
    max_pages: 30

# data_policy: disposable         # attest the data can be rebuilt, then set write_mode below
# explore:
#   write_mode: allow             # unlocks stored XSS, POST-body injection, upload flaws
"""


def _yaml_block(obj, indent: int) -> str:
    """Render a small mapping/list as YAML at a fixed indent (no PyYAML styling surprises)."""
    pad = " " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, dict):
                lines.append(f"{pad}{k}:")
                lines.append(_yaml_block(v, indent + 2))
            else:
                lines.append(f"{pad}{k}: {json.dumps(v)}")
        return "\n".join(lines)
    return f"{pad}{json.dumps(obj)}"


def render_config(app_id: str, base_url: str, login_url: str, steps: list[dict], proof: dict,
                  authenticated_routes: list[str], model: str | None = None) -> str:
    """Render the app.yaml for a discovered application. Pure; the caller writes the file."""
    host = base_url.split("://")[-1].split("/")[0].split(":")[0]
    step_lines = "\n".join(
        "    - {" + ", ".join(f"{k}: {json.dumps(v)}" for k, v in s.items()) + "}"
        for s in steps)
    routes = ("\n" + "\n".join(f"    - {r}" for r in authenticated_routes)) if \
        authenticated_routes else " []                 # TODO routes worth visiting after login"
    seed = ", ".join(json.dumps(r) for r in (authenticated_routes[:2] or ["/"]))
    provenance = f", proposed by {model} and verified live" if model else ""
    return _TEMPLATE.format(
        app_id=app_id, base_url=base_url, host=host, login_url=login_url,
        steps=step_lines, proof=_yaml_block(proof, 4), routes=routes, seed=seed,
        env_prefix=app_id.replace("-", "_").upper(), provenance=provenance,
    )


# ---- the live half -----------------------------------------------------------------------

def summarize_login_page(page) -> dict:
    """What the model is shown: the page's forms, their fields and their controls.

    Structure only — no values, no cookies, no storage. There is nothing secret on a login
    page before anyone logs in, and keeping the summary structural keeps it that way.
    """
    forms = page.evaluate(
        "() => Array.from(document.querySelectorAll('form')).map((f, i) => {"
        "  const fid = f.getAttribute('id');"
        "  return {form: fid ? '#' + fid : 'form >> nth=' + i,"
        "          action: f.getAttribute('action'),"
        "          method: (f.getAttribute('method') || 'GET').toUpperCase(),"
        "          inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(e => ({"
        "            name: e.getAttribute('name'), type: e.getAttribute('type'),"
        "            id: e.getAttribute('id'), placeholder: e.getAttribute('placeholder')})),"
        "          buttons: Array.from(f.querySelectorAll('button,[type=submit]')).map(b => ({"
        "            text: (b.innerText || b.value || '').trim().slice(0, 40),"
        "            type: b.getAttribute('type'), name: b.getAttribute('name'),"
        "            id: b.getAttribute('id')}))};"
        "})")
    return {"url": page.url, "title": page.title(), "forms": forms}


def propose_auth(summary: dict, model: str, api_key: str | None = None) -> dict:
    """Ask the model how to log in and how to prove it worked. Raises on any failure.

    Routed through llm_backend so it uses the selected provider (Anthropic, or the Copilot CLI
    that is the approved path inside Nationwide); the model still only emits validated DATA.
    """
    system = (
        "You read a web application's login page and say how to log in. Output ONLY a JSON "
        "object — no prose, no code fences — validating against this schema:\n"
        + _SCHEMA.read_text() +
        "\nRules: `steps` uses the page's real selectors, preferring stable attributes "
        "(name, id) over position. `value` says WHICH credential to type — never a literal. "
        "For `proof_candidates`, propose two to four ordered best-first, and prefer things "
        "that cannot be true when logged out: an element that only exists for a signed-in "
        "user, a token in web storage, or an authenticated route that redirects away when "
        "the session is missing. Each candidate is tested against the running application "
        "both logged in and logged out, and any that is true in both is discarded — so a "
        "confident guess costs nothing but a wrong one is caught."
    )
    user = "Login page:\n" + json.dumps(summary, indent=2)
    text = llm_backend.complete(system, user, model, api_key=api_key, max_tokens=2048)
    return parse_proposal(text)


def _log_in(page, base_url: str, login_url: str, steps: list[dict], values: dict) -> None:
    """Perform the proposed login on a fresh page."""
    page.goto(base_url + login_url, wait_until="networkidle")
    for step in steps:
        action, sel = step["action"], step["selector"]
        if action == "fill":
            page.fill(sel, values[step.get("value", "identifier")], timeout=10000)
        elif action == "click":
            page.click(sel, timeout=10000)
        elif action == "press":
            page.press(sel, step.get("key", "Enter"), timeout=10000)
        elif action == "wait_for":
            page.wait_for_selector(sel, timeout=10000)
    page.wait_for_load_state("networkidle", timeout=10000)


def _holds(page, candidate: dict, base_url: str) -> bool:
    """Evaluate one proof against the page as it currently stands."""
    mode = next(iter(candidate))
    if mode == "js":
        return bool(page.evaluate(f"() => !!({candidate['js']})"))
    if mode == "selector":
        return page.locator(candidate["selector"]).count() > 0
    spec = candidate["route"]
    resp = page.goto(base_url + spec["path"], wait_until="networkidle")
    status = getattr(resp, "status", None)
    expected = spec.get("expect_status")
    ok = (status == expected) if expected else (status is not None and 200 <= int(status) < 400)
    forbid = spec.get("forbid_redirect_to")
    return bool(ok and not (forbid and forbid in page.url))


def discover_auth(base_url: str, login_url: str, identifier: str, secret: str, *,
                  model: str | None = None, api_key: str | None = None,
                  zap_proxy: str | None = None, headless: bool = True) -> dict:
    """Propose an auth block, verify it live, and return {steps, proof, summary, model}.

    Raises DiscoveryFailed when nothing survives verification — with what was tried, so the
    operator can finish the job by hand instead of debugging a silently wrong config.
    """
    import os

    from playwright.sync_api import sync_playwright

    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not llm_backend.available(api_key):
        raise DiscoveryFailed(
            "discovery needs a model: set ANTHROPIC_API_KEY, or LLM_PROVIDER=copilot with the "
            "copilot CLI on PATH")
    model = model or llm_backend.default_model()

    launch = {"headless": headless}
    if zap_proxy:
        launch["proxy"] = {"server": zap_proxy}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch)
        try:
            page = browser.new_context(ignore_https_errors=True).new_page()
            page.goto(base_url + login_url, wait_until="networkidle")
            summary = summarize_login_page(page)
            proposal = propose_auth(summary, model, api_key)

            # Observe every candidate logged OUT first, in one clean context.
            out_page = browser.new_context(ignore_https_errors=True).new_page()
            out_page.goto(base_url + login_url, wait_until="networkidle")
            logged_out = {}
            for i, candidate in enumerate(proposal["proof_candidates"]):
                try:
                    logged_out[i] = _holds(out_page, candidate, base_url)
                except Exception:
                    logged_out[i] = None          # unevaluable here; choose_proof will skip it

            # Then log in with the proposed steps, in another clean context.
            values = {"identifier": identifier, "secret": secret}

            def observe(i, candidate):
                if logged_out[i] is None:
                    raise RuntimeError("candidate could not be evaluated on the login page")
                # A fresh session per candidate: evaluating a route proof navigates, so one
                # candidate must not be able to move the ground under the next.
                fresh = browser.new_context(ignore_https_errors=True).new_page()
                try:
                    _log_in(fresh, base_url, login_url, proposal["steps"], values)
                    return logged_out[i], _holds(fresh, candidate, base_url)
                finally:
                    fresh.context.close()

            proof = choose_proof(proposal["proof_candidates"], observe)
            return {"steps": proposal["steps"], "proof": proof, "summary": summary,
                    "model": model,
                    "authenticated_routes": proposal.get("authenticated_routes", [])}
        finally:
            browser.close()
