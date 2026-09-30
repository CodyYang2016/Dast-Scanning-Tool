"""dast — one command per intent.

    dast onboard <app> --base-url URL     write the app.yaml skeleton to fill in
    dast author  <app>                    record (or seed+explore) -> generate -> validate
    dast scan    <app>                    preflight -> replay -> ZAP -> normalize -> coverage
    dast report  <app>                    lifecycle diff -> SARIF -> (optionally) GitHub

The remediation plan's rule is "config in, contracts out, one command, one artifact"
(docs/dast_poc_remediation_plan.md §1). This module is the "one command" half: a thin facade
that composes the existing module entry points with the arguments they already accept, so a
command run by hand behaves identically to the same step run through here — nothing is
reimplemented, and the underlying CLIs stay the documented interface for anything unusual.

Artifacts land in one predictable place per application:

    out/<app>/authoring/        trace/ and bundle/ from `author`
    out/<app>/scans/<scan_id>/  records, coverage, gate, SARIF from `scan` and `report`
    out/<app>/state.json        lifecycle state across scans

This module names no application: everything app-specific comes from
security/dast/<app>/app.yaml (enforced by tests/test_no_app_specifics.py).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from authoring import appconfig, llm_backend

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

_DEFAULT_ZAP = "http://localhost:8080"


def resolve_out(config_dir=None, cli=None, env=None) -> Path:
    """Resolve --out > DAST_OUT > app.yaml output.dir > repository out/."""
    chosen = next((value for value in (cli, env, config_dir) if value is not None), None)
    if chosen is None:
        return ROOT / "out"
    expanded = os.path.expanduser(os.path.expandvars(str(chosen))).strip()
    if not expanded:
        raise ValueError("output directory is empty; remove the setting to use the default")
    path = Path(expanded)
    return path if path.is_absolute() else ROOT / path


def paths_for(args) -> Path:
    config_dir = None
    try:
        config_dir = appconfig.output_dir(appconfig.load_app_config(args.app))
    except Exception:
        pass
    return resolve_out(config_dir, getattr(args, "out", None), os.environ.get("DAST_OUT"))


def default_category(app_id: str) -> str:
    return f"dast/{app_id}"


# ---- where things live (one predictable layout per app) ---------------------------------

def authoring_dir(app_id: str) -> Path:
    return OUT / app_id / "authoring"


def bundle_dir(app_id: str) -> Path:
    """The generated scan bundle: flow.py, scope.json, journey.json and the rest."""
    return authoring_dir(app_id) / "bundle"


def trace_dir(app_id: str) -> Path:
    return authoring_dir(app_id) / "trace"


def scans_dir(app_id: str) -> Path:
    return OUT / app_id / "scans"


def state_path(app_id: str) -> Path:
    return OUT / app_id / "state.json"


def new_scan_dir(app_id: str) -> Path:
    d = scans_dir(app_id) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d.mkdir(parents=True, exist_ok=True)
    return d


def latest_scan_dir(app_id: str) -> Path | None:
    """Most recent scan directory, or None when the app has never been scanned."""
    if not scans_dir(app_id).is_dir():
        return None
    runs = sorted(p for p in scans_dir(app_id).iterdir() if p.is_dir())
    return runs[-1] if runs else None


# ---- onboard ----------------------------------------------------------------------------

SKELETON = """\
# {app_id} — everything this tool needs to know about the application.
#
# Onboarding is this file: nothing under authoring/ or runner/ may name an application.
# Validated against contracts/app.schema.json — an unknown key is an error, not a typo that
# gets ignored. Fill in every TODO, then run:  dast author {app_id}

app_id: {app_id}
environment_class: {environment_class}   # dev | test | staging — never prod (preflight refuses it)
base_url: {base_url}          # the target exactly as ZAP resolves it

scope:
  allow: [{host}]             # hosts that may be reached AND attacked
  deny: []                    # wildcard patterns, e.g. "*.analytics.example"
  avoid_actions: [logout, delete, purchase, change-password]

auth:
  mode: {mode}
  login_url: /login           # TODO the login page
  # Either this three-field shorthand...
  selectors:
    email: "input[name=username]"     # TODO the identifier field (email, username, employee id)
    password: "input[type=password]"  # TODO
    submit: "button[type=submit]"     # TODO
  # ...or, for a username field, a two-page login or a keypress, replace `selectors` with:
  # steps:
  #   - {{action: fill, selector: "input[name=user]", value: identifier}}
  #   - {{action: click, selector: "#next"}}
  #   - {{action: wait_for, selector: "input[name=pass]"}}
  #   - {{action: fill, selector: "input[name=pass]", value: secret}}
  #   - {{action: press, selector: "input[name=pass]", key: Enter}}

  # How we PROVE the login worked. Exactly one, no default: an unproven session is never
  # scanned. Pick the one that matches the application.
  proof:
    route:                    # cookie session: an authenticated page answers and does not bounce
      path: /                 # TODO an authenticated route
      forbid_redirect_to: login
  #  js: "window.localStorage.getItem('token')"   # SPA with a token in web storage
  #  selector: "nav a[href='/logout']"            # an element only present when logged in

  identity: provisioned       # provisioned = a test account already exists (the usual case)
  credentials:                # environment variable NAMES; the values never live in this file
    email_env: {app_env}_USER
    password_env: {app_env}_PASS
  storage_state: .secrets/{app_id}-storageState.json

ui:
  dismiss_selectors: []       # cookie banners / modals covering the login form, if any

record:
  authenticated_routes: []    # TODO routes to visit after login so the app shows its surface

# api:
#   patterns: ["/api/", "/rest/"]    # what counts as an API call; omit for a server-rendered app

explore:
  seed_routes: []             # TODO entry points for the exploration loop
  safe_forms: []              # targets where a state-changing submit is allowed (empty = read-only)
  budgets:
    max_pages: 12
"""


def cmd_onboard(args) -> int:
    path = appconfig.app_config_path(args.app)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    if getattr(args, "discover", False):
        return _discover(args, path)
    return _write_skeleton(args, path)


def _write_skeleton(args, path) -> int:
    host = args.base_url.split("://")[-1].split("/")[0].split(":")[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SKELETON.format(
        app_id=args.app, base_url=args.base_url, host=host, mode=args.auth,
        environment_class=args.environment_class,
        app_env=args.app.replace("-", "_").upper(),
    ))
    print(f"wrote {path.relative_to(ROOT)}")
    try:
        appconfig.load_app_config(args.app)
        print("config is already schema-valid; fill in the TODOs, then: "
              f"dast author {args.app}")
    except Exception as exc:
        print(f"fill in the TODOs — the skeleton is not valid yet: {exc}".split("\n")[0])
    return 0


def _discover(args, path) -> int:
    """Have a model propose the auth block, verify it live, and write the config.

    A proof is written only after it has been observed to hold while logged in AND to fail
    while logged out. If none survives, this leaves the skeleton rather than a config that
    looks finished and is not. The model call goes through llm_backend, so it uses the
    approved Copilot CLI inside Nationwide (LLM_PROVIDER=copilot) or the Anthropic API.
    """
    import os

    from authoring import discover

    env = args.app.replace("-", "_").upper()
    identifier = os.environ.get(f"{env}_USER") or os.environ.get("AUTH_EMAIL")
    secret = os.environ.get(f"{env}_PASS") or os.environ.get("AUTH_PASSWORD")
    if not (identifier and secret):
        print(f"--discover verifies the login by performing it, so it needs credentials: "
              f"export {env}_USER and {env}_PASS", file=sys.stderr)
        return 2

    print(f"reading {args.base_url}{args.login_url} …")
    try:
        found = discover.discover_auth(args.base_url, args.login_url, identifier, secret,
                                       model=args.model, zap_proxy=args.zap_proxy,
                                       headless=not args.headed)
    except discover.DiscoveryFailed as exc:
        print(f"\ndiscovery failed: {exc}\n\nWriting the skeleton instead — fill in "
              f"`auth:` by hand.", file=sys.stderr)
        return _write_skeleton(args, path)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(discover.render_config(
        app_id=args.app, base_url=args.base_url, login_url=args.login_url,
        steps=found["steps"], proof=found["proof"],
        authenticated_routes=found.get("authenticated_routes", []), model=found["model"]))
    print(f"\nwrote {path.relative_to(ROOT)}")
    print(f"  login:  {len(found['steps'])} steps against {args.login_url}")
    print(f"  proof:  {json.dumps(found['proof'])}")
    print("          verified: holds when logged in, fails when logged out")
    print(f"\nreview it, then: dast author {args.app}")
    return 0


# ---- author: trace -> bundle -------------------------------------------------------------

def explore_inputs(app_id: str, config: dict, seed_override: str | None) -> tuple[Path, Path]:
    """Locate the exploration seed + scope, deriving either from app.yaml when not committed.

    Every value they hold is already in app.yaml, so an application that ships only a config
    is authorable — onboarding stays a config change (see authoring/appconfig.py). A committed
    file always wins, so an app that needs a hand-tuned scope or extra seed routes keeps it.
    """
    app_dir = appconfig.app_config_path(app_id).parent
    derived = authoring_dir(app_id) / "derived"

    scope_file = app_dir / "scope.json"
    if not scope_file.is_file():
        derived.mkdir(parents=True, exist_ok=True)
        scope_file = derived / "scope.json"
        scope_file.write_text(json.dumps(appconfig.scope_from_config(config), indent=2) + "\n")

    if seed_override:
        return Path(seed_override), scope_file
    seed_file = app_dir / "seed.json"
    if not seed_file.is_file():
        derived.mkdir(parents=True, exist_ok=True)
        seed = appconfig.seed_from_config(config)
        seed["target"]["scope_file"] = str(scope_file)
        seed["exploration"] = {"max_pages": appconfig.max_pages(config)}
        seed_file = derived / "seed.json"
        seed_file.write_text(json.dumps(seed, indent=2) + "\n")
    return seed_file, scope_file


def cmd_author(args) -> int:
    from authoring import generate as generate_mod
    from authoring import record as record_mod
    from authoring import validate as validate_mod

    if args.require_llm and args.no_llm:  # before seeding a session or sending any traffic
        print("--require-llm contradicts --no-llm", file=sys.stderr)
        return 2

    global OUT
    OUT = paths_for(args)
    config = appconfig.load_app_config(args.app)
    base_url = appconfig.base_url(config)
    traced, bundle = trace_dir(args.app), bundle_dir(args.app)

    if args.explore:
        from authoring import explore as explore_mod
        from authoring import seed as seed_mod
        rc = seed_mod.main(["--app", args.app, "--zap-proxy", args.zap_proxy, "--assisted"])
        if rc:
            return rc
        seed_file, scope_file = explore_inputs(args.app, config, args.seed)
        rc = explore_mod.main(["--app", args.app, "--seed", str(seed_file),
            "--scope", str(scope_file),
            "--max-pages", str(appconfig.max_pages(config)),
            "--zap-proxy", args.zap_proxy, "--out-dir", str(traced),
            *(["--no-llm"] if args.no_llm else []),
            *(["--require-llm"] if args.require_llm else []),
            *(["--headed"] if args.headed else [])])
    else:
        rc = record_mod.main(["--app", args.app, "--zap-proxy", args.zap_proxy,
                              "--out-dir", str(traced),
                              *(["--headed"] if args.headed else [])])
    if rc:
        return rc

    trace = json.loads((traced / "trace.json").read_text())
    try:
        summary = generate_mod.generate(trace, str(bundle), config, use_llm=not args.no_llm,
                                        require_llm=args.require_llm)
    except llm_backend.LLMRequiredError as exc:
        print(f"AUTHOR ABORT: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(summary, indent=2))

    rc = validate_mod.main([
        "--plan", str(bundle / "journey.json"), "--scope", str(bundle / "scope.json"),
        "--flow", str(bundle / "flow.py"), "--base-url", base_url,
        "--zap-proxy", args.zap_proxy, "--report", str(authoring_dir(args.app) / "validation-report.json"),
        *(["--no-replay"] if args.no_replay else []),
    ])
    if rc == 0:
        print(f"\nbundle ready: {bundle.relative_to(ROOT)} — next: dast scan {args.app}")
    return rc


# ---- scan --------------------------------------------------------------------------------

def cmd_scan(args) -> int:
    from runner import main as runner_main

    global OUT
    OUT = paths_for(args)
    config = appconfig.load_app_config(args.app)
    bundle = bundle_dir(args.app)
    if not (bundle / "flow.py").exists():
        print(f"no bundle at {bundle.relative_to(ROOT)} — run: dast author {args.app}",
              file=sys.stderr)
        return 2
    run_dir = new_scan_dir(args.app)
    rc = runner_main.main([
        "--flow", str(bundle / "flow.py"), "--scope", str(bundle / "scope.json"),
        "--base-url", appconfig.base_url(config),
        "--zap-api", args.zap_api, "--zap-proxy", args.zap_proxy,
        "--records-out", str(run_dir / "records.json"),
        "--coverage-out", str(run_dir / "coverage.json"),
    ])
    print(f"\nscan artifacts: {run_dir.relative_to(ROOT)} — next: dast report {args.app}")
    return rc


# ---- report ------------------------------------------------------------------------------

def cmd_report(args) -> int:
    from detections import lifecycle_diff, sarif_export

    global OUT
    OUT = paths_for(args)

    run_dir = latest_scan_dir(args.app)
    if run_dir is None or not (run_dir / "records.json").exists():
        print(f"no scan to report on — run: dast scan {args.app}", file=sys.stderr)
        return 2

    labeled = run_dir / "labeled.json"
    rc = lifecycle_diff.main([str(run_dir / "records.json"), "--app-id", args.app,
                              "--state", str(state_path(args.app)),
                              "--coverage", str(run_dir / "coverage.json"),
                              "-o", str(labeled)])
    if rc:
        return rc
    counts: dict[str, int] = {}
    for rec in json.loads(labeled.read_text()):
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    print("lifecycle: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    # Coverage-aware publishing: the export drops `resolved` and carries `not_scanned`
    # forward, so GitHub never closes a finding this scan did not look for.
    config = appconfig.load_app_config(args.app)
    configured = appconfig.github_publish(config)
    owner = args.owner or os.environ.get("DAST_GH_OWNER") or configured.get("owner")
    repo = args.repo or os.environ.get("DAST_GH_REPO") or configured.get("repo")
    ref = args.ref or configured.get("ref") or "refs/heads/main"
    category = args.category or configured.get("category") or default_category(args.app)
    (run_dir / "settings.json").write_text(json.dumps({
        "output_dir": str(OUT),
        "github": {"owner": owner, "repo": repo, "ref": ref, "category": category},
    }, indent=2) + "\n")

    sarif = run_dir / "results.sarif"
    rc = sarif_export.main([str(labeled), "--app-id", args.app,
                            "--driver-version", args.driver_version,
                            "--category", category, "-o", str(sarif)])
    if rc:
        return rc
    print(f"SARIF: {sarif.relative_to(ROOT)}")

    if args.upload:
        from detections import github_upload
        if not (owner and repo):
            print("--upload needs --owner and --repo", file=sys.stderr)
            return 2
        return github_upload.main([str(sarif), "--owner", owner, "--repo", repo, "--ref", ref])
    return 0


def cmd_explain(args) -> int:
    from detections import explain
    global OUT
    OUT = paths_for(args)
    runs = sorted(p for p in scans_dir(args.app).iterdir()
                  if p.is_dir() and (p / "records.json").exists()) \
        if scans_dir(args.app).is_dir() else []
    if len(runs) < 2:
        print(f"need two scans to compare; {args.app} has {len(runs)}", file=sys.stderr)
        return 2
    previous, current = runs[-2], runs[-1]
    def load_json(directory: Path, name: str, default):
        path = directory / name
        return json.loads(path.read_text()) if path.exists() else default

    previous_records = load_json(previous, "records.json", [])
    current_records = load_json(current, "records.json", [])
    current_coverage = load_json(current, "coverage.json", {})
    previous_coverage = load_json(previous, "coverage.json", {})
    explanations = explain.explain_disappearance(
        previous_records, current_records, current_coverage, previous_coverage)
    print(f"comparing {previous.name} -> {current.name}")
    print("nothing disappeared." if not explanations else
          "what happened: " + ", ".join(f"{k}={v}" for k, v in
                                         sorted(explain.summarize(explanations).items())))
    for item in explanations[:args.limit]:
        print(f"  [{item['severity']}] {item['title']} -> {item['reason']}: {item['detail']}")
    return 0


# ---- argument surface ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dast", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("app", help="App id (security/dast/<app>/app.yaml)")
        sp.add_argument("--out", default=None, help="Artifact root; overrides DAST_OUT and app.yaml")
        return sp

    o = common(sub.add_parser("onboard", help="write an app.yaml skeleton to fill in"))
    o.add_argument("--base-url", required=True, help="Target as ZAP resolves it")
    o.add_argument("--auth", default="form", choices=["form", "seeded"])
    o.add_argument("--environment-class", default="dev", choices=["dev", "test", "staging"])
    o.add_argument("--force", action="store_true", help="overwrite an existing config")
    o.add_argument("--discover", action="store_true",
                   help="have a model propose the auth block and verify it live (needs creds)")
    o.add_argument("--login-url", default="/login", help="Login page path (with --discover)")
    o.add_argument("--zap-proxy", default=None, help="Discover through ZAP (matches the scan)")
    o.add_argument("--model", default=None,
                   help="LLM model id; defaults to the LLM_PROVIDER's default (Anthropic or Copilot)")
    o.add_argument("--headed", action="store_true", help="show the browser during discovery")
    o.set_defaults(func=cmd_onboard)

    a = common(sub.add_parser("author", help="record (or seed+explore) -> generate -> validate"))
    a.add_argument("--explore", action="store_true",
                   help="seed a session and explore instead of the recorded walk")
    a.add_argument("--seed", default=None, help="seed config (defaults to the app dir's seed.json)")
    a.add_argument("--zap-proxy", default=_DEFAULT_ZAP)
    a.add_argument("--headed", action="store_true")
    a.add_argument("--no-llm", action="store_true", help="force the deterministic path")
    a.add_argument("--require-llm", action="store_true",
                   help="fail loudly instead of falling back when the LLM path is unavailable")
    a.add_argument("--no-replay", action="store_true", help="skip validate's live auth replay")
    a.set_defaults(func=cmd_author)

    s = common(sub.add_parser("scan", help="run the generated bundle through the scanner"))
    s.add_argument("--zap-api", default=_DEFAULT_ZAP)
    s.add_argument("--zap-proxy", default=_DEFAULT_ZAP)
    s.set_defaults(func=cmd_scan)

    r = common(sub.add_parser("report", help="lifecycle diff -> SARIF -> (optionally) GitHub"))
    r.add_argument("--driver-version", default="ZAP 2.17.0")
    r.add_argument("--upload", action="store_true", help="publish to GitHub code scanning")
    r.add_argument("--owner", default=None)
    r.add_argument("--repo", default=None)
    r.add_argument("--ref", default=None)
    r.add_argument("--category", default=None)
    r.set_defaults(func=cmd_report)

    e = common(sub.add_parser("explain", help="explain disappeared findings"))
    e.add_argument("--limit", type=int, default=10)
    e.set_defaults(func=cmd_explain)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
