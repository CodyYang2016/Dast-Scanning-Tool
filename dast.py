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
import sys
from datetime import datetime, timezone
from pathlib import Path

from authoring import appconfig

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

_DEFAULT_ZAP = "http://localhost:8080"


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


def _discover(args, path) -> int:
    """Have a model propose the auth block, verify it live, and write the config.

    The proposal is only ever a suggestion: a proof is written into the config after it has
    been observed to hold while logged in and to fail while logged out. If none survives,
    this fails loudly and leaves the operator the skeleton rather than a config that looks
    finished and is not.
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
              f"`auth:` by hand; see docs/onboarding_a_new_application.md §3.", file=sys.stderr)
        return _write_skeleton(args, path)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(discover.render_config(
        app_id=args.app, base_url=args.base_url, login_url=args.login_url,
        steps=found["steps"], proof=found["proof"],
        authenticated_routes=found.get("authenticated_routes", []), model=found["model"]))
    print(f"\nwrote {path.relative_to(ROOT)}")
    print(f"  login:  {len(found['steps'])} steps against {args.login_url}")
    print(f"  proof:  {json.dumps(found['proof'])}")
    print(f"          verified: holds when logged in, fails when logged out")
    print(f"\nreview it, then: dast author {args.app}")
    return 0


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


def cmd_onboard(args) -> int:
    path = appconfig.app_config_path(args.app)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    if args.discover:
        return _discover(args, path)
    return _write_skeleton(args, path)


# ---- author: trace -> bundle -------------------------------------------------------------

def cmd_author(args) -> int:
    from authoring import generate as generate_mod
    from authoring import record as record_mod
    from authoring import validate as validate_mod

    config = appconfig.load_app_config(args.app)
    base_url = appconfig.base_url(config)
    traced, bundle = trace_dir(args.app), bundle_dir(args.app)

    if args.explore:
        from authoring import explore as explore_mod
        from authoring import seed as seed_mod
        rc = seed_mod.main(["--app", args.app, "--zap-proxy", args.zap_proxy, "--assisted"])
        if rc:
            return rc
        # Everything explore needs — scope, seeded session, entry points, budgets — comes
        # from app.yaml; --seed remains for a hand-written legacy bundle.
        rc = explore_mod.main(["--app", args.app,
                               *(["--seed", args.seed] if args.seed else []),
                               "--zap-proxy", args.zap_proxy, "--out-dir", str(traced),
                               "--max-pages", str(appconfig.max_pages(config, 30)),
                               *(["--no-llm"] if args.no_llm else []),
                               *(["--headed"] if args.headed else [])])
    else:
        rc = record_mod.main(["--app", args.app, "--zap-proxy", args.zap_proxy,
                              "--out-dir", str(traced),
                              *(["--headed"] if args.headed else [])])
    if rc:
        return rc

    trace = json.loads((traced / "trace.json").read_text())
    summary = generate_mod.generate(trace, str(bundle), config, use_llm=not args.no_llm)
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
        "--evidence-dir", str(run_dir),
        "--records-out", str(run_dir / "records.json"),
        "--coverage-out", str(run_dir / "coverage.json"),
    ])
    print(f"\nscan artifacts: {run_dir.relative_to(ROOT)} — next: dast report {args.app}")
    return rc


# ---- report ------------------------------------------------------------------------------

def cmd_report(args) -> int:
    from detections import lifecycle_diff, sarif_export

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
    sarif = run_dir / "results.sarif"
    rc = sarif_export.main([str(labeled), "--app-id", args.app,
                            "--driver-version", args.driver_version, "-o", str(sarif)])
    if rc:
        return rc
    print(f"SARIF: {sarif.relative_to(ROOT)}")

    if args.upload:
        from detections import github_upload
        if not (args.owner and args.repo):
            print("--upload needs --owner and --repo", file=sys.stderr)
            return 2
        return github_upload.main([str(sarif), "--owner", args.owner, "--repo", args.repo,
                                   "--ref", args.ref])
    return 0


def cmd_explain(args) -> int:
    """Why did findings disappear between the last two scans? (W6-9)"""
    from detections import explain as explain_mod

    runs = sorted(scans_dir(args.app).iterdir()) if scans_dir(args.app).is_dir() else []
    runs = [r for r in runs if (r / "records.json").exists()]
    if len(runs) < 2:
        print(f"need two scans to compare; {args.app} has {len(runs)}", file=sys.stderr)
        return 2
    prev, cur = runs[-2], runs[-1]

    def _load(run, name):
        path = run / name
        return json.loads(path.read_text()) if path.exists() else {}

    out = explain_mod.explain_disappearance(
        _load(prev, "records.json"), _load(cur, "records.json"),
        _load(cur, "coverage.json"), _load(prev, "coverage.json"))
    print(f"comparing {prev.name} -> {cur.name}")
    if not out:
        print("nothing disappeared.")
        return 0
    print("what happened to the findings that are gone:",
          ", ".join(f"{k}={v}" for k, v in sorted(explain_mod.summarize(out).items())))
    shown = [e for e in out if e["severity"] in ("critical", "high", "medium")] or out
    for e in shown[:args.limit]:
        print(f"\n  [{e['severity']}] {e['title']} -> {e['endpoint']}")
        print(f"    {e['reason']}: {e['detail']}")
    if len(shown) > args.limit:
        print(f"\n  … and {len(shown) - args.limit} more (use --limit)")
    return 0


# ---- argument surface ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dast", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("app", help="App id (security/dast/<app>/app.yaml)")
        return sp

    o = common(sub.add_parser("onboard", help="write an app.yaml skeleton to fill in"))
    o.add_argument("--base-url", required=True, help="Target as ZAP resolves it")
    o.add_argument("--auth", default="form", choices=["form", "seeded"])
    o.add_argument("--environment-class", default="dev", choices=["dev", "test", "staging"])
    o.add_argument("--force", action="store_true", help="overwrite an existing config")
    o.add_argument("--discover", action="store_true",
                   help="have a model read the login page and propose the auth block, then "
                        "verify it by logging in — needs <APP>_USER/<APP>_PASS and a model key")
    o.add_argument("--login-url", default="/login", help="Login page path (with --discover)")
    o.add_argument("--zap-proxy", default=None, help="Discover through ZAP (matches the scan)")
    o.add_argument("--model", default="claude-opus-4-8")
    o.add_argument("--headed", action="store_true", help="Watch the verification log in")
    o.set_defaults(func=cmd_onboard)

    a = common(sub.add_parser("author", help="record (or seed+explore) -> generate -> validate"))
    a.add_argument("--explore", action="store_true",
                   help="seed a session and explore instead of the recorded walk")
    a.add_argument("--seed", default=None, help="seed config (defaults to the app dir's seed.json)")
    a.add_argument("--zap-proxy", default=_DEFAULT_ZAP)
    a.add_argument("--headed", action="store_true")
    a.add_argument("--no-llm", action="store_true", help="force the deterministic path")
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
    r.add_argument("--ref", default="refs/heads/main")
    r.set_defaults(func=cmd_report)

    e = common(sub.add_parser("explain",
                              help="why did findings disappear between the last two scans?"))
    e.add_argument("--limit", type=int, default=10)
    e.set_defaults(func=cmd_explain)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
