"""End-to-end runner — the Phase 1 "minimum viable scanner" gate.

Chains the whole safe-scan loop into one command:

    preflight (FR-S3/NFR-2) -> fresh ZAP session -> authenticated replay through the ZAP
    proxy (FR-S1/R2) with the scope guard active (FR-S4/NFR-4) -> bounded active scan
    (FR-S1/S2) -> normalize into detection records (FR-N1).

Exit code is the gate: 0 only if the scan authenticated, stayed in scope, and produced at
least one high/medium detection. See docs/junior_engineer/runner_design.md and the demo
plan's Phase 1 gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from detections.normalizer import normalize, write_json_array
from runner import coverage as coverage_capture
from runner import evidence
from runner.preflight import PreflightError, preflight
from runner.replay import SessionDeadError, load_flow, replay, replay_seeded
from runner import zapapi
from runner import session_refresh
from runner.reset import ResetError
from runner.scan import (ScanScopeError, ZapUnavailableError, add_anti_csrf_tokens,
                         dom_xss_pass, import_openapi, pause_all,
                         resume_all, load_policy, new_session,
                        exclusion_regexes as scan_exclusions,
                         resolved_policy, scan)
from runner.scope_guard import ScopeViolation

_DEFAULT_SCHEMA = "contracts/scope.schema.json"


def _scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _zap_can_reach(zap_api: str, target: str, timeout: float = 10.0) -> bool:
    """True if ZAP can fetch the target (checked THROUGH ZAP via accessUrl).

    The runner reaches the target only via ZAP (ZAP resolves the host, e.g. `juice` on the
    docker network), so readiness must be checked from ZAP's perspective — not by the runner
    polling the target directly, which fails on the host where `juice` doesn't resolve.
    """
    try:
        return bool(zapapi.call(zap_api, "/JSON/core/action/accessUrl/",
                                {"url": target, "followRedirects": "true"}, timeout).get("accessUrl"))
    except zapapi.ZapAuthError:
        raise                        # a wrong key is not "not ready yet" — say so immediately
    except Exception:
        return False


def _zap_up(zap_api: str) -> bool:
    """Is ZAP's API answering? Through the keyed client: an unkeyed probe of a keyed ZAP is
    refused, which used to read as "ZAP is down" and wait out the whole timeout."""
    try:
        zapapi.call(zap_api, "/JSON/core/view/version/", timeout=3.0)
        return True
    except zapapi.ZapAuthError:
        raise
    except Exception:
        return False


def wait_ready(zap_api: str, base_url: str, timeout: float = 120.0, interval: float = 2.0) -> None:
    """Poll until the ZAP API is up AND ZAP can reach the target (robust start ordering).

    Works on the host and in compose alike, because both reach ZAP and it's ZAP that resolves
    the target host. Returns immediately when ready; raises after `timeout`.
    """
    end = time.monotonic() + timeout
    while True:
        if _zap_up(zap_api) and _zap_can_reach(zap_api, base_url):
            return
        if time.monotonic() >= end:
            raise RuntimeError(f"services not ready within {timeout:.0f}s (zap={zap_api}, target={base_url})")
        time.sleep(interval)


def resolve_max_scan_min(cli_value: int | None, policy: dict | None, default: int = 4) -> int:
    """Wall-clock bound for the active scan: an explicit flag, else the bundle's policy budget,
    else the historical default. A truncated scan is not a clean bill of health, so whichever
    wins is recorded in the coverage artifact."""
    if cli_value is not None:
        return cli_value
    if policy and policy.get("max_scan_min"):
        return int(policy["max_scan_min"])
    return default


def resolve_max_rule_min(cli_value: int | None, policy: dict | None, default: int = 1) -> int:
    """Per-rule bound for the active scan, resolved like max_scan_min: an explicit value, else
    the bundle's policy budget, else the historical default.

    Separate from the wall-clock budget because they fail differently: the scan budget stops
    the whole scan, this one stops ONE rule and leaves the rest running, which is why a
    truncated rule is recorded individually in coverage (W6-2).
    """
    if cli_value is not None:
        return cli_value
    if policy and policy.get("max_rule_min"):
        return int(policy["max_rule_min"])
    return default


def bundle_app_config(scope_path: str) -> dict | None:
    """The app.yaml for the application this bundle belongs to, if it can be found.

    The bundle carries app_id; the config lives at security/dast/<app_id>/app.yaml. It is
    optional — a hand-written bundle has none — and supplies the state a scan depends on:
    cookies to seed and probes to fingerprint (W6-8).
    """
    try:
        from authoring import appconfig
        scope = json.loads(Path(scope_path).read_text())
        return appconfig.load_app_config(scope["app_id"])
    except Exception:
        return None


def bundle_policy(scope_path: str) -> dict | None:
    """The `zap-policy.yaml` that `generate` emitted beside this scope, if any (W2-4).

    Closing the loop the demo script used to disclose as a gap: the policy was generated and
    consumed by nobody, so scan depth was whatever the daemon happened to be set to.
    """
    return load_policy(str(Path(scope_path).resolve().parent / "zap-policy.yaml"))


def resolve_evidence_dir(scope_path: str, evidence_dir: str | None, scan_id: str) -> Path:
    """Where this scan's evidence goes: `<evidence_dir>/evidence` when given, else the app
    directory (the historical layout, kept so existing invocations are unchanged).

    An explicit directory keeps a scan's HAR and screenshots with its records and coverage
    instead of accumulating inside the reusable bundle (FR-E1).
    """
    if evidence_dir:
        return Path(evidence_dir) / "evidence"
    return Path(scope_path).resolve().parent / "evidence" / scan_id


def evidence_prefix(evidence_dir: str | None, scan_id: str) -> str:
    """The evidence directory as a records-relative path — derived from the SAME rule as
    resolve_evidence_dir, so a recorded path always points at where the file is.

    With an explicit directory (how `dast scan` runs) evidence sits beside the records in
    `evidence/`; in the legacy layout it sits under the app directory as `evidence/<scan_id>`.
    Recording the legacy form for both once left every exchange_path pointing at a directory that
    never existed.
    """
    return "evidence" if evidence_dir else f"evidence/{scan_id}"


def evaluate_gate(authenticated: bool, scope_ok: bool, records: list[dict], coverage=None,
                  expect_findings: bool = False) -> dict:
    """The scan stage's gate. Pure/testable.

    The default is a HEALTH gate: the scan authenticated, stayed in scope, and tested at least one
    route. It used to require a high/medium finding, which suits a demo against a deliberately
    vulnerable app and makes a CLEAN application fail every pipeline (W3-2). That condition now
    applies only with `expect_findings`, for self-tests where zero findings means the scanner is
    broken. Whether findings should fail a build is decided later, by the report stage's policy
    gate, which can see which findings are new.

    "Tested at least one route" is the W6-13 lesson: a login exclusion once excluded all of Juice
    Shop and the old gate passed on passive findings alone. Unknown coverage fails closed.
    """
    has_high_or_medium = any(r["severity"] in ("critical", "high", "medium") for r in records)
    routes_tested = len((coverage or {}).get("routes") or [])
    # W5-1: a session lost mid-scan means everything after that point attacked a logged-out
    # app. Unknown (no usable probe) does not fail the gate, but it is reported as unknown.
    # W5-2: a loss re-established by logging in again still counts against the scan — it is
    # degraded, and lifecycle_diff will not resolve findings from it — but it is not unhealthy.
    session = (coverage or {}).get("session") or {}
    session_alive = session.get("alive_at_end", session.get("alive_throughout"))
    healthy = (bool(authenticated) and bool(scope_ok) and routes_tested > 0
               and session_alive is not False)
    return {
        "mode": "expect-findings" if expect_findings else "health",
        "authenticated": bool(authenticated),
        "scope_ok": bool(scope_ok),
        "routes_tested": routes_tested,
        "session_alive": session_alive,
        "session_degraded": session.get("alive_throughout") is False,
        "has_high_or_medium": has_high_or_medium,
        "detections": len(records),
        "passed": healthy and (has_high_or_medium or not expect_findings),
    }


def _dom_cfg(app_cfg: dict) -> dict:
    from authoring import appconfig
    return appconfig.dom_xss(app_cfg)


def declared_surface(source: str, zap_api: str, fetch_text=None) -> dict:
    """The routes an OpenAPI/Swagger spec declares (W6-4), for the coverage denominator. A URL
    is fetched through ZAP, which is what resolves the target's host."""
    from detections import inventory
    if source.startswith(("http://", "https://")):
        text = (fetch_text or (lambda u: coverage_capture.fetch_probe_full(zap_api, u)[1]))(source)
    else:
        p = Path(source)
        text = (p if p.is_absolute() else Path(__file__).resolve().parent.parent / p).read_text()
    ops = inventory.from_openapi(inventory.parse_spec(text))
    return {"source": "openapi", "spec": source, "operations": len(ops),
            "routes": sorted({route for _m, route in ops})}


def with_exclusions(scope: dict, app_cfg: dict | None) -> dict:
    """The scope with app.yaml's `scope.exclude` merged in, so a bundle generated before an
    exclusion was added still honours it in the browser (W4-5). app.yaml is the source of truth."""
    if not app_cfg:
        return scope
    from authoring import appconfig
    paths = list(scope.get("exclude_paths") or [])
    paths += [p for p in appconfig.exclude_paths(app_cfg) if p not in paths]
    return {**scope, "exclude_paths": paths}


def refuse_zap_port(base_url: str, zap_proxy: str) -> None:
    """Refuse a target on the port ZAP itself listens on (W4-7).

    ZAP bound to 0.0.0.0 treats a proxied request arriving for its own port as a call to its
    API, whatever the host. Measured onboarding WebGoat on 8080: every request was answered by
    ZAP (`No enum constant …Format.WEBGOAT`), the application never saw one, and the scan
    "succeeded" against nothing. Refusing here turns that silence into an error.
    """
    from runner.scope_guard import _parts
    target, zap = _parts(base_url), _parts(zap_proxy)
    if target and zap and target[2] == zap[2]:
        raise ScanScopeError(
            f"refusing to scan {base_url!r}: it is on port {target[2]}, the port ZAP listens on "
            f"({zap_proxy}). ZAP would answer every request as its own API and the application "
            f"would never be reached. Move the application or ZAP to another port.")


def _seed_ttl(scope_path) -> float:
    """The stored-session TTL from the bundle's app config, else the default (W5-3)."""
    cfg = bundle_app_config(scope_path)
    if cfg:
        from authoring import appconfig
        return appconfig.storage_state_ttl_hours(cfg)
    return 12.0


def run(scope_path, schema, flow_path, base_url, zap_api, zap_proxy,
        fresh=True, do_spider=True, max_scan_min=None, wait=True,
        storage_state=None, seed_routes=None, evidence_dir=None):
    """Execute the full loop. Returns (scope, replay_result, guard, records, scan_id, coverage).

    `coverage` is the (route x rule) surface this scan exercised (R2), for the lifecycle diff.
    If `storage_state` is given, replay a seeded session (Phase A) instead of the login flow,
    falling back to the hand-authored flow if the seeded session is dead (fail closed)."""
    scope = preflight(scope_path, schema)              # safety layer 1 (offline; fail fast)
    refuse_zap_port(base_url, zap_proxy)               # W4-7: ZAP would answer as its API
    if wait:
        wait_ready(zap_api, base_url)                  # tolerate container startup ordering
    # Is ZAP's API open to anyone who can reach it (W4-4)? Recorded for every scan; refused for a
    # shared test/staging environment, where it would hand the scanner — and every request and
    # session cookie it has captured — to anyone on that network.
    zap_open = zapapi.is_open(zap_api)
    zapapi.require_closed_for(scope["environment_class"], zap_open)
    if zap_open:
        print("WARNING: ZAP's API answers without a key. Acceptable for a disposable dev "
              "container only; start ZAP with -config api.key=<secret> and export ZAP_API_KEY.",
              file=sys.stderr)
    scan_id = _scan_id()
    ev_dir = resolve_evidence_dir(scope_path, evidence_dir, scan_id)   # FR-E1
    ev_dir.mkdir(parents=True, exist_ok=True)

    app_cfg = bundle_app_config(scope_path)
    scope = with_exclusions(scope, app_cfg)          # the browser honours scope.exclude too
    cookies = probes = None
    exclusions: list[str] = []
    throttle: dict = {}
    if app_cfg:
        from authoring import appconfig
        cookies = appconfig.scan_cookies(app_cfg)
        probes = appconfig.state_probes(app_cfg)
        throttle = appconfig.scan_throttle(app_cfg)
        # What exploration already refuses, the scanner must refuse too: attacking the login
        # form or a database-reset page changes the application underneath its own scan.
        exclusions = scan_exclusions(appconfig.avoid_actions(app_cfg),
                                     appconfig.login_url(app_cfg),
                                     paths=appconfig.exclude_paths(app_cfg))

    # The scan's own session, collected from the browser so the state probes can see the app
    # as the scan saw it. Never written to an artifact — only used to fetch the probes.
    live_session: dict = {}
    # W6-1: a disposable app's own data reset, BEFORE the fresh ZAP session so its traffic is
    # not part of what gets attacked. A reset that does not verify stops the scan here.
    reset_result = None
    if app_cfg and appconfig.scan_reset(app_cfg):
        from runner.reset import browser_driver, run_reset
        env_names = appconfig.credential_env_names(app_cfg)
        reset_result = run_reset(
            appconfig.scan_reset(app_cfg), base_url,
            drive=browser_driver(scope, zap_proxy, os.environ.get(env_names[0], ""),
                                 os.environ.get(env_names[1], "")),
            fetch=lambda url: coverage_capture.fetch_probe_full(
                zap_api, url, None, allow=scope["fqdn_allow_list"]))
    if fresh:
        new_session(zap_api)                           # clean per-scan session
    if storage_state:
        try:
            result, guard = replay_seeded(scope, base_url, zap_proxy, storage_state,
                                          seed_routes or [], evidence_dir=str(ev_dir),
                                          on_session=live_session.update)
        except SessionDeadError as exc:
            print(f"SEEDED SESSION DEAD ({exc}); falling back to hand-authored flow",
                  file=sys.stderr)
            flow = load_flow(flow_path)
            result, guard = replay(scope, flow, base_url, zap_proxy, evidence_dir=str(ev_dir),
                                   cookies=cookies, on_session=live_session.update)
    else:
        flow = load_flow(flow_path)
        result, guard = replay(scope, flow, base_url, zap_proxy, evidence_dir=str(ev_dir),
                               cookies=cookies, on_session=live_session.update)

    # Redact the HAR immediately after capture — before it can be published (hard requirement).
    har = ev_dir / "active-scan.har"
    if har.exists():
        evidence.redact_har_file(str(har))

    policy = bundle_policy(scope_path)
    max_scan_min = resolve_max_scan_min(max_scan_min, policy)
    max_rule_min = resolve_max_rule_min(None, policy)

    # The scan's session, assembled BEFORE the scan now: the liveness monitor needs it while ZAP
    # attacks, and the state probes need it afterwards.
    session = live_session or coverage_capture.session_cookies(storage_state, base_url)
    probe_jar = {**session, **(cookies or {})}

    # Is the scan still logged in while ZAP attacks (W5-1)? Probed through ZAP at most once a
    # minute during the active scan; a lost session fails the health gate.
    from runner.liveness import SessionMonitor, probe_path
    path = probe_path(app_cfg) if app_cfg else None
    monitor = None
    if not path:
        session_result = SessionMonitor.unavailable(
            "no scan.liveness_path, auth.proof.route or scan.state_probes to probe")
    elif not session:
        session_result = SessionMonitor.unavailable("no session cookies to probe with")
    else:
        from authoring import appconfig as _ac
        reauth_cfg = _ac.scan_reauth(app_cfg)
        bearer = _ac.bearer_from_cookie(app_cfg)

        def login_again() -> dict:
            """Log in again the way this scan first did (W5-2), then point ZAP's attacks at the
            new session. No evidence dir: the scan's own HAR must not be overwritten."""
            jar: dict = {}
            if storage_state:
                try:
                    replay_seeded(scope, base_url, zap_proxy, storage_state, seed_routes or [],
                                  on_session=jar.update)
                except SessionDeadError:
                    replay(scope, load_flow(flow_path), base_url, zap_proxy, cookies=cookies,
                           on_session=jar.update)
            else:
                replay(scope, load_flow(flow_path), base_url, zap_proxy, cookies=cookies,
                       on_session=jar.update)
            fresh_jar = {**jar, **(cookies or {})}
            session_refresh.install(zap_api, fresh_jar, bearer)
            print(f"SESSION RE-ESTABLISHED mid-scan ({len(jar)} session cookies)", file=sys.stderr)
            return fresh_jar

        monitor = SessionMonitor(
            base_url.rstrip("/") + path, probe_jar, login_path=_ac.login_url(app_cfg),
            fetch=lambda url, jar: coverage_capture.fetch_probe_full(
                zap_api, url, jar, allow=scope["fqdn_allow_list"]),
            reauth=login_again if reauth_cfg["enabled"] else None,
            pause=lambda: pause_all(zap_api), resume=lambda: resume_all(zap_api),
            max_reauth=reauth_cfg["max"])
        try:
            monitor.start()
        except Exception as exc:
            monitor = None
            session_result = SessionMonitor.unavailable(f"liveness probe failed to start: {exc}")

    declared = None
    if app_cfg:
        from authoring import appconfig as _ac
        add_anti_csrf_tokens(zap_api, _ac.anti_csrf_tokens(app_cfg))   # W5-2
        spec = _ac.openapi_spec(app_cfg)
        if spec:
            # W6-4: what SHOULD be tested — and, imported into ZAP, more for it to attack.
            try:
                declared = declared_surface(spec, zap_api)
                declared.update(import_openapi(zap_api, spec, base_url,
                                               os.environ.get("DAST_ZAP_SPEC_DIR")))
            except Exception as exc:
                declared = {"source": "openapi", "spec": spec, "error": f"{exc}"[:200]}
                print(f"WARNING: OpenAPI spec not used ({exc})", file=sys.stderr)
    try:
        report = scan(zap_api, base_url, scope["fqdn_allow_list"],
                      do_spider=do_spider, max_scan_min=max_scan_min, policy=policy,
                      max_rule_min=max_rule_min, throttle=throttle,
                      exclusions=exclusions, liveness=monitor)
        if monitor is not None:
            monitor.finish()             # always a check at the end; see SessionMonitor.finish
            session_result = monitor.result()
        # W6-3: DOM-XSS on its own, AFTER the main alerts are in hand — if it exhausts ZAP,
        # the pass is lost and recorded, not the scan.
        dom = None
        if app_cfg and _dom_cfg(app_cfg)["enabled"]:
            cfg = _dom_cfg(app_cfg)
            from authoring import appconfig as _ac2
            dom = dom_xss_pass(zap_api, base_url, scope["fqdn_allow_list"], exclusions,
                               max_min=cfg["max_min"], routes=cfg["routes"],
                               session=monitor.cookies if monitor is not None else probe_jar,
                               bearer_cookie=_ac2.bearer_from_cookie(app_cfg))
            seen = {a.get("id") for a in report["alerts"]}
            report["alerts"] += [a for a in dom["alerts"] if a.get("id") not in seen]
            if dom["record"]["error"]:
                print(f"WARNING: DOM-XSS pass failed ({dom['record']['error']}); the main "
                      f"scan's results are kept", file=sys.stderr)
    finally:
        session_refresh.remove(zap_api)  # only present if a re-login installed it
    records = list(normalize(report["alerts"], scope["app_id"], scan_id))
    # Reference the scan's evidence from each record (FR-E1).
    prefix = evidence_prefix(evidence_dir, scan_id)
    relpath = f"{prefix}/active-scan.har"
    for r in records:
        r["evidence_path"] = relpath
    # The request and response behind each high/medium finding (W1-3), fetched NOW: the next
    # scan starts a fresh ZAP session and they are gone. Redacted before anything is written.
    from runner import exchange
    exchange_counts = exchange.attach(
        report["alerts"], records, ev_dir, prefix,
        fetch=lambda message_id: exchange.fetch_message(zap_api, message_id))
    # Capture the (route x rule) surface this scan exercised, for the coverage-aware diff (R2).
    # Probes carry the scan's own session: without it they see the login page, and a digest of
    # the login page is the same whatever changed behind it (measured: sha256("") twice over).
    coverage = coverage_capture.capture(zap_api, base_url, scan_id=report.get("ascan_id"),
                                        probes=probes, cookies=probe_jar,
                                        authenticated=bool(session),
                                        excluded=report.get("exclusions"))
    # Pin the policy that produced this coverage, so a later diff can tell "we fixed it" from
    # "we scanned it less hard this time" (R2).
    coverage["policy"] = resolved_policy(policy, max_scan_min, max_rule_min, throttle)
    # Recorded with what the scan did, so a missing reproduction is explained, not mysterious.
    coverage["exchanges"] = exchange_counts
    coverage["zap_api_open"] = zap_open
    coverage["zap_context"] = report.get("context")
    coverage["session"] = session_result
    if declared is not None:
        coverage["declared"] = declared
    if dom is not None:
        coverage["dom_xss"] = dom["record"]
    if reset_result is not None:
        coverage["reset"] = reset_result
    return scope, result, guard, records, scan_id, coverage


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="End-to-end DAST runner (Phase 1 gate).")
    p.add_argument("--scope", required=True, help="App scope.json")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--flow", required=True, help="Hand-authored flow.py (also the seeded-session fallback)")
    p.add_argument("--seed", default=None,
                   help="Seed config (Phase A): replay a seeded storageState + seed routes instead "
                        "of the login flow; falls back to --flow if the session is dead")
    p.add_argument("--base-url", required=True, help="Target as ZAP resolves it")
    p.add_argument("--zap-api", default="http://localhost:8080")
    p.add_argument("--zap-proxy", default="http://localhost:8080")
    p.add_argument("--records-out", default=None, help="Write detection records here")
    p.add_argument("--evidence-dir", default=None,
                   help="Directory for this scan's evidence; defaults to the app directory")
    p.add_argument("--coverage-out", default=None,
                   help="Write this scan's (route x rule) coverage here for the lifecycle diff (R2)")
    p.add_argument("--no-spider", action="store_true")
    p.add_argument("--no-fresh", action="store_true", help="Do not reset the ZAP session first")
    p.add_argument("--no-wait", action="store_true", help="Do not wait for ZAP/target readiness")
    p.add_argument("--max-scan-min", type=int, default=None,
                   help="Override the bundle policy's scan budget (minutes)")
    p.add_argument("--expect-findings", action="store_true",
                   help="Self-test mode: also require >=1 high/medium finding. For deliberately "
                        "vulnerable targets, where finding nothing means the scanner is broken")
    args = p.parse_args(argv)

    storage_state = seed_routes = None
    if args.seed:
        from authoring.seed import load_seed
        seed_cfg = load_seed(args.seed)
        storage_state = seed_cfg["session"]["storage_state"]
        seed_routes = seed_cfg["seed_routes"]

    from runner.session_store import SessionStoreError, open_storage_state
    try:
        try:
            state_cm = open_storage_state(storage_state, ttl_hours=_seed_ttl(args.scope))
            state_path = state_cm.__enter__()
        except SessionStoreError as exc:
            if not exc.stale:
                raise
            # A stale session is a dead session: log in with the flow instead (never scan
            # unauthenticated), exactly as a SessionDeadError does.
            print(f"STORED SESSION NOT USED ({exc}); falling back to hand-authored flow",
                  file=sys.stderr)
            state_cm, state_path = None, None
        try:
            scope, result, guard, records, scan_id, coverage = run(
                args.scope, args.schema, args.flow, args.base_url, args.zap_api, args.zap_proxy,
                fresh=not args.no_fresh, do_spider=not args.no_spider,
                max_scan_min=args.max_scan_min, wait=not args.no_wait,
                storage_state=state_path, seed_routes=seed_routes,
                evidence_dir=args.evidence_dir,
            )
        finally:
            if state_cm is not None:
                state_cm.__exit__(None, None, None)
    except (PreflightError, ScanScopeError, ScopeViolation, ZapUnavailableError,
            zapapi.ZapAuthError, SessionStoreError, ResetError) as exc:
        print(f"RUNNER ABORT: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # scan._poll has already told ZAP to stop; say so, so nobody wonders if it is still going.
        print("\nRUNNER STOPPED at operator request — ZAP's spider and active scan were told to "
              "stop. Nothing was recorded for this run.", file=sys.stderr)
        return 130

    gate = evaluate_gate(result.get("authenticated"), guard.ok, records, coverage,
                         expect_findings=args.expect_findings)
    coverage["health_gate"] = gate      # kept with the scan, for the report's summary
    if args.records_out:
        with open(args.records_out, "w") as fh:
            write_json_array(records, fh)
    if args.coverage_out:
        with open(args.coverage_out, "w") as fh:
            json.dump(coverage, fh, indent=2)

    print(json.dumps({
        "scan_id": scan_id,
        "app_id": scope["app_id"],
        "requests_seen": len(guard.decisions),
        "blocked": len(guard.violations),
        "gate": gate,
    }, indent=2))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
