"""Active-scan orchestration (FR-S1, FR-S2).

Drives the ZAP daemon to spider + bounded active-scan a target, then exports raw ZAP alerts in
the shape the detections pipeline already consumes (contracts/sample_zap_output.json). This is
the Python port of the proven runner/capture_zap_fixture.sh choreography (accessUrl -> spider
-> bounded ascan -> alerts export), plus a scope safety pre-check.

Bounded to allow-listed hosts (D5/NFR-2): the target host MUST be in the scope allow-list, or
the scan refuses to run. Typically invoked AFTER runner/replay.py has populated ZAP with
authenticated traffic, so the active scan attacks authenticated endpoints too.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from runner.preflight import preflight
from runner import zapapi
from runner.scope_guard import host_of, in_scope

_DEFAULT_SCHEMA = "contracts/scope.schema.json"
_SLOW_SCANNERS = "40026"  # DOM-XSS (browser-based) — wedges the API; the historical default


class ZapUnavailableError(Exception):
    """Raised when the ZAP daemon stops answering mid-scan.

    Distinct from a scan that merely takes a long time: a run should not end in a raw socket
    traceback when the daemon has died (observed: the container OOM-killed by a browser-driven
    rule), because the operator cannot tell those apart from the stack alone.
    """


class ScanScopeError(Exception):
    """Raised when the scan target is not covered by the scope allow-list (safety)."""


def _api(zap_api: str, path: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    # Always through the keyed client (W4-4).
    return zapapi.call(zap_api, path, params, timeout)


def new_session(zap_api: str, name: str = "") -> None:
    """Start a fresh in-memory ZAP session so results are per-scan, not accumulated across runs."""
    params = {"overwrite": "true"}
    if name:
        params["name"] = name
    _api(zap_api, "/JSON/core/action/newSession/", params)


def load_policy(path: str) -> dict | None:
    """Read a generated `zap-policy.yaml`, or None when the bundle has none.

    `generate` writes JSON, which is valid YAML, so either form loads.
    """
    p = Path(path)
    if not p.is_file():
        return None
    loaded = yaml.safe_load(p.read_text())
    return loaded if isinstance(loaded, dict) else None


def resolved_policy(policy: dict | None, max_scan_min: int, max_rule_min: int,
                    throttle: dict | None = None) -> dict:
    """What this scan was actually configured to do, for the coverage artifact (R2).

    Recording it is what lets two scans of the same application be compared honestly: a
    finding that vanished because a rule was switched off is not a fix, and without this the
    difference is invisible.
    """
    policy = policy or {}
    return {
        "write_mode": policy.get("write_mode", "deny"),
        "attack_strength": policy.get("attack_strength", "default"),
        "alert_threshold": policy.get("alert_threshold", "default"),
        "disabled_scanners": list(policy.get("disabled_scanners", [_SLOW_SCANNERS])),
        "max_scan_min": max_scan_min,
        "max_rule_min": max_rule_min,
        "throttle": dict(throttle) if throttle else "zap defaults",
    }


def configure_policy(zap_api: str, max_scan_min: int = 4, max_rule_min: int | None = None,
                     policy: dict | None = None, throttle: dict | None = None) -> None:
    """Bound the active scan, and apply the bundle's `zap-policy.yaml` when there is one.

    Without a policy this behaves as it always did (time budgets + the historically disabled
    DOM-XSS scanner), so compose and hand-run scans are unaffected.

    With one, attack strength and alert threshold — the two knobs that actually govern DAST
    depth and noise — are applied to every scanner category, and the rule set is reset with
    `enableAllScanners` before the policy's exclusions are applied. That reset matters: ZAP's
    scanner state is daemon-global and outlives a session, so without it a rule switched off
    by an earlier run stays off and this scan silently covers less than its policy claims.
    """
    # The per-rule budget comes from the bundle's policy unless a caller overrides it. It used
    # to be a parameter defaulting to 1 that nothing ever passed, so `generate` wrote
    # max_rule_min into zap-policy.yaml, the scan ignored it, and coverage.json reported the
    # value that had not been used — config and artifact agreeing while both contradicted it.
    if max_rule_min is None:
        max_rule_min = int((policy or {}).get("max_rule_min") or 1)
    # How hard the scan pushes (W4-3). A shared environment has other users; ZAP's defaults are
    # tuned for throughput, not courtesy. Unset leaves ZAP's defaults exactly as they were.
    throttle = throttle or {}
    if throttle.get("threads_per_host"):
        _api(zap_api, "/JSON/ascan/action/setOptionThreadPerHost/",
             {"Integer": int(throttle["threads_per_host"])})
        _api(zap_api, "/JSON/spider/action/setOptionThreadCount/",
             {"Integer": int(throttle["threads_per_host"])})
    if throttle.get("delay_ms") is not None:
        _api(zap_api, "/JSON/ascan/action/setOptionDelayInMs/", {"Integer": int(throttle["delay_ms"])})
    _api(zap_api, "/JSON/ascan/action/setOptionMaxScanDurationInMins/", {"Integer": max_scan_min})
    _api(zap_api, "/JSON/ascan/action/setOptionMaxRuleDurationInMins/", {"Integer": max_rule_min})

    if policy:
        categories = [p["id"] for p in _api(zap_api, "/JSON/ascan/view/policies/").get("policies", [])]
        strength = str(policy.get("attack_strength", "medium")).upper()
        threshold = str(policy.get("alert_threshold", "medium")).upper()
        for cid in categories:
            _api(zap_api, "/JSON/ascan/action/setPolicyAttackStrength/",
                 {"id": cid, "attackStrength": strength})
            _api(zap_api, "/JSON/ascan/action/setPolicyAlertThreshold/",
                 {"id": cid, "alertThreshold": threshold})

    _api(zap_api, "/JSON/ascan/action/enableAllScanners/")   # deterministic starting point
    disabled = list(policy.get("disabled_scanners", [])) if policy else [_SLOW_SCANNERS]
    if disabled:
        _api(zap_api, "/JSON/ascan/action/disableScanners/", {"ids": ",".join(map(str, disabled))})


_MAX_CONSECUTIVE_API_FAILURES = 3


def stop_all(zap_api: str) -> dict:
    """Stop every spider and active scan ZAP is running (W4-3). Both are tried even if one fails:
    a half-stopped scanner is still attacking. Returns which stopped."""
    stopped = {}
    for kind in ("ascan", "spider"):
        try:
            _api(zap_api, f"/JSON/{kind}/action/stopAllScans/")
            stopped[kind] = True
        except Exception:
            stopped[kind] = False
    return stopped


def _poll(zap_api: str, view_path: str, scan_id: str, poll_s: float, max_polls: int,
          on_tick=None) -> None:
    """Poll a ZAP scan to completion, tolerating a slow answer but not a dead daemon."""
    try:
        _poll_until_done(zap_api, view_path, scan_id, poll_s, max_polls, on_tick)
    except KeyboardInterrupt:
        # Ctrl-C used to kill the runner and leave ZAP attacking the application on its own.
        stop_all(zap_api)
        raise


def _poll_until_done(zap_api: str, view_path: str, scan_id: str, poll_s: float,
                     max_polls: int, on_tick=None) -> None:
    failures = 0
    for _ in range(max_polls):
        try:
            status = _api(zap_api, view_path, {"scanId": scan_id}).get("status")
            failures = 0
        except zapapi.ZapAuthError:
            raise                       # a refused key is not a busy daemon; say so at once
        except Exception as exc:        # a busy daemon can miss a poll; a dead one misses all
            failures += 1
            if failures >= _MAX_CONSECUTIVE_API_FAILURES:
                raise ZapUnavailableError(
                    f"ZAP stopped responding after {failures} consecutive failed polls "
                    f"({exc}). The daemon may have been killed — check `docker logs zap` for "
                    f"an OOM (exit 137); browser-driven rules such as DOM-XSS (40026) at high "
                    f"attack strength are the usual cause."
                ) from exc
            time.sleep(poll_s)
            continue
        if on_tick:
            on_tick()            # e.g. the session-liveness check (W5-1); it rate-limits itself
        if status == "100":
            return
        time.sleep(poll_s)


def exclusion_regexes(avoid_actions, login_url: str | None) -> list[str]:
    """URL patterns the scanner must not attack, from what the config already declares.

    `scope.avoid_actions` was only ever enforced during exploration; ZAP itself was free to
    attack anything it found. Measured on DVWA: one 10-minute scan submitted the "Create /
    Reset Database" form about 325 times and POSTed to the login form about 1,000 times, so
    roughly half of all /vulnerabilities/* responses came back as redirects to the login page.
    The scan was resetting and logging out of the application it was scanning, which is the
    real cause of findings that appeared and vanished between runs.

    The login page is excluded whether or not it was named: attacking the form that holds the
    session is how a scan loses the session. Terms are matched as substrings anywhere in the
    URL, case-insensitively; a login path is escaped so it matches literally.
    """
    out: list[str] = []
    for term in (avoid_actions or []):
        term = str(term).strip()
        if term:
            out.append(f"(?i).*{re.escape(term)}.*")
    if login_url:
        # Only the PATH reaches the server. A hash-routed login (/#/login, as in any Angular or
        # hash-mode SPA) is a fragment: the browser requests "/", so there is no server-side
        # login page to exclude. Measured: treating "/" as the login path produced (?i).*/.*,
        # which excluded every URL and turned a Juice Shop scan into a scan of nothing.
        path = urllib.parse.urlsplit(str(login_url)).path
        if path.strip("/"):
            rx = f"(?i).*{re.escape(path)}.*"
            if rx not in out:
                out.append(rx)
    return out


def refuse_exclusions_covering(target: str, regexes) -> None:
    """Refuse to scan if any exclusion would cover the whole application.

    An exclusion that matches the target's root is never what anyone meant — a hash-routed login
    path, an avoid term that happens to name the host — and its effect is silent: ZAP skips
    everything, the scan passes, and the empty result reads as a clean one. Failing here turns
    that into an error message before any traffic, which is the only honest outcome.
    """
    roots = {target.rstrip("/"), target.rstrip("/") + "/"}
    for rx in regexes or []:
        try:
            if any(re.match(rx, root) for root in roots):
                raise ScanScopeError(
                    f"refusing to scan {target!r}: exclusion {rx!r} matches the application's "
                    f"root, which would exclude the whole application from the spider and the "
                    f"active scan and report the resulting silence as a clean scan. Check "
                    f"scope.avoid_actions and auth.login_url.")
        except re.error:
            continue


def apply_exclusions(zap_api: str, regexes) -> None:
    """Tell ZAP to leave these URLs alone, for the spider and the active scan alike.

    Exclusions live in the ZAP session, so this must run AFTER new_session. A failure is
    raised rather than logged: continuing would attack exactly what we undertook not to.
    """
    for rx in regexes or []:
        for view in ("/JSON/spider/action/excludeFromScan/",
                     "/JSON/ascan/action/excludeFromScan/"):
            _api(zap_api, view, {"regex": rx})


def context_regexes(allow_entries) -> list[str]:
    """ZAP context include patterns from the allow list (W4-1).

    An origin admits exactly that scheme, host and port (the default port may be written or
    omitted); a bare host admits that host on any scheme and port — the same meanings the browser
    guard uses (runner/scope_guard.entry_matches). Anchored, with the host escaped, so a lookalike
    (`dvwa.evil.example`) or a host buried in a query string never matches. Kept to the regex
    subset Java and Python agree on, since ZAP evaluates them and the tests use Python.
    """
    from runner.scope_guard import _DEFAULT_PORT, _parts, is_origin
    tail = r"(?:[/?#].*)?$"
    out = []
    for entry in allow_entries or []:
        entry = str(entry).strip()
        if is_origin(entry):
            parts = _parts(entry)
            if parts is None:
                continue
            scheme, host, port = parts
            port_rx = (f"(?::{port})?" if port == _DEFAULT_PORT.get(scheme) else f":{port}")
            out.append(f"^{scheme}://{re.escape(host)}{port_rx}{tail}")
        elif entry:
            out.append(f"^https?://{re.escape(entry.lower())}(?::\\d+)?{tail}")
    return out


def spider(zap_api: str, target: str, poll_s: float = 3.0, max_polls: int = 120,
           context_name: str | None = None) -> str:
    params = {"url": target, "recurse": "true"}
    if context_name:
        params["contextName"] = context_name
    scan_id = _api(zap_api, "/JSON/spider/action/scan/", params)["scan"]
    _poll(zap_api, "/JSON/spider/view/status/", scan_id, poll_s, max_polls)
    return scan_id


def active_scan(zap_api: str, target: str, poll_s: float = 5.0, max_polls: int = 120,
                context_id: str | None = None, on_tick=None) -> str:
    params = {"url": target, "recurse": "true"}
    if context_id:
        params["contextId"] = context_id
    scan_id = _api(zap_api, "/JSON/ascan/action/scan/", params)["scan"]
    _poll(zap_api, "/JSON/ascan/view/status/", scan_id, poll_s, max_polls, on_tick)
    return scan_id


def export_alerts(zap_api: str, target: str) -> dict:
    """Return {"alerts": [...]} for the target — the raw ZAP shape the normalizer consumes."""
    return _api(zap_api, "/JSON/alert/view/alerts/", {"baseurl": target})


def scan(zap_api: str, target: str, allow_hosts, do_spider: bool = True,
         max_scan_min: int = 4, policy: dict | None = None, exclusions=None,
         max_rule_min: int | None = None, throttle: dict | None = None, liveness=None) -> dict:
    """Spider + bounded active-scan `target`; return raw ZAP alerts plus the active scan's
    id. Refuses out-of-scope targets before touching ZAP (safety pre-check)."""
    host = host_of(target)
    if host is None or not in_scope(target, allow_hosts):
        raise ScanScopeError(
            f"refusing to scan {target!r}: host {host!r} not in allow-list {sorted(allow_hosts)} (NFR-2)."
        )
    # Before ZAP is touched: an exclusion that covers everything must stop the run, not
    # produce an empty one.
    refuse_exclusions_covering(target, exclusions)
    configure_policy(zap_api, max_scan_min=max_scan_min, max_rule_min=max_rule_min,
                     policy=policy, throttle=throttle)
    apply_exclusions(zap_api, exclusions)
    # A ZAP context bounds the spider and the active scan themselves (W4-1). Our two safety
    # layers only ever covered requests WE send; ZAP's own traffic was bounded by nothing but
    # the seed URL. Built from the same allow list, removed afterwards whatever happens.
    import time as _time
    ctx_name = f"dast-{int(_time.time() * 1000)}"
    includes = context_regexes(allow_hosts)
    ctx_id = str(_api(zap_api, "/JSON/context/action/newContext/",
                      {"contextName": ctx_name}).get("contextId"))
    try:
        for rx in includes:
            _api(zap_api, "/JSON/context/action/includeInContext/",
                 {"contextName": ctx_name, "regex": rx})
        for rx in exclusions or []:
            _api(zap_api, "/JSON/context/action/excludeFromContext/",
                 {"contextName": ctx_name, "regex": rx})
        _api(zap_api, "/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
        if do_spider:
            spider(zap_api, target, context_name=ctx_name)
        ascan_id = active_scan(zap_api, target, context_id=ctx_id,
                               on_tick=liveness.check if liveness else None)
        report = export_alerts(zap_api, target)
    finally:
        try:
            _api(zap_api, "/JSON/context/action/removeContext/", {"contextName": ctx_name})
        except Exception:
            pass          # the session is replaced on the next scan anyway
    report["context"] = {"name": ctx_name, "include": includes, "exclude": list(exclusions or [])}
    # Carried so coverage can read back what each rule did (W6-2): "ran and found nothing"
    # and "never ran" are otherwise the same sentence.
    report["ascan_id"] = ascan_id
    # Carried so coverage can subtract them: an excluded route was NOT scanned, and must not
    # be counted as covered or a finding on it would resolve itself.
    report["exclusions"] = list(exclusions or [])
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ZAP active-scan orchestration (FR-S1/S2).")
    p.add_argument("--scope", required=True, help="App scope.json (target host must be allow-listed)")
    p.add_argument("--schema", default=_DEFAULT_SCHEMA)
    p.add_argument("--target", required=True, help="Target base URL as ZAP resolves it")
    p.add_argument("--zap-api", default="http://localhost:8080")
    p.add_argument("--no-spider", action="store_true", help="Skip the spider (scan what ZAP already saw)")
    p.add_argument("--max-scan-min", type=int, default=4)
    p.add_argument("-o", "--out", default="-", help="Raw ZAP alerts output path, or - for stdout")
    args = p.parse_args(argv)

    scope = preflight(args.scope, args.schema)  # safety layer 1 before any traffic
    try:
        report = scan(
            args.zap_api, args.target, scope["fqdn_allow_list"],
            do_spider=not args.no_spider, max_scan_min=args.max_scan_min,
        )
    except ScanScopeError as exc:
        print(f"SCAN ABORT: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(report, indent=2)
    if args.out == "-":
        print(payload)
    else:
        with open(args.out, "w") as fh:
            fh.write(payload + "\n")
    print(f"scanned {args.target}: {len(report.get('alerts', []))} alerts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
