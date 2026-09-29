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
from runner.scope_guard import host_of

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
    url = zap_api.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


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


def resolved_policy(policy: dict | None, max_scan_min: int, max_rule_min: int) -> dict:
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
    }


def configure_policy(zap_api: str, max_scan_min: int = 4, max_rule_min: int | None = None,
                     policy: dict | None = None) -> None:
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


def _poll(zap_api: str, view_path: str, scan_id: str, poll_s: float, max_polls: int) -> None:
    """Poll a ZAP scan to completion, tolerating a slow answer but not a dead daemon."""
    failures = 0
    for _ in range(max_polls):
        try:
            status = _api(zap_api, view_path, {"scanId": scan_id}).get("status")
            failures = 0
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
        path = urllib.parse.urlsplit(str(login_url)).path or str(login_url)
        rx = f"(?i).*{re.escape(path)}.*"
        if rx not in out:
            out.append(rx)
    return out


def apply_exclusions(zap_api: str, regexes) -> None:
    """Tell ZAP to leave these URLs alone, for the spider and the active scan alike.

    Exclusions live in the ZAP session, so this must run AFTER new_session. A failure is
    raised rather than logged: continuing would attack exactly what we undertook not to.
    """
    for rx in regexes or []:
        for view in ("/JSON/spider/action/excludeFromScan/",
                     "/JSON/ascan/action/excludeFromScan/"):
            _api(zap_api, view, {"regex": rx})


def spider(zap_api: str, target: str, poll_s: float = 3.0, max_polls: int = 120) -> str:
    scan_id = _api(zap_api, "/JSON/spider/action/scan/", {"url": target, "recurse": "true"})["scan"]
    _poll(zap_api, "/JSON/spider/view/status/", scan_id, poll_s, max_polls)
    return scan_id


def active_scan(zap_api: str, target: str, poll_s: float = 5.0, max_polls: int = 120) -> str:
    scan_id = _api(zap_api, "/JSON/ascan/action/scan/", {"url": target, "recurse": "true"})["scan"]
    _poll(zap_api, "/JSON/ascan/view/status/", scan_id, poll_s, max_polls)
    return scan_id


def export_alerts(zap_api: str, target: str) -> dict:
    """Return {"alerts": [...]} for the target — the raw ZAP shape the normalizer consumes."""
    return _api(zap_api, "/JSON/alert/view/alerts/", {"baseurl": target})


def scan(zap_api: str, target: str, allow_hosts, do_spider: bool = True,
         max_scan_min: int = 4, policy: dict | None = None, exclusions=None,
         max_rule_min: int | None = None) -> dict:
    """Spider + bounded active-scan `target`; return raw ZAP alerts plus the active scan's
    id. Refuses out-of-scope targets before touching ZAP (safety pre-check)."""
    host = host_of(target)
    allow = {h.strip().lower() for h in allow_hosts}
    if host is None or host not in allow:
        raise ScanScopeError(
            f"refusing to scan {target!r}: host {host!r} not in allow-list {sorted(allow)} (NFR-2)."
        )
    configure_policy(zap_api, max_scan_min=max_scan_min, max_rule_min=max_rule_min,
                     policy=policy)
    apply_exclusions(zap_api, exclusions)
    _api(zap_api, "/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
    if do_spider:
        spider(zap_api, target)
    ascan_id = active_scan(zap_api, target)
    report = export_alerts(zap_api, target)
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
