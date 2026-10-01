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
_SLOW_SCANNERS = "40026"  # DOM-XSS (browser-based) — wedges the API; disabled for bounded runs


class ScanScopeError(Exception):
    """Raised when the scan target is not covered by the scope allow-list (safety)."""


class ZapUnavailableError(Exception):
    """Raised when ZAP stops answering during a scan."""


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
    p = Path(path)
    if not p.is_file():
        return None
    loaded = yaml.safe_load(p.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else None


def resolved_policy(policy: dict | None, max_scan_min: int, max_rule_min: int) -> dict:
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
    """Bound + lighten the active scan using the bundle policy when present."""
    if max_rule_min is None:
        max_rule_min = int((policy or {}).get("max_rule_min") or 1)
    _api(zap_api, "/JSON/ascan/action/setOptionMaxScanDurationInMins/", {"Integer": max_scan_min})
    _api(zap_api, "/JSON/ascan/action/setOptionMaxRuleDurationInMins/", {"Integer": max_rule_min})
    if policy:
        categories = [item["id"] for item in
                      _api(zap_api, "/JSON/ascan/view/policies/").get("policies", [])]
        strength = str(policy.get("attack_strength", "medium")).upper()
        threshold = str(policy.get("alert_threshold", "medium")).upper()
        for category in categories:
            _api(zap_api, "/JSON/ascan/action/setPolicyAttackStrength/",
                 {"id": category, "attackStrength": strength})
            _api(zap_api, "/JSON/ascan/action/setPolicyAlertThreshold/",
                 {"id": category, "alertThreshold": threshold})
    _api(zap_api, "/JSON/ascan/action/enableAllScanners/")
    disabled = list(policy.get("disabled_scanners", [])) if policy else [_SLOW_SCANNERS]
    if disabled:
        _api(zap_api, "/JSON/ascan/action/disableScanners/",
             {"ids": ",".join(map(str, disabled))})
    _api(zap_api, "/JSON/ascan/action/disableScanners/", {"ids": _SLOW_SCANNERS})


def _poll(zap_api: str, view_path: str, scan_id: str, poll_s: float, max_polls: int) -> None:
    failures = 0
    for _ in range(max_polls):
        try:
            status = _api(zap_api, view_path, {"scanId": scan_id}).get("status")
            failures = 0
        except Exception as exc:
            failures += 1
            if failures >= 3:
                raise ZapUnavailableError(f"ZAP stopped responding after {failures} failed polls: {exc}") from exc
            time.sleep(poll_s)
            continue
        if status == "100":
            return
        time.sleep(poll_s)


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


def exclusion_regexes(avoid_actions, login_url: str | None) -> list[str]:
    out = [f"(?i).*{re.escape(str(term).strip())}.*" for term in (avoid_actions or [])
           if str(term).strip()]
    if login_url:
        path = urllib.parse.urlsplit(str(login_url)).path or str(login_url)
        pattern = f"(?i).*{re.escape(path)}.*"
        if pattern not in out:
            out.append(pattern)
    return out


def apply_exclusions(zap_api: str, regexes) -> None:
    for regex in regexes or []:
        for endpoint in ("/JSON/spider/action/excludeFromScan/",
                         "/JSON/ascan/action/excludeFromScan/"):
            _api(zap_api, endpoint, {"regex": regex})


def scan(zap_api: str, target: str, allow_hosts, do_spider: bool = True,
         max_scan_min: int = 4, policy: dict | None = None,
         max_rule_min: int | None = None, exclusions=None) -> dict:
    """Spider + bounded active-scan `target`, return raw ZAP alerts. Refuses out-of-scope
    targets before touching ZAP (safety pre-check)."""
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
    report["ascan_id"] = ascan_id
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
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    print(f"scanned {args.target}: {len(report.get('alerts', []))} alerts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
