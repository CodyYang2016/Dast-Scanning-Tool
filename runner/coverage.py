"""Scan coverage capture (R2): the (route x rule) surface a scan actually exercised.

`resolved` in the lifecycle diff (FR-L2) must mean a real fix, not "we stopped looking". So after
a scan we record what the active scan actually exercised:

  - the routes ZAP accessed under the target, canonicalized with the SAME endpoint_pattern used
    for detection fingerprints (so routes are directly comparable), and
  - the rule ids (ZAP pluginIds, active AND passive) that were ENABLED for this scan.

A previously-open finding is only labeled `resolved` if its (endpoint_pattern, rule_id) pair is in
this coverage; otherwise it is `not_scanned`. This is what stops a disabled rule (or a re-authored
flow that dropped a route) from being mis-reported as a fix. Coverage is represented compactly as
{"routes": [...], "rules": [...]} and consumed by detections.lifecycle_diff.diff(..., covered=).

See R2 in docs/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import json
import hashlib
import urllib.parse
import urllib.request

from detections.fingerprint import endpoint_pattern
from runner.scope_guard import host_of


def _api(zap_api: str, path: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    url = zap_api.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def accessed_routes(zap_api: str, target: str) -> set[str]:
    """Canonical endpoint patterns ZAP accessed under `target` (filtered to the target host).

    Uses the same endpoint_pattern() as the fingerprint, so the returned routes line up exactly
    with the `endpoint` field on detection records.
    """
    data = _api(zap_api, "/JSON/core/view/urls/", {"baseurl": target})
    host = host_of(target)
    routes: set[str] = set()
    for url in data.get("urls", []):
        if host is None or host_of(url) == host:
            routes.add(endpoint_pattern(url))
    return routes


def accessed_params(zap_api: str, target: str) -> dict[str, list[str]]:
    """Query-parameter names ZAP actually sent, grouped by canonical route."""
    from urllib.parse import parse_qs, urlsplit
    data = _api(zap_api, "/JSON/core/view/urls/", {"baseurl": target})
    host = host_of(target)
    out: dict[str, set[str]] = {}
    for url in data.get("urls", []):
        if host is not None and host_of(url) != host:
            continue
        route = endpoint_pattern(url)
        out.setdefault(route, set()).update(parse_qs(urlsplit(url).query).keys())
    return {route: sorted(names) for route, names in sorted(out.items())}


def rule_outcomes(zap_api: str, scan_id: str) -> dict:
    """Return best-effort per-rule request/alert outcomes from ZAP."""
    try:
        data = _api(zap_api, "/JSON/ascan/view/scanProgress/", {"scanId": scan_id})
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for entry in data.get("scanProgress", []):
        if not isinstance(entry, dict) or "HostProcess" not in entry:
            continue
        for row in entry["HostProcess"]:
            plugin = row.get("Plugin") if isinstance(row, dict) else row
            if not plugin or len(plugin) < 7:
                continue
            name, rule_id, _quality, state, requests, _total, alerts = plugin[:7]
            out[str(rule_id)] = {"name": name, "state": state,
                                 "requests": int(requests or 0), "alerts": int(alerts or 0)}
    return out


def truncated_rules(outcomes: dict) -> list[str]:
    return sorted(rule_id for rule_id, outcome in outcomes.items()
                  if "skip" in outcome["state"].lower() and "time" in outcome["state"].lower())


def _fetch_probe(zap_api: str, url: str, cookies: dict | None = None) -> tuple[int | None, str]:
    host = host_of(url) or ""
    lines = [f"GET {url} HTTP/1.1", f"Host: {host}"]
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in sorted(cookies.items())))
    try:
        raw = "\r\n".join(lines) + "\r\n\r\n"
        data = _api(zap_api, "/JSON/core/action/sendRequest/",
                    {"request": raw, "followRedirects": "true"})
        entry = (data.get("sendRequest") or [{}])[-1]
        header = entry.get("responseHeader", "")
        status = int(header.split()[1]) if header.startswith("HTTP/") else None
        return status, entry.get("responseBody", "")
    except Exception:
        return None, ""


def state_fingerprint(zap_api: str, target: str, probes, cookies: dict | None = None) -> dict:
    """Store short response digests without storing probe response bodies."""
    result = {}
    for path in probes or []:
        status, body = _fetch_probe(zap_api, target.rstrip("/") + path, cookies)
        result[path] = {"status": status,
                        "digest": hashlib.sha256((body or "").encode()).hexdigest()[:16]}
    return {"probes": result, "authenticated": bool(cookies)} if result else {}


def enabled_rule_ids(zap_api: str) -> set[str]:
    """Plugin ids currently enabled, active AND passive (matches record rule_id = ZAP pluginId).

    Reflects the policy AFTER runner.scan.configure_policy() has disabled slow/unwanted scanners,
    so a rule disabled for this scan is correctly excluded from coverage. Passive scanners are
    included because they fire on every route the scan touches (e.g. 90022 error disclosure,
    10098 CORS); without them a passive finding could never honestly be `resolved`. If the pscan
    view is unavailable, fall back to active-only (conservative: more `not_scanned`).
    """
    out: set[str] = set()
    for view in ("/JSON/ascan/view/scanners/", "/JSON/pscan/view/scanners/"):
        try:
            data = _api(zap_api, view)
        except Exception:
            if view.startswith("/JSON/ascan/"):
                raise
            continue
        for scanner in data.get("scanners", []):
            if str(scanner.get("enabled")).lower() == "true":
                rid = str(scanner.get("id", "")).strip()
                if rid:
                    out.add(rid)
    return out


def capture(zap_api: str, target: str, scan_id: str | None = None,
            excluded: list[str] | None = None, probes=None, cookies=None) -> dict:
    """Return routes, enabled rules, exercised parameters and rule outcomes."""
    routes = accessed_routes(zap_api, target)
    params = accessed_params(zap_api, target)
    out = {
        "routes": sorted(routes),
        "rules": sorted(enabled_rule_ids(zap_api)),
        "route_params": {route: names for route, names in params.items() if route in routes},
    }
    if excluded:
        out["excluded"] = list(excluded)
    if scan_id is not None:
        outcomes = rule_outcomes(zap_api, scan_id)
        if outcomes:
            out["rule_outcomes"] = outcomes
            out["truncated_rules"] = truncated_rules(outcomes)
    state = state_fingerprint(zap_api, target, probes, cookies)
    if state:
        out["app_state"] = state
    return out
