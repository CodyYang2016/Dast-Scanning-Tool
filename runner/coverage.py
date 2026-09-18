"""Scan coverage capture (R2): the (route x rule) surface a scan actually exercised.

`resolved` in the lifecycle diff (FR-L2) must mean a real fix, not "we stopped looking". So after
a scan we record what the active scan actually exercised:

  - the routes ZAP accessed under the target, canonicalized with the SAME endpoint_pattern used
    for detection fingerprints (so routes are directly comparable), and
  - the active-scan rule ids (ZAP pluginIds) that were ENABLED for this scan.

A previously-open finding is only labeled `resolved` if its (endpoint_pattern, rule_id) pair is in
this coverage; otherwise it is `not_scanned`. This is what stops a disabled rule (or a re-authored
flow that dropped a route) from being mis-reported as a fix. Coverage is represented compactly as
{"routes": [...], "rules": [...]} and consumed by detections.lifecycle_diff.diff(..., covered=).

See R2 in docs/junior_engineer/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import json
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


def enabled_rule_ids(zap_api: str) -> set[str]:
    """Active-scan plugin ids currently enabled (matches record rule_id = ZAP pluginId).

    Reflects the policy AFTER runner.scan.configure_policy() has disabled slow/unwanted scanners,
    so a rule disabled for this scan is correctly excluded from coverage.
    """
    data = _api(zap_api, "/JSON/ascan/view/scanners/")
    out: set[str] = set()
    for scanner in data.get("scanners", []):
        if str(scanner.get("enabled")).lower() == "true":
            rid = str(scanner.get("id", "")).strip()
            if rid:
                out.add(rid)
    return out


def capture(zap_api: str, target: str) -> dict:
    """Return this scan's coverage as {"routes": [...], "rules": [...]} (sorted, JSON-friendly)."""
    return {
        "routes": sorted(accessed_routes(zap_api, target)),
        "rules": sorted(enabled_rule_ids(zap_api)),
    }
