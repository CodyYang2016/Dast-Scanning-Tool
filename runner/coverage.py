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

See R2 in docs/junior_engineer/seeded_session_exploration_design.md.
"""

from __future__ import annotations

import hashlib
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


def _fetch_probe(zap_api: str, url: str) -> tuple[int | None, str]:
    """Fetch a probe URL THROUGH ZAP, so it is seen exactly as the scan sees the app."""
    try:
        data = _api(zap_api, "/JSON/core/action/accessUrl/",
                    {"url": url, "followRedirects": "true"})
        entry = (data.get("accessUrl") or [{}])[0]
        header = entry.get("responseHeader", "")
        status = int(header.split()[1]) if header.startswith("HTTP/") else None
        return status, entry.get("responseBody", "")
    except Exception:
        return None, ""


def state_fingerprint(zap_api: str, base_url: str, probes) -> dict:
    """A digest of what a few chosen URLs returned, so two scans can be compared for
    "was the application even in the same condition?" (W6-8).

    Findings depend on state the scanner does not own — a security level, a feature flag, a
    seeded dataset. Measured here: one scan found five high-severity findings and the next
    found none, with the SQL-injection rule completing 660 requests, because the application
    had changed underneath. Only a digest is stored: a probe response may contain anything.

    Limitation worth knowing: probes are fetched through ZAP WITHOUT the scan's session, so
    they describe the application's unauthenticated state. That catches a redeploy, a wiped
    database or a flipped feature flag; it will not catch a change visible only behind the
    login. Probing through the authenticated session is the obvious next step.
    """
    probes = list(probes or [])
    if not probes:
        return {}
    out = {}
    for path in probes:
        status, body = _fetch_probe(zap_api, base_url.rstrip("/") + path)
        out[path] = {"status": status,
                     "digest": hashlib.sha256((body or "").encode()).hexdigest()[:16]}
    return {"probes": out}


def rule_outcomes(zap_api: str, scan_id: str) -> dict:
    """What each active-scan rule actually did: state, requests sent, alerts raised.

    Coverage used to record which rules were ENABLED, which cannot tell "ran and found
    nothing" from "never ran". ZAP knows: scanProgress reports per-rule state — Complete, or
    Skipped with a reason such as exceeding the per-rule time budget. Recording it is what
    makes a disappeared finding explainable instead of a mystery (W6-2).

    Returns {} if the view is unavailable: a scan must not fail because its bookkeeping did.
    """
    try:
        data = _api(zap_api, "/JSON/ascan/view/scanProgress/", {"scanId": scan_id})
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for entry in data.get("scanProgress", []):
        if not isinstance(entry, dict) or "HostProcess" not in entry:
            continue
        for row in entry["HostProcess"]:
            p = row.get("Plugin") if isinstance(row, dict) else row
            if not p or len(p) < 7:
                continue
            name, rule_id, _quality, state, reqs, _total, alerts = p[:7]
            out[str(rule_id)] = {"name": name, "state": state,
                                 "requests": int(reqs or 0), "alerts": int(alerts or 0)}
    return out


def truncated_rules(outcomes: dict) -> list[str]:
    """Rule ids that ZAP stopped early for time — the honest definition of a truncated scan."""
    return sorted(rid for rid, o in outcomes.items()
                  if "skip" in o["state"].lower() and "time" in o["state"].lower())


def capture(zap_api: str, target: str, scan_id: str | None = None, probes=None) -> dict:
    """This scan's coverage: what it exercised, what each rule did, and what state the
    application was in while it did so.

    The last two exist because "no finding" had three indistinguishable causes — the rule did
    not run, the rule ran and found nothing, or the application was not vulnerable at the
    time (W6-2, W6-8).
    """
    out = {
        "routes": sorted(accessed_routes(zap_api, target)),
        "rules": sorted(enabled_rule_ids(zap_api)),
    }
    if scan_id is not None:
        outcomes = rule_outcomes(zap_api, scan_id)
        if outcomes:
            out["rule_outcomes"] = outcomes
            out["truncated_rules"] = truncated_rules(outcomes)
    state = state_fingerprint(zap_api, target, probes)
    if state:
        out["app_state"] = state
    return out
