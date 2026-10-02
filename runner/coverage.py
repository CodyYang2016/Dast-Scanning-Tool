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

from detections.fingerprint import endpoint_pattern
from runner import zapapi
from runner.scope_guard import host_of


def _api(zap_api: str, path: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    # Always through the keyed client (W4-4).
    return zapapi.call(zap_api, path, params, timeout)


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
    """Query-parameter names ZAP actually sent, per canonical route (W6-10).

    A finding's identity is (route, parameter, rule), but coverage recorded only routes — so
    /vulnerabilities/sqli visited without `?id=` counted as covered and the findings on that
    parameter would have been called fixed, when nothing had ever tested them. The query
    strings were there all along; endpoint_pattern drops them, so they are collected here
    before that happens.

    Limitation: this sees GET parameters. Parameters carried in a POST body are not in the
    URL list, so a finding on one cannot be shown as exercised and will not be claimed as
    fixed — the conservative direction, and the reason to read body parameters from ZAP's
    message store eventually.
    """
    from urllib.parse import parse_qs, urlsplit
    data = _api(zap_api, "/JSON/core/view/urls/", {"baseurl": target})
    host = host_of(target)
    out: dict[str, set[str]] = {}
    for url in data.get("urls", []):
        if host is not None and host_of(url) != host:
            continue
        route = endpoint_pattern(url)
        names = set(parse_qs(urlsplit(url).query).keys())
        out.setdefault(route, set()).update(names)
    return {route: sorted(names) for route, names in sorted(out.items())}


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


def session_cookies(storage_state, base_url: str) -> dict[str, str]:
    """Just the cookies the scan's recorded session holds for this host — no configured state.

    Kept separate from probe_cookies so a caller can tell a real session from `auth.cookies`:
    a scan with no session file still sends something, and that must not be reported as having
    seen the authenticated application.
    """
    out: dict[str, str] = {}
    host = host_of(base_url)
    if not storage_state:
        return out
    try:
        with open(storage_state, encoding="utf-8") as fh:
            saved = json.load(fh)
    except Exception:
        return out
    for c in saved.get("cookies", []):
        domain = str(c.get("domain", "")).lstrip(".")
        if host is None or domain == host or host.endswith("." + domain):
            out[c["name"]] = c["value"]
    return out


def probe_cookies(storage_state, base_url: str, extra: dict | None = None) -> dict[str, str]:
    """The cookies a state probe should carry: the scan's own session, plus the state the
    config says the scan depends on.

    Without the session a probe sees the login page, which is the same page whatever has
    happened behind it — measured: /security.php digested to sha256("") on two scans that
    differed by five high-severity findings, so the state check could never fire.

    Cookies belonging to another host are dropped, and the configured cookies win over the
    recorded ones: `auth.cookies` is the operator stating the state the scan requires, while a
    cookie in the session file is only what the browser happened to hold when it was captured.
    An unreadable session file degrades to the configured cookies rather than failing a scan.
    """
    out = session_cookies(storage_state, base_url)
    out.update(extra or {})
    return out


_MAX_HOPS = 5


def _send_once(zap_api: str, url: str, cookies: dict | None):
    """One request through ZAP, redirects NOT followed: (status, location, body)."""
    lines = [f"GET {url} HTTP/1.1", f"Host: {host_of(url) or ''}"]
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in sorted(cookies.items())))
    data = _api(zap_api, "/JSON/core/action/sendRequest/",
                {"request": "\r\n".join(lines) + "\r\n\r\n", "followRedirects": "false"})
    entry = (data.get("sendRequest") or [{}])[-1]
    header = entry.get("responseHeader", "")
    status = int(header.split()[1]) if header.startswith("HTTP/") else None
    location = None
    for line in header.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            location = value.strip()
    return status, location, entry.get("responseBody", "")


def fetch_probe_full(zap_api: str, url: str, cookies: dict | None = None, allow=None):
    """(status, body, final_url) for a probe fetched through ZAP with the given cookies. The final
    url is where the redirects ended — a session that died shows up as a bounce to the login page
    (W5-1). Raises on failure; callers decide what a failed probe means.

    Redirects are followed HERE, one hop at a time, rather than by ZAP: ZAP would follow one to
    any host. A hop whose target is outside `allow` (default: the probe's own origin) is not
    fetched — the redirect itself is returned, with its target as the final url, which is what
    a bounce to an off-scope identity provider looks like (KI2).
    """
    from runner.scope_guard import in_scope, origin_of
    allow = list(allow) if allow else [origin_of(url)]
    current = url
    for _ in range(_MAX_HOPS + 1):
        status, location, body = _send_once(zap_api, current, cookies)
        if not (status and 300 <= status < 400 and location):
            return status, body, current
        target = urllib.parse.urljoin(current, location)
        if not in_scope(target, allow):
            return status, body, target
        current = target
    return status, body, current


def _fetch_probe(zap_api: str, url: str, cookies: dict | None = None) -> tuple[int | None, str]:
    """Fetch a probe URL THROUGH ZAP, carrying the scan's session so the page is the one the
    scan actually saw.

    accessUrl cannot set headers, so an authenticated probe is sent as a raw request through
    core/sendRequest instead. Redirects are followed and the LAST response is the one digested,
    which is what makes a silent bounce to the login page visible as a change rather than as a
    constant.
    """
    try:
        status, body, _final = fetch_probe_full(zap_api, url, cookies)
        return status, body
    except Exception:
        return None, ""


def state_fingerprint(zap_api: str, base_url: str, probes, cookies: dict | None = None,
                      authenticated: bool | None = None) -> dict:
    """A digest of what a few chosen URLs returned, so two scans can be compared for
    "was the application even in the same condition?" (W6-8).

    Findings depend on state the scanner does not own — a security level, a feature flag, a
    seeded dataset. Measured here: one scan found five high-severity findings and the next
    found none, with the SQL-injection rule completing 660 requests, because the application
    had changed underneath. Only a digest is stored: a probe response may contain anything.

    Probes carry the scan's own session when one is available, so they describe the app as the
    scan saw it rather than as an anonymous visitor would. `authenticated` records which of the
    two it was, because an unauthenticated digest is a much weaker claim and the artifact should
    say so rather than let a reader assume.
    """
    probes = list(probes or [])
    if not probes:
        return {}
    out = {}
    for path in probes:
        status, body = _fetch_probe(zap_api, base_url.rstrip("/") + path, cookies)
        out[path] = {"status": status,
                     "digest": hashlib.sha256((body or "").encode()).hexdigest()[:16]}
    return {"probes": out,
            "authenticated": bool(cookies) if authenticated is None else authenticated}


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


def _excluded_matcher(excluded):
    """A predicate for "the scanner was told not to touch this route".

    A regex ZAP accepted but Python cannot compile is ignored rather than treated as matching
    everything: the failure mode of a bad pattern must be recording too MUCH coverage to
    review, never silently deleting all of it.
    """
    import re as _re
    patterns = []
    for rx in excluded or []:
        try:
            patterns.append(_re.compile(rx))
        except _re.error:
            continue
    return lambda route: any(p.match(route) or p.search(route) for p in patterns)


def capture(zap_api: str, target: str, scan_id: str | None = None, probes=None,
            cookies: dict | None = None, authenticated: bool | None = None,
            excluded=None) -> dict:
    """This scan's coverage: what it exercised, what each rule did, and what state the
    application was in while it did so.

    The last two exist because "no finding" had three indistinguishable causes — the rule did
    not run, the rule ran and found nothing, or the application was not vulnerable at the
    time (W6-2, W6-8).
    """
    # A route the scanner was told to leave alone was NOT scanned, however many times the
    # browser walked through it. Counting it as covered would let a finding on it resolve
    # itself the moment the exclusion was added — the same false-fix this module exists to
    # prevent, arriving through the front door.
    is_excluded = _excluded_matcher(excluded)
    out = {
        "routes": sorted(r for r in accessed_routes(zap_api, target) if not is_excluded(r)),
        "rules": sorted(enabled_rule_ids(zap_api)),
        # Per-route parameters, so a fix claim needs evidence that the finding's own
        # parameter was exercised and not merely its route (W6-10).
        "route_params": {r: p for r, p in accessed_params(zap_api, target).items()
                         if not is_excluded(r)},
    }
    if excluded:
        out["excluded"] = list(excluded)
    if scan_id is not None:
        outcomes = rule_outcomes(zap_api, scan_id)
        if outcomes:
            out["rule_outcomes"] = outcomes
            out["truncated_rules"] = truncated_rules(outcomes)
    state = state_fingerprint(zap_api, target, probes, cookies, authenticated)
    if state:
        out["app_state"] = state
    return out
