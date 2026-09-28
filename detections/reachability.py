"""What the application exposes vs. what the scan actually sent (W6-12).

`coverage.route_params` records the parameters a scan sent, which is what stops a fix being
claimed for a parameter nothing tested (W6-10). It cannot say what was *missed*, because it has
no inventory of what existed. The exploration trace does: it records every form it observed,
submitted or not, with that form's field names.

The difference between the two is a detection gap, and it was invisible until now. Measured on
DVWA: `/vulnerabilities/sqli` was reached, appears in coverage, and rule 40018 ran to completion
against it — but the walk only ever visited it bare, so the two high-severity findings on `?id=`
could not be found by any scan built from that bundle.

Only GET forms count. A POST body's parameters never appear in a URL, so ZAP's URL list cannot
show them as sent; reporting them would create a gap nobody could ever close.
"""

from __future__ import annotations

import re

from detections.fingerprint import endpoint_pattern


def exposed_params(trace: dict) -> dict[str, list[str]]:
    """Parameter names the application offered, per canonical route.

    Canonicalised with the same endpoint_pattern as coverage and as finding identity, so the
    two sides line up exactly rather than approximately.
    """
    out: dict[str, set[str]] = {}
    for form in trace.get("forms", []):
        if str(form.get("method", "GET")).upper() != "GET":
            continue
        route = endpoint_pattern(form.get("url", ""))
        names = {n for n in (form.get("fields") or []) if n}
        if names:
            out.setdefault(route, set()).update(names)
    return {route: sorted(names) for route, names in sorted(out.items())}


def _is_excluded(route: str, coverage: dict) -> bool:
    for rx in coverage.get("excluded") or []:
        try:
            if re.match(rx, route) or re.search(rx, route):
                return True
        except re.error:
            continue
    return False


def unexercised(exposed: dict, coverage: dict) -> dict[str, list[str]]:
    """Exposed parameters the scan never sent — the gap, per route.

    A route excluded on purpose (W6-11) is not a gap: it is a declared decision, already
    reported as `route_excluded`. Coverage written before parameters were recorded carries no
    evidence either way, so it reports nothing rather than inventing a gap on every route.
    """
    sent = coverage.get("route_params")
    if not sent:
        return {}
    out: dict[str, list[str]] = {}
    for route, names in exposed.items():
        if _is_excluded(route, coverage):
            continue
        missing = sorted(set(names) - set(sent.get(route, [])))
        if missing:
            out[route] = missing
    return out


def summarize(exposed: dict, coverage: dict) -> dict:
    """Counts for a one-line answer to "did the scan reach what the app offers?"."""
    gaps = unexercised(exposed, coverage)
    total = sum(len(v) for v in exposed.values())
    missing = sum(len(v) for v in gaps.values())
    return {"exposed": total, "exercised": total - missing,
            "routes_with_gaps": len(gaps), "gaps": gaps}
