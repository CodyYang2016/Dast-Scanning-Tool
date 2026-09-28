"""Compare parameters exposed by the application with parameters sent by the scan."""

from __future__ import annotations

import re

from detections.fingerprint import endpoint_pattern


def exposed_params(trace: dict) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    for form in trace.get("forms", []):
        if str(form.get("method", "GET")).upper() != "GET":
            continue
        route = endpoint_pattern(form.get("url", ""))
        names = {name for name in (form.get("fields") or []) if name}
        if names:
            out.setdefault(route, set()).update(names)
    return {route: sorted(names) for route, names in sorted(out.items())}


def _is_excluded(route: str, coverage: dict) -> bool:
    for pattern in coverage.get("excluded") or []:
        try:
            if re.match(pattern, route) or re.search(pattern, route):
                return True
        except re.error:
            continue
    return False


def unexercised(exposed: dict, coverage: dict) -> dict[str, list[str]]:
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
    gaps = unexercised(exposed, coverage)
    total = sum(len(names) for names in exposed.values())
    missing = sum(len(names) for names in gaps.values())
    return {"exposed": total, "exercised": total - missing,
            "routes_with_gaps": len(gaps), "gaps": gaps}
