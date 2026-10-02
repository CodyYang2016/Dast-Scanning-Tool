"""What should this scan have tested? A denominator for coverage (W6-4).

`coverage.json` says which routes ZAP exercised. Without a denominator that number reads as
coverage when it is only activity: "tested 80 routes" is excellent out of 85 and alarming out of
600. The denominator comes from the application's own OpenAPI/Swagger spec when it has one, or
otherwise from the routes the authoring walk discovered — labelled with its source, since a walk
can only list what it found.

Everything is expressed as `fingerprint.endpoint_pattern` routes, so a declared route and an
exercised one compare directly: spec templates (`/Users/{id}`) and observed URLs (`/Users/42`)
both become `/users/{id}`. Pure; reading the spec and talking to ZAP happen in the runner.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from detections.fingerprint import endpoint_pattern

_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


def parse_spec(text: str) -> dict:
    """An OpenAPI/Swagger document, JSON or YAML."""
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    import yaml
    return yaml.safe_load(text)


def _prefix(spec: dict) -> str:
    if spec.get("swagger"):
        return (spec.get("basePath") or "").rstrip("/")
    servers = spec.get("servers") or []
    url = servers[0].get("url", "") if servers else ""
    return urlparse(url).path.rstrip("/") if url else ""


def _pattern(path: str) -> str:
    # A template segment stands for an id; give it one, then use the fingerprint's own rule.
    return endpoint_pattern("http://x" + re.sub(r"\{[^/}]+\}", "1", path))


def from_openapi(spec: dict) -> list[tuple[str, str]]:
    """Declared operations as (METHOD, route pattern), in spec order."""
    prefix = _prefix(spec)
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        for method in (item or {}):
            if method.lower() in _METHODS:
                ops.append((method.upper(), _pattern(prefix + path)))
    return ops


def from_trace(trace: dict) -> list[str]:
    """Routes the authoring walk discovered: pages visited and API calls seen."""
    urls = list(trace.get("index") or []) + [a.get("url") for a in trace.get("api") or []]
    return sorted({endpoint_pattern(u) for u in urls if u})


def _excluded(route: str, patterns) -> bool:
    for rx in patterns or []:
        try:
            if re.match(rx, route) or re.search(rx, route):
                return True
        except re.error:
            continue
    return False


def summarize(declared_routes, coverage: dict, source: str) -> dict:
    """Declared vs exercised. Routes excluded on purpose count on neither side: they are a
    disclosed decision, not a gap."""
    excluded = coverage.get("excluded") or []
    declared = sorted({r for r in declared_routes})
    kept = [r for r in declared if not _excluded(r, excluded)]
    exercised_set = set(coverage.get("routes") or [])
    exercised = [r for r in kept if r in exercised_set]
    return {"source": source, "declared": len(kept), "exercised": len(exercised),
            "percent": round(100 * len(exercised) / len(kept)) if kept else None,
            "missing": [r for r in kept if r not in exercised_set],
            "excluded": len(declared) - len(kept)}
