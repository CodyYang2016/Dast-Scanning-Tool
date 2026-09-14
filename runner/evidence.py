"""Evidence capture for a scan (FR-E1): a HAR of the traffic + at least one screenshot.

Evidence is stored under security/dast/<app>/evidence/<scan_id>/ and referenced from each
detection record's evidence_path (and, via the SARIF exporter, from the results).

**Redaction is a hard requirement, not polish** (demo plan Phase 2): a raw HAR contains auth
cookies, bearer tokens, and credentials. `redact_har` strips them BEFORE the HAR is written to
disk, so nothing sensitive ever lands in an evidence file (which could later be published as a
CI artifact / SARIF link). The pure redactor is unit-tested; capture wiring is validated live.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_REDACTED = "REDACTED"

# Request/response headers whose values must never be kept.
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-auth-token", "proxy-authorization"}

# JWT-ish and generic token/password patterns to scrub from bodies (best-effort).
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_TOKEN_FIELD = re.compile(r'("(?:token|password|passwordRepeat|access_token|refresh_token)"\s*:\s*")[^"]*(")')


def _redact_headers(headers: list[dict]) -> list[dict]:
    out = []
    for h in headers:
        name = (h.get("name") or "").lower()
        if name in _SENSITIVE_HEADERS:
            out.append({**h, "value": _REDACTED})
        else:
            out.append(h)
    return out


def _redact_text(text: str | None) -> str | None:
    if not text:
        return text
    text = _JWT.sub(_REDACTED, text)
    text = _TOKEN_FIELD.sub(rf"\1{_REDACTED}\2", text)
    return text


def redact_har(har: dict) -> dict:
    """Return a copy of a HAR with auth headers, cookies, and token/password bodies scrubbed."""
    log = har.get("log", {})
    entries = []
    for entry in log.get("entries", []):
        req = dict(entry.get("request", {}))
        res = dict(entry.get("response", {}))
        req["headers"] = _redact_headers(req.get("headers", []))
        res["headers"] = _redact_headers(res.get("headers", []))
        req["cookies"] = [{**c, "value": _REDACTED} for c in req.get("cookies", [])]
        res["cookies"] = [{**c, "value": _REDACTED} for c in res.get("cookies", [])]
        if "postData" in req and isinstance(req["postData"], dict):
            pd = dict(req["postData"])
            pd["text"] = _redact_text(pd.get("text"))
            req["postData"] = pd
        if "content" in res and isinstance(res["content"], dict):
            ct = dict(res["content"])
            ct["text"] = _redact_text(ct.get("text"))
            res["content"] = ct
        entries.append({**entry, "request": req, "response": res})
    return {**har, "log": {**log, "entries": entries}}


def evidence_dir(app_dir: str, scan_id: str) -> Path:
    """Absolute evidence directory for a scan (created if missing)."""
    d = Path(app_dir) / "evidence" / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def evidence_relpath(scan_id: str, filename: str = "active-scan.har") -> str:
    """Relative path recorded in a detection's evidence_path (matches requirements §7.2)."""
    return f"evidence/{scan_id}/{filename}"


def redact_har_file(path: str) -> None:
    """Redact a HAR file in place (read, scrub, overwrite)."""
    p = Path(path)
    har = json.loads(p.read_text())
    p.write_text(json.dumps(redact_har(har), indent=2))
