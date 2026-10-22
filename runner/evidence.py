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
import sys
from pathlib import Path

# Request/response headers whose values must never be kept — one list, shared with redact_text.
from runner.redact import REDACTED as _REDACTED
from runner.redact import SENSITIVE_HEADERS as _SENSITIVE_HEADERS
from runner.redact import _is_secret_key, redact_text

# One redactor, not two that drift apart: everything below delegates to runner.redact, the same
# code that cleans stored exchanges and what the LLM sees. (This module used to keep its own JWT
# and JSON-key patterns, which missed form logins, query tokens and CSRF headers.)


def _redact_headers(headers: list[dict]) -> list[dict]:
    out = []
    for h in headers or []:
        name = (h.get("name") or "").lower()
        if name in _SENSITIVE_HEADERS:
            out.append({**h, "value": _REDACTED})
        else:                                   # e.g. a Referer or Location carrying a token
            out.append({**h, "value": redact_text(h.get("value"))})
    return out


def _redact_params(params: list[dict]) -> list[dict]:
    """queryString[] and postData.params[]: a secret-named value goes; others are pattern-scrubbed."""
    out = []
    for p in params or []:
        if _is_secret_key(p.get("name")):
            out.append({**p, "value": _REDACTED})
        else:
            out.append({**p, "value": redact_text(p.get("value"))})
    return out


def redact_har(har: dict) -> dict:
    """A copy of a HAR with credentials scrubbed from headers, cookies, URLs, query strings,
    form parameters and bodies. Shape is kept: methods, paths, statuses and header names."""
    log = har.get("log", {})
    entries = []
    for entry in log.get("entries", []):
        req = dict(entry.get("request", {}))
        res = dict(entry.get("response", {}))
        req["url"] = redact_text(req.get("url"))
        req["headers"] = _redact_headers(req.get("headers", []))
        res["headers"] = _redact_headers(res.get("headers", []))
        req["queryString"] = _redact_params(req.get("queryString", []))
        req["cookies"] = [{**c, "value": _REDACTED} for c in req.get("cookies", [])]
        res["cookies"] = [{**c, "value": _REDACTED} for c in res.get("cookies", [])]
        if isinstance(req.get("postData"), dict):
            pd = dict(req["postData"])
            pd["text"] = redact_text(pd.get("text"))
            if "params" in pd:
                pd["params"] = _redact_params(pd.get("params"))
            req["postData"] = pd
        if isinstance(res.get("content"), dict):
            ct = dict(res["content"])
            ct["text"] = redact_text(ct.get("text"))
            res["content"] = ct
        if "redirectURL" in res:
            res["redirectURL"] = redact_text(res.get("redirectURL"))
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
    har = json.loads(p.read_text(encoding="utf-8"))
    p.write_text(json.dumps(redact_har(har), indent=2), encoding="utf-8")


def unredacted(directory) -> list[Path]:
    """Evidence files under `directory` that redaction would still change: every HAR and every
    stored exchange (messages/). Empty means the evidence is safe to publish."""
    root = Path(directory)
    dirty = []
    for har in sorted(root.rglob("*.har")):
        try:
            data = json.loads(har.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            dirty.append(har)                    # unreadable: can't vouch for it
            continue
        if redact_har(data) != data:
            dirty.append(har)
    for msg in sorted(p for p in root.rglob("*") if p.is_file() and p.parent.name == "messages"):
        try:
            text = msg.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            dirty.append(msg)
            continue
        if redact_text(text) != text:
            dirty.append(msg)
    return dirty


def main(argv: list[str] | None = None) -> int:
    """`python -m runner.evidence --check DIR`: exit 1 naming any file that still holds a secret."""
    import argparse
    p = argparse.ArgumentParser(description=main.__doc__)
    p.add_argument("--check", required=True, metavar="DIR")
    args = p.parse_args(argv)
    dirty = unredacted(args.check)
    for f in dirty:
        print(f"not redacted: {f}", file=sys.stderr)
    if dirty:
        print(f"{len(dirty)} evidence file(s) still hold secrets — do not publish them.",
              file=sys.stderr)
        return 1
    print(f"evidence clean: {args.check}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
