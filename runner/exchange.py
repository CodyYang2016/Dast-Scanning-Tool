"""The request ZAP sent and the response that proved the finding (W1-3).

A finding a developer can read but not replay gets argued about instead of fixed. ZAP keeps the
exact exchange behind every alert (`messageId`), but only until the next scan: each scan starts
a fresh ZAP session. So the exchange is fetched inside the same run, for high and medium
findings, redacted, and stored per fingerprint in the scan's evidence directory.

Everything stored goes through runner/redact.py first. A real Juice Shop attack carried the test
account's password in its body and a session cookie in its headers; neither may reach a file a
developer opens, an artifact, or GitHub.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

from runner.redact import redact_text

_FETCH_SEVERITIES = {"critical", "high", "medium"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}
_MAX_EXCHANGES = 500          # per scan; a noisy target must not turn one scan into 10k API calls
_REQUEST_BODY_CAP = 2000
_RESPONSE_WINDOW = 600        # characters either side of the evidence


def fetch_message(zap_api: str, message_id) -> dict:
    url = (zap_api.rstrip("/") + "/JSON/core/view/message/?"
           + urllib.parse.urlencode({"id": message_id}))
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode())["message"]


def request_line(message: dict) -> str | None:
    """`POST /rest/user/login` — method and path-with-query, host dropped, redacted."""
    first = (message.get("requestHeader") or "").split("\r\n", 1)[0].split("\n", 1)[0]
    parts = first.split(" ")
    if len(parts) < 2:
        return None
    target = urllib.parse.urlsplit(parts[1])
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    return redact_text(f"{parts[0]} {path}")


def response_status(message: dict) -> int | None:
    first = (message.get("responseHeader") or "").split("\n", 1)[0].split(" ")
    try:
        return int(first[1])
    except (IndexError, ValueError):
        return None


def _window(body: str, evidence: str | None) -> str:
    """The part of the response that proves the finding, not the whole page."""
    if not body:
        return ""
    at = body.find(evidence) if evidence else -1
    if at < 0:
        start, end = 0, min(len(body), 2 * _RESPONSE_WINDOW)
    else:
        start = max(0, at - _RESPONSE_WINDOW)
        end = min(len(body), at + len(evidence) + _RESPONSE_WINDOW)
    head = "[… cut]\n" if start > 0 else ""
    tail = "\n[… cut]" if end < len(body) else ""
    return head + body[start:end] + tail


def exchange_text(message: dict, evidence: str | None = None) -> str:
    """The stored, redacted exchange: full request (body capped), response cut around evidence."""
    req_body = message.get("requestBody") or ""
    if len(req_body) > _REQUEST_BODY_CAP:
        req_body = req_body[:_REQUEST_BODY_CAP] + "\n[… cut]"
    # Redact the response body as a whole BEFORE cutting it, so a secret is never split across
    # the window edge into an unrecognisable fragment.
    resp_body = _window(redact_text(message.get("responseBody") or ""), evidence)
    parts = [
        "--- request ---",
        redact_text((message.get("requestHeader") or "").rstrip()),
        "",
        redact_text(req_body),
        "",
        "--- response ---",
        redact_text((message.get("responseHeader") or "").rstrip()),
        "",
        resp_body,
    ]
    return "\n".join(parts).replace("\r\n", "\n") + "\n"


def attach(alerts, records, evidence_dir, evidence_relpath: str, fetch, cap: int = _MAX_EXCHANGES):
    """Fetch, store and reference the exchange for each high/medium finding.

    `alerts` and `records` are parallel — the normalizer yields one record per alert, in order.
    A failed fetch is counted and skipped: a scan must not fail because its bookkeeping did.
    Findings sharing a fingerprint share one file. Returns counts, including whether the cap bit.
    """
    if len(alerts) != len(records):
        raise ValueError("alerts and records must be parallel (one record per alert)")
    out_dir = Path(evidence_dir) / "messages"
    stored: dict[str, tuple] = {}
    counts = {"attached": 0, "failed": 0, "capped": False}
    # Most severe first, so a cap drops mediums rather than highs. In ZAP's own order ~520
    # Juice Shop mediums came first, spent the 500 cap, and 2 of 3 highs got no exchange.
    order = sorted(range(len(records)),
                   key=lambda i: _SEVERITY_ORDER.get(records[i].get("severity"), 99))
    for alert, rec in ((alerts[i], records[i]) for i in order):
        if rec.get("severity") not in _FETCH_SEVERITIES:
            continue
        fp = rec["fingerprint"]
        if fp not in stored:
            if len(stored) >= cap:
                counts["capped"] = True
                continue
            try:
                message = fetch(alert.get("messageId"))
            except Exception:
                counts["failed"] += 1
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{fp}.txt").write_text(exchange_text(message, alert.get("evidence")))
            stored[fp] = (request_line(message), response_status(message),
                          f"{evidence_relpath}/messages/{fp}.txt")
        line, status, path = stored[fp]
        if line:
            rec["request_line"] = line
        if status is not None:
            rec["response_status"] = status
        rec["exchange_path"] = path
        counts["attached"] += 1
    return counts
