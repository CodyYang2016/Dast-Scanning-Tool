"""Triage: recorded decisions about findings, applied after the lifecycle diff (W1-5).

The lifecycle diff says what a finding IS — new, open, resolved, not scanned. Triage records what
people DECIDED about it: a false positive, an accepted risk, won't fix, test data. Without it a
dismissed false positive stays `open` in our records, counts and gate forever.

Decisions live in a reviewable file, security/dast/<app>/suppressions.yaml, keyed by fingerprint.
Applying them is a view over the diff, not part of it: the lifecycle state keeps the true status,
and a suppressed record carries what it `was`. Suppressed findings are still published — dropping
a result is exactly how GitHub closes an alert as "fixed" — and accepted risk must expire.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
from pathlib import Path

import jsonschema
import yaml

from detections.fingerprint import fingerprint, payload_family

_SCHEMA = Path(__file__).resolve().parent.parent / "contracts" / "suppressions.schema.json"
_SUPPRESSIBLE = {"new", "open", "not_scanned"}       # a resolved finding is fixed, not suppressed
_GITHUB_REASON = {"false positive": "false_positive", "won't fix": "wont_fix",
                  "used in tests": "test_data"}
_REVIEW_AFTER = dt.timedelta(days=90)
_PARAM_IN_MESSAGE = re.compile(r"\bin parameter `([^`]*)`")


def validate(doc: dict) -> None:
    jsonschema.validate(doc, json.loads(_SCHEMA.read_text(encoding="utf-8")))


def load(path) -> list[dict]:
    """Suppressions from a file, validated; a missing file means none."""
    p = Path(path)
    if not p.exists():
        return []
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {"suppressions": []}
    validate(doc)
    return doc["suppressions"]


def _expired(entry: dict, today: dt.date) -> bool:
    return bool(entry.get("expires")) and dt.date.fromisoformat(str(entry["expires"])) < today


def apply(records, suppressions, today: dt.date) -> list[dict]:
    """A copy of `records` with active suppressions applied. Pure; inputs are not mutated."""
    by_fp = {s["fingerprint"]: s for s in suppressions}
    out = []
    for rec in records:
        entry = by_fp.get(rec.get("fingerprint"))
        if entry is None or rec.get("status") not in _SUPPRESSIBLE:
            out.append(rec)
            continue
        rec = copy.deepcopy(rec)
        info = {"reason": entry["reason"], "justification": entry["justification"]}
        for k in ("owner", "expires"):
            if entry.get(k):
                info[k] = str(entry[k])
        if _expired(entry, today):
            rec["suppression"] = {**info, "expired": True}   # counts again, and says why
        else:
            rec["suppression"] = {**info, "expired": False, "was": rec["status"]}
            rec["status"] = "suppressed"
        out.append(rec)
    return out


def _alert_fingerprint_candidates(alert: dict, records) -> list[dict]:
    """Our records this GitHub alert could be. Exact when the message names its parameter."""
    rule = str(alert["rule"]["id"])
    inst = alert.get("most_recent_instance") or {}
    path = (inst.get("location") or {}).get("path")
    named = _PARAM_IN_MESSAGE.search((inst.get("message") or {}).get("text") or "")
    if named:
        fp = fingerprint(rule, path, named.group(1), payload_family(rule))
        return [r for r in records if r.get("fingerprint") == fp]
    return [r for r in records if str(r.get("rule_id")) == rule and r.get("endpoint") == path]


def from_github(alerts, records, existing, today: dt.date) -> dict:
    """Proposed suppressions from GitHub dismissals — for review, never applied automatically.

    GitHub's API does not expose SARIF fingerprints, so each dismissed alert is matched by
    recomputing ours from its rule, location and the parameter named in its message. An alert
    whose message predates that (no parameter) matches only when its rule and route identify a
    single finding; anything else is listed as ambiguous or unmatched rather than guessed.
    """
    have = {s["fingerprint"] for s in existing}
    seen: set[str] = set()
    proposed, ambiguous, unmatched = [], [], []
    for alert in alerts:
        if alert.get("state") != "dismissed":
            continue
        candidates = _alert_fingerprint_candidates(alert, records)
        unique = {r["fingerprint"]: r for r in candidates}
        brief = {"number": alert.get("number"), "rule_id": str(alert["rule"]["id"]),
                 "path": ((alert.get("most_recent_instance") or {}).get("location") or {}).get("path")}
        if not unique:
            unmatched.append(brief)
            continue
        if len(unique) > 1:
            ambiguous.append({**brief, "candidates": sorted(unique)})
            continue
        (fp, rec), = unique.items()
        if fp in have or fp in seen:
            continue
        seen.add(fp)
        reason = _GITHUB_REASON.get(alert.get("dismissed_reason"), "false_positive")
        who = (alert.get("dismissed_by") or {}).get("login")
        entry = {
            "fingerprint": fp,
            "reason": reason,
            "justification": alert.get("dismissed_comment")
                             or f"Dismissed on GitHub ({alert.get('dismissed_reason')}) by {who}",
            "rule_id": str(rec.get("rule_id")),
            "endpoint": rec.get("endpoint"),
            "parameter": rec.get("parameter"),
            "github_alert": alert.get("number"),
        }
        if who:
            entry["owner"] = who
        if reason in ("accepted_risk", "wont_fix"):
            # The contract requires a review date; propose one rather than leave it invalid.
            entry["expires"] = (today + _REVIEW_AFTER).isoformat()
        proposed.append(entry)
    return {"proposed": proposed, "ambiguous": ambiguous, "unmatched": unmatched}
