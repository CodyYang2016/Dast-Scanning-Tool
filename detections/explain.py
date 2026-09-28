"""Explain why a finding disappeared from a later scan."""

from __future__ import annotations


def _route_covered(record: dict, coverage: dict) -> bool:
    return record.get("endpoint") in set(coverage.get("routes") or [])


def _excluded(record: dict, coverage: dict) -> str | None:
    import re
    endpoint = record.get("endpoint") or ""
    for pattern in coverage.get("excluded") or []:
        try:
            if re.match(pattern, endpoint) or re.search(pattern, endpoint):
                return pattern
        except re.error:
            continue
    return None


def _parameter_exercised(record: dict, coverage: dict) -> bool:
    params = coverage.get("route_params")
    if not params or not record.get("parameter"):
        return True
    return record["parameter"] in set(params.get(record.get("endpoint"), []))


def _state_difference(current: dict, previous: dict) -> str | None:
    now = (current.get("app_state") or {}).get("probes") or {}
    before = (previous.get("app_state") or {}).get("probes") or {}
    if not now or not before:
        return None
    for path, snapshot in now.items():
        old = before.get(path)
        if old and (old.get("digest"), old.get("status")) != (
                snapshot.get("digest"), snapshot.get("status")):
            return (f"{path} answered differently (status {old.get('status')} to "
                    f"{snapshot.get('status')}, body digest changed)")
    return None


def explain_one(record: dict, coverage: dict, previous_coverage: dict) -> dict:
    """Attribute a disappeared finding, preferring concrete coverage causes."""
    rule = str(record.get("rule_id"))
    outcome = (coverage.get("rule_outcomes") or {}).get(rule, {})
    if (pattern := _excluded(record, coverage)):
        reason, detail = "route_excluded", f"{record.get('endpoint')} was excluded by {pattern!r}"
    elif not _route_covered(record, coverage):
        reason, detail = "route_not_covered", f"{record.get('endpoint')} was not exercised"
    elif not _parameter_exercised(record, coverage):
        seen = (coverage.get("route_params") or {}).get(record.get("endpoint")) or []
        reason, detail = "parameter_not_exercised", (
            f"parameter {record.get('parameter')!r} was not sent; only {seen or 'none'} were sent")
    elif rule not in set(coverage.get("rules") or []):
        reason, detail = "rule_not_enabled", f"rule {rule} was not enabled"
    elif rule in set(coverage.get("truncated_rules") or []):
        reason, detail = "rule_truncated", f"rule {rule} stopped early"
    elif (diff := _state_difference(coverage, previous_coverage)):
        reason, detail = "app_state_changed", diff
    elif (coverage.get("policy") or {}).get("write_mode") == "allow":
        reason, detail = "scan_changed_the_app", "scan writes changed application state"
    elif outcome and outcome.get("requests", 0) < 10:
        reason, detail = "rule_found_nothing", f"rule {rule} sent too few requests"
    else:
        reason, detail = "fixed", f"rule {rule} ran against {record.get('endpoint')} and found nothing"
    return {"fingerprint": record.get("fingerprint"), "endpoint": record.get("endpoint"),
            "rule_id": rule, "severity": record.get("severity"), "title": record.get("title"),
            "reason": reason, "detail": detail}


def explain_disappearance(previous_records, current_records, coverage: dict,
                          previous_coverage: dict | None = None) -> list[dict]:
    current = {r["fingerprint"] for r in current_records}
    return [explain_one(r, coverage, previous_coverage or {}) for r in previous_records
            if r["fingerprint"] not in current]


def summarize(explanations: list[dict]) -> dict:
    out: dict[str, int] = {}
    for explanation in explanations:
        reason = explanation["reason"]
        out[reason] = out.get(reason, 0) + 1
    return out
