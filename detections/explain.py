"""Why did a finding disappear? (W6-9)

The lifecycle diff gives the honest label — `resolved` when the route and rule were
exercised, `not_scanned` when they were not — and never the reason. That left the operator
to do forensics by hand: working out why five high-severity findings became zero took an hour
of querying ZAP and reading container logs, and the answer (the application was not in the
same state) existed in no artifact at all.

Everything needed to answer it is now recorded in `coverage.json`: the routes exercised, the
rules enabled, what each rule actually did, whether any ran out of time, whether the scan was
allowed to write, and a digest of the application's own state. This module turns that into an
attribution, most specific cause first:

    route_not_covered      this scan never visited the finding's route
    parameter_not_exercised  the route was visited, but never with this parameter
    rule_not_enabled       the rule that found it was switched off
    rule_truncated         the rule ran out of time before finishing
    app_state_changed      the application answered differently than last time
    scan_changed_the_app   this scan was allowed to write, so state drifted under it
    rule_found_nothing     the rule ran, sent requests, and raised nothing — but sent few
    fixed                  the rule ran properly against the route and the finding is gone

Only the last is a claim that something was fixed, and it carries the evidence for it.
"""

from __future__ import annotations


def _route_covered(record: dict, coverage: dict) -> bool:
    return record.get("endpoint") in set(coverage.get("routes") or [])


def _parameter_exercised(record: dict, coverage: dict) -> bool:
    """Was this finding's own parameter sent, not merely its route visited? (W6-10)

    Coverage artifacts written before parameters were recorded have no `route_params`, and
    those keep their previous answer rather than turning every old finding unscanned.
    """
    params = coverage.get("route_params")
    if not params:
        return True
    parameter = record.get("parameter")
    if not parameter:
        return True                       # header and page-level findings have no parameter
    return parameter in set(params.get(record.get("endpoint"), []))


def _state_difference(current: dict, previous: dict) -> str | None:
    """The first probe whose response changed between the two scans, if state was recorded."""
    now = (current.get("app_state") or {}).get("probes") or {}
    before = (previous.get("app_state") or {}).get("probes") or {}
    if not now or not before:
        return None            # nothing recorded last time: do not invent a difference
    for path, snapshot in now.items():
        was = before.get(path)
        if was and (was.get("digest"), was.get("status")) != (snapshot.get("digest"),
                                                              snapshot.get("status")):
            return (f"{path} answered differently (status {was.get('status')}→"
                    f"{snapshot.get('status')}, body digest changed)")
    return None


def explain_one(record: dict, coverage: dict, previous_coverage: dict) -> dict:
    """Attribute a single disappeared finding. Most specific cause wins."""
    rule = str(record.get("rule_id"))
    outcome = (coverage.get("rule_outcomes") or {}).get(rule, {})

    if not _route_covered(record, coverage):
        reason, detail = "route_not_covered", (
            f"{record.get('endpoint')} was not among the {len(coverage.get('routes') or [])} "
            f"routes this scan exercised, so nothing looked for it")
    elif not _parameter_exercised(record, coverage):
        seen = (coverage.get("route_params") or {}).get(record.get("endpoint")) or []
        reason, detail = "parameter_not_exercised", (
            f"{record.get('endpoint')} was visited, but never with the parameter "
            f"'{record.get('parameter')}' — only {seen or 'no parameters'} were sent, so "
            f"nothing tested it")
    elif rule not in set(coverage.get("rules") or []):
        reason, detail = "rule_not_enabled", f"rule {rule} was not enabled for this scan"
    elif rule in set(coverage.get("truncated_rules") or []):
        reason, detail = "rule_truncated", (
            f"rule {rule} was stopped early: {outcome.get('state', 'exceeded its budget')}")
    elif (diff := _state_difference(coverage, previous_coverage)):
        reason, detail = "app_state_changed", (
            f"the application was not in the same condition: {diff}")
    elif (coverage.get("policy") or {}).get("write_mode") == "allow":
        reason, detail = "scan_changed_the_app", (
            "this scan was allowed to submit writes, so the application's state moved "
            "underneath the comparison; no fix can be claimed from it")
    elif outcome and outcome.get("requests", 0) < 10:
        reason, detail = "rule_found_nothing", (
            f"rule {rule} ran but sent only {outcome.get('requests')} requests — too few to "
            f"treat its silence as evidence")
    else:
        reason, detail = "fixed", (
            f"rule {rule} ran to completion against {record.get('endpoint')} "
            f"({outcome.get('requests', 'some')} requests) and raised nothing")

    return {"fingerprint": record.get("fingerprint"), "endpoint": record.get("endpoint"),
            "rule_id": rule, "severity": record.get("severity"), "title": record.get("title"),
            "reason": reason, "detail": detail}


def explain_disappearance(previous_records, current_records, coverage: dict,
                          previous_coverage: dict | None = None) -> list[dict]:
    """Attribute every finding present in the previous scan and absent from this one."""
    current = {r["fingerprint"] for r in current_records}
    return [explain_one(r, coverage, previous_coverage or {})
            for r in previous_records if r["fingerprint"] not in current]


def summarize(explanations: list[dict]) -> dict:
    """Counts by reason, for a one-line answer to "what happened to the findings?"."""
    out: dict[str, int] = {}
    for e in explanations:
        out[e["reason"]] = out.get(e["reason"], 0) + 1
    return out
