"""Should this scan's findings fail the build? The report stage's policy gate (W3-2).

The scan stage can only say whether the scan was HEALTHY — authenticated, in scope, and actually
tested something. Whether findings should block a pipeline needs the lifecycle diff, the first
point that knows which findings are NEW. That distinction is the whole design: an existing
finding has already been seen and is somebody's decision; failing every build on it forever is
how a gate gets switched off, and a gate that has been switched off protects nothing.

Suppressed findings (W1-5) never block: suppression is the recorded decision not to.
"""

from __future__ import annotations

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
THRESHOLDS = ("critical", "high", "medium", "low", "none")


def policy_gate(records, fail_on: str) -> dict:
    """Fail when any NEW finding is at or above `fail_on`; `none` disables the gate."""
    if fail_on not in THRESHOLDS:
        raise ValueError(f"fail_on must be one of {', '.join(THRESHOLDS)}; got {fail_on!r}")
    if fail_on == "none":
        return {"passed": True, "fail_on": fail_on, "blocking": []}
    floor = _RANK[fail_on]
    blocking = [r for r in records
                if r.get("status") == "new" and _RANK.get(r.get("severity"), 0) >= floor]
    return {"passed": not blocking, "fail_on": fail_on, "blocking": blocking}
