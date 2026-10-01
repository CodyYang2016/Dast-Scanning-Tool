"""A one-page Markdown summary of a scan (W1-6).

A scan produces hundreds of findings, a coverage file, a settings file and two gates. Before this,
a person had to open all of them to answer the first questions anyone asks: did it pass, is the
scan itself trustworthy, what is new, and what did it not reach. This answers them on one page,
verdict first, and is what `dast report` appends to the GitHub Actions run page.

Pure: records, coverage and settings in, Markdown out. Endpoints, parameters and titles come from
the TARGET's traffic, so every one is escaped — a table cell must not be closable by a `|` and a
code span must not be closable by a backtick (the same rule as the SARIF message, W1-2).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter

from detections.sarif_export import _code

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(_SEVERITIES)}
# Statuses a reader acts on, in the order they matter. `resolved` is reported as a count only.
_STATUSES = (("new", "New"), ("open", "Open"), ("not_scanned", "Not scanned"),
             ("suppressed", "Suppressed"))
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")


def _text(value) -> str:
    """Plain text from the target, inert in Markdown and in a table cell."""
    return _MD_SPECIAL.sub(r"\\\1", str(value))


def _cell_code(value) -> str:
    """A code span that also survives a table cell: GitHub splits cells on `|` even in code."""
    return _code(str(value), markdown=True).replace("|", "\\|")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _session_line(session: dict | None) -> tuple[str, bool]:
    """(description, is_problem)."""
    s = session or {}
    alive = s.get("alive_throughout")
    if alive is True:
        return f"alive throughout ({_plural(s.get('checks', 0), 'check')})", False
    if alive is False:
        return f"**LOST** after {s.get('lost_after_s', '?')} s", True
    return f"not verified — {s.get('reason') or 'no usable probe'}", False


def _verdict(settings: dict, coverage: dict) -> list[str]:
    gate = (settings or {}).get("gate") or {}
    fail_on = ((gate.get("fail_on") or {}).get("value")) or "high"

    # A scan that was not healthy says so before any finding is read: its findings describe
    # something other than the logged-in application that was meant to be tested.
    problems = []
    session = coverage.get("session")
    if (session or {}).get("alive_throughout") is False:
        problems.append(f"the session was lost after {session.get('lost_after_s', '?')} s — "
                        f"findings after that point describe a logged-out application")
    if not coverage.get("routes"):
        problems.append("no routes were tested")
    if (coverage.get("app_state") or {}).get("authenticated") is False:
        problems.append("the scan did not authenticate")
    health = coverage.get("health_gate") or {}
    unhealthy = bool(problems) or health.get("passed") is False

    lines = []
    if gate.get("passed") is False:
        n = gate.get("blocking", 0)
        lines.append(f"**Verdict: FAILED** — {_plural(n, 'new finding')} at or above "
                     f"{fail_on}.")
    elif unhealthy:
        # "Passed" here would be read as "clean", from a scan that could not see the app.
        lines.append(f"**Verdict: NOT RELIABLE** — no new findings at or above {fail_on}, but "
                     f"the scan itself was unhealthy, so that says little.")
    elif "passed" not in gate:
        lines.append("**Verdict: not evaluated** — no policy gate ran on this scan.")
    elif fail_on == "none":
        lines.append("**Verdict: Passed** — the policy gate is disabled (`fail_on: none`).")
    else:
        lines.append(f"**Verdict: Passed** — no new findings at or above {fail_on}.")
    if unhealthy:
        why = "; ".join(problems) or "see the scan log"
        lines.append(f"**Scan health: UNHEALTHY** — {why}.")
    if coverage.get("zap_api_open"):
        lines.append("**Warning:** ZAP's API answered without a key — anyone who can reach it "
                     "can drive it.")
    return lines


def _counts(records: list[dict]) -> list[str]:
    grid = Counter((r.get("severity"), r.get("status")) for r in records)
    resolved = sum(1 for r in records if r.get("status") == "resolved")
    header = "| Severity | " + " | ".join(label for _, label in _STATUSES) + " |"
    rows = [header, "|---|" + "---:|" * len(_STATUSES)]
    for sev in _SEVERITIES:
        cells = [grid[(sev, st)] for st, _ in _STATUSES]
        if any(cells):
            rows.append(f"| {sev.capitalize()} | " + " | ".join(map(str, cells)) + " |")
    totals = [sum(grid[(sev, st)] for sev in _SEVERITIES) for st, _ in _STATUSES]
    rows.append("| **Total** | " + " | ".join(map(str, totals)) + " |")
    if resolved:
        rows.append("")
        rows.append(f"{_plural(resolved, 'finding')} resolved since the last scan (its route "
                    f"and rule were tested again and it was not found).")
    return rows


def _new_findings(records: list[dict], max_new: int) -> list[str]:
    # Findings that differ only in what the fingerprint saw (e.g. one per fuzzed User-Agent)
    # are one line to a reader: grouped, with a count.
    groups = Counter((r.get("severity"), r.get("title") or r.get("rule_id"),
                      r.get("endpoint") or "", r.get("parameter") or "")
                     for r in records if r.get("status") == "new")
    if not groups:
        return ["None."]
    ordered = sorted(groups.items(), key=lambda kv: (_RANK.get(kv[0][0], 99), kv[0][1:]))
    total = sum(groups.values())
    rows = ["| Severity | Finding | Where | Parameter |", "|---|---|---|---|"]
    for (sev, title, endpoint, param), n in ordered[:max_new]:
        times = f" ×{n}" if n > 1 else ""
        rows.append(f"| {_text((sev or '').capitalize())} | {_text(title)}{times} "
                    f"| {_cell_code(endpoint)} | {_cell_code(param) if param else ''} |")
    rest = sum(n for _, n in ordered[max_new:])
    if rest:
        rows.append("")
        rows.append(f"…and {rest} more of {total} in the SARIF and `labeled.json`.")
    return rows


def _top(records: list[dict], key, n: int = 5) -> list[tuple[str, int]]:
    live = [r for r in records if r.get("status") in ("new", "open")]
    return Counter(key(r) for r in live).most_common(n)


def _coverage(coverage: dict, reachability: dict | None) -> list[str]:
    lines = [f"- Tested **{_plural(len(coverage.get('routes') or []), 'route')}** with "
             f"**{_plural(len(coverage.get('rules') or []), 'rule')}**."]
    truncated = coverage.get("truncated_rules") or []
    if truncated:
        lines.append(f"- Stopped early by the per-rule time limit: "
                     f"{', '.join(_cell_code(t) for t in truncated)} — their routes are not "
                     f"fully tested.")
    if reachability and reachability.get("exposed"):
        line = (f"- Reached {reachability['exercised']}/{reachability['exposed']} exposed "
                f"parameters")
        gaps = reachability.get("gaps") or {}
        if gaps:
            shown = "; ".join(f"{_cell_code(route)} ({', '.join(map(_text, params))})"
                              for route, params in sorted(gaps.items())[:5])
            more = f" and {len(gaps) - 5} more" if len(gaps) > 5 else ""
            line += f" — never sent: {shown}{more}"
        lines.append(line + ".")
    excluded = coverage.get("excluded") or []
    if excluded:
        lines.append(f"- Excluded from the scan: {', '.join(_cell_code(e) for e in excluded)}.")
    ex = coverage.get("exchanges") or {}
    if ex:
        line = f"- Request/response stored for {_plural(ex.get('attached', 0), 'finding')}"
        if ex.get("failed"):
            line += f", {ex['failed']} could not be fetched"
        if ex.get("capped"):
            line += " (capped — lower-severity findings past the cap have none)"
        lines.append(line + ".")
    session_desc, _ = _session_line(coverage.get("session"))
    lines.append(f"- Session: {session_desc}.")
    if "zap_api_open" in coverage:
        api = "**OPEN** (no key needed)" if coverage["zap_api_open"] else "key required"
        lines.append(f"- ZAP API: {api}.")
    ctx = coverage.get("zap_context") or {}
    if ctx.get("include"):
        lines.append(f"- ZAP was confined to: {', '.join(_cell_code(i) for i in ctx['include'])}.")
    policy = coverage.get("policy") or {}
    if policy:
        lines.append(f"- Policy: strength {policy.get('attack_strength', '?')}, threshold "
                     f"{policy.get('alert_threshold', '?')}, write mode "
                     f"{policy.get('write_mode', '?')}, throttle "
                     f"{_text(policy.get('throttle', 'zap defaults'))}.")
    return lines


def _suppressions(records: list[dict]) -> list[str]:
    active = [r for r in records if r.get("status") == "suppressed"]
    expired = [r for r in records if (r.get("suppression") or {}).get("expired")]
    if not (active or expired):
        return []
    lines = ["", "## Suppressions", ""]
    if active:
        lines.append(f"- {_plural(len(active), 'finding')} suppressed by a recorded decision.")
    for r in expired:
        lines.append(f"- expired {r['suppression'].get('expires', '?')}: "
                     f"[{_text(r.get('severity'))}] {_text(r.get('title'))} — "
                     f"{_cell_code(r.get('endpoint', ''))} counts again.")
    return lines


def _published(settings: dict, uploaded: bool | None) -> list[str]:
    gh = (settings or {}).get("github") or {}
    val = lambda k: (gh.get(k) or {}).get("value")  # noqa: E731
    if not (val("owner") and val("repo")):
        return ["", "## Results", "", "- No GitHub destination configured; SARIF written locally."]
    state = {True: "uploaded", False: "not uploaded (`--upload` publishes)", None: ""}[uploaded]
    line = f"- GitHub: `{val('owner')}/{val('repo')}`, category `{val('category')}`"
    if val("ref"):
        line += f", attributed to `{val('ref')}`"
        if val("commit"):
            line += f" @ `{str(val('commit'))[:12]}`"
    return ["", "## Results", "", line + (f" — {state}." if state else ".")]


def render(records: list[dict], coverage: dict, settings: dict, *, app_id: str, scan_id: str,
           reachability: dict | None = None, uploaded: bool | None = None,
           max_new: int = 20) -> str:
    coverage = coverage or {}
    out = [f"# DAST scan — {_text(app_id)}", "", f"Scan `{scan_id}`", ""]
    out += "\n\n".join(_verdict(settings, coverage)).split("\n")   # one paragraph each
    out += ["", "## Findings", ""] + _counts(records)
    out += ["", "## New findings", ""] + _new_findings(records, max_new)
    rules = _top(records, lambda r: r.get("title") or r.get("rule_id"))
    routes = _top(records, lambda r: r.get("endpoint") or "")
    if rules:
        out += ["", "## Where the open findings are", "", "| Rule | Open |", "|---|---:|"]
        out += [f"| {_text(name)} | {n} |" for name, n in rules]
        out += ["", "| Route | Open |", "|---|---:|"]
        out += [f"| {_cell_code(name)} | {n} |" for name, n in routes]
    out += ["", "## Coverage", ""] + _coverage(coverage, reachability)
    out += _suppressions(records)
    out += _published(settings, uploaded)
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Render a one-page Markdown summary of a scan.")
    p.add_argument("labeled", help="Labelled detection records (JSON array)")
    p.add_argument("--coverage", required=True)
    p.add_argument("--settings", default=None, help="settings.json from `dast report`, if any")
    p.add_argument("--app-id", required=True)
    p.add_argument("--scan-id", default="")
    p.add_argument("-o", "--out", default="-")
    args = p.parse_args(argv)
    records = json.load(open(args.labeled))
    settings = json.load(open(args.settings)) if args.settings else {}
    scan_id = args.scan_id or max((r.get("scan_id") or "" for r in records), default="")
    page = render(records, json.load(open(args.coverage)), settings,
                  app_id=args.app_id, scan_id=scan_id)
    if args.out == "-":
        sys.stdout.write(page)
    else:
        with open(args.out, "w") as fh:
            fh.write(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
