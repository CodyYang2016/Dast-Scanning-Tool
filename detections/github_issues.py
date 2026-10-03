"""Publish DAST findings as GitHub Issues — for repositories without code scanning.

Code scanning on a private or internal repository needs GitHub Advanced Security. Issues need
nothing beyond the repository, so this is the publishing route when that licence is absent.

One issue per (application, rule), not per finding: a scan of a real application reports the
same missing header on hundreds of routes, and hundreds of issues is how a tracker gets ignored.
The issue lists every affected location, and it is found again on the next scan by a marker in
its body, so a rescan updates it rather than opening a duplicate:

    rule has new/open findings, no issue        -> create
    rule has new/open findings, issue closed    -> reopen  (unless closed as "not planned")
    rule's findings all resolved, issue open    -> close
    anything else                               -> update the body, or leave it alone

`resolved` is the lifecycle diff's coverage-aware verdict, so an issue is never closed for a
location this scan did not re-test; `not_scanned` locations keep it open. A rule with no records
at all in this scan is left alone: that says nothing about whether it was fixed.

Bodies carry what a developer needs to find and fix the problem. They do NOT carry attack
payloads or response excerpts: more people can read a repository's issues than its security
alerts, and that evidence stays in the scan's artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time

LABEL = "dast"
_LABEL_SPEC = {"name": LABEL, "color": "b60205", "description": "Finding from the DAST scanner"}
_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_RANK = {s: i for i, s in enumerate(_SEVERITIES)}
_MARKER = re.compile(r"<!-- dast-issue v1 app=(\S+) rule=(\S+) -->")
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]")
_MAX_ROWS = 100
_MAX_CELL = 200
_PAUSE = 1.0     # GitHub asks for a second between content-creating requests


def marker(app_id: str, rule_id: str) -> str:
    return (f"<!-- dast-issue v1 app={_SAFE_ID.sub('_', app_id)} "
            f"rule={_SAFE_ID.sub('_', str(rule_id))} -->")


def _key(app_id: str, rule_id: str) -> tuple[str, str]:
    m = _MARKER.search(marker(app_id, rule_id))
    return m.group(1), m.group(2)


def _cell(value) -> str:
    """Target-derived text as an inline code cell that can neither end the span nor the row."""
    text = " ".join(str(value).split())
    if len(text) > _MAX_CELL:
        text = text[:_MAX_CELL] + "…"
    text = text.replace("|", "\\|")
    longest = max((len(r) for r in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}" if longest else f"{fence}{text}{fence}"


def group(records, min_severity: str = "low") -> dict[str, dict]:
    """Records at or above `min_severity`, grouped by rule and split by lifecycle status."""
    if min_severity not in _RANK:
        raise ValueError(f"min severity must be one of {', '.join(_SEVERITIES)}, "
                         f"got {min_severity!r}")
    out: dict[str, dict] = {}
    for rec in records:
        if _RANK.get(rec.get("severity"), len(_RANK)) > _RANK[min_severity]:
            continue
        status = rec.get("status")
        bucket = "active" if status in ("new", "open") else status
        if bucket not in ("active", "not_scanned", "resolved", "suppressed"):
            continue
        g = out.setdefault(str(rec["rule_id"]), {"active": [], "not_scanned": [],
                                                 "resolved": [], "suppressed": []})
        g[bucket].append(rec)
    return out


def _severity(g: dict) -> str:
    recs = g["active"] + g["not_scanned"] + g["resolved"] + g["suppressed"]
    return min((r["severity"] for r in recs), key=lambda s: _RANK.get(s, len(_RANK)))


def _first(g: dict) -> dict:
    return (g["active"] + g["not_scanned"] + g["resolved"] + g["suppressed"])[0]


def title(app_id: str, g: dict) -> str:
    rec = _first(g)
    return f"[DAST][{_severity(g)}] {rec.get('title') or rec['rule_id']} — {app_id}"


def _table(heading: str, recs: list[dict], with_status: bool = False) -> list[str]:
    if not recs:
        return []
    rows = sorted(recs, key=lambda r: (r.get("status") or "", r.get("endpoint") or "",
                                       r.get("parameter") or ""))
    lines = [f"### {heading} ({len(rows)})", ""]
    lines.append("| Status | Endpoint | Parameter |" if with_status else "| Endpoint | Parameter |")
    lines.append("|---|---|---|" if with_status else "|---|---|")
    for r in rows[:_MAX_ROWS]:
        param = _cell(r["parameter"]) if r.get("parameter") else "—"
        cells = [_cell(r.get("endpoint") or "/"), param]
        lines.append("| " + " | ".join(([r.get("status") or ""] if with_status else []) + cells)
                     + " |")
    if len(rows) > _MAX_ROWS:
        lines.append(f"\n+{len(rows) - _MAX_ROWS} more in this scan's `labeled.json`.")
    return lines + [""]


def body(app_id: str, rule_id: str, g: dict, scan_id: str | None,
         ref: str | None = None, commit: str | None = None) -> str:
    rec = _first(g)
    facts = [f"**Severity:** {_severity(g)}", f"**ZAP rule:** {rule_id}"]
    if rec.get("cwe_id"):
        facts.append(f"**CWE:** {rec['cwe_id']}")
    facts.append(f"**Application:** `{app_id}`")
    scan = [f"**Last scan:** `{scan_id}`"] if scan_id else []
    if ref and commit:
        scan.append(f"**Deployed build:** `{ref}` @ `{commit[:12]}`")
    lines = [marker(app_id, rule_id), f"## {rec.get('title') or rule_id}", "",
             " · ".join(facts), ""]
    if scan:
        lines += [" · ".join(scan), ""]
    lines += _table("Affected locations", g["active"], with_status=True)
    lines += _table("Not re-tested in this scan", g["not_scanned"])
    lines += _table("Fixed in this scan", g["resolved"])
    lines += _table("Suppressed", g["suppressed"])
    if rec.get("description"):
        lines += ["### Description", "", rec["description"], ""]
    if rec.get("solution"):
        lines += ["### How to fix", "", "  \n".join(rec["solution"].splitlines()), ""]
    if rec.get("references"):
        lines += ["### References", ""] + [f"- <{u}>" for u in rec["references"]] + [""]
    lines += ["---", "_Kept up to date by the DAST scanner: each scan rewrites this description "
              "and the issue is closed once every location is re-tested and no longer found. "
              "Request/response evidence stays with the scan's artifacts. To accept a finding, "
              "record it in the app's `suppressions.yaml`, or close this issue as "
              "\"not planned\" so later scans do not reopen it._"]
    return "\n".join(lines) + "\n"


def index(issues, app_id: str) -> dict[tuple[str, str], dict]:
    """Existing scanner issues for this app by (app, rule). An open one wins over a closed one,
    then the newest."""
    out: dict[tuple[str, str], dict] = {}
    app = _SAFE_ID.sub("_", app_id)
    for issue in issues:
        if issue.get("pull_request"):
            continue
        m = _MARKER.search(issue.get("body") or "")
        if not m or m.group(1) != app:
            continue
        key = (m.group(1), m.group(2))
        cur = out.get(key)
        rank = (issue.get("state") == "open", issue.get("number", 0))
        if cur is None or rank > (cur.get("state") == "open", cur.get("number", 0)):
            out[key] = issue
    return out


def plan(groups: dict[str, dict], existing: dict, app_id: str, scan_id: str | None,
         ref: str | None = None, commit: str | None = None) -> list[dict]:
    """What to do to the repository's issues. Pure: no GitHub calls."""
    actions = []
    for rule_id in sorted(groups, key=lambda r: (_RANK.get(_severity(groups[r]), 9), r)):
        g = groups[rule_id]
        issue = existing.get(_key(app_id, rule_id))
        t, b = title(app_id, g), body(app_id, rule_id, g, scan_id, ref, commit)
        live = bool(g["active"])
        if issue is None:
            if live:
                actions.append({"op": "create", "rule": rule_id, "title": t, "body": b})
            continue
        number, state = issue["number"], issue.get("state")
        if state == "open" and not live and not g["not_scanned"] and g["resolved"]:
            actions.append({"op": "close", "rule": rule_id, "number": number, "title": t,
                            "body": b, "comment": f"Not found by scan `{scan_id}`, which "
                            "re-tested every location listed here. Closing as fixed."})
        elif state == "closed" and live:
            if issue.get("state_reason") == "not_planned":
                actions.append({"op": "skip", "rule": rule_id, "number": number,
                                "reason": "closed as not planned"})
            else:
                actions.append({"op": "reopen", "rule": rule_id, "number": number, "title": t,
                                "body": b, "comment": f"Found again by scan `{scan_id}`."})
        elif state == "open":
            if issue.get("title") != t or issue.get("body") != b:
                actions.append({"op": "update", "rule": rule_id, "number": number,
                                "title": t, "body": b})
    return actions


def _ensure_label(owner: str, repo: str) -> None:
    from detections import github_api
    names = {lb.get("name") for lb in github_api.paginate(f"/repos/{owner}/{repo}/labels?per_page=100")}
    if LABEL not in names:
        github_api.request("POST", f"/repos/{owner}/{repo}/labels", _LABEL_SPEC)


def existing_issues(owner: str, repo: str) -> list[dict]:
    from detections import github_api
    return github_api.paginate(
        f"/repos/{owner}/{repo}/issues?labels={LABEL}&state=all&per_page=100")


def execute(owner: str, repo: str, actions: list[dict], pause: float = _PAUSE) -> None:
    from detections import github_api
    base = f"/repos/{owner}/{repo}/issues"
    if any(a["op"] == "create" for a in actions):
        _ensure_label(owner, repo)
    for a in actions:
        op = a["op"]
        if op == "skip":
            continue
        if op == "create":
            a["number"] = github_api.request(
                "POST", base, {"title": a["title"], "body": a["body"], "labels": [LABEL]}
            ).get("number")
        else:
            patch = {"title": a["title"], "body": a["body"]}
            if op == "close":
                patch.update(state="closed", state_reason="completed")
            elif op == "reopen":
                patch.update(state="open")
            if a.get("comment"):
                github_api.request("POST", f"{base}/{a['number']}/comments",
                                   {"body": a["comment"]})
            github_api.request("PATCH", f"{base}/{a['number']}", patch)
        if pause:
            time.sleep(pause)


def sync(owner: str, repo: str, records, app_id: str, min_severity: str = "low",
         ref: str | None = None, commit: str | None = None, dry_run: bool = False,
         pause: float = _PAUSE) -> list[dict]:
    records = list(records)
    scan_ids = [r["scan_id"] for r in records if r.get("scan_id")]
    groups = group(records, min_severity)
    actions = plan(groups, index(existing_issues(owner, repo), app_id), app_id,
                   max(scan_ids) if scan_ids else None, ref, commit)
    if not dry_run:
        execute(owner, repo, actions, pause)
    return actions


def report(actions: list[dict], owner: str, repo: str, dry_run: bool = False) -> str:
    counts: dict[str, int] = {}
    for a in actions:
        counts[a["op"]] = counts.get(a["op"], 0) + 1
    verb = "would " if dry_run else ""
    lines = [f"issues ({owner}/{repo}): {verb}" + (", ".join(
        f"{op} {n}" for op, n in sorted(counts.items())) or "nothing to change")]
    for a in actions:
        ref = f"#{a['number']}" if a.get("number") else "new"
        lines.append(f"  {a['op']:<7} {ref:<6} {a.get('title') or a.get('reason', '')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Publish DAST findings as GitHub Issues, one per rule.")
    p.add_argument("records", help="Labeled detection records (labeled.json from the lifecycle diff)")
    p.add_argument("--app-id", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--min-severity", default="low", choices=_SEVERITIES,
                   help="Ignore findings below this severity (default: low)")
    p.add_argument("--ref", default=None, help="Ref of the deployed build, shown on each issue")
    p.add_argument("--commit", default=None, help="Commit of the deployed build, shown on each issue")
    p.add_argument("--dry-run", action="store_true",
                   help="Read existing issues and print the plan; change nothing")
    args = p.parse_args(argv)

    with open(args.records, encoding="utf-8") as fh:
        records = json.load(fh)
    actions = sync(args.owner, args.repo, records, args.app_id, args.min_severity,
                   args.ref, args.commit, args.dry_run)
    print(report(actions, args.owner, args.repo, args.dry_run))
    return 0


if __name__ == "__main__":
    sys.exit(main())
