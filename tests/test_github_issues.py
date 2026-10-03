"""GitHub Issues publishing: grouping, rendering, and the create/update/reopen/close plan.

The GitHub API is replaced by a recorder, so these tests check exactly which requests a scan
would make. The lifecycle states are the diff's; this module only maps them to issue state.
"""

import json

import pytest

from detections import github_api, github_issues as gi

APP = "juice-shop"


def rec(rule="40018", status="new", endpoint="http://juice:3000/rest/search", parameter="q",
        severity="high", **extra):
    return {"app_id": APP, "scan_id": "20261002T204846Z", "rule_id": rule,
            "title": "SQL Injection", "severity": severity, "cwe_id": "CWE-89",
            "endpoint": endpoint, "parameter": parameter, "status": status,
            "description": "Input reaches a query.", "solution": "Use bound parameters.",
            "references": ["https://owasp.org/sqli"], **extra}


def issue(number, rule="40018", state="open", app=APP, state_reason=None, **extra):
    return {"number": number, "state": state, "state_reason": state_reason, "title": "old",
            "body": gi.marker(app, rule) + "\nold body", **extra}


class FakeGitHub:
    def __init__(self, monkeypatch, issues=(), labels=({"name": "dast"},)):
        self.calls = []
        self.issues, self.labels, self.next_number = list(issues), list(labels), 100
        monkeypatch.setattr(github_api, "paginate", self.paginate)
        monkeypatch.setattr(github_api, "request", self.request)

    def paginate(self, path):
        self.calls.append(("GET", path, None))
        return self.labels if "/labels" in path else self.issues

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "POST" and path.endswith("/issues"):
            self.next_number += 1
            return {"number": self.next_number}
        return {}

    def writes(self):
        return [(m, p, b) for m, p, b in self.calls if m != "GET"]


def sync(records, **kw):
    return gi.sync("o", "r", records, APP, pause=0, **kw)


def test_one_issue_per_rule_listing_every_location(monkeypatch):
    gh = FakeGitHub(monkeypatch)
    actions = sync([rec(endpoint="http://juice:3000/a"), rec(endpoint="http://juice:3000/b"),
                    rec(rule="10038", title="CSP Header Not Set", severity="medium",
                        parameter=None)])
    assert [a["op"] for a in actions] == ["create", "create"]
    posts = [b for m, p, b in gh.writes() if p == "/repos/o/r/issues"]
    assert [b["title"] for b in posts] == ["[DAST][high] SQL Injection — juice-shop",
                                           "[DAST][medium] CSP Header Not Set — juice-shop"]
    assert all(b["labels"] == ["dast"] for b in posts)
    assert "/a`" in posts[0]["body"] and "/b`" in posts[0]["body"]
    assert posts[0]["body"].startswith(gi.marker(APP, "40018"))


def test_body_has_fix_guidance_but_no_attack_or_response_evidence():
    g = gi.group([rec(attack="' OR 1=1--", evidence_excerpt="SQLITE_ERROR near users")])
    body = gi.body(APP, "40018", g["40018"], "S1", "refs/heads/main", "a" * 40)
    assert "Use bound parameters." in body and "<https://owasp.org/sqli>" in body
    assert "CWE-89" in body and "`refs/heads/main` @ `aaaaaaaaaaaa`" in body
    assert "OR 1=1" not in body and "SQLITE_ERROR" not in body


def test_target_text_cannot_break_out_of_its_table_cell():
    g = gi.group([rec(endpoint="http://juice:3000/x|y`z\n## injected", parameter="p")])
    row = [ln for ln in gi.body(APP, "40018", g["40018"], "S1").splitlines()
           if ln.startswith("| new")][0]
    assert "\\|" in row and "## injected" in row and "\n" not in row
    assert row.count(" | ") == 2          # status | endpoint | parameter: no extra column
    assert "`` " in row                  # fence longer than the backtick inside


def test_existing_open_issue_is_updated_not_duplicated(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(7)])
    actions = sync([rec(status="open")])
    assert [(a["op"], a["number"]) for a in actions] == [("update", 7)]
    (method, path, body), = gh.writes()
    assert (method, path) == ("PATCH", "/repos/o/r/issues/7")
    assert "state" not in body and "labels" not in body   # people's labels/state are kept


def test_unchanged_issue_is_left_alone(monkeypatch):
    g = gi.group([rec(status="open")])["40018"]
    current = {**issue(7), "title": gi.title(APP, g),
               "body": gi.body(APP, "40018", g, "20261002T204846Z")}
    gh = FakeGitHub(monkeypatch, [current])
    assert sync([rec(status="open")]) == []
    assert gh.writes() == []


def test_closed_issue_is_reopened_when_the_finding_returns(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(7, state="closed", state_reason="completed")])
    assert [a["op"] for a in sync([rec(status="new")])] == ["reopen"]
    comment, patch = gh.writes()
    assert comment[1] == "/repos/o/r/issues/7/comments"
    assert patch[2]["state"] == "open"


def test_issue_closed_as_not_planned_is_not_reopened(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(7, state="closed", state_reason="not_planned")])
    assert [a["op"] for a in sync([rec(status="open")])] == ["skip"]
    assert gh.writes() == []


def test_closes_only_when_every_location_is_resolved(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(7)])
    assert [a["op"] for a in sync([rec(status="resolved")])] == ["close"]
    patch = gh.writes()[-1]
    assert patch[2]["state"] == "closed" and patch[2]["state_reason"] == "completed"


@pytest.mark.parametrize("records", [
    [rec(status="resolved"), rec(status="not_scanned", endpoint="http://juice:3000/other")],
    [rec(status="not_scanned")],
    [],
], ids=["partly-not-scanned", "not-scanned", "absent"])
def test_not_rescanned_or_absent_findings_keep_the_issue_open(monkeypatch, records):
    gh = FakeGitHub(monkeypatch, [issue(7)])
    actions = sync(records)
    assert all(a["op"] != "close" for a in actions)
    assert all(b is None or b.get("state") != "closed" for _, _, b in gh.writes())


def test_suppressed_findings_neither_open_nor_close_an_issue(monkeypatch):
    gh = FakeGitHub(monkeypatch)
    assert sync([rec(status="suppressed")]) == []
    gh = FakeGitHub(monkeypatch, [issue(7)])
    assert all(a["op"] == "update" for a in sync([rec(status="suppressed")]))
    assert all(b.get("state") is None for _, _, b in gh.writes())


def test_issues_of_other_apps_and_pull_requests_are_ignored(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(5, app="other-app"),
                                  issue(6, pull_request={"url": "x"})])
    assert [a["op"] for a in sync([rec()])] == ["create"]
    assert gh.writes()[-1][1] == "/repos/o/r/issues"


def test_open_issue_wins_over_a_closed_duplicate():
    found = gi.index([issue(3), issue(9, state="closed")], APP)
    assert found[(APP, "40018")]["number"] == 3


def test_min_severity_filters_findings(monkeypatch):
    FakeGitHub(monkeypatch)
    actions = sync([rec(), rec(rule="10038", severity="low")], min_severity="medium")
    assert [a["rule"] for a in actions] == ["40018"]
    with pytest.raises(ValueError):
        gi.group([], "severe")


def test_label_is_created_only_when_missing(monkeypatch):
    gh = FakeGitHub(monkeypatch, labels=[])
    sync([rec()])
    assert ("POST", "/repos/o/r/labels", gi._LABEL_SPEC) in gh.writes()
    gh = FakeGitHub(monkeypatch)
    sync([rec()])
    assert all(p != "/repos/o/r/labels" for _, p, _ in gh.writes())


def test_dry_run_reads_but_never_writes(monkeypatch):
    gh = FakeGitHub(monkeypatch, [issue(7, state="closed")])
    actions = sync([rec(), rec(rule="10038")], dry_run=True)
    assert {a["op"] for a in actions} == {"reopen", "create"}
    assert gh.writes() == []
    assert "would " in gi.report(actions, "o", "r", dry_run=True)


def test_cli_prints_plan(monkeypatch, tmp_path, capsys):
    FakeGitHub(monkeypatch)
    path = tmp_path / "labeled.json"
    path.write_text(json.dumps([rec()]), encoding="utf-8")
    assert gi.main([str(path), "--app-id", APP, "--owner", "o", "--repo", "r", "--dry-run"]) == 0
    assert "would create 1" in capsys.readouterr().out


def test_api_errors_propagate_without_the_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secretvalue123")

    def boom(method, url, body, token):
        raise github_api.GitHubError(github_api._scrub(f"GitHub API → 403: bad {token}", token))
    monkeypatch.setattr(github_api, "_http", boom)
    with pytest.raises(github_api.GitHubError) as exc:
        gi.sync("o", "r", [rec()], APP, pause=0)
    assert "ghp_secretvalue123" not in str(exc.value)
