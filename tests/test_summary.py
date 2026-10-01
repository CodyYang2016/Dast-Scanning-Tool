"""The per-scan summary (W1-6): what a person reads first on the Actions run page."""

from detections.summary import render


def _rec(sev, status="new", title="SQL Injection", endpoint="http://app/a", **kw):
    return {"severity": sev, "status": status, "title": title, "endpoint": endpoint,
            "rule_id": kw.pop("rule_id", "40018"), "fingerprint": kw.pop("fp", title + endpoint),
            **kw}


COV = {"routes": ["/a", "/b"], "rules": ["40018", "40012"], "truncated_rules": ["40019"],
       "excluded": ["(?i).*logout.*"], "exchanges": {"attached": 3, "failed": 0, "capped": False},
       "zap_api_open": False, "session": {"method": "probe", "checks": 4,
                                          "alive_throughout": True},
       "health_gate": {"passed": True}}
SETTINGS = {"gate": {"fail_on": {"value": "high", "source": "default"}, "passed": False,
                     "blocking": 1},
            "github": {"owner": {"value": "o"}, "repo": {"value": "r"},
                       "category": {"value": "dast/app"}}}


def test_the_verdict_comes_first_and_names_the_threshold():
    md = render([_rec("high")], COV, SETTINGS, app_id="app", scan_id="S1")
    head = md.split("\n## ")[0]
    assert "FAILED" in head and "1 new finding at or above high" in head


def test_a_passing_gate_says_so():
    s = {**SETTINGS, "gate": {**SETTINGS["gate"], "passed": True, "blocking": 0}}
    md = render([_rec("medium")], COV, s, app_id="app", scan_id="S1")
    assert "Passed" in md.split("\n## ")[0]


def test_an_unhealthy_scan_is_stated_before_the_findings():
    cov = {**COV, "session": {"method": "probe", "alive_throughout": False, "lost_after_s": 91},
           "health_gate": {"passed": False}}
    head = render([], cov, SETTINGS, app_id="app", scan_id="S1").split("\n## ")[0]
    assert "session was lost after 91 s" in head


def test_counts_by_severity_and_status():
    recs = [_rec("high"), _rec("high", "open", endpoint="http://app/b"),
            _rec("low", "suppressed", title="X", suppression={"justification": "ok"})]
    md = render(recs, COV, SETTINGS, app_id="app", scan_id="S1")
    assert "| High | 1 | 1 |" in md
    assert "| **Total** | 1 | 1 |" in md


def test_new_findings_are_listed_most_severe_first():
    recs = [_rec("low", title="Cookie"), _rec("high", title="SQLi", parameter="id")]
    md = render(recs, COV, SETTINGS, app_id="app", scan_id="S1")
    new = md.split("## New findings")[1]
    assert new.index("SQLi") < new.index("Cookie") and "`id`" in new


def test_the_new_list_is_capped_and_says_how_many_more():
    recs = [_rec("medium", endpoint=f"http://app/{i}") for i in range(30)]
    md = render(recs, COV, SETTINGS, app_id="app", scan_id="S1", max_new=10)
    assert "and 20 more of 30" in md


def test_target_text_cannot_break_the_table_or_inject_markdown():
    rec = _rec("high", endpoint="http://app/x|y`[click](http://evil)`", parameter="a|b")
    md = render([rec], COV, SETTINGS, app_id="app", scan_id="S1")
    row = [l for l in md.splitlines() if "http://app/x" in l][0]
    assert "x\\|y" in row and "a\\|b" in row
    assert row.count("|") - row.count("\\|") == 5          # 4 columns: the row is intact
    assert "``" in row                                    # the backtick is fenced, not closing


def test_coverage_names_session_api_and_truncation():
    md = render([], COV, SETTINGS, app_id="app", scan_id="S1")
    cov = md.split("## Coverage")[1]
    assert "alive throughout (4 checks)" in cov
    assert "key required" in cov
    assert "40019" in cov and "2 routes" in cov


def test_unknown_session_and_open_api_are_not_presented_as_fine():
    cov = {**COV, "zap_api_open": True,
           "session": {"method": "unknown", "alive_throughout": None, "reason": "no probe"}}
    md = render([], cov, SETTINGS, app_id="app", scan_id="S1")
    assert "not verified — no probe" in md and "OPEN" in md


def test_expired_suppressions_are_listed():
    rec = _rec("high", "new", suppression={"expired": True, "expires": "2026-01-01"})
    md = render([rec], COV, SETTINGS, app_id="app", scan_id="S1")
    assert "expired 2026-01-01" in md


def test_reachability_gaps_are_shown_when_given():
    md = render([], COV, SETTINGS, app_id="app", scan_id="S1",
                reachability={"exposed": 5, "exercised": 3, "gaps": {"/a": ["q", "r"]}})
    assert "3/5 exposed parameters" in md and "/a" in md


def test_where_results_go_is_stated():
    md = render([], COV, SETTINGS, app_id="app", scan_id="S1", uploaded=False)
    assert "o/r" in md and "dast/app" in md and "not uploaded" in md


def test_an_unhealthy_scan_is_never_headlined_as_passed():
    cov = {**COV, "session": {"method": "probe", "alive_throughout": False, "lost_after_s": 5}}
    s = {**SETTINGS, "gate": {**SETTINGS["gate"], "passed": True, "blocking": 0}}
    head = render([], cov, s, app_id="app", scan_id="S1").split("\n## ")[0]
    assert "NOT RELIABLE" in head and "Passed" not in head


def test_verdict_lines_are_separate_paragraphs():
    cov = {**COV, "zap_api_open": True}
    head = render([_rec("high")], cov, SETTINGS, app_id="app", scan_id="S1").split("\n## ")[0]
    assert "\n\n**Warning:**" in head


def test_identical_new_findings_are_grouped_with_a_count():
    recs = [_rec("info", title="User Agent Fuzzer", fp=str(i)) for i in range(12)]
    md = render(recs, COV, SETTINGS, app_id="app", scan_id="S1")
    assert md.count("User Agent Fuzzer ×12") == 1


def test_without_a_policy_gate_the_verdict_is_not_evaluated():
    head = render([_rec("high")], COV, {}, app_id="app", scan_id="S1").split("\n## ")[0]
    assert "not evaluated" in head and "Passed" not in head


def test_the_cli_renders_from_files(tmp_path):
    import json
    from detections import summary
    (tmp_path / "l.json").write_text(json.dumps([_rec("high", scan_id="S9")]))
    (tmp_path / "c.json").write_text(json.dumps(COV))
    summary.main([str(tmp_path / "l.json"), "--coverage", str(tmp_path / "c.json"),
                  "--app-id", "app", "-o", str(tmp_path / "s.md")])
    md = (tmp_path / "s.md").read_text()
    assert "Scan `S9`" in md and "not evaluated" in md


def test_a_recovered_session_is_degraded_not_unhealthy():
    cov = {**COV, "session": {"method": "probe", "alive_throughout": False, "alive_at_end": True,
                              "losses": [{"at_s": 91, "recovered": True}]}}
    s = {**SETTINGS, "gate": {**SETTINGS["gate"], "passed": True, "blocking": 0}}
    md = render([], cov, s, app_id="app", scan_id="S1")
    head = md.split("\n## ")[0]
    assert "**Degraded**" in head and "UNHEALTHY" not in head and "Passed" in head
    assert "re-established each time" in md
