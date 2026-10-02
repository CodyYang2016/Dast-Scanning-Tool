"""Structured scan events (W3-3, NFR-4): what did the scan do, refuse, and when?

One JSON line per event in the run's events.jsonl, every line carrying a timestamp, the scan id
and the app id. Written alongside the scan's other artifacts, so an unattended run leaves an
audit trail. Logging never fails a scan.
"""

import json

from runner import events


def _lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_each_event_is_one_json_line_with_its_context(tmp_path):
    log = events.EventLog(app_id="dvwa")
    log.bind(scan_id="S1")
    log.attach(tmp_path / "events.jsonl")
    log.emit("auth", outcome="ok")
    (line,) = _lines(tmp_path / "events.jsonl")
    assert line["event"] == "auth" and line["outcome"] == "ok"
    assert line["scan_id"] == "S1" and line["app_id"] == "dvwa" and line["ts"].endswith("Z")


def test_events_before_the_file_exists_are_kept_and_flushed(tmp_path):
    # The run directory is created only after preflight: those events must not be lost.
    log = events.EventLog(app_id="a")
    log.emit("preflight", outcome="ok")
    log.attach(tmp_path / "events.jsonl")
    log.emit("auth", outcome="ok")
    assert [e["event"] for e in _lines(tmp_path / "events.jsonl")] == ["preflight", "auth"]


def test_strings_are_redacted(tmp_path):
    log = events.EventLog(app_id="a"); log.attach(tmp_path / "e.jsonl")
    log.emit("scope_decision", url="https://app/x?token=eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl")
    assert "eyJhbGciOi" not in (tmp_path / "e.jsonl").read_text()


def test_a_failing_write_never_raises(tmp_path):
    log = events.EventLog(app_id="a")
    log.attach(tmp_path / "no-such-dir" / "deeper" / "e.jsonl")
    (tmp_path / "no-such-dir").write_text("a file, so the directory cannot be created")
    log.emit("auth", outcome="ok")                      # does not raise


def test_json_mode_mirrors_events_to_stderr(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DAST_LOG_FORMAT", "json")
    log = events.EventLog(app_id="a"); log.attach(tmp_path / "e.jsonl")
    log.emit("auth", outcome="ok")
    assert json.loads(capsys.readouterr().err.strip())["event"] == "auth"


def test_the_module_level_log_is_a_no_op_until_started(tmp_path):
    events.reset()
    events.emit("anything", x=1)                         # no file, no error
    log = events.start(app_id="a")
    log.attach(tmp_path / "e.jsonl")
    events.emit("auth", outcome="ok")
    assert _lines(tmp_path / "e.jsonl")[0]["event"] == "auth"
    events.reset()


def test_scope_blocks_and_traverses_are_events_but_allows_are_not(tmp_path):
    from runner.scope_guard import ScopeGuard
    log = events.start(app_id="a"); log.attach(tmp_path / "e.jsonl")
    g = ScopeGuard({"fqdn_allow_list": ["app"], "traverse_list": ["https://idp.example"]})
    g.check("http://app/x"); g.check("https://idp.example/login"); g.check("http://evil/x")
    kinds = [(e["event"], e["decision"]) for e in _lines(tmp_path / "e.jsonl")]
    assert kinds == [("scope_decision", "traverse"), ("scope_decision", "block")]
    events.reset()


def test_an_abort_is_recorded_with_its_reason(tmp_path, monkeypatch):
    from runner import main as rm
    from runner.replay import AuthenticationError
    ev = tmp_path / "run"; ev.mkdir()

    def fake_run(*a, **k):
        events.get().attach(ev / "events.jsonl")
        raise AuthenticationError("login page element not found: #email")
    monkeypatch.setattr(rm, "run", fake_run)
    rm.main(["--scope", "s.json", "--flow", "f.py", "--base-url", "http://x",
             "--evidence-dir", str(ev)])
    last = _lines(ev / "events.jsonl")[-1]
    assert last["event"] == "abort" and "login page element not found" in last["reason"]
    events.reset()


def test_the_report_appends_its_events_to_the_scans_trail(tmp_path, monkeypatch):
    from tests.test_cli import _report, _scan_dir
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    d = _scan_dir(tmp_path)
    _report(tmp_path, "--fail-on", "none")
    kinds = [e["event"] for e in _lines(d / "events.jsonl")]
    assert kinds[:3] == ["lifecycle", "policy_gate", "sarif_written"]
    assert "Audit trail:" in (d / "summary.md").read_text()
    events.reset()


def test_events_held_before_the_scan_id_existed_are_stamped_with_it(tmp_path):
    log = events.EventLog(app_id="a")
    log.emit("preflight", outcome="ok")          # before the scan id is known
    log.bind(scan_id="S7")
    log.attach(tmp_path / "e.jsonl")
    assert _lines(tmp_path / "e.jsonl")[0]["scan_id"] == "S7"
