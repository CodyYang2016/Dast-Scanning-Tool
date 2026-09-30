"""Pure unit tests for the replay flow loader.

The browser/proxy path in runner/replay.py is validated LIVE (see runner_design.md §9), not
here. These cover the flow-loading contract, which needs neither Playwright nor a network.
"""

from pathlib import Path

import pytest

from runner.replay import load_flow

ROOT = Path(__file__).resolve().parent.parent
FLOW = ROOT / "security" / "dast" / "juice-shop" / "flow.py"


def test_load_flow_exposes_run():
    module = load_flow(str(FLOW))
    assert callable(module.run)


def test_load_flow_rejects_missing_run(tmp_path):
    bad = tmp_path / "bad_flow.py"
    bad.write_text("x = 1\n")  # no run()
    with pytest.raises(RuntimeError):
        load_flow(str(bad))


# ---- unexecutable journeys report as themselves -----------------------------------------

def test_a_download_navigation_becomes_a_flow_error():
    """`dast scan` used to exit with a raw Playwright traceback when a step hit a document."""
    from runner.replay import FlowError, _as_flow_error

    original = RuntimeError('Page.goto: Download is starting\nCall log:\n  - navigating to "..."')
    translated = _as_flow_error(original)
    assert isinstance(translated, FlowError)
    assert "file download" in str(translated) and "Page.goto" in str(translated)


def test_any_other_failure_is_passed_through_untouched():
    """Only the unexecutable-plan case is reclassified; real faults must keep their own type."""
    from runner.replay import _as_flow_error

    original = TimeoutError("Page.goto: Timeout 30000ms exceeded")
    assert _as_flow_error(original) is original


def test_the_runner_reports_a_flow_error_as_an_abort_not_a_traceback(monkeypatch, capsys):
    import runner.main as runner_main
    from runner.replay import FlowError

    def boom(*args, **kwargs):
        raise FlowError("a journey step navigated to a file download rather than a page")

    monkeypatch.setattr(runner_main, "run", boom)
    rc = runner_main.main(["--scope", "s.json", "--flow", "f.py", "--base-url", "http://dvwa"])
    assert rc == 2
    assert "RUNNER ABORT" in capsys.readouterr().err
