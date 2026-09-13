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
