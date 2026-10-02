"""Reset a disposable application's data before each scan (W6-1).

A write-enabled scan changes the application; without a reset, scan N+1 starts from wherever
scan N left it, and findings come and go with the data rather than the code. The reset runs
first, through ZAP and the scope guard, and `verify` proves it worked — a scan that cannot
prove its starting state does not start.
"""

import pytest

from runner.reset import ResetError, run_reset

CFG = {"url": "/setup.php", "steps": [{"action": "click", "selector": "input[name=create_db]"}],
       "verify": {"path": "/login.php", "contains": "Login"}}


def _drive(calls):
    return lambda url, steps: calls.append((url, steps))


def test_the_steps_run_on_the_reset_page_and_the_result_is_verified():
    calls = []
    out = run_reset(CFG, "http://dvwa", drive=_drive(calls),
                    fetch=lambda url: (200, "<form>Login</form>", url))
    assert calls == [("http://dvwa/setup.php", CFG["steps"])]
    assert out == {"ran": True, "verified": True}


def test_a_failed_verification_stops_the_scan():
    with pytest.raises(ResetError, match="did not verify"):
        run_reset(CFG, "http://dvwa", drive=_drive([]),
                  fetch=lambda url: (500, "Database error", url))


def test_a_failing_step_stops_the_scan():
    def boom(url, steps): raise RuntimeError("selector not found")
    with pytest.raises(ResetError, match="selector not found"):
        run_reset(CFG, "http://dvwa", drive=boom, fetch=lambda url: (200, "Login", url))


def test_without_verify_it_runs_but_is_recorded_unverified():
    cfg = {k: v for k, v in CFG.items() if k != "verify"}
    out = run_reset(cfg, "http://dvwa", drive=_drive([]), fetch=None)
    assert out == {"ran": True, "verified": None}


def test_config_and_contract():
    import json
    import pathlib
    import jsonschema
    from authoring import appconfig
    assert appconfig.scan_reset({"scan": {"reset": CFG}}) == CFG
    assert appconfig.scan_reset({"scan": {}}) is None
    schema = json.loads((pathlib.Path(__file__).resolve().parent.parent / "contracts" /
                         "app.schema.json").read_text())
    jsonschema.validate(CFG, schema["properties"]["scan"]["properties"]["reset"])


def test_the_summary_warns_when_writes_run_without_a_reset():
    from detections.summary import render
    cov = {"routes": ["/a"], "policy": {"write_mode": "allow"}}
    md = render([], cov, {}, app_id="a", scan_id="S")
    assert "without a data reset" in md
    md = render([], {**cov, "reset": {"ran": True, "verified": True}}, {}, app_id="a", scan_id="S")
    assert "Data reset before the scan: verified" in md and "without a data reset" not in md
