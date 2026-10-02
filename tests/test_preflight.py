"""Objective, TEST-FIRST suite for the runner preflight safety gate (FR-S3 / NFR-2).

Written and frozen BEFORE runner/preflight.py exists — the implementation must conform to
these. This is the single most important guardrail (never scan prod / never scan unbounded),
so it is tested adversarially. Oracle: the safety rules stated independently here + the
committed contracts/scope.json and scope.schema.json.

See docs/junior_engineer/runner_design.md §7 for the frozen API and criteria.
"""

import json
from pathlib import Path

import pytest

# Import target does not exist yet (test-first): this module is "red" at collection until
# runner/preflight.py is implemented.
from runner.preflight import PreflightError, check_scope, main, preflight

ROOT = Path(__file__).resolve().parent.parent
SCOPE = ROOT / "contracts" / "scope.json"
SCHEMA = ROOT / "contracts" / "scope.schema.json"


def valid_scope(**overrides):
    s = {
        "app_id": "juice-shop",
        "environment_class": "dev",
        "target_fqdn": "localhost",
        "fqdn_allow_list": ["localhost"],
        "fqdn_deny_list": ["*.google-analytics.com"],
        "avoid_action_list": ["logout", "delete-account"],
    }
    s.update(overrides)
    return s


def _write(tmp_path, scope):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope))
    return str(p)


# ---- check_scope (pure, no I/O) ---------------------------------------------------------

def test_valid_scope_passes():
    check_scope(valid_scope())  # must not raise


def test_prod_aborts():
    with pytest.raises(PreflightError):
        check_scope(valid_scope(environment_class="prod"))


def test_prod_case_insensitive_aborts():
    for value in ("PROD", "Prod", "production", "Production"):
        with pytest.raises(PreflightError):
            check_scope(valid_scope(environment_class=value))


def test_missing_environment_class_aborts():
    s = valid_scope()
    del s["environment_class"]
    with pytest.raises(PreflightError):
        check_scope(s)


def test_missing_allow_list_aborts():
    s = valid_scope()
    del s["fqdn_allow_list"]
    with pytest.raises(PreflightError):
        check_scope(s)


def test_empty_allow_list_aborts():
    with pytest.raises(PreflightError):
        check_scope(valid_scope(fqdn_allow_list=[]))


# ---- preflight (file + JSON-Schema) -----------------------------------------------------

def test_committed_scope_passes():
    # Ground truth: the real contract must pass its own safety gate.
    assert preflight(str(SCOPE), str(SCHEMA))["app_id"] == "juice-shop"


def test_missing_file_aborts(tmp_path):
    with pytest.raises(PreflightError):
        preflight(str(tmp_path / "nope.json"), str(SCHEMA))


def test_schema_violation_aborts(tmp_path):
    path = _write(tmp_path, valid_scope(unexpected_field=1))  # additionalProperties: false
    with pytest.raises(PreflightError):
        preflight(path, str(SCHEMA))


def test_invalid_environment_class_aborts(tmp_path):
    path = _write(tmp_path, valid_scope(environment_class="qa"))  # not in schema enum
    with pytest.raises(PreflightError):
        preflight(path, str(SCHEMA))


def test_preflight_returns_validated_scope(tmp_path):
    path = _write(tmp_path, valid_scope())
    assert preflight(path, str(SCHEMA))["app_id"] == "juice-shop"


# ---- CLI exit codes (non-zero MUST gate any scan wrapper) --------------------------------

def test_cli_exit_zero_on_valid(tmp_path):
    assert main(["--scope", _write(tmp_path, valid_scope()), "--schema", str(SCHEMA)]) == 0


def test_cli_exit_nonzero_on_prod(tmp_path):
    path = _write(tmp_path, valid_scope(environment_class="prod"))
    assert main(["--scope", path, "--schema", str(SCHEMA)]) != 0
