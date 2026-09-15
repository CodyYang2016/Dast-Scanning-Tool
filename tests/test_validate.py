"""TEST-FIRST suite for validate's deterministic checks (FR-V2/V3).

Frozen before authoring/validate.py exists. The live auth-replay (FR-V1) is verified by running
it; here we pin the allow-list coverage check and the report/exit-code contract. Oracle:
hand-built plans + scopes with known allow/deny outcomes, and the committed scope contract.
"""

import json
from pathlib import Path

from authoring.validate import build_report, check_allowlist, main, plan_hosts

SCOPE = {
    "app_id": "juice-shop",
    "environment_class": "dev",
    "target_fqdn": "juice",
    "fqdn_allow_list": ["juice"],
    "fqdn_deny_list": [],
    "avoid_action_list": [],
}

PLAN_IN_SCOPE = {
    "app_id": "juice-shop",
    "base_url": "http://juice:3000",
    "login": {"url": "/#/login", "email_selector": "#e", "password_selector": "#p", "submit_selector": "#s"},
    "journey": [{"action": "goto", "target": "/#/basket"}],
}

PLAN_OUT_OF_SCOPE = {
    **PLAN_IN_SCOPE,
    "journey": [{"action": "api_get", "target": "http://evil.example.com/steal"}],
}


def test_plan_hosts_includes_base_and_absolute_targets():
    hosts = plan_hosts(PLAN_OUT_OF_SCOPE)
    assert "juice" in hosts and "evil.example.com" in hosts


def test_allowlist_passes_in_scope():
    assert check_allowlist(PLAN_IN_SCOPE, SCOPE) == []


def test_allowlist_flags_out_of_scope_host():
    violations = check_allowlist(PLAN_OUT_OF_SCOPE, SCOPE)
    assert "evil.example.com" in violations


def test_build_report_shape_and_overall():
    report = build_report({"allowlist": (True, "ok"), "auth": (False, "no token")})
    names = {c["name"] for c in report["checks"]}
    assert names == {"allowlist", "auth"}
    assert report["passed"] is False  # any failing check -> overall fail


def test_main_exit_zero_in_scope(tmp_path):
    plan = tmp_path / "journey.json"
    plan.write_text(json.dumps(PLAN_IN_SCOPE))
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps(SCOPE))
    report = tmp_path / "validation-report.json"
    rc = main(["--plan", str(plan), "--scope", str(scope), "--no-replay", "--report", str(report)])
    assert rc == 0
    assert json.loads(report.read_text())["passed"] is True


def test_main_exit_nonzero_out_of_scope(tmp_path):
    plan = tmp_path / "journey.json"
    plan.write_text(json.dumps(PLAN_OUT_OF_SCOPE))
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps(SCOPE))
    rc = main(["--plan", str(plan), "--scope", str(scope), "--no-replay",
               "--report", str(tmp_path / "r.json")])
    assert rc != 0  # FR-V3: failing check -> non-zero exit
