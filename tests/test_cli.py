"""Objective tests for the `dast` CLI facade (W2-6).

The CLI is the operator's whole interface, so what matters here is: the four verbs exist and
route correctly, the artifact layout is predictable, and `dast onboard` produces a file that
the schema actually accepts once its TODOs are filled. Anything that touches a browser, ZAP or
GitHub is delegated to the module entry points those steps already have, and is verified by
running them — not mocked here.
"""

from pathlib import Path

import pytest
import yaml

import dast
from authoring import appconfig


# ---- verbs and routing -------------------------------------------------------------------

def test_the_four_verbs_exist():
    parser = dast.build_parser()
    for verb in ("onboard", "author", "scan", "report"):
        args = parser.parse_args([verb, "someapp"] + (["--base-url", "http://x"] if verb == "onboard" else []))
        assert args.app == "someapp" and callable(args.func)


def test_a_verb_requires_an_app():
    with pytest.raises(SystemExit):
        dast.build_parser().parse_args(["scan"])


def test_an_unknown_verb_is_rejected():
    with pytest.raises(SystemExit):
        dast.build_parser().parse_args(["deploy", "someapp"])


# ---- artifact layout: one predictable place per app --------------------------------------

def test_artifacts_are_grouped_under_the_app():
    p = dast.Paths(dast.ROOT / "out", "a")
    for path in (p.bundle, p.trace, p.scans, p.state):
        assert "/out/a/" in path.as_posix()


# ---- onboard: the skeleton is real config, not prose -------------------------------------

def _onboard(tmp_path, monkeypatch, app="newapp", base="http://newapp.dev.example"):
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path)
    monkeypatch.setattr(dast, "ROOT", tmp_path)
    args = dast.build_parser().parse_args(["onboard", app, "--base-url", base])
    assert dast.cmd_onboard(args) == 0
    return tmp_path / app / "app.yaml"


def test_onboard_writes_a_parseable_config(tmp_path, monkeypatch):
    cfg = yaml.safe_load(_onboard(tmp_path, monkeypatch).read_text())
    assert cfg["app_id"] == "newapp"
    assert cfg["base_url"] == "http://newapp.dev.example"


def test_onboard_seeds_the_allow_list_from_the_target_host(tmp_path, monkeypatch):
    cfg = yaml.safe_load(_onboard(tmp_path, monkeypatch, base="https://app.dev.example:8443/x").read_text())
    assert cfg["scope"]["allow"] == ["app.dev.example"]


def test_onboard_names_credential_env_vars_never_values(tmp_path, monkeypatch):
    cfg = yaml.safe_load(_onboard(tmp_path, monkeypatch).read_text())
    creds = cfg["auth"]["credentials"]
    # The contract is names-only (NFR-3): every key ends in _env and every value is an
    # environment variable name, so the skeleton cannot become a place secrets get typed.
    assert creds == {"email_env": "NEWAPP_USER", "password_env": "NEWAPP_PASS"}
    assert all(k.endswith("_env") and v.isupper() for k, v in creds.items())


def test_onboard_defaults_to_a_provisioned_identity_and_no_writes(tmp_path, monkeypatch):
    cfg = yaml.safe_load(_onboard(tmp_path, monkeypatch).read_text())
    assert cfg["auth"]["identity"] == "provisioned"     # never creates an account by default
    assert cfg["explore"]["safe_forms"] == []           # read-only until someone opts in
    assert "bootstrap" not in cfg["auth"]


def test_onboard_refuses_to_clobber_an_existing_config(tmp_path, monkeypatch):
    _onboard(tmp_path, monkeypatch)
    args = dast.build_parser().parse_args(["onboard", "newapp", "--base-url", "http://x"])
    assert dast.cmd_onboard(args) == 2                  # and --force is the way past it


def test_the_skeleton_validates_once_its_todos_are_filled(tmp_path, monkeypatch):
    """The skeleton must be a config, not a prose template: fill the TODOs, it validates."""
    path = _onboard(tmp_path, monkeypatch)
    cfg = yaml.safe_load(path.read_text())
    cfg["auth"]["login_url"] = "/login.php"
    cfg["record"]["authenticated_routes"] = ["/index.php"]
    cfg["explore"]["seed_routes"] = ["/index.php"]
    path.write_text(yaml.safe_dump(cfg))
    loaded = appconfig.load_app_config(str(path))       # raises if off-contract
    assert appconfig.proof_mode(loaded) == "route"


def test_scan_without_a_bundle_tells_you_what_to_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path)
    _onboard(tmp_path, monkeypatch, app="unbuilt", base="http://unbuilt")
    args = dast.build_parser().parse_args(["scan", "unbuilt", "--out", str(tmp_path)])
    assert dast.cmd_scan(args) == 2
    assert "dast author unbuilt" in capsys.readouterr().err


# ---- where artifacts go: config default, per-machine override ----------------------------

def test_the_default_is_out_under_the_repo():
    assert dast.resolve_out(None, None, None) == dast.ROOT / "out"


def test_config_beats_the_default(tmp_path):
    assert dast.resolve_out(str(tmp_path), None, None) == tmp_path


def test_env_beats_config(tmp_path):
    other = tmp_path / "env"
    assert dast.resolve_out(str(tmp_path), None, str(other)) == other


def test_cli_beats_env(tmp_path):
    cli, env = tmp_path / "cli", tmp_path / "env"
    assert dast.resolve_out(str(tmp_path), str(cli), str(env)) == cli


def test_a_relative_value_resolves_from_the_repo_not_the_cwd(monkeypatch, tmp_path):
    # Running `dast` from a subdirectory must not scatter artifacts.
    monkeypatch.chdir(tmp_path)
    assert dast.resolve_out("artifacts", None, None) == dast.ROOT / "artifacts"


def test_a_home_relative_value_expands():
    from pathlib import Path
    assert dast.resolve_out("~/dast-out", None, None) == Path.home() / "dast-out"


def test_an_environment_variable_in_the_value_expands(monkeypatch, tmp_path):
    monkeypatch.setenv("DAST_TEST_BASE", str(tmp_path))
    assert dast.resolve_out("${DAST_TEST_BASE}/scans", None, None) == tmp_path / "scans"


def test_an_empty_value_is_refused_rather_than_writing_to_the_repo_root():
    for bad in ("", "   "):
        with pytest.raises(ValueError):
            dast.resolve_out(bad, None, None)


# ---- Paths: the whole workspace moves together, and instances do not interfere ------------

def test_every_artifact_kind_sits_under_the_chosen_root(tmp_path):
    p = dast.Paths(tmp_path, "a")
    for path in (p.bundle, p.trace, p.scans, p.state, p.authoring):
        assert tmp_path in path.parents or path == tmp_path


def test_two_roots_do_not_interfere(tmp_path):
    # The property a module-level global could not offer, and the reason for the dataclass.
    a, b = dast.Paths(tmp_path / "a", "app"), dast.Paths(tmp_path / "b", "app")
    assert a.bundle != b.bundle


def test_latest_scan_dir_is_none_before_any_scan_with_paths(tmp_path):
    assert dast.Paths(tmp_path, "never-scanned").latest_scan() is None


def test_latest_scan_dir_picks_the_newest_run_with_paths(tmp_path):
    for stamp in ("20260101T000000Z", "20260301T000000Z", "20260201T000000Z"):
        (tmp_path / "a" / "scans" / stamp).mkdir(parents=True)
    assert dast.Paths(tmp_path, "a").latest_scan().name == "20260301T000000Z"


# ---- printing a path that is not under the repo must not raise ---------------------------

def test_a_path_inside_the_repo_prints_relative():
    assert dast.display(dast.ROOT / "out" / "x") == "out/x"


def test_a_path_outside_the_repo_prints_absolute_instead_of_raising():
    # Path.relative_to raises ValueError outside its base; every command ended with such a
    # print, so a redirected run would have died after doing all the work.
    shown = dast.display(Path("/tmp/dast-artifacts/x"))
    assert shown == "/tmp/dast-artifacts/x"


# ---- publish destination ------------------------------------------------------------------

def test_publish_precedence_is_cli_then_env_then_config():
    assert dast._first_set("cli", "env", "cfg", "default") == ("cli", "cli")
    assert dast._first_set(None, "env", "cfg", "default") == ("env", "env")
    assert dast._first_set(None, None, "cfg", "default") == ("cfg", "config")
    assert dast._first_set(None, None, None, "default") == ("default", "default")


def test_the_category_defaults_to_one_per_application():
    assert dast.default_category("dvwa") != dast.default_category("juice-shop")
    assert dast.default_category("dvwa") == "dast/dvwa"


def test_the_recorded_output_source_names_the_rung_that_won(monkeypatch, tmp_path):
    args = dast.build_parser().parse_args(["report", "someapp", "--out", str(tmp_path)])
    assert dast.output_source(args) == "cli"
    args = dast.build_parser().parse_args(["report", "someapp"])
    monkeypatch.setenv("DAST_OUT", str(tmp_path))
    assert dast.output_source(args) == "env"
    monkeypatch.delenv("DAST_OUT")
    assert dast.output_source(args) == "default"


# ---- W1-8: publish against the scanned deployment, never the scanner's checkout ----------

_SHA = "0123456789abcdef0123456789abcdef01234567"


def _target(cli=None, env=None, cfg=None, app="dvwa"):
    import argparse
    a = argparse.Namespace(owner=None, repo=None, ref=None, commit=None, category=None, app=app)
    for k, v in (cli or {}).items():
        setattr(a, k, v)
    return dast.publish_target(a, cfg or {}, env or {})


def test_the_deployed_commit_comes_from_cli_then_pipeline_then_config():
    assert _target(cli={"commit": _SHA}, env={"DAST_TARGET_COMMIT": "e" * 40},
                   cfg={"commit": "d" * 40})["commit"] == {"value": _SHA, "source": "cli"}
    assert _target(env={"DAST_TARGET_COMMIT": "e" * 40},
                   cfg={"commit": "d" * 40})["commit"] == {"value": "e" * 40, "source": "env"}
    assert _target(cfg={"commit": "d" * 40})["commit"] == {"value": "d" * 40, "source": "config"}


def test_with_nothing_supplied_there_is_no_commit_and_no_ref():
    # Previously the ref silently defaulted to refs/heads/main and the commit to the DAST tool's
    # own HEAD. Unset now stays unset, and says so.
    t = _target()
    assert t["commit"] == {"value": None, "source": "unset"}
    assert t["ref"] == {"value": None, "source": "unset"}


def test_the_ref_follows_the_same_ladder():
    assert _target(env={"DAST_TARGET_REF": "refs/heads/release"})["ref"]["source"] == "env"


def test_the_category_still_defaults_per_application():
    assert _target(app="dvwa")["category"] == {"value": "dast/dvwa", "source": "default"}


def test_a_config_commit_is_accepted_by_the_contract():
    import yaml
    cfg = yaml.safe_load(open(appconfig._APPS_DIR / "dvwa" / "app.yaml"))
    cfg["publish"] = {"github": {"owner": "o", "repo": "r", "ref": "refs/heads/main",
                                 "commit": _SHA}}
    import jsonschema, json
    jsonschema.validate(cfg, json.loads((dast.ROOT / "contracts" / "app.schema.json").read_text()))


def test_report_accepts_a_commit_flag():
    args = dast.build_parser().parse_args(["report", "dvwa", "--commit", _SHA])
    assert args.commit == _SHA


# ---- W3-2: the report's policy gate decides the exit code ----------------------------------

def _scan_dir(root, app="gateapp", severities=("high",)):
    """A minimal scan on disk: records + coverage, as `dast scan` leaves them."""
    import json
    d = root / app / "scans" / "20261001T000000Z"
    d.mkdir(parents=True)
    recs = [{"app_id": app, "scan_id": "20261001T000000Z", "fingerprint": f"{i:064x}",
             "rule_id": "40018", "title": "SQL Injection", "severity": sev,
             "cwe_id": "CWE-89", "endpoint": f"/r{i}", "parameter": "id", "status": "open",
             "evidence_path": None} for i, sev in enumerate(severities)]
    (d / "records.json").write_text(json.dumps(recs))
    (d / "coverage.json").write_text(json.dumps({"routes": [f"/r{i}" for i in
                                                            range(len(severities))],
                                                 "rules": ["40018"]}))
    return d


def _report(tmp_path, *extra, app="gateapp"):
    args = dast.build_parser().parse_args(["report", app, "--out", str(tmp_path), *extra])
    return dast.cmd_report(args)


def test_a_new_high_fails_the_report(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    _scan_dir(tmp_path)
    assert _report(tmp_path) == 1


def test_the_same_finding_on_the_next_scan_is_open_and_passes(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    _scan_dir(tmp_path)
    _report(tmp_path)                       # first sight: new
    assert _report(tmp_path) == 0           # second: open — already somebody's decision


def test_fail_on_none_never_fails(tmp_path):
    _scan_dir(tmp_path)
    assert _report(tmp_path, "--fail-on", "none") == 0


def test_a_new_medium_passes_the_default_threshold(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    _scan_dir(tmp_path, severities=("medium",))
    assert _report(tmp_path) == 0


def test_the_pipeline_can_set_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("DAST_FAIL_ON", "medium")
    _scan_dir(tmp_path, severities=("medium",))
    assert _report(tmp_path) == 1


def test_sarif_is_still_written_when_the_gate_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    d = _scan_dir(tmp_path)
    assert _report(tmp_path) == 1 and (d / "results.sarif").exists()


def test_the_gate_and_its_source_are_recorded(tmp_path, monkeypatch):
    import json
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    d = _scan_dir(tmp_path)
    _report(tmp_path)
    g = json.loads((d / "settings.json").read_text())["gate"]
    assert g["fail_on"] == {"value": "high", "source": "default"} and g["passed"] is False


def test_scan_accepts_expect_findings():
    assert dast.build_parser().parse_args(["scan", "x", "--expect-findings"]).expect_findings


def test_the_contract_accepts_a_gate_threshold():
    import json, jsonschema, yaml
    cfg = yaml.safe_load(open(appconfig._APPS_DIR / "dvwa" / "app.yaml"))
    cfg["gate"] = {"fail_on": "medium"}
    jsonschema.validate(cfg, json.loads((dast.ROOT / "contracts" / "app.schema.json").read_text()))


# ---- W1-5: report applies suppressions; triage proposes them from GitHub ------------------

def _suppress(tmp_path, monkeypatch, app, fps, reason="false_positive"):
    import yaml
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")
    d = tmp_path / "apps" / app; d.mkdir(parents=True, exist_ok=True)
    (d / "suppressions.yaml").write_text(yaml.safe_dump({"suppressions": [
        {"fingerprint": fp, "reason": reason, "justification": "verified by hand"} for fp in fps]}))


def test_a_suppressed_new_high_does_not_fail_the_report(tmp_path, monkeypatch, capsys):
    import json
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    d = _scan_dir(tmp_path / "out")
    _suppress(tmp_path, monkeypatch, "gateapp", [f"{0:064x}"])
    assert _report(tmp_path / "out") == 0
    out = capsys.readouterr().out
    assert "suppressed=1" in out
    rec = json.loads((d / "labeled.json").read_text())[0]
    assert rec["status"] == "suppressed" and rec["suppression"]["was"] == "new"


def test_suppression_does_not_change_the_lifecycle_history(tmp_path, monkeypatch):
    # Triage is a view over the diff: the next scan must still see the finding as `open`.
    import json
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    _scan_dir(tmp_path / "out")
    _suppress(tmp_path, monkeypatch, "gateapp", [f"{0:064x}"])
    _report(tmp_path / "out")
    state = json.loads((tmp_path / "out" / "gateapp" / "state.json").read_text())
    assert all(r["status"] != "suppressed" for r in state["gateapp"]["records"])


def test_triage_writes_proposals_from_github_dismissals(tmp_path, monkeypatch, capsys):
    import json
    import yaml
    from detections.fingerprint import fingerprint, payload_family
    d = _scan_dir(tmp_path / "out")
    # Matching RECOMPUTES the fingerprint from the alert, so this record needs its real one.
    recs = json.loads((d / "records.json").read_text())
    recs[0]["fingerprint"] = fingerprint("40018", "/r0", "id", payload_family("40018"))
    (d / "records.json").write_text(json.dumps(recs))
    _report(tmp_path / "out", "--fail-on", "none")
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")
    (tmp_path / "apps" / "gateapp").mkdir(parents=True)
    alert = {"number": 9, "state": "dismissed", "dismissed_reason": "false positive",
             "dismissed_comment": "not injectable", "dismissed_by": {"login": "rev"},
             "rule": {"id": "40018"},
             "most_recent_instance": {"location": {"path": "/r0"},
                                      "message": {"text": "SQL Injection in parameter `id`."}}}
    monkeypatch.setattr(dast, "_dismissed_alerts", lambda owner, repo: [alert])
    args = dast.build_parser().parse_args(["triage", "gateapp", "--from-github",
                                           "--owner", "o", "--repo", "r",
                                           "--out", str(tmp_path / "out")])
    assert dast.cmd_triage(args) == 0
    proposed = yaml.safe_load((tmp_path / "apps" / "gateapp" /
                               "suppressions.proposed.yaml").read_text())
    assert proposed["suppressions"][0]["github_alert"] == 9
    assert "1 proposed" in capsys.readouterr().out


def test_triage_never_touches_the_real_suppressions_file(tmp_path, monkeypatch):
    _scan_dir(tmp_path / "out")
    _report(tmp_path / "out", "--fail-on", "none")
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")
    (tmp_path / "apps" / "gateapp").mkdir(parents=True)
    monkeypatch.setattr(dast, "_dismissed_alerts", lambda o, r: [])
    args = dast.build_parser().parse_args(["triage", "gateapp", "--from-github", "--owner", "o",
                                           "--repo", "r", "--out", str(tmp_path / "out")])
    dast.cmd_triage(args)
    assert not (tmp_path / "apps" / "gateapp" / "suppressions.yaml").exists()


def test_dast_stop_stops_both_scanners(monkeypatch, capsys):
    from runner import scan as scan_mod
    seen = []
    monkeypatch.setattr(scan_mod, "stop_all", lambda z: seen.append(z) or {"ascan": True, "spider": True})
    args = dast.build_parser().parse_args(["stop", "dvwa", "--zap-api", "http://zap:8080"])
    assert dast.cmd_stop(args) == 0 and seen == ["http://zap:8080"]
    assert "stopped" in capsys.readouterr().out


def test_the_contract_accepts_a_throttle():
    import json, jsonschema, yaml
    cfg = yaml.safe_load(open(appconfig._APPS_DIR / "dvwa" / "app.yaml"))
    cfg["scan"]["throttle"] = {"threads_per_host": 2, "delay_ms": 250}
    jsonschema.validate(cfg, json.loads((dast.ROOT / "contracts" / "app.schema.json").read_text()))
    assert appconfig.scan_throttle(cfg) == {"threads_per_host": 2, "delay_ms": 250}


# ---- W1-6: a summary per scan ------------------------------------------------------------

def test_report_writes_a_summary_beside_the_sarif(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    d = _scan_dir(tmp_path)
    _report(tmp_path)
    md = (d / "summary.md").read_text()
    assert md.startswith("# DAST scan — gateapp") and "FAILED" in md


def test_in_actions_the_summary_is_appended_to_the_run_page(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_FAIL_ON", raising=False)
    page = tmp_path / "step_summary.md"
    page.write_text("earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(page))
    _scan_dir(tmp_path)
    _report(tmp_path)
    text = page.read_text()
    assert text.startswith("earlier step\n") and "# DAST scan — gateapp" in text


# ---- W1-4: the evidence link resolves like every other setting -----------------------------

def test_the_evidence_url_is_recorded_with_its_source(tmp_path, monkeypatch):
    import json
    monkeypatch.setenv("DAST_EVIDENCE_URL", "https://ci.example/runs/7")
    d = _scan_dir(tmp_path)
    _report(tmp_path, "--fail-on", "none")
    s = json.loads((d / "settings.json").read_text())
    assert s["evidence_url"] == {"value": "https://ci.example/runs/7", "source": "env"}


def test_a_bad_evidence_url_stops_the_report(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_EVIDENCE_URL", raising=False)
    _scan_dir(tmp_path)
    assert _report(tmp_path, "--evidence-url", "javascript:alert(1)") == 2


def test_the_contract_accepts_an_evidence_url_and_refuses_other_schemes():
    import json, jsonschema, pytest, yaml
    schema = json.loads((dast.ROOT / "contracts" / "app.schema.json").read_text())
    cfg = yaml.safe_load(open(appconfig._APPS_DIR / "dvwa" / "app.yaml"))
    cfg["publish"] = {"evidence_url": "https://store.example/{scan_id}/{path}"}
    jsonschema.validate(cfg, schema)
    cfg["publish"] = {"evidence_url": "file:///{path}"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(cfg, schema)
