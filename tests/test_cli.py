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
