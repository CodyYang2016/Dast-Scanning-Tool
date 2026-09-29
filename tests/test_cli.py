"""Objective tests for the `dast` CLI facade (W2-6).

The CLI is the operator's whole interface, so what matters here is: the four verbs exist and
route correctly, the artifact layout is predictable, and `dast onboard` produces a file that
the schema actually accepts once its TODOs are filled. Anything that touches a browser, ZAP or
GitHub is delegated to the module entry points those steps already have, and is verified by
running them — not mocked here.
"""

import json
import pathlib

import pytest
import yaml

import dast
from authoring import appconfig

_DVWA_YAML = str(appconfig.app_config_path("dvwa"))


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
    for path in (dast.bundle_dir("a"), dast.trace_dir("a"), dast.scans_dir("a"),
                 dast.state_path("a")):
        assert "/out/a/" in path.as_posix()


def test_latest_scan_dir_is_none_before_any_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(dast, "OUT", tmp_path)
    assert dast.latest_scan_dir("never-scanned") is None


def test_latest_scan_dir_picks_the_newest_run(monkeypatch, tmp_path):
    monkeypatch.setattr(dast, "OUT", tmp_path)
    for stamp in ("20260101T000000Z", "20260301T000000Z", "20260201T000000Z"):
        (tmp_path / "a" / "scans" / stamp).mkdir(parents=True)
    assert dast.latest_scan_dir("a").name == "20260301T000000Z"


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
    monkeypatch.setattr(dast, "OUT", tmp_path)
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path)
    _onboard(tmp_path, monkeypatch, app="unbuilt", base="http://unbuilt")
    args = dast.build_parser().parse_args(["scan", "unbuilt"])
    assert dast.cmd_scan(args) == 2
    assert "dast author unbuilt" in capsys.readouterr().err


# ---- author: an app that ships only app.yaml is still authorable -------------------------

def _dvwa_config():
    """A real committed config, read by path so tests can repoint _APPS_DIR at a tmp dir."""
    return appconfig.load_app_config(_DVWA_YAML)


def test_explore_inputs_derives_seed_and_scope_when_only_app_yaml_is_committed(
        tmp_path, monkeypatch):
    monkeypatch.setattr(dast, "OUT", tmp_path)
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")   # nothing committed
    (tmp_path / "apps" / "dvwa").mkdir(parents=True)
    config = _dvwa_config()

    seed_file, scope_file = dast.explore_inputs("dvwa", config, None)

    scope = json.loads(scope_file.read_text())
    assert scope == appconfig.scope_from_config(config)
    seed = json.loads(seed_file.read_text())
    assert seed["target"]["scope_file"] == str(scope_file)
    assert seed["session"]["storage_state"] == appconfig.storage_state(config)
    assert seed["exploration"]["max_pages"] == appconfig.max_pages(config)
    # Derived, not invented: both must satisfy the contracts the runner preflights against.
    from authoring.seed import load_seed
    from runner.preflight import preflight
    load_seed(str(seed_file))
    preflight(str(scope_file))


def test_explore_inputs_prefers_committed_files_over_derived(tmp_path, monkeypatch):
    monkeypatch.setattr(dast, "OUT", tmp_path)
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")
    app_dir = tmp_path / "apps" / "dvwa"
    app_dir.mkdir(parents=True)
    (app_dir / "scope.json").write_text("{}")
    (app_dir / "seed.json").write_text("{}")

    seed_file, scope_file = dast.explore_inputs("dvwa", _dvwa_config(), None)

    assert (seed_file, scope_file) == (app_dir / "seed.json", app_dir / "scope.json")


def test_explore_inputs_honours_an_explicit_seed_override(tmp_path, monkeypatch):
    monkeypatch.setattr(dast, "OUT", tmp_path)
    monkeypatch.setattr(appconfig, "_APPS_DIR", tmp_path / "apps")
    (tmp_path / "apps" / "dvwa").mkdir(parents=True)

    seed_file, _ = dast.explore_inputs("dvwa", _dvwa_config(), "/tmp/mine.json")

    assert seed_file == pathlib.Path("/tmp/mine.json")
