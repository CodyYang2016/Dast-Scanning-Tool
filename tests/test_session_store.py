"""The stored browser session (W5-3): a live credential, handled like one.

A storageState file is a working login. It sat in a working tree with no expiry, readable by
anyone on the machine. Now: it can come from a secret store via an environment variable (and
then exists on disk only for the run), and a file copy is refused when stale, readable by other
users, or inside the repository without being git-ignored.
"""

import base64
import json
import os
import stat
import time

import pytest

from runner import session_store
from runner.session_store import POSIX_PERMISSIONS, SessionStoreError, open_storage_state

posix_only = pytest.mark.skipif(not POSIX_PERMISSIONS, reason="Windows has no POSIX mode bits")

STATE = {"cookies": [{"name": "PHPSESSID", "value": "abc", "domain": "dvwa", "path": "/"}],
         "origins": []}


@pytest.fixture(autouse=True)
def _outside_repo(monkeypatch):
    monkeypatch.setattr(session_store, "_unignored_in_repo", lambda p: False)


def _file(tmp_path, mode=0o600, age_h=0):
    f = tmp_path / "state.json"
    f.write_text(json.dumps(STATE))
    os.chmod(f, mode)
    if age_h:
        t = time.time() - age_h * 3600
        os.utime(f, (t, t))
    return f


def test_a_fresh_private_file_is_used_in_place(tmp_path):
    f = _file(tmp_path)
    with open_storage_state(str(f), ttl_hours=12) as path:
        assert path == str(f)
    assert f.exists()                                   # the operator's file is left alone


def test_a_stale_file_is_refused_and_says_how_to_reseed(tmp_path):
    f = _file(tmp_path, age_h=13)
    with pytest.raises(SessionStoreError, match="re-seed") as e:
        with open_storage_state(str(f), ttl_hours=12):
            pass
    assert e.value.stale


@posix_only
def test_a_file_readable_by_others_is_refused(tmp_path):
    f = _file(tmp_path, mode=0o644)
    with pytest.raises(SessionStoreError, match="chmod 600") as e:
        with open_storage_state(str(f), ttl_hours=12):
            pass
    assert not e.value.stale


def test_mode_bits_are_not_checked_where_the_os_has_none(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "POSIX_PERMISSIONS", False)
    f = _file(tmp_path, mode=0o644)
    with open_storage_state(str(f), ttl_hours=12) as path:
        assert path == str(f)


def test_a_file_in_the_repo_that_git_does_not_ignore_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "_unignored_in_repo", lambda p: True)
    f = _file(tmp_path)
    with pytest.raises(SessionStoreError, match="ignored"):
        with open_storage_state(str(f), ttl_hours=12):
            pass


@pytest.mark.parametrize("encode", [lambda s: s, lambda s: base64.b64encode(s.encode()).decode()])
def test_an_env_source_exists_on_disk_only_for_the_run(monkeypatch, encode):
    monkeypatch.setenv("DVWA_SESSION", encode(json.dumps(STATE)))
    with open_storage_state("env:DVWA_SESSION", ttl_hours=12) as path:
        assert json.loads(open(path).read()) == STATE
        if POSIX_PERMISSIONS:
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not os.path.exists(path)


def test_the_temp_file_is_removed_even_when_the_run_fails(monkeypatch):
    monkeypatch.setenv("DVWA_SESSION", json.dumps(STATE))
    with pytest.raises(RuntimeError):
        with open_storage_state("env:DVWA_SESSION", ttl_hours=12) as path:
            raise RuntimeError("scan blew up")
    assert not os.path.exists(path)


def test_a_missing_or_malformed_env_source_is_an_error(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    with pytest.raises(SessionStoreError, match="NOPE"):
        with open_storage_state("env:NOPE", ttl_hours=12):
            pass
    monkeypatch.setenv("BAD", "not json at all")
    with pytest.raises(SessionStoreError, match="storageState"):
        with open_storage_state("env:BAD", ttl_hours=12):
            pass


def test_nothing_configured_yields_none():
    with open_storage_state(None, ttl_hours=12) as path:
        assert path is None


def test_config_carries_the_ttl():
    from authoring import appconfig
    assert appconfig.storage_state_ttl_hours({"auth": {}}) == 12
    assert appconfig.storage_state_ttl_hours({"auth": {"storage_state_ttl_hours": 2}}) == 2


@posix_only
def test_the_seed_writes_a_private_file(tmp_path):
    from authoring.seed import _make_private
    f = tmp_path / "s.json"; f.write_text("{}"); os.chmod(f, 0o644)
    _make_private(str(f))
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


# ---- the runner: stale falls back to a login, mishandled stops the run ---------------------

def _runner(tmp_path, monkeypatch, state_file):
    from runner import main as rm
    seen = {}

    def fake_run(*a, storage_state=None, **k):
        seen["state"] = storage_state
        raise rm.PreflightError("stop here")         # enough: we only need what run() received
    monkeypatch.setattr(rm, "run", fake_run)
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"target": {"base_url": "http://dvwa"},
                                "session": {"storage_state": str(state_file)},
                                "seed_routes": ["/"]}))
    monkeypatch.setattr("authoring.seed.load_seed", lambda p: json.loads(open(p).read()))
    rc = rm.main(["--scope", str(tmp_path / "scope.json"), "--flow", "f.py",
                  "--base-url", "http://dvwa", "--seed", str(seed)])
    return rc, seen


def test_the_runner_falls_back_to_a_login_when_the_stored_session_is_stale(tmp_path, monkeypatch):
    rc, seen = _runner(tmp_path, monkeypatch, _file(tmp_path, age_h=48))
    assert "state" in seen and seen["state"] is None


@posix_only
def test_the_runner_stops_on_a_mishandled_stored_session(tmp_path, monkeypatch, capsys):
    rc, seen = _runner(tmp_path, monkeypatch, _file(tmp_path, mode=0o644))
    assert rc == 2 and "state" not in seen
    assert "chmod 600" in capsys.readouterr().err
