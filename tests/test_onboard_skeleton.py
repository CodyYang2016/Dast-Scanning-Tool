"""`dast onboard` keeps the login page it was given, including when it falls back to the skeleton."""
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _onboard(tmp_path, *extra):
    out = tmp_path / "staged.yaml"
    env = {**os.environ, "DAST_APPS_DIR": str(tmp_path / "apps")}
    r = subprocess.run([sys.executable, "-m", "dast", "onboard", "lab", "--base-url",
                        "http://localhost:8084", "--config-out", str(out), *extra],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return yaml.safe_load(out.read_text())


def test_skeleton_uses_given_login_url(tmp_path):
    assert _onboard(tmp_path, "--login-url", "/signin")["auth"]["login_url"] == "/signin"


def test_skeleton_default_login_url(tmp_path):
    assert _onboard(tmp_path)["auth"]["login_url"] == "/login"
