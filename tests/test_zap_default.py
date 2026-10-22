"""$DAST_ZAP_API sets the default ZAP address every `dast` command uses."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _default(env_value):
    env = {k: v for k, v in os.environ.items() if k != "DAST_ZAP_API"}
    if env_value is not None:
        env["DAST_ZAP_API"] = env_value
    code = "import dast; print(dast._DEFAULT_ZAP)"
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True,
                          text=True, check=True).stdout.strip()


def test_default_without_override():
    assert _default(None) == "http://localhost:8080"


def test_override_from_environment():
    assert _default("http://127.0.0.1:18080") == "http://127.0.0.1:18080"
