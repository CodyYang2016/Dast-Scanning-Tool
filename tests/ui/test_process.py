"""SEC-1, GEN-1 — the real `python -m dast ui` process."""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time

import pytest

from tests.ui.harness import ROOT


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _non_loopback_ip() -> str | None:
    """This machine's address on its default route (a UDP connect sends nothing)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def _can_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _env(ws, dist):
    return {**os.environ, "DAST_UI_DIST": str(dist), "DAST_APPS_DIR": str(ws.apps_dir),
            "DAST_OUT": str(ws.out_dir), "DAST_ENV_REGISTRY": str(ws.registry)}


def test_gen1_missing_frontend_build_exits_2_with_fix(ws, tmp_path):
    r = subprocess.run([sys.executable, "-m", "dast", "ui", "--no-open", "--port", str(_free_port())],
                       cwd=ROOT, env=_env(ws, tmp_path / "no-such-dist"), capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2
    assert "npm run build" in (r.stderr + r.stdout)


def test_sec1_listens_on_loopback_only(ws):
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "dast", "ui", "--no-open", "--port", str(port)],
                            cwd=ROOT, env=_env(ws, ws.dist_dir), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        url = None
        end = time.monotonic() + 30
        while time.monotonic() < end and url is None:
            line = proc.stdout.readline()
            m = re.search(r"http://127\.0\.0\.1:(\d+)/auth\?token=\S+", line or "")
            if m:
                url = m.group(0)
                assert int(m.group(1)) == port
        assert url, "dast ui never printed its launch URL"
        for _ in range(50):
            if _can_connect("127.0.0.1", port):
                break
            time.sleep(0.1)
        assert _can_connect("127.0.0.1", port)
        other = _non_loopback_ip()
        if other is None:
            pytest.skip("no non-loopback address on this machine")
        assert not _can_connect(other, port)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
