"""Shared harness for the UI acceptance tests (docs/ui-docs/ui_acceptance_criteria.md).

Everything here talks to the UI only through the contract: `webui.app.create_app(UIConfig)` and
HTTP. The fixtures are real app configs and a trimmed real self-test run, copied into a temporary
workspace so no test touches the repository's own config or output.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FAKE_DAST = Path(__file__).resolve().parent / "fake_dast.py"
PORT = 8765
HOST = f"127.0.0.1:{PORT}"
LAUNCH_TOKEN = "t" * 43
ACTOR = "tester"
COMPLETE_RUN = "20261019T125049Z"
ABORTED_RUN = "20261020T080000Z"
LATER_RUN = "20261021T090000Z"


class Workspace:
    """A throwaway copy of the fixtures, laid out the way the UI is configured to read it."""

    def __init__(self, base: Path):
        self.root = base
        self.apps_dir = base / "security" / "dast"
        self.out_dir = base / "out"
        self.registry = self.apps_dir / "environments.yaml"
        self.audit_log = base / "out" / "ui-audit.jsonl"
        self.dist_dir = base / "dist"
        self.fake_log = base / "fake-dast.jsonl"
        shutil.copytree(FIXTURES / "apps", self.apps_dir)
        shutil.copytree(FIXTURES / "out", self.out_dir)
        self.dist_dir.mkdir()
        (self.dist_dir / "index.html").write_text(
            "<!doctype html><html><head><title>DAST</title></head><body><div id=root></div>"
            "</body></html>", encoding="utf-8")
        self.python = base / "fake-python"
        self.python.write_text(f"#!/bin/sh\nexec {sys.executable} {FAKE_DAST} \"$@\"\n",
                               encoding="utf-8")
        self.python.chmod(self.python.stat().st_mode | stat.S_IEXEC)

    def app_yaml(self, app: str) -> Path:
        return self.apps_dir / app / "app.yaml"

    def suppressions(self, app: str) -> Path:
        return self.apps_dir / app / "suppressions.yaml"

    def run_dir(self, app: str, scan_id: str) -> Path:
        return self.out_dir / app / "scans" / scan_id

    def invocations(self) -> list[dict]:
        if not self.fake_log.exists():
            return []
        return [json.loads(line) for line in self.fake_log.read_text().splitlines() if line]

    def audit(self) -> list[dict]:
        if not self.audit_log.exists():
            return []
        return [json.loads(line) for line in self.audit_log.read_text().splitlines() if line]


@pytest.fixture
def ws(tmp_path, monkeypatch) -> Workspace:
    w = Workspace(tmp_path)
    monkeypatch.setenv("FAKE_DAST_LOG", str(w.fake_log))
    return w


class _ZapStub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — http.server's naming
        body = b'{"version": "2.17.0"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def zap_up():
    """A local stand-in that answers ZAP's version call, so 'ZAP reachable' is a real check."""
    srv = socketserver.TCPServer(("127.0.0.1", 0), _ZapStub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


ZAP_DOWN = "http://127.0.0.1:9"          # discard port: nothing answers


def make_app(ws: Workspace, zap_api: str = ZAP_DOWN, **overrides):
    from webui.app import create_app
    from webui.config import UIConfig
    cfg = dict(repo_root=ws.root, apps_dir=ws.apps_dir, out_dir=ws.out_dir,
               registry_path=ws.registry, dist_dir=ws.dist_dir, audit_log=ws.audit_log,
               port=PORT, launch_token=LAUNCH_TOKEN, actor=ACTOR, python=str(ws.python),
               zap_api=zap_api)
    cfg.update(overrides)
    return create_app(UIConfig(**cfg))


def client_for(app):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url=f"http://{HOST}")


def logged_in(app):
    """A client with a session cookie, and the CSRF header set for every request."""
    c = client_for(app)
    r = c.get(f"/auth?token={LAUNCH_TOKEN}", follow_redirects=False)
    assert r.status_code == 303, r.text
    csrf = c.get("/api/session").json()["csrf_token"]
    c.headers["X-CSRF-Token"] = csrf
    return c


@pytest.fixture
def api(ws):
    return logged_in(make_app(ws))


@pytest.fixture
def api_zap(ws, zap_up):
    return logged_in(make_app(ws, zap_api=zap_up))


def wait_for(predicate, timeout=10.0, interval=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not met within %.1fs" % timeout)


def wait_job(client, job_id, timeout=15.0) -> dict:
    return wait_for(lambda: (lambda j: j if j["status"] != "running" else None)(
        client.get(f"/api/jobs/{job_id}").json()), timeout)


def env_without(*names):
    return {k: v for k, v in os.environ.items() if k not in names}
