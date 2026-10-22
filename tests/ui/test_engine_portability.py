"""The web UI on the Nationwide user's setup (Podman, Windows, Git Bash) as well as on Docker.

- Stopping a job works without `os.killpg`, which Windows doesn't have.
- What the UI tells people to run names no single container engine.
- The exported CI workflow reaches ZAP (QA-16) and lets a Podman runner choose its compose command.
- `scripts/ui_stack.sh` picks the engine and compose command the way docs/podman_and_docker.md says.
- compose.demo.yaml and compose.yaml render exactly as before when no new variable is set, so the
  Nationwide checklist's steps behave as they did.
"""
from __future__ import annotations

import re
import shutil
import signal
import subprocess

import pytest
import yaml

from tests.ui.harness import ROOT

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="needs bash (Git Bash on Windows)")


# ── stopping a job, on Windows and on POSIX ───────────────────────────────────────────────

class _Proc:
    pid = 4242

    def __init__(self):
        self.calls = []

    def send_signal(self, sig):
        self.calls.append(("send_signal", sig))

    def kill(self):
        self.calls.append(("kill",))


def test_windows_jobs_start_in_their_own_group_and_stop_without_killpg(monkeypatch):
    from webui import jobs
    monkeypatch.setattr(jobs, "_windows", lambda: True)
    monkeypatch.setattr(jobs.os, "killpg", lambda *a: pytest.fail("killpg isn't available on Windows"),
                        raising=False)
    assert jobs._spawn_kwargs() == {"creationflags": 0x00000200}     # CREATE_NEW_PROCESS_GROUP
    p = _Proc()
    jobs._interrupt(p)
    jobs._kill(p)
    assert p.calls == [("send_signal", 1), ("kill",)]                  # CTRL_BREAK_EVENT, then kill


def test_posix_jobs_keep_their_session_and_process_group_signals(monkeypatch):
    from webui import jobs
    monkeypatch.setattr(jobs, "_windows", lambda: False)
    sent = []
    monkeypatch.setattr(jobs.os, "killpg", lambda pid, sig: sent.append((pid, sig)), raising=False)
    assert jobs._spawn_kwargs() == {"start_new_session": True}
    jobs._interrupt(_Proc())
    jobs._kill(_Proc())
    assert sent == [(4242, signal.SIGINT), (4242, getattr(signal, "SIGKILL", 9))]


# ── what the UI tells people to run ───────────────────────────────────────────────────────

def test_zap_down_hint_names_the_launcher_not_one_engine(api):
    r = api.post("/api/apps/juice-shop/jobs", json={"command": "scan", "options": {}})
    assert r.status_code == 422, r.text
    fix = r.json()["detail"]["fix"]
    assert "scripts/ui_stack.sh up" in fix
    assert "docker" not in fix.lower() and "podman" not in fix.lower()


def test_exported_workflow_reaches_zap_and_lets_podman_runners_choose(api):
    content = api.get("/api/apps/juice-shop/workflow").json()["content"]
    wf = yaml.safe_load(content)
    steps = wf["jobs"]["scan"]["steps"]
    start = next(s for s in steps if s.get("name") == "start ZAP")["run"]
    assert "${{ vars.DAST_COMPOSE || 'docker compose' }}" in start
    assert "-f compose.yaml -f compose.demo.yaml up -d zap" in start
    scan = next(s for s in steps if s.get("name") == "author and scan")
    assert scan["env"]["DAST_ZAP_API"] == "http://127.0.0.1:8080"
    assert scan["env"]["ZAP_API_ALLOW"] == ".*"
    assert "DAST_COMPOSE=podman-compose" in content           # the comment a Podman runner needs
    assert not re.search(r"run: docker compose", content)


# ── scripts/ui_stack.sh: which engine, which compose command ─────────────────────────────

def _stub(dirpath, name, code=0):
    p = dirpath / name
    p.write_text(f"#!/bin/sh\nexit {code}\n", encoding="utf-8")
    p.chmod(0o755)
    return str(p)


def _dry_run(tmp_path, *, docker=None, podman=None, podman_compose=None, **env):
    missing = str(tmp_path / "not-installed")
    full = {"PATH": __import__("os").environ["PATH"], "HOME": str(tmp_path),
            "DOCKER_BIN": docker or missing, "PODMAN_BIN": podman or missing,
            "PODMAN_COMPOSE_BIN": podman_compose or missing, **env}
    r = subprocess.run([BASH, str(ROOT / "scripts" / "ui_stack.sh"), "--dry-run", "up", "juice"],
                       cwd=ROOT, env=full, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


@needs_bash
def test_ui_stack_podman_only_uses_podman_compose_on_8080(tmp_path):
    out = _dry_run(tmp_path, podman=_stub(tmp_path, "podman"),
                   podman_compose=_stub(tmp_path, "podman-compose"))
    assert "engine: podman" in out
    assert re.search(r"podman-compose -f compose\.yaml -f compose\.demo\.yaml up -d zap juice", out)
    assert "DAST_ZAP_API=http://127.0.0.1:8080" in out


@needs_bash
def test_ui_stack_podman_without_podman_compose_uses_podman_compose_subcommand(tmp_path):
    out = _dry_run(tmp_path, podman=_stub(tmp_path, "podman"))
    assert re.search(r"(?<!-)podman compose -f compose\.yaml -f compose\.demo\.yaml up -d zap juice", out)


@needs_bash
def test_ui_stack_docker_only_uses_docker_compose(tmp_path):
    out = _dry_run(tmp_path, docker=_stub(tmp_path, "docker"))
    assert "engine: docker" in out
    assert re.search(r"docker compose -f compose\.yaml -f compose\.demo\.yaml up -d zap juice", out)


@needs_bash
def test_ui_stack_prefers_a_working_docker_unless_told_podman(tmp_path):
    kw = dict(docker=_stub(tmp_path, "docker"), podman=_stub(tmp_path, "podman"),
              podman_compose=_stub(tmp_path, "podman-compose"))
    assert "engine: docker" in _dry_run(tmp_path, **kw)
    assert "engine: podman" in _dry_run(tmp_path, DAST_CONTAINER_ENGINE="podman", **kw)


@needs_bash
def test_ui_stack_falls_back_to_podman_when_docker_isnt_running(tmp_path):
    out = _dry_run(tmp_path, docker=_stub(tmp_path, "docker", code=1), podman=_stub(tmp_path, "podman"),
                   podman_compose=_stub(tmp_path, "podman-compose"))
    assert "engine: podman" in out


@needs_bash
def test_ui_stack_honours_the_zap_port(tmp_path):
    out = _dry_run(tmp_path, docker=_stub(tmp_path, "docker"), DAST_ZAP_PORT="18080")
    assert "DAST_ZAP_API=http://127.0.0.1:18080" in out


@needs_bash
def test_ui_stack_dry_run_writes_nothing_and_prints_no_key(tmp_path):
    out = _dry_run(tmp_path, docker=_stub(tmp_path, "docker"), ZAP_API_KEY="sentinel-key-not-printed")
    assert "sentinel-key-not-printed" not in out
    assert not (tmp_path / ".secrets").exists()


# ── the compose files render as before when no new variable is set ───────────────────────

def _expand_defaults(value: str) -> str:
    return re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", value)


def test_compose_demo_ports_default_to_what_the_nationwide_checklist_uses():
    demo = yaml.safe_load((ROOT / "compose.demo.yaml").read_text(encoding="utf-8"))
    assert [_expand_defaults(p) for p in demo["services"]["zap"]["ports"]] == ["127.0.0.1:8080:8080"]
    assert [_expand_defaults(p) for p in demo["services"]["juice"]["ports"]] == ["127.0.0.1:3000:3000"]


def test_compose_dvwa_image_defaults_to_the_same_digest():
    base = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    image = base["services"]["dvwa"]["image"]
    assert _expand_defaults(image) == (
        "vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7")
    assert "DVWA_IMAGE" in image                                # the NTR mirror can be swapped in

