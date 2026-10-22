"""Running `dast` commands for the UI (UI-2, UI-7, UI-8).

A job is `python -m dast <command> …` in a subprocess: the same command a person would type, with
the UI's locations and user passed in the environment. One job per app at a time. Output is kept
for the job's log with every secret value masked out. Stopping sends the job an interrupt — the
runner then tells ZAP to stop and records a `stop` event — and also runs `dast stop` in case the
job was past listening.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from webui.audit import now
from webui.secret_refs import mask

# What to do about each kind of refusal the runner records in its `abort` event (UI-8).
FIXES = {
    "PreflightError": "Check the app's environment and hosts. A test or staging host must be "
                      "listed in the environment registry; ask Governance to add it.",
    "ScanScopeError": "Check the hosts in scope for this app.",
    "ScopeViolation": "The app sent the browser outside its scope. Add the host to scope if it "
                      "belongs to the app, or to login-only hosts if it is a sign-in service.",
    "ZapUnavailableError": "Start ZAP, then run the scan again.",
    "ZapAuthError": "ZAP refused the API key. Restart ZAP with the key the UI uses.",
    "authentication": "Check the test account's username and password variables, and the login "
                      "page and steps.",
    "SessionStoreError": "Sign in again to refresh the saved session.",
    "ResetError": "The data reset failed. Check the app's reset steps.",
    "FlowError": "Run the authoring step again: the recorded login no longer matches the app.",
    "ScanPolicyError": "Check the scan policy settings for this app.",
}


@dataclass
class Job:
    job_id: str
    app_id: str
    kind: str
    argv: list[str]
    command: str
    actor: str
    secrets: list[str]
    started_at: str
    proc: subprocess.Popen | None = None
    status: str = "running"
    exit_code: int | None = None
    ended_at: str | None = None
    scan_id: str | None = None
    refusal: dict | None = None
    summary: dict | None = None
    stopped_by: str | None = None
    output: list[str] = field(default_factory=list)
    on_exit: object = None
    scans_dir: Path | None = None
    scans_before: set = field(default_factory=set)

    def find_scan(self) -> str | None:
        """The run directory this job's command created, once it exists."""
        if self.scan_id is None and self.scans_dir is not None and self.scans_dir.is_dir():
            new = sorted(p.name for p in self.scans_dir.iterdir()
                         if p.is_dir() and p.name not in self.scans_before)
            if new:
                self.scan_id = new[-1]
        return self.scan_id

    def public(self) -> dict:
        d = {"job_id": self.job_id, "app_id": self.app_id, "kind": self.kind,
             "command": self.command, "status": self.status, "exit_code": self.exit_code,
             "actor": self.actor, "started_at": self.started_at, "ended_at": self.ended_at,
             "scan_id": self.scan_id}
        if self.refusal:
            d["refusal"] = self.refusal
        if self.summary:
            d["summary"] = self.summary
        return d

    def log(self) -> str:
        return mask("".join(self.output), self.secrets)


class JobManager:
    def __init__(self, config):
        self.config = config
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ── queries ───────────────────────────────────────────────────────────────────────────
    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def active(self, app: str) -> Job | None:
        for j in self.jobs.values():
            if j.app_id == app and j.status == "running":
                return j
        return None

    def running_scan(self, app: str) -> str | None:
        j = self.active(app)
        return j.scan_id if j else None

    # ── start ─────────────────────────────────────────────────────────────────────────────
    def start(self, app: str, kind: str, args: list[str], actor: str, *,
              env_extra: dict | None = None, secrets: list[str] = (), on_exit=None) -> Job:
        with self._lock:
            if self.active(app):
                raise RuntimeError("busy")
            argv = [kind, *args]
            job = Job(job_id=uuid.uuid4().hex[:12], app_id=app, kind=kind, argv=argv,
                      command=" ".join(["python -m dast", *argv]), actor=actor,
                      secrets=[s for s in secrets if s], started_at=now(), on_exit=on_exit)
            self.jobs[job.job_id] = job
        env = self.config.job_env()
        env["DAST_ACTOR"] = actor
        env.update(env_extra or {})
        scans = self.config.out_dir / app / "scans"
        job.scans_dir = scans
        job.scans_before = set(p.name for p in scans.iterdir()) if scans.is_dir() else set()
        job.proc = subprocess.Popen([self.config.python, "-m", "dast", *argv],
                                    cwd=self.config.repo_root, env=env, text=True, bufsize=1,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        threading.Thread(target=self._follow, args=(job,), daemon=True).start()
        threading.Thread(target=self._watch_scan, args=(job,), daemon=True).start()
        return job

    @staticmethod
    def _watch_scan(job: Job):
        """A quiet command prints nothing for a long time; find its run directory anyway."""
        while job.proc is not None and job.proc.poll() is None and job.find_scan() is None:
            time.sleep(0.2)

    def _follow(self, job: Job):
        assert job.proc and job.proc.stdout
        for line in job.proc.stdout:
            job.output.append(line)
            job.find_scan()
        code = job.proc.wait()
        job.find_scan()
        job.exit_code = code
        job.ended_at = now()
        if job.status != "stopped":
            job.status = "succeeded" if code == 0 else "failed"
        job.refusal = self._refusal(job)
        job.summary = self._summary(job)
        if job.on_exit:
            try:
                job.on_exit(job)
            except Exception:
                pass

    def _refusal(self, job: Job) -> dict | None:
        if job.status != "failed":
            return None
        if job.scan_id is None:
            return self._refusal_from_output(job)
        events_path = self.config.out_dir / job.app_id / "scans" / job.scan_id / "events.jsonl"
        aborts = []
        if events_path.exists():
            for line in events_path.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("event") == "abort":
                    aborts.append(e)
        if not aborts:
            return self._refusal_from_output(job)
        e = aborts[-1]
        kind = str(e.get("kind") or "abort")
        reason = mask(str(e.get("reason") or "The run stopped before scanning."), job.secrets)
        message = reason[0].upper() + reason[1:]
        if not message.endswith("."):
            message += "."
        return {"kind": kind, "message": message,
                "fix": e.get("hint") or FIXES.get(kind, "See the job's log for details.")}

    @staticmethod
    def _refusal_from_output(job: Job) -> dict:
        """A command that stopped without an abort event still said why: use its own words."""
        lines = [ln.strip() for ln in mask("".join(job.output), job.secrets).splitlines()
                 if ln.strip() and not ln.startswith((" ", "\t", "File ", "Traceback"))]
        said = next((ln for ln in reversed(lines) if "ABORT" in ln or " — run: " in ln), None)
        said = said or (lines[-1] if lines else f"`{job.command}` stopped with exit code {job.exit_code}.")
        for prefix in ("RUNNER ABORT:", "AUTHOR ABORT:", "SEED ABORT:", "EXPLORE ABORT:"):
            said = said.replace(prefix, "").strip()
        fix = "See the job's log for details."
        if " — run: " in said:
            said, _, command = said.partition(" — run: ")
            fix = f"Run `python -m {command.strip()}` first."
        message = said[0].upper() + said[1:] if said else "The command stopped."
        return {"kind": "command", "message": message if message.endswith(".") else message + ".",
                "fix": fix}

    @staticmethod
    def _summary(job: Job) -> dict | None:
        """The JSON block an author run prints, for its steps_by_source (UI-12)."""
        if job.kind != "author":
            return None
        text = "".join(job.output)
        for start in [i for i, ch in enumerate(text) if ch == "{"]:
            try:
                obj, _ = json.JSONDecoder().raw_decode(text[start:])
            except ValueError:
                continue
            if isinstance(obj, dict) and "steps_by_source" in obj:
                return {"steps_by_source": obj["steps_by_source"]}
        return None

    # ── stop ──────────────────────────────────────────────────────────────────────────────
    def stop(self, job: Job, actor: str) -> None:
        if job.status != "running" or job.proc is None:
            return
        job.find_scan()
        job.status = "stopped"
        job.stopped_by = actor
        try:
            os.killpg(job.proc.pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
        env = self.config.job_env()
        env["DAST_ACTOR"] = actor
        subprocess.run([self.config.python, "-m", "dast", "stop", job.app_id,
                        "--zap-api", self.config.zap_api],
                       cwd=self.config.repo_root, env=env, capture_output=True, timeout=30)
        deadline = time.monotonic() + 10
        while job.proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        if job.proc.poll() is None:
            try:
                os.killpg(job.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
