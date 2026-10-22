"""Starting and stopping `dast author | scan | report` (UI-2, UI-7, UI-8)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from webui import registry_check
from webui.app import error
from webui.routers.apps import zap_status


class JobRequest(BaseModel):
    command: Literal["author", "scan", "report"]
    options: dict = Field(default_factory=dict)


def start_job(ctx, request, app: str, kind: str, args: list[str], *, needs_zap: bool,
              env_extra: dict | None = None, extra_secrets: list[str] = (), audit_event="job.start",
              audit_detail: dict | None = None, on_exit=None):
    """Start a dast job for an app, or refuse in plain words. Shared by every router that runs one."""
    zap = zap_status(ctx.config.zap_api) if needs_zap else "ok"
    if zap == "key":
        error(422, f"ZAP at {ctx.config.zap_api} refused this UI's API key, so nothing was started.",
              "Start `python -m dast ui` with ZAP_API_KEY set to the key ZAP was started with.")
    if zap == "down":
        error(422, f"ZAP isn't answering at {ctx.config.zap_api}, so nothing was started.",
              "Start ZAP with `bash scripts/ui_stack.sh up`, then try again.")
    actor = ctx.actor(request)
    try:
        job = ctx.jobs.start(app, kind, args, actor, env_extra=env_extra,
                             secrets=ctx.app_secret_values(app) + list(extra_secrets),
                             on_exit=on_exit)
    except RuntimeError:
        error(409, f"{app} already has a job running.", "Wait for it to finish, or stop it first.")
    ctx.audit.record(actor, audit_event, app, job_id=job.job_id, command=job.command,
                     **(audit_detail or {}))
    return job


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api")

    @r.post("/apps/{app}/jobs", status_code=201)
    def start(app: str, body: JobRequest, request: Request):
        if not ctx.store.exists(app):
            error(404, f"There is no application called {app}.")
        if body.command in ("author", "scan"):
            _, cfg = ctx.store.read(app)
            refused = registry_check.refusal(ctx.config.registry_path, cfg.get("base_url", ""),
                                             cfg.get("environment_class", ""))
            if refused:
                error(422, *refused)
        args = [app]
        if body.command == "author":
            if body.options.get("explore"):
                args.append("--explore")
            if body.options.get("headed"):
                args.append("--headed")
            if body.options.get("no_llm"):
                args.append("--no-llm")
        job = start_job(ctx, request, app, body.command, args,
                        needs_zap=body.command in ("author", "scan"))
        return job.public()

    def _job(job_id: str):
        job = ctx.jobs.get(job_id)
        if job is None:
            error(404, "No such job.")
        return job

    @r.get("/jobs/{job_id}")
    def get(job_id: str):
        return _job(job_id).public()

    @r.get("/jobs/{job_id}/log", response_class=PlainTextResponse)
    def log(job_id: str):
        return _job(job_id).log()

    @r.post("/jobs/{job_id}/stop")
    def stop(job_id: str, request: Request):
        job = _job(job_id)
        if job.status != "running":
            error(409, "That job isn't running.")
        actor = ctx.actor(request)
        ctx.jobs.stop(job, actor)
        if job.scan_id:
            ctx.runs.mark_stopped(job.app_id, job.scan_id, actor)
        ctx.audit.record(actor, "job.stop", job.app_id, job_id=job.job_id, scan_id=job.scan_id)
        return {"status": "stopped"}

    return r
