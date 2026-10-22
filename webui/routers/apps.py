"""Session, system status, apps and their settings, and the read-only views of runs."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from authoring import llm_backend
from runner import zapapi
from webui.app import error
from webui.config_store import ConfigError
from webui.routers.triage import suppressions_by_fp
from webui.runs import replay_line


class Changes(BaseModel):
    etag: str
    changes: dict


def zap_status(url: str) -> str:
    """'ok', 'key' (answering, but refused our ZAP_API_KEY) or 'down'.

    Through the runner's own keyed client: a keyed ZAP drops an unkeyed request without a word,
    which a plain probe would misread as ZAP being down.
    """
    try:
        zapapi.call(url, "/JSON/core/view/version/", timeout=2.0)
        return "ok"
    except zapapi.ZapAuthError:
        return "key"
    except Exception:
        return "down"


def zap_reachable(url: str) -> bool:
    return zap_status(url) == "ok"


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api")

    @r.get("/session")
    def session(request: Request):
        return {"actor": ctx.actor(request), "csrf_token": request.state.csrf}

    @r.get("/system")
    def system():
        zap = zap_status(ctx.config.zap_api)
        return {"zap": {"url": ctx.config.zap_api, "reachable": zap == "ok", "status": zap},
                "ai": {"provider": llm_backend.provider(), "available": llm_backend.available()}}

    @r.get("/secrets/{name}")
    def secret_status(name: str):
        """Whether a variable is set, for the onboarding wizard. Never its value (UI-4)."""
        if not ctx.secrets.valid_name(name):
            error(422, f"{name!r} isn't a valid environment variable name.")
        return ctx.secrets.status(name)

    @r.get("/apps")
    def apps():
        out = []
        for app in ctx.store.apps():
            try:
                _, cfg = ctx.store.read(app)
            except Exception:
                cfg = {}
            runs = ctx.runs.list(app)
            out.append({"app_id": app, "environment_class": cfg.get("environment_class"),
                        "base_url": cfg.get("base_url"),
                        "latest_run": ({"scan_id": runs[0]["scan_id"], "status": runs[0]["status"]}
                                       if runs else None)})
        return out

    @r.get("/apps/{app}/settings")
    def settings(app: str):
        return ctx.store.settings(app)

    @r.post("/apps/{app}/settings/preview")
    def preview(app: str, body: Changes):
        return ctx.store.preview(app, body.etag, body.changes)

    @r.put("/apps/{app}/settings")
    def save(app: str, body: Changes, request: Request):
        result = ctx.store.save(app, body.etag, body.changes)
        ctx.audit.record(ctx.actor(request), "settings.save", app, changed=sorted(body.changes))
        return result

    # ── runs (read-only) ──────────────────────────────────────────────────────────────────
    def _app_or_404(app: str):
        if not ctx.store.exists(app) and not ctx.runs.paths(app).scans.is_dir():
            error(404, f"There is no application called {app}.")

    @r.get("/apps/{app}/runs")
    def runs(app: str):
        _app_or_404(app)
        return ctx.runs.list(app)

    @r.get("/apps/{app}/runs/{scan_id}")
    def run(app: str, scan_id: str):
        d = ctx.runs.detail(app, scan_id)
        if d is None:
            error(404, f"No run {scan_id} for {app}.")
        return d

    @r.get("/apps/{app}/runs/{scan_id}/events")
    async def events(app: str, scan_id: str, request: Request):
        if not ctx.runs.run_dir(app, scan_id).is_dir():
            error(404, f"No run {scan_id} for {app}.")
        return StreamingResponse(ctx.runs.stream_events(app, scan_id, request),
                                 media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    def _finding(rec: dict, supp: dict, today: dt.date) -> dict:
        item = {k: rec.get(k) for k in ("fingerprint", "severity", "rule_id", "title", "endpoint",
                                        "parameter", "status")}
        entry = supp.get(rec.get("fingerprint"))
        if entry:
            expires = entry.get("expires")
            item["suppression"] = {
                "reason": entry.get("reason"), "status": entry.get("status", "approved"),
                "expires": str(expires) if expires else None,
                "expired": bool(expires) and dt.date.fromisoformat(str(expires)) < today}
        return item

    @r.get("/apps/{app}/runs/{scan_id}/findings")
    def findings(app: str, scan_id: str):
        if not ctx.runs.run_dir(app, scan_id).is_dir():
            error(404, f"No run {scan_id} for {app}.")
        supp = suppressions_by_fp(ctx, app)
        today = dt.date.today()
        return [_finding(rec, supp, today) for rec in ctx.runs.records(app, scan_id)]

    @r.get("/apps/{app}/runs/{scan_id}/findings/{fingerprint}")
    def finding(app: str, scan_id: str, fingerprint: str):
        rec = next((x for x in ctx.runs.records(app, scan_id)
                    if x.get("fingerprint") == fingerprint), None)
        if rec is None:
            error(404, "No such finding in this run.")
        try:
            base = (ctx.store.read(app)[1] or {}).get("base_url") or ""
        except ConfigError:
            base = ""
        out = _finding(rec, suppressions_by_fp(ctx, app), dt.date.today())
        out.update(attack=rec.get("attack"), evidence=rec.get("evidence_excerpt"),
                   solution=rec.get("solution"), references=rec.get("references"),
                   request_line=rec.get("request_line"), description=rec.get("description"),
                   confidence=rec.get("confidence"), cwe_id=rec.get("cwe_id"),
                   response_status=rec.get("response_status"),
                   replay=replay_line(rec, base))
        return out

    return r
