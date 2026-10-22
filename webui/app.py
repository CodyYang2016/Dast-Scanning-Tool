"""The FastAPI application: `create_app(UIConfig)` (contract: ui_acceptance_criteria.md §3)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from webui import security
from webui.audit import AuditLog
from webui.config import UIConfig
from webui.config_store import ConfigError, ConfigStore
from webui.identity import Identity
from webui.jobs import JobManager
from webui.runs import Runs
from webui.secret_refs import EnvSecrets
from webui.tiers import TierMap


@dataclass
class Context:
    config: UIConfig
    identity: Identity
    secrets: EnvSecrets
    tiers: TierMap
    store: ConfigStore
    jobs: JobManager
    runs: Runs
    audit: AuditLog

    def actor(self, request: Request | None = None) -> str:
        return self.identity.current(request)

    def app_secret_values(self, app: str) -> list[str]:
        """Values of the secrets an app's config names, so job output can be masked."""
        try:
            _, cfg = self.store.read(app)
        except ConfigError:
            return []
        creds = (cfg.get("auth") or {}).get("credentials") or {}
        names = [creds.get("email_env"), creds.get("password_env"), "AUTH_EMAIL", "AUTH_PASSWORD",
                 "GITHUB_TOKEN", "GH_TOKEN"]
        return [v for v in (self.secrets.value(n) for n in names if n) if v]


def error(status: int, message: str, fix: str | None = None):
    raise HTTPException(status_code=status, detail={"message": message, "fix": fix})


def create_app(config: UIConfig) -> FastAPI:
    app = FastAPI(title="DAST UI", docs_url=None, redoc_url=None, openapi_url=None)
    secrets = EnvSecrets()
    tiers = TierMap(config.tiers_file)
    jobs = JobManager(config)
    ctx = Context(config=config, identity=Identity(config), secrets=secrets, tiers=tiers,
                  store=ConfigStore(config.apps_dir, tiers, secrets), jobs=jobs,
                  runs=Runs(config.out_dir, jobs), audit=AuditLog(config.audit_log))
    app.state.ctx = ctx
    security.install(app, config, security.Sessions(config.launch_token))

    @app.exception_handler(ConfigError)
    async def _config_error(_: Request, exc: ConfigError):
        return JSONResponse({"detail": {"message": exc.message, "fix": exc.fix}},
                            status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _bad_request(_: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
        return JSONResponse({"detail": {"message": f"{where}: {first.get('msg', 'invalid')}",
                                        "fix": None}}, status_code=422)

    from webui.routers import apps, governance, jobs as jobs_routes, onboard, triage
    for module in (apps, jobs_routes, triage, onboard, governance):
        app.include_router(module.router(ctx))

    _serve_frontend(app, config.dist_dir)
    return app


def _serve_frontend(app: FastAPI, dist: Path):
    """The built React app. Unknown paths get index.html so client-side routes work on reload."""

    @app.get("/{path:path}", include_in_schema=False)
    async def frontend(path: str):
        if path.startswith("api/") or path == "api":
            error(404, "No such API endpoint.")
        root = dist.resolve()
        candidate = (root / path).resolve()
        if path and candidate.is_file() and root in candidate.parents:
            return FileResponse(candidate)
        index = root / "index.html"
        if not index.is_file():
            return HTMLResponse("The UI hasn't been built.", status_code=500)
        return HTMLResponse(index.read_text(encoding="utf-8"))
