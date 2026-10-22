"""Onboarding (UI-3, UI-4, UI-5): `dast onboard`, staged until a person confirms the login proof.

The registry check runs first and refuses what preflight would refuse later: production-like
hosts, and test or staging hosts nobody has registered. Discovery (with an AI provider) or the
skeleton (without one) is written to a staging file; the app's real app.yaml appears only after
the proof is confirmed, with the secret variable names the person chose.
"""
from __future__ import annotations

import io
import re
from typing import Literal
from urllib.parse import urlparse

import yaml
from fastapi import APIRouter, Request
from pydantic import BaseModel
from ruamel.yaml import YAML

from authoring import appconfig, llm_backend
from runner import env_registry
from webui import registry_check
from webui.app import error

_APP_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class Check(BaseModel):
    app_id: str
    base_url: str
    environment_class: Literal["dev", "test", "staging"]


class Start(Check):
    auth: Literal["form", "seeded"] = "form"
    login_url: str = "/login"
    user_env: str
    pass_env: str
    overwrite: bool = False


class Confirm(BaseModel):
    proof_confirmed: bool
    authenticated_routes: list[str] | None = None


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api/onboard")
    pending: dict[str, dict] = {}

    def staged(app: str):
        return ctx.config.out_dir / ".ui-staging" / f"{app}.yaml"

    def check(body: Check, overwrite: bool = False) -> dict:
        if not _APP_ID.match(body.app_id):
            error(422, "Use lowercase letters, digits and dashes for the application id.")
        host = (urlparse(body.base_url).hostname or "").lower()
        if not host or urlparse(body.base_url).scheme not in ("http", "https"):
            error(422, "The address must start with http:// or https:// and name a host.")
        refused = registry_check.refusal(ctx.config.registry_path, body.base_url, body.environment_class)
        if refused:
            error(422, *refused)
        registered = env_registry.load(ctx.config.registry_path).lookup(host)
        if ctx.store.exists(body.app_id) and not overwrite:
            error(409, f"{body.app_id} is already onboarded.",
                  "Pick another id, or confirm you want to replace its settings.")
        return {"ok": True, "host": host,
                "registry": f"registered as {registered}" if registered else "not listed (dev hosts needn't be)"}

    @r.post("/check")
    def check_route(body: Check):
        return check(body)

    @r.post("", status_code=201)
    def start(body: Start, request: Request):
        from webui.routers.jobs import start_job
        check(body, overwrite=body.overwrite)
        for name in (body.user_env, body.pass_env):
            if not ctx.secrets.valid_name(name):
                error(422, f"{name!r} isn't a valid environment variable name.")
        discover = llm_backend.available()
        out = staged(body.app_id)
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            out.unlink()
        args = [body.app_id, "--base-url", body.base_url, "--environment-class",
                body.environment_class, "--auth", body.auth, "--login-url", body.login_url,
                "--config-out", str(out)]
        # Discover the way the scan will reach the app: through ZAP, when it's answering. An app
        # only the scanner can route to (one on ZAP's network, say) is otherwise out of reach
        # (QA-14). With ZAP down, discovery still runs directly, as it needs nothing from ZAP.
        via_zap = False
        if discover:
            from webui.routers.apps import zap_status
            args.append("--discover")
            if zap_status(ctx.config.zap_api) in ("ok", "key"):    # the proxy needs no API key
                args += ["--zap-proxy", ctx.config.zap_api]
                via_zap = True
        env_extra, secret_values = {}, []
        user, password = ctx.secrets.value(body.user_env), ctx.secrets.value(body.pass_env)
        if user and password:           # discovery signs in with them, under the names it reads
            env_extra = {"AUTH_EMAIL": user, "AUTH_PASSWORD": password}
            secret_values = [user, password]
        pending[body.app_id] = {"user_env": body.user_env, "pass_env": body.pass_env,
                                "mode": "discover" if discover else "skeleton",
                                "overwrite": body.overwrite}
        job = start_job(ctx, request, body.app_id, "onboard", args, needs_zap=False,
                        env_extra=env_extra, extra_secrets=secret_values,
                        audit_event="onboard.start",
                        audit_detail={"mode": pending[body.app_id]["mode"]})
        pending[body.app_id]["job_id"] = job.job_id
        message = (f"Reading the login page{' through ZAP' if via_zap else ''} and signing in with "
                   "the test account."
                   if discover else
                   "No AI provider is available, so the login steps must be filled in by hand "
                   "under Advanced after saving.")
        return {"job_id": job.job_id, "mode": pending[body.app_id]["mode"], "message": message,
                "command": job.command}

    @r.get("/{app}/proposal")
    def proposal(app: str):
        p = staged(app)
        if not p.exists():
            error(404, f"Nothing is waiting to be confirmed for {app}.",
                  "Start onboarding, and wait for it to finish.")
        cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        auth = cfg.get("auth") or {}
        info = pending.get(app, {})
        problem = None
        job = ctx.jobs.get(info.get("job_id", ""))
        if job is not None and info.get("mode") == "discover":
            # `dast onboard --discover` falls back to the skeleton when no proof verifies; say so.
            for line in job.log().splitlines():
                if line.startswith("discovery failed:"):
                    problem = line.removeprefix("discovery failed:").strip()
                    info["mode"] = "skeleton"
                    break
        return {"app_id": app, "mode": info.get("mode", "skeleton"), "problem": problem,
                "steps": auth.get("steps") or [], "proof": auth.get("proof") or {},
                "authenticated_routes": (cfg.get("record") or {}).get("authenticated_routes") or [],
                "base_url": cfg.get("base_url"), "login_url": auth.get("login_url")}

    @r.post("/{app}/confirm", status_code=201)
    def confirm(app: str, body: Confirm, request: Request):
        if not body.proof_confirmed:
            error(422, "Confirm that the page only shows when someone is signed in.",
                  "If it doesn't, go back and choose another page.")
        p = staged(app)
        if not p.exists():
            error(404, f"Nothing is waiting to be confirmed for {app}.")
        info = pending.get(app, {})
        if ctx.store.exists(app) and not info.get("overwrite"):
            error(409, f"{app} is already onboarded.")
        y = _yaml()
        doc = y.load(p.read_text(encoding="utf-8"))
        creds = doc.setdefault("auth", {}).setdefault("credentials", {})
        if info.get("user_env"):
            creds["email_env"] = info["user_env"]
            creds["password_env"] = info["pass_env"]
        if body.authenticated_routes:
            doc.setdefault("record", {})["authenticated_routes"] = body.authenticated_routes
        buf = io.StringIO()
        y.dump(doc, buf)
        text = buf.getvalue()
        valid, problem = True, None
        try:
            appconfig.validate_app_config(yaml.safe_load(text), source=f"{app}'s app.yaml")
        except Exception as exc:
            valid, problem = False, getattr(exc, "message", None) or str(exc).splitlines()[0]
            if info.get("mode") == "discover":
                error(422, f"The discovered settings aren't valid: {problem}")
        target = ctx.store.path(app)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        p.unlink()
        pending.pop(app, None)
        ctx.audit.record(ctx.actor(request), "onboard.confirm", app, valid=valid)
        return {"app_id": app, "path": str(target), "valid": valid, "problem": problem}

    @r.post("/{app}/sign-in", status_code=201)
    def sign_in(app: str, request: Request):
        from webui.routers.jobs import start_job
        _, cfg = ctx.store.read(app)
        if (cfg.get("auth") or {}).get("mode") != "seeded":
            error(409, f"{app} signs in with a form; there's nothing to sign in to by hand.")
        job = start_job(ctx, request, app, "author", [app, "--explore", "--headed"], needs_zap=True)
        return job.public()

    return r
