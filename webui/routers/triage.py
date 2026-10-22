"""Triage in the UI (UI-10) and publishing through `dast report` (UI-11).

Decisions live in the app's suppressions.yaml, the file `dast report` already reads. A proposal
(status: proposed) is a suggestion that changes nothing until someone approves it. Publishing is
the real `dast report … --upload|--issues`; the GitHub token reaches it only in its environment.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import re
from typing import Literal

import yaml
from fastapi import APIRouter, Request
from pydantic import BaseModel
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from detections import triage as core_triage
from webui.app import error

REASONS = ("false_positive", "accepted_risk", "wont_fix", "test_data")
NEEDS_EXPIRY = ("accepted_risk", "wont_fix")
_SHA = re.compile(r"^[0-9a-f]{7,40}$")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path(ctx, app: str):
    return ctx.config.apps_dir / app / "suppressions.yaml"


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _load(ctx, app: str):
    p = _path(ctx, app)
    if p.exists():
        doc = _yaml().load(p.read_text(encoding="utf-8"))
        if doc is None:
            doc = CommentedMap()
    else:
        doc = CommentedMap()
    if "suppressions" not in doc or doc["suppressions"] is None:
        doc["suppressions"] = []
    return doc


def _write(ctx, app: str, doc) -> None:
    out = io.StringIO()
    _yaml().dump(doc, out)
    text = out.getvalue()
    try:
        core_triage.validate(yaml.safe_load(text))
    except Exception as exc:
        message = getattr(exc, "message", None) or str(exc).splitlines()[0]
        error(422, f"That decision isn't valid: {message}")
    p = _path(ctx, app)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")


def suppressions_by_fp(ctx, app: str) -> dict:
    p = _path(ctx, app)
    if not p.exists():
        return {}
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {e["fingerprint"]: e for e in doc.get("suppressions") or [] if "fingerprint" in e}


def _public(entry: dict, today: dt.date) -> dict:
    expires = entry.get("expires")
    return {"fingerprint": entry.get("fingerprint"), "reason": entry.get("reason"),
            "justification": entry.get("justification"), "status": entry.get("status", "approved"),
            "expires": str(expires) if expires else None,
            "expired": bool(expires) and dt.date.fromisoformat(str(expires)) < today,
            "proposed_by": entry.get("proposed_by"), "approved_by": entry.get("approved_by"),
            "decided_at": entry.get("decided_at"), "rule_id": entry.get("rule_id"),
            "endpoint": entry.get("endpoint"), "parameter": entry.get("parameter")}


class Proposal(BaseModel):
    fingerprint: str
    reason: Literal["false_positive", "accepted_risk", "wont_fix", "test_data"]
    justification: str
    expires: str | None = None


class Publish(BaseModel):
    destination: Literal["code-scanning", "issues"]
    owner: str
    repo: str
    ref: str
    commit: str = ""
    token_env: str


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api")

    def _record(app: str, fp: str) -> dict | None:
        latest = ctx.runs.latest_with_records(app)
        if latest is None:
            return None
        return next((x for x in ctx.runs.records(app, latest.name) if x.get("fingerprint") == fp), None)

    @r.get("/apps/{app}/suppressions")
    def listing(app: str):
        today = dt.date.today()
        return [_public(e, today) for e in suppressions_by_fp(ctx, app).values()]

    @r.post("/apps/{app}/suppressions", status_code=201)
    def propose(app: str, body: Proposal, request: Request):
        if not body.justification.strip():
            error(422, "Say why this finding should be set aside.")
        if body.reason in NEEDS_EXPIRY and not body.expires:
            error(422, "Accepted risks and won't-fix decisions need a date to review them again.",
                  "Add an expiry date.")
        if body.expires:
            try:
                dt.date.fromisoformat(body.expires)
            except ValueError:
                error(422, "The expiry must be a date like 2026-12-31.")
        doc = _load(ctx, app)
        entries = doc["suppressions"]
        for i, e in enumerate(entries):
            if e.get("fingerprint") == body.fingerprint:
                if e.get("status", "approved") == "approved":
                    error(409, "This finding already has an approved decision.")
                del entries[i]
                break
        entry = CommentedMap(fingerprint=body.fingerprint, reason=body.reason,
                             justification=body.justification.strip())
        if body.expires:
            entry["expires"] = body.expires
        rec = _record(app, body.fingerprint)
        if rec:
            for k in ("rule_id", "endpoint", "parameter"):
                if rec.get(k) is not None:
                    entry[k] = str(rec[k]) if k == "rule_id" else rec[k]
        actor = ctx.actor(request)
        entry["status"] = "proposed"
        entry["proposed_by"] = actor
        entries.append(entry)
        _write(ctx, app, doc)
        ctx.audit.record(actor, "suppression.propose", app, fingerprint=body.fingerprint,
                         reason=body.reason)
        return _public(dict(entry), dt.date.today())

    @r.post("/apps/{app}/suppressions/{fingerprint}/approve")
    def approve(app: str, fingerprint: str, request: Request):
        doc = _load(ctx, app)
        entry = next((e for e in doc["suppressions"] if e.get("fingerprint") == fingerprint), None)
        if entry is None:
            error(404, "There is no proposal for this finding.")
        if entry.get("status", "approved") == "approved":
            error(409, "This decision is already approved.")
        actor = ctx.actor(request)
        entry["status"] = "approved"
        entry["approved_by"] = actor
        entry["decided_at"] = _now()
        _write(ctx, app, doc)
        ctx.audit.record(actor, "suppression.approve", app, fingerprint=fingerprint)
        return _public(dict(entry), dt.date.today())

    # ── publishing ────────────────────────────────────────────────────────────────────────
    def _check_publish(app: str, body: Publish):
        if not ctx.store.exists(app):
            error(404, f"There is no application called {app}.")
        if not _SHA.match(body.commit.strip().lower()):
            error(422, "Which build was scanned? Enter the deployed commit (its full SHA).",
                  "This tool's own code isn't the app that was scanned, so there's no default.")
        if not ctx.secrets.valid_name(body.token_env) or not ctx.secrets.is_set(body.token_env):
            error(422, f"The token variable {body.token_env} isn't set.",
                  f"Set {body.token_env} in the shell that started `python -m dast ui`, then restart it.")
        latest = ctx.runs.latest_with_records(app)
        if latest is None:
            error(422, f"{app} has no completed scan to publish.", "Run a scan first.")
        return latest

    def _preview(app: str, body: Publish, latest) -> dict:
        _, cfg = ctx.store.read(app)
        category = ((cfg.get("publish") or {}).get("github") or {}).get("category") or f"dast/{app}"
        labeled = latest / "labeled.json"
        records = json.loads((labeled if labeled.exists() else latest / "records.json")
                             .read_text(encoding="utf-8"))
        return {"destination": body.destination, "owner": body.owner, "repo": body.repo,
                "ref": body.ref, "commit": body.commit, "count": len(records),
                "category": category, "scan_id": latest.name,
                "command": " ".join(["python -m dast", *_report_args(app, body)])}

    def _report_args(app: str, body: Publish) -> list[str]:
        return ["report", app, "--upload" if body.destination == "code-scanning" else "--issues",
                "--owner", body.owner, "--repo", body.repo, "--ref", body.ref,
                "--commit", body.commit.strip()]

    @r.post("/apps/{app}/publish/preview")
    def preview(app: str, body: Publish):
        return _preview(app, body, _check_publish(app, body))

    @r.post("/apps/{app}/publish", status_code=201)
    def publish(app: str, body: Publish, request: Request):
        from webui.routers.jobs import start_job
        _check_publish(app, body)
        token = ctx.secrets.value(body.token_env)
        job = start_job(ctx, request, app, "report", _report_args(app, body)[1:], needs_zap=False,
                        env_extra={"GITHUB_TOKEN": token}, extra_secrets=[token],
                        audit_event="publish",
                        audit_detail={"destination": body.destination, "commit": body.commit})
        return job.public()

    return r
