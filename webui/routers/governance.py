"""Governance (UI-13) and exporting a CI workflow (UI-14). Read-only: nothing here writes.

Who approved a tier C setting, and when, comes from git: the author and date of the commit that
last changed that line of app.yaml. That is where approvals happen (ui_requirements.md §8 Q3), so
the UI reports them rather than keeping a second record.
"""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from fastapi import APIRouter

from runner import env_registry
from webui.app import error
from webui.runs import read_events

OUTSIDE = "outside the UI"
_EVENT_META = {"ts", "scan_id", "app_id", "event", "actor"}


def blame(repo: Path, file: Path, line: int) -> tuple[str | None, str | None]:
    try:
        rel = file.resolve().relative_to(repo.resolve())
    except ValueError:
        return None, None
    try:
        out = subprocess.run(["git", "-C", str(repo), "blame", "--porcelain", "-L", f"{line},{line}",
                              "--", str(rel)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    if out.returncode != 0:
        return None, None
    meta = dict(ln.split(" ", 1) for ln in out.stdout.splitlines()
                if " " in ln and not ln.startswith("\t"))
    author = meta.get("author")
    if not author or author == "Not Committed Yet" or "author-time" not in meta:
        return None, None
    when = dt.datetime.fromtimestamp(int(meta["author-time"]), dt.timezone.utc)
    return author, when.isoformat()


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api")

    def approvals() -> list[dict]:
        out = []
        for app in ctx.store.apps():
            _, cfg = ctx.store.read(app)
            for dotted, value in ctx.tiers.fields(cfg):
                if ctx.tiers.resolve(dotted, cfg).tier != "C":
                    continue
                line = ctx.store.line_of(app, dotted)
                who, when = blame(ctx.config.repo_root, ctx.store.path(app), line) if line else (None, None)
                out.append({"app_id": app, "path": dotted, "value": value,
                            "approved_by": who, "approved_at": when})
        return out

    def gaps() -> list[dict]:
        out = []
        for app in ctx.store.apps():
            _, cfg = ctx.store.read(app)
            for rule in ((cfg.get("scan") or {}).get("policy") or {}).get("disabled_rules") or []:
                out.append({"app_id": app, "kind": "disabled_rule", "item": str(rule), "decided": True})
            for path in (cfg.get("scope") or {}).get("exclude") or []:
                out.append({"app_id": app, "kind": "exclude", "item": path, "decided": True})
        for p in ctx.tiers.postures:
            out.append({"app_id": "*", "kind": "posture", "item": f"{p['id']} {p['title']}",
                        "decided": bool(p.get("decided"))})
        return out

    def registry() -> dict:
        reg = env_registry.load(ctx.config.registry_path)
        return {"hosts": reg.hosts, "prod_patterns": reg.prod_host_patterns}

    def audit() -> list[dict]:
        entries = [{"ts": e["ts"], "actor": e.get("actor") or OUTSIDE, "app_id": e.get("app_id"),
                    "event": e.get("event"), "detail": e.get("detail") or {}}
                   for e in ctx.audit.entries() if e.get("ts")]
        out_dir = ctx.config.out_dir
        if out_dir.is_dir():
            for events in sorted(out_dir.glob("*/scans/*/events.jsonl")):
                for e in read_events(events):
                    if not e.get("ts"):
                        continue
                    detail = {k: v for k, v in e.items() if k not in _EVENT_META}
                    detail["scan_id"] = e.get("scan_id")
                    entries.append({"ts": e["ts"], "actor": e.get("actor") or OUTSIDE,
                                    "app_id": e.get("app_id") or events.parts[-4],
                                    "event": e.get("event"), "detail": detail})
        entries.sort(key=lambda x: x["ts"], reverse=True)
        return entries[:1000]

    @r.get("/governance")
    def governance():
        return {"approvals": approvals(), "gaps": gaps(), "registry": registry(), "audit": audit()}

    @r.get("/apps/{app}/workflow")
    def workflow(app: str):
        if not ctx.store.exists(app):
            error(404, f"There is no application called {app}.")
        _, cfg = ctx.store.read(app)
        creds = (cfg.get("auth") or {}).get("credentials") or {}
        names = [n for n in (creds.get("email_env"), creds.get("password_env")) if n]
        env_lines = "".join(f"          {n}: ${{{{ secrets.{n} }}}}\n" for n in names)
        content = (
            f"# Scheduled DAST scan for {app}, exported by `python -m dast ui`.\n"
            f"# Add {', '.join(names) or 'the test account variables'} as repository secrets first.\n"
            f"name: dast-{app}\n"
            "on:\n"
            "  schedule:\n"
            "    - cron: \"0 6 * * 1\"   # Mondays 06:00 UTC\n"
            "  workflow_dispatch:\n"
            "permissions:\n"
            "  contents: read\n"
            "  security-events: write\n"
            "jobs:\n"
            "  scan:\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 45\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: actions/setup-python@v5\n"
            "        with:\n"
            "          python-version: \"3.12\"\n"
            "      - name: install\n"
            "        run: pip install -r requirements.txt && python -m playwright install --with-deps chromium\n"
            "      - name: ZAP key for this run\n"
            "        run: echo \"ZAP_API_KEY=$(openssl rand -hex 24)\" >> \"$GITHUB_ENV\"\n"
            "      - name: start ZAP\n"
            "        run: docker compose up -d zap\n"
            "      - name: author and scan\n"
            + (f"        env:\n{env_lines}" if env_lines else "")
            + "        run: |\n"
            f"          python -m dast author {app} --no-llm\n"
            f"          python -m dast scan {app}\n"
            "      - name: report and publish\n"
            "        env:\n"
            "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
            "        run: |\n"
            f"          python -m dast report {app} --upload \\\n"
            "            --ref \"$DEPLOYED_REF\" --commit \"$DEPLOYED_SHA\"   # from your deploy job\n"
        )
        return {"path": f".github/workflows/dast-{app}.yml", "content": content}

    return r
