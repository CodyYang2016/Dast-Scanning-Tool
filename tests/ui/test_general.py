"""GEN-4, GEN-5 — every UI write is audited; the UI names no application."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from tests.test_no_app_specifics import APP_MARKERS
from tests.ui.harness import ACTOR, LATER_RUN, ROOT, wait_job

WEBUI = ROOT / "webui"


# ── GEN-4: every write leaves an attributed audit entry ───────────────────────────────────

def test_gen4_every_write_is_audited(api_zap, ws, monkeypatch):
    monkeypatch.setenv("UI_TEST_GH_TOKEN", "token-value")
    monkeypatch.setenv("FAKE_DAST_SCAN", "slow")
    labeled = json.loads((ws.run_dir("juice-shop", LATER_RUN) / "labeled.json").read_text())
    fp = next(r for r in labeled if r["status"] == "open")["fingerprint"]

    def last():
        return ws.audit()[-1]

    etag = api_zap.get("/api/apps/orders-portal/settings").json()["etag"]
    api_zap.put("/api/apps/orders-portal/settings",
                json={"etag": etag, "changes": {"scan.throttle.delay_ms": 400}})
    assert last()["event"] == "settings.save"
    api_zap.post("/api/apps/juice-shop/suppressions",
                 json={"fingerprint": fp, "reason": "false_positive", "justification": "x"})
    assert last()["event"] == "suppression.propose"
    api_zap.post(f"/api/apps/juice-shop/suppressions/{fp}/approve")
    assert last()["event"] == "suppression.approve"
    job = api_zap.post("/api/apps/orders-portal/jobs", json={"command": "scan", "options": {}}).json()
    assert last()["event"] == "job.start"
    api_zap.post(f"/api/jobs/{job['job_id']}/stop")
    assert last()["event"] == "job.stop"
    wait_job(api_zap, job["job_id"])
    monkeypatch.setenv("FAKE_DAST_SCAN", "ok")
    pub = api_zap.post("/api/apps/juice-shop/publish", json={
        "destination": "code-scanning", "owner": "o", "repo": "r", "ref": "refs/heads/main",
        "commit": "5658473cf8814459bf89000ce373b20ed0b4eb37", "token_env": "UI_TEST_GH_TOKEN"})
    assert last()["event"] == "publish"
    wait_job(api_zap, pub.json()["job_id"])
    ob = api_zap.post("/api/onboard", json={
        "app_id": "billing", "base_url": "http://billing.dev.local", "environment_class": "dev",
        "auth": "form", "login_url": "/signin", "user_env": "B_USER", "pass_env": "B_PASS"})
    assert last()["event"] == "onboard.start"
    wait_job(api_zap, ob.json()["job_id"])
    api_zap.post("/api/onboard/billing/confirm", json={"proof_confirmed": True})
    assert last()["event"] == "onboard.confirm"
    assert all(e["actor"] == ACTOR and e.get("ts") for e in ws.audit())


# ── GEN-5: the UI names no application ────────────────────────────────────────────────────

def _python_strings(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                  and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.value


def _frontend_code(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)//.*$", "", line) for line in text.splitlines())


def test_gen5_webui_names_no_application():
    assert WEBUI.is_dir(), "webui/ does not exist yet"
    offenders = []
    for py in WEBUI.rglob("*.py"):
        for s in _python_strings(py):
            low = s.lower()
            offenders += [(str(py), m) for m in APP_MARKERS if m in low]
    src = WEBUI / "frontend" / "src"
    for f in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
        low = _frontend_code(f).lower()
        offenders += [(str(f), m) for m in APP_MARKERS if m in low]
    assert not offenders, offenders
