"""GOV-1..GOV-4, CI-1 — what scans may do, what they don't test, who did what; and CI export."""
from __future__ import annotations

import datetime as dt
import subprocess

import yaml

from tests.ui.harness import ACTOR, logged_in, make_app

GOV = "Gov Approver <gov@example.com>"
GOV_DATE = "2026-09-30T12:00:00+00:00"


def _git(ws, *args, author=None, date=None):
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "HOME": str(ws.root), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    if author:
        name, email = author[:-1].split(" <")
        env.update(GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                   GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    return subprocess.run(["git", "-C", str(ws.root), *args], env=env, check=True,
                          capture_output=True, text=True, encoding="utf-8").stdout


def _repo_with_history(ws):
    """orders-portal's file committed by Governance; a later, unrelated line by someone else."""
    _git(ws, "init", "-q")
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "orders-portal approved", author=GOV, date=GOV_DATE)
    path = ws.app_yaml("orders-portal")
    path.write_text(path.read_text(encoding="utf-8").replace("max_scan_min: 8", "max_scan_min: 9"), encoding="utf-8",
                    newline="\n")
    _git(ws, "commit", "-q", "-am", "longer scan", author="Sec Engineer <sec@example.com>",
         date="2026-10-10T09:00:00+00:00")


def _blame(ws, rel, needle):
    lines = ws.root.joinpath(rel).read_text(encoding="utf-8").splitlines()
    n = next(i for i, ln in enumerate(lines, 1) if needle in ln)
    out = _git(ws, "blame", "--porcelain", "-L", f"{n},{n}", "--", rel)
    meta = dict(line.split(" ", 1) for line in out.splitlines() if " " in line and not line.startswith("\t"))
    when = dt.datetime.fromtimestamp(int(meta["author-time"]), dt.timezone.utc)
    return meta["author"], when


# ── GOV-1: approvals carry who and when, from git ─────────────────────────────────────────

def test_gov1_approvals_match_git_blame(ws):
    _repo_with_history(ws)
    c = logged_in(make_app(ws))
    approvals = {(a["app_id"], a["path"]): a for a in c.get("/api/governance").json()["approvals"]}
    rel = "security/dast/orders-portal/app.yaml"
    for path, needle in (("gate.fail_on", "fail_on:"), ("data_policy", "data_policy:")):
        who, when = _blame(ws, rel, needle)
        a = approvals[("orders-portal", path)]
        assert a["approved_by"] == who == "Gov Approver"
        assert dt.datetime.fromisoformat(a["approved_at"]).astimezone(dt.timezone.utc) == when


# ── GOV-2: every gap is listed ─────────────────────────────────────────────────────────────

def test_gov2_gaps_cover_rules_exclusions_and_postures(api, ws):
    gaps = api.get("/api/governance").json()["gaps"]
    have = {(g["app_id"], g["kind"], str(g["item"])) for g in gaps}
    for app_dir in ws.apps_dir.iterdir():
        f = app_dir / "app.yaml"
        if not f.exists():
            continue
        cfg = yaml.safe_load(f.read_text(encoding="utf-8"))
        for rule in cfg.get("scan", {}).get("policy", {}).get("disabled_rules", []):
            assert (cfg["app_id"], "disabled_rule", str(rule)) in have
        for path in cfg.get("scope", {}).get("exclude", []):
            assert (cfg["app_id"], "exclude", path) in have
    postures = {g["item"] for g in gaps if g["kind"] == "posture" and not g["decided"]}
    # Undecided per ui_requirements.md §8 Q5 (SP-5 is effectively decided).
    for sp in ("SP-1", "SP-1a", "SP-2", "SP-3", "SP-4", "SP-6", "SP-7"):
        assert any(str(item).startswith(sp) for item in postures), sp


# ── GOV-3: the registry is read-only ──────────────────────────────────────────────────────

def test_gov3_registry_has_no_write_route(ws):
    app = make_app(ws)
    for route in app.routes:
        path = getattr(route, "path", "")
        if "registry" in path or "environment" in path:
            assert set(getattr(route, "methods", set())) <= {"GET", "HEAD"}, path
    c = logged_in(app)
    for verb in ("post", "put", "patch", "delete"):
        assert getattr(c, verb)("/api/governance/registry").status_code in (404, 405)


# ── GOV-4: one audit trail, newest first, every entry attributed ──────────────────────────

def test_gov4_audit_merges_runs_and_ui_actions(api):
    etag = api.get("/api/apps/orders-portal/settings").json()["etag"]
    assert api.put("/api/apps/orders-portal/settings",
                   json={"etag": etag, "changes": {"scan.throttle.delay_ms": 300}}).status_code == 200
    audit = api.get("/api/governance").json()["audit"]
    assert all(e.get("actor") for e in audit)
    assert [e["ts"] for e in audit] == sorted([e["ts"] for e in audit], reverse=True)
    assert any(e["actor"] == ACTOR and e["event"] == "settings.save" for e in audit)
    juice = [e for e in audit if e.get("app_id") == "juice-shop" and e["event"] == "preflight"]
    assert juice and all(e["actor"] == "outside the UI" for e in juice)


# ── CI-1: the exported workflow ───────────────────────────────────────────────────────────

def test_ci1_workflow_runs_the_loop_with_secret_references(api, monkeypatch):
    monkeypatch.setenv("ORDERS_PORTAL_USER", "s3ntinel-user")
    monkeypatch.setenv("ORDERS_PORTAL_PASS", "s3ntinel-pass")
    r = api.get("/api/apps/orders-portal/workflow")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["path"] == ".github/workflows/dast-orders-portal.yml"
    content = body["content"]
    doc = yaml.safe_load(content)
    runs = [s.get("run", "") for job in doc["jobs"].values() for s in job["steps"]]
    joined = "\n".join(runs)
    order = [joined.find(f"dast {cmd} orders-portal") for cmd in ("author", "scan", "report")]
    assert all(i >= 0 for i in order) and order == sorted(order), order
    assert "secrets.ORDERS_PORTAL_USER" in content and "secrets.ORDERS_PORTAL_PASS" in content
    assert "s3ntinel" not in content
