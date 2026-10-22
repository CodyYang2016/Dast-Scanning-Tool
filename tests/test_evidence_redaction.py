"""RED-1..RED-9 — evidence never keeps a secret (docs/evidence_hosting_gap_analysis.md).

Written before the fix and committed failing. Each secret is a unique sentinel; every test asserts
the sentinel is absent from what is written or returned. The sample HAR carries each secret the
gap analysis found surviving `redact_har` on main.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from runner import evidence

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SCAN = ROOT / "tests" / "ui" / "fixtures" / "out" / "juice-shop" / "scans" / "20261019T125049Z"
SECRETS = {
    "form_pass": "hunter2-FORM", "form_password": "hunter3-FORM", "query_token": "TOKEN-QS-123",
    "csrf": "csrf-ABC-999", "xsrf": "xsrf-DEF-888", "session": "sess-JSON-777",
    "apikey": "apikey-JSON-666", "bearer": "bearer-BODY-555", "cookie": "cookie-VAL-444",
}


def dirty_har() -> dict:
    s = SECRETS
    return {"log": {"version": "1.2", "entries": [{
        "request": {
            "method": "POST",
            "url": f"http://app.test/login?next=/home&access_token={s['query_token']}",
            "queryString": [{"name": "next", "value": "/home"},
                            {"name": "access_token", "value": s["query_token"]}],
            "headers": [{"name": "X-CSRF-Token", "value": s["csrf"]},
                        {"name": "X-XSRF-Token", "value": s["xsrf"]},
                        {"name": "Cookie", "value": f"PHPSESSID={s['cookie']}"},
                        {"name": "Accept", "value": "text/html"}],
            "cookies": [{"name": "PHPSESSID", "value": s["cookie"]}],
            "postData": {"mimeType": "application/x-www-form-urlencoded",
                         "text": f"user=admin&pass={s['form_pass']}&password={s['form_password']}",
                         "params": [{"name": "user", "value": "admin"},
                                    {"name": "pass", "value": s["form_pass"]},
                                    {"name": "password", "value": s["form_password"]}]}},
        "response": {
            "status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
            "cookies": [],
            "content": {"mimeType": "application/json", "text": json.dumps(
                {"sessionId": s["session"], "apikey": s["apikey"],
                 "note": f"Authorization: Bearer {s['bearer']}", "greeting": "hello admin"})}}}]}}


def _entry(har):
    return har["log"]["entries"][0]


def _leaks(text: str) -> list[str]:
    return [k for k, v in SECRETS.items() if v in text]


# ── RED-1..RED-5: the cleaner itself ───────────────────────────────────────────────────────

def test_red1_form_login_password_removed():
    req = _entry(evidence.redact_har(dirty_har()))["request"]
    assert SECRETS["form_pass"] not in req["postData"]["text"]
    assert SECRETS["form_password"] not in req["postData"]["text"]
    assert not _leaks(json.dumps(req["postData"]["params"]))


def test_red2_query_token_removed():
    req = _entry(evidence.redact_har(dirty_har()))["request"]
    assert SECRETS["query_token"] not in req["url"]
    assert SECRETS["query_token"] not in json.dumps(req["queryString"])


def test_red3_csrf_headers_removed():
    headers = json.dumps(_entry(evidence.redact_har(dirty_har()))["request"]["headers"])
    assert SECRETS["csrf"] not in headers and SECRETS["xsrf"] not in headers


def test_red4_json_secrets_and_bearer_in_body_removed():
    body = _entry(evidence.redact_har(dirty_har()))["response"]["content"]["text"]
    assert not _leaks(body), _leaks(body)


def test_red5_shape_kept_and_harmless_values_untouched():
    out = evidence.redact_har(dirty_har())
    assert not _leaks(json.dumps(out)), _leaks(json.dumps(out))
    e = _entry(out)
    assert e["request"]["method"] == "POST"
    assert e["request"]["url"].startswith("http://app.test/login?next=/home")
    assert e["response"]["status"] == 200
    assert [h["name"] for h in e["request"]["headers"]] == ["X-CSRF-Token", "X-XSRF-Token", "Cookie", "Accept"]
    assert {"name": "Accept", "value": "text/html"} in e["request"]["headers"]
    assert {"name": "next", "value": "/home"} in e["request"]["queryString"]
    assert "hello admin" in e["response"]["content"]["text"]


# ── RED-6 / RED-7: replay leaves only a cleaned HAR, even when the login fails ─────────────

class _FakePage:
    def __init__(self, context, fail_goto=False):
        self.context = context
        self.screenshots: list[dict] = []
        self._fail_goto = fail_goto

    def route(self, *a, **k):
        pass

    def locator(self, selector):
        return ("locator", selector)

    def screenshot(self, **kwargs):
        self.screenshots.append(kwargs)
        Path(kwargs["path"]).write_bytes(b"png")

    def goto(self, *a, **k):
        if self._fail_goto:
            raise RuntimeError("navigation failed")


class _FakeContext:
    def __init__(self, har_path, fail_goto):
        self.har_path = har_path
        self.page = _FakePage(self, fail_goto)

    def on(self, *a, **k):
        pass

    def new_page(self):
        return self.page

    def add_cookies(self, *a, **k):
        pass

    def cookies(self, *a, **k):
        return []

    def close(self):                       # Playwright writes the HAR when the context closes
        if self.har_path:
            Path(self.har_path).write_text(json.dumps(dirty_har()), encoding="utf-8")


class _FakeBrowser:
    def __init__(self, fail_goto):
        self.fail_goto = fail_goto
        self.contexts: list[_FakeContext] = []

    def new_context(self, **kwargs):
        ctx = _FakeContext(kwargs.get("record_har_path"), self.fail_goto)
        self.contexts.append(ctx)
        return ctx

    def close(self):
        pass


class _FakePlaywright:
    def __init__(self, fail_goto=False):
        self.browser = _FakeBrowser(fail_goto)
        self.chromium = self

    def launch(self, **kwargs):
        return self.browser

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def fake_browser(monkeypatch):
    holder = {}

    def install(fail_goto=False):
        pw = _FakePlaywright(fail_goto)
        holder["pw"] = pw
        monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: pw)
        return pw
    return install


SCOPE = {"app_id": "app", "environment_class": "dev", "fqdn_allow_list": ["app.test"]}


class _FailingFlow:
    @staticmethod
    def run(page, base_url):
        raise RuntimeError("login button never appeared")


def test_red6_failed_login_leaves_a_clean_har(tmp_path, fake_browser):
    from runner import replay
    fake_browser()
    with pytest.raises(Exception):
        replay.replay(SCOPE, _FailingFlow, "http://app.test", "http://127.0.0.1:9",
                      evidence_dir=str(tmp_path))
    har = (tmp_path / "active-scan.har").read_text(encoding="utf-8")
    assert not _leaks(har), _leaks(har)


def test_red6_failed_seeded_session_leaves_a_clean_har(tmp_path, fake_browser):
    from runner import replay
    fake_browser(fail_goto=True)
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception):
        replay.replay_seeded(SCOPE, "http://app.test", "http://127.0.0.1:9", str(state), ["/home"],
                             evidence_dir=str(tmp_path / "ev"))
    har = (tmp_path / "ev" / "active-scan.har").read_text(encoding="utf-8")
    assert not _leaks(har), _leaks(har)


def test_red7_screenshot_masks_password_fields(tmp_path, fake_browser):
    from runner import replay
    pw = fake_browser()
    with pytest.raises(Exception):
        replay.replay(SCOPE, _FailingFlow, "http://app.test", "http://127.0.0.1:9",
                      evidence_dir=str(tmp_path))
    shots = pw.browser.contexts[0].page.screenshots
    assert shots, "no screenshot was taken"
    assert all(("locator", "input[type=password]") in (s.get("mask") or []) for s in shots)


# ── RED-8: the check before anything is published ──────────────────────────────────────────

def _check(directory) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "runner.evidence", "--check", str(directory)],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_red8_check_flags_unredacted_evidence(tmp_path):
    (tmp_path / "messages").mkdir()
    (tmp_path / "active-scan.har").write_text(json.dumps(dirty_har()), encoding="utf-8")
    (tmp_path / "messages" / "abc").write_text(
        f"POST /login HTTP/1.1\nCookie: PHPSESSID={SECRETS['cookie']}\n\npass={SECRETS['form_pass']}",
        encoding="utf-8")
    r = _check(tmp_path)
    assert r.returncode == 1
    assert "active-scan.har" in r.stdout + r.stderr
    assert "abc" in r.stdout + r.stderr
    assert not _leaks(r.stdout + r.stderr)


def test_red8_check_passes_clean_evidence(tmp_path):
    (tmp_path / "active-scan.har").write_text(json.dumps(evidence.redact_har(dirty_har())), encoding="utf-8")
    r = _check(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_red8_check_passes_real_selftest_output(tmp_path):
    shutil.copytree(FIXTURE_SCAN, tmp_path / "scan")
    r = _check(tmp_path / "scan")
    assert r.returncode == 0, r.stdout + r.stderr


# ── RED-9: dast report won't publish unredacted evidence ───────────────────────────────────

@pytest.mark.parametrize("flag", ["--upload", "--issues"])
def test_red9_report_refuses_to_publish_unredacted_evidence(tmp_path, flag):
    out = tmp_path / "out"
    scan = out / "juice-shop" / "scans" / "20261019T125049Z"
    shutil.copytree(FIXTURE_SCAN, scan)
    (scan / "active-scan.har").write_text(json.dumps(dirty_har()), encoding="utf-8")
    env = {**os.environ, "DAST_OUT": str(out), "GITHUB_TOKEN": "not-a-real-token",
           "GITHUB_API_URL": "http://127.0.0.1:9",           # any upload attempt fails to connect
           "DAST_APPS_DIR": str(ROOT / "tests" / "ui" / "fixtures" / "apps")}
    r = subprocess.run([sys.executable, "-m", "dast", "report", "juice-shop", flag,
                        "--owner", "o", "--repo", "r", "--ref", "refs/heads/main",
                        "--commit", "5658473cf8814459bf89000ce373b20ed0b4eb37"],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "active-scan.har" in r.stderr
    assert "127.0.0.1:9" not in r.stdout + r.stderr          # it never tried to publish
    assert not _leaks(r.stdout + r.stderr)
