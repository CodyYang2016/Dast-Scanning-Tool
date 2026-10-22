"""QA-12: the settings page knows whether an app's login has been recorded, so it can offer to
record it (docs/ui-docs/ui_qa_findings.md). The page half is webui/frontend/tests/qa12_13.test.tsx.
"""
from __future__ import annotations


def _settings(api, app):
    r = api.get(f"/api/apps/{app}/settings")
    assert r.status_code == 200, r.text
    return r.json()


def test_qa12_login_not_recorded(api, ws):
    assert not (ws.out_dir / "juice-shop" / "authoring").exists()
    assert _settings(api, "juice-shop")["login_recorded"] is False


def test_qa12_login_recorded_once_the_bundle_exists(api, ws):
    bundle = ws.out_dir / "juice-shop" / "authoring" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "flow.py").write_text("# recorded login\n")
    assert _settings(api, "juice-shop")["login_recorded"] is True
