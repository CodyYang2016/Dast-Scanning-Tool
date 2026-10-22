"""CFG-1..CFG-11 — editing app.yaml through the UI, tier by tier."""
from __future__ import annotations

import copy
import difflib
import hashlib
import json

import jsonschema
import pytest
import yaml

from tests.ui.harness import ROOT, logged_in, make_app

SCHEMA = json.loads((ROOT / "contracts" / "app.schema.json").read_text())

# ui_requirements.md §4, resolved per fixture app. Typed from the document, not from the code.
# orders-portal: test environment, durable data.  dvwa: dev environment, disposable data.
EXPECTED_TIERS = {
    "orders-portal": {
        "app_id": "A", "base_url": "A", "environment_class": "A", "scope.allow": "A",
        "scope.exclude": "A",                                  # A when data is durable
        "auth.mode": "A", "auth.login_url": "A",
        "auth.credentials.email_env": "A", "auth.credentials.password_env": "A",
        "record.authenticated_routes": "A",
        "auth.steps": "D", "auth.proof.route.path": "D", "auth.proof.route.forbid_redirect_to": "D",
        "auth.identity": "C", "data_policy": "C",
        "scan.policy.attack_strength": "C", "scan.policy.alert_threshold": "C",   # C in test/staging
        "scan.policy.disabled_rules": "C", "scan.budgets.max_scan_min": "B",
        "scan.throttle.threads_per_host": "B", "scan.throttle.delay_ms": "B",
        "gate.fail_on": "C",
    },
    "dvwa": {
        "app_id": "A", "base_url": "A", "environment_class": "A", "scope.allow": "A",
        "auth.mode": "A", "auth.login_url": "A",
        "auth.credentials.email_env": "A", "auth.credentials.password_env": "A",
        "record.authenticated_routes": "A",
        "auth.steps": "D", "auth.storage_state": "D", "auth.cookies": "B",
        "auth.identity": "C", "data_policy": "C",
        "explore.seed_routes": "B", "explore.safe_forms": "C", "explore.write_mode": "C",
        "explore.test_data": "B", "explore.budgets.max_pages": "B",
        "scan.policy.attack_strength": "B", "scan.policy.alert_threshold": "B",   # B in dev
        "scan.policy.disabled_rules": "C", "scan.budgets.max_scan_min": "B",
        "scan.state_probes": "B", "scan.anti_csrf_tokens": "B", "scan.dom_xss.enabled": "B",
        "scan.dom_xss.max_min": "B",
    },
}
TIER_C_PATHS = ["explore.write_mode", "gate.fail_on", "data_policy", "scan.policy.disabled_rules",
                "auth.identity"]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _settings(c, app):
    r = c.get(f"/api/apps/{app}/settings")
    assert r.status_code == 200, r.text
    return r.json()


def _fields(c, app):
    return {f["path"]: f for f in _settings(c, app)["fields"]}


# ── CFG-6: tiers resolve per app as §4 says ───────────────────────────────────────────────

@pytest.mark.parametrize("app", sorted(EXPECTED_TIERS))
def test_cfg6_tiers_match_requirements(api, app):
    fields = _fields(api, app)
    for path, tier in EXPECTED_TIERS[app].items():
        assert path in fields, f"{path} missing from {app}"
        assert fields[path]["tier"] == tier, (path, fields[path]["tier"], tier)
    for f in fields.values():
        assert f["tier"] in {"A", "B", "C", "D"}
        if f["tier"] == "C":
            assert f["editable"] is False


def test_cfg6_every_leaf_of_the_file_is_reported(api, ws):
    cfg = yaml.safe_load(ws.app_yaml("orders-portal").read_text())
    reported = set(_fields(api, "orders-portal"))

    def covered(path):
        return any(path == r or path.startswith(r + ".") for r in reported)

    def walk(node, prefix=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from walk(v, f"{prefix}.{k}" if prefix else k)
        else:
            yield prefix

    missing = [p for p in walk(cfg) if not covered(p)]
    assert not missing, missing


# ── CFG-7 / CFG-8: the mapping is configuration, and it fails closed ──────────────────────

def test_cfg7_unknown_field_is_tier_c(ws):
    path = ws.app_yaml("orders-portal")
    path.write_text(path.read_text() + "output:\n  dir: out-elsewhere\n", encoding="utf-8")
    c = logged_in(make_app(ws, tiers_path=_tiers_without(ws, "output.dir")))
    f = _fields(c, "orders-portal")["output.dir"]
    assert f["tier"] == "C" and f["editable"] is False


def _tiers_without(ws, dotted):
    from webui.config import UIConfig  # noqa: F401 — the default mapping ships with the UI
    import webui
    src = (webui.__path__[0] + "/tiers.yaml")
    data = yaml.safe_load(open(src, encoding="utf-8"))
    data["fields"] = [f for f in data["fields"] if f["path"] != dotted]
    out = ws.root / "tiers-custom.yaml"
    out.write_text(yaml.safe_dump(data), encoding="utf-8")
    return out


def test_cfg8_changing_the_mapping_changes_the_tier(ws):
    import webui
    data = yaml.safe_load(open(webui.__path__[0] + "/tiers.yaml", encoding="utf-8"))
    entry = next(f for f in data["fields"] if f["path"] == "scan.budgets.max_scan_min")
    entry["tier"] = "C"
    entry.pop("when", None)
    custom = ws.root / "tiers-custom.yaml"
    custom.write_text(yaml.safe_dump(data), encoding="utf-8")
    c = logged_in(make_app(ws, tiers_path=custom))
    f = _fields(c, "orders-portal")["scan.budgets.max_scan_min"]
    assert f["tier"] == "C" and f["editable"] is False


# ── CFG-1 / CFG-2 / CFG-10: a save changes one value and nothing else ─────────────────────

def test_cfg1_cfg2_save_changes_only_that_line(api, ws):
    path = ws.app_yaml("orders-portal")
    before = path.read_text().splitlines(keepends=True)
    etag = _settings(api, "orders-portal")["etag"]
    preview = api.post("/api/apps/orders-portal/settings/preview",
                       json={"etag": etag, "changes": {"scan.budgets.max_scan_min": 12}})
    assert preview.status_code == 200, preview.text
    saved = api.put("/api/apps/orders-portal/settings",
                    json={"etag": etag, "changes": {"scan.budgets.max_scan_min": 12}})
    assert saved.status_code == 200, saved.text
    after = path.read_text().splitlines(keepends=True)
    changed = [line for line in difflib.ndiff(before, after) if line[:2] in ("- ", "+ ")]
    assert changed == ["-     max_scan_min: 8\n", "+     max_scan_min: 12\n"]
    real = "".join(difflib.unified_diff(before, after))
    for diff in (preview.json()["diff"], saved.json()["diff"]):
        assert [ln for ln in diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")] == \
               [ln for ln in real.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]


def test_cfg10_saved_file_loads_like_a_hand_edit(api, ws, monkeypatch):
    from authoring import appconfig
    monkeypatch.setenv("DAST_APPS_DIR", str(ws.apps_dir))
    expected = copy.deepcopy(appconfig.load_app_config("orders-portal"))
    expected["scan"]["throttle"]["delay_ms"] = 500
    etag = _settings(api, "orders-portal")["etag"]
    r = api.put("/api/apps/orders-portal/settings",
                json={"etag": etag, "changes": {"scan.throttle.delay_ms": 500}})
    assert r.status_code == 200, r.text
    assert appconfig.load_app_config("orders-portal") == expected


# ── CFG-3 / CFG-4 / CFG-5 / CFG-9: what a save must refuse ────────────────────────────────

@pytest.mark.parametrize("dotted,value", [("explore.write_mode", "allow"), ("gate.fail_on", "none"),
                                          ("data_policy", "disposable"),
                                          ("scan.policy.disabled_rules", []),
                                          ("auth.identity", "self-register")])
def test_cfg3_tier_c_write_refused(api, ws, dotted, value):
    path = ws.app_yaml("orders-portal")
    h = _sha(path)
    etag = _settings(api, "orders-portal")["etag"]
    for verb, url in (("post", "/api/apps/orders-portal/settings/preview"),
                      ("put", "/api/apps/orders-portal/settings")):
        r = getattr(api, verb)(url, json={"etag": etag, "changes": {dotted: value}})
        assert r.status_code == 403, (dotted, r.text)
    assert _sha(path) == h


@pytest.mark.parametrize("dotted,value", [("auth.storage_state", ".secrets/elsewhere.json")])
def test_cfg4_non_editable_tier_d_refused(api, ws, dotted, value):
    path = ws.app_yaml("dvwa")
    h = _sha(path)
    f = _fields(api, "dvwa")[dotted]
    assert f["tier"] == "D" and f["editable"] is False
    etag = _settings(api, "dvwa")["etag"]
    r = api.put("/api/apps/dvwa/settings", json={"etag": etag, "changes": {dotted: value}})
    assert r.status_code == 403
    assert _sha(path) == h


def test_cfg5_schema_violation_refused(api, ws):
    path = ws.app_yaml("orders-portal")
    h = _sha(path)
    bad = yaml.safe_load(path.read_text())
    bad["scan"]["budgets"]["max_scan_min"] = "ten"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, SCHEMA)                       # the oracle agrees
    etag = _settings(api, "orders-portal")["etag"]
    r = api.put("/api/apps/orders-portal/settings",
                json={"etag": etag, "changes": {"scan.budgets.max_scan_min": "ten"}})
    assert r.status_code == 422
    assert _sha(path) == h


def test_cfg9_stale_etag_refused(api, ws):
    path = ws.app_yaml("orders-portal")
    etag = _settings(api, "orders-portal")["etag"]
    path.write_text(path.read_text().replace("delay_ms: 200", "delay_ms: 250"), encoding="utf-8")
    h = _sha(path)
    r = api.put("/api/apps/orders-portal/settings",
                json={"etag": etag, "changes": {"scan.budgets.max_scan_min": 9}})
    assert r.status_code == 409
    assert _sha(path) == h


# ── CFG-11: secrets are names and set/unset only ──────────────────────────────────────────

def test_cfg11_secret_fields_are_names_only(api, monkeypatch):
    monkeypatch.setenv("ORDERS_PORTAL_USER", "someone")
    monkeypatch.delenv("ORDERS_PORTAL_PASS", raising=False)
    fields = _fields(api, "orders-portal")
    user = fields["auth.credentials.email_env"]["secret"]
    pw = fields["auth.credentials.password_env"]["secret"]
    assert user == {"name": "ORDERS_PORTAL_USER", "set": True}
    assert pw == {"name": "ORDERS_PORTAL_PASS", "set": False}
