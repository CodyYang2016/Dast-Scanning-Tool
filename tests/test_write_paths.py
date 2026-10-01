"""Exercise write paths (W6-1).

ZAP's spider already submits HTML forms. What never reached ZAP were the writes an app makes from
its own JavaScript — `fetch`/XHR POST, PUT, PATCH — because the trace kept only their method and
URL and the generated flow replayed GETs only. Now their (redacted) bodies are recorded, and a
write the app's posture allows is replayed so ZAP can attack it.
"""

import json

from authoring import generate
from authoring.record import build_trace, request_event


class Req:
    def __init__(self, method, url, body=None, ctype=None):
        self.method, self.url, self.post_data = method, url, body
        self.headers = {"content-type": ctype} if ctype else {}


# ---- capture ------------------------------------------------------------------------------

def test_a_get_carries_no_body():
    assert request_event(Req("GET", "http://app/api/x")) == \
        {"type": "request", "method": "GET", "url": "http://app/api/x"}


def test_a_json_write_body_is_kept_with_secrets_redacted():
    ev = request_event(Req("POST", "http://app/api/Users",
                           json.dumps({"email": "alice@example.com", "password": "hunter2", "name": "x"}),
                           "application/json"))
    body = json.loads(ev["body"])
    assert body["password"] == "REDACTED" and body["name"] == "x"
    assert "alice@example.com" not in ev["body"] and ev["content_type"] == "application/json"


def test_a_form_write_body_is_redacted_as_text():
    ev = request_event(Req("POST", "http://app/x", "user=bob&password=hunter2",
                           "application/x-www-form-urlencoded"))
    assert "hunter2" not in ev["body"] and "user=bob" in ev["body"]


def test_a_huge_body_is_not_kept():
    ev = request_event(Req("POST", "http://app/x", "a" * 50_000, "text/plain"))
    assert "body" not in ev and ev["body_omitted"] == "too large"


def test_the_trace_keeps_body_and_content_type():
    t = build_trace("app", "http://app", [
        {"type": "request", "method": "POST", "url": "http://app/api/Products",
         "body": '{"name":"x"}', "content_type": "application/json"}])
    assert t["api"][0]["body"] == '{"name":"x"}'
    assert t["api"][0]["content_type"] == "application/json"


# ---- which writes are replayed ------------------------------------------------------------

def _cfg(write_mode="allow", data_policy="disposable", safe_forms=(), exclude=(), avoid=()):
    return {"app_id": "app", "environment_class": "dev", "base_url": "http://app",
            "data_policy": data_policy,
            "scope": {"allow": ["app"], "exclude": list(exclude), "avoid_actions": list(avoid)},
            "explore": {"write_mode": write_mode, "safe_forms": list(safe_forms)},
            "auth": {"mode": "form", "login_url": "/login",
                     "selectors": {"email": "#e", "password": "#p", "submit": "#s"},
                     "credentials": {"email_env": "E", "password_env": "P"},
                     "proof": {"route": {"path": "/home"}}}}


TRACE = {"app_id": "app", "base_url": "http://app", "index": ["http://app/home"],
         "api": [{"method": "POST", "url": "http://app/api/Products", "body": '{"name":"x"}',
                  "content_type": "application/json"},
                 {"method": "DELETE", "url": "http://app/api/Products/3"},
                 {"method": "PUT", "url": "http://app/api/payments/1", "body": "{}",
                  "content_type": "application/json"},
                 {"method": "POST", "url": "http://app/rest/user/change-password",
                  "body": '{"current":"REDACTED","new":"REDACTED","repeat":"REDACTED"}',
                  "content_type": "application/json"},
                 {"method": "GET", "url": "http://app/api/Products"}]}


def _sends(cfg):
    return [s for s in generate.journey_from_trace(TRACE, cfg)["journey"]
            if s["action"] == "api_send"]


def test_read_only_postures_replay_no_writes():
    assert _sends(_cfg(write_mode="deny")) == []
    assert _sends(_cfg(data_policy="durable")) == []


def test_an_allowed_write_is_replayed_with_its_body():
    (send,) = [s for s in _sends(_cfg(exclude=["/api/payments"])) if s["method"] == "POST"]
    assert send == {"action": "api_send", "target": "/api/Products", "method": "POST",
                    "body": '{"name":"x"}', "content_type": "application/json"}


def test_delete_needs_the_safe_form_list():
    assert not [s for s in _sends(_cfg()) if s["method"] == "DELETE"]
    assert [s for s in _sends(_cfg(safe_forms=["/api/Products/3"])) if s["method"] == "DELETE"]


def test_excluded_paths_and_credential_changes_are_never_replayed():
    targets = [s["target"] for s in _sends(_cfg(exclude=["/api/payments"]))]
    assert "/api/payments/1" not in targets
    assert "/rest/user/change-password" not in targets


def test_read_only_journeys_are_unchanged():
    # The regression guard: an app that does not allow writes gets exactly today's plan.
    plan = generate.journey_from_trace(TRACE, _cfg(write_mode="deny"))
    assert [s["action"] for s in plan["journey"]] == ["goto", "api_get"]


# ---- how a write is sent ------------------------------------------------------------------

def test_a_write_is_sent_from_the_page_so_the_scope_guard_sees_it():
    plan = {"journey": [{"action": "api_send", "target": "/api/Products", "method": "POST",
                         "body": '{"name":"x"}', "content_type": "application/json"}]}
    src = generate.render_flow(plan, _cfg())
    assert "page.evaluate(" in src and "fetch(" in src
    assert '"POST"' in src and '"application/json"' in src
    compile(src, "flow.py", "exec")


def test_a_bearer_from_cookie_is_added_when_configured():
    cfg = _cfg(); cfg["auth"]["bearer_from_cookie"] = "token"
    plan = {"journey": [{"action": "api_send", "target": "/api/Products", "method": "POST",
                         "body": "{}", "content_type": "application/json"}]}
    src = generate.render_flow(plan, cfg)
    assert '"token"' in src and "Bearer" in src


def test_the_journey_contract_accepts_api_send():
    generate.validate_plan({"app_id": "app", "base_url": "http://app",
                            "login": generate.login_block(_cfg()),
                            "journey": [{"action": "api_send", "target": "/api/Products",
                                         "method": "POST", "body": "{}",
                                         "content_type": "application/json"}]})
