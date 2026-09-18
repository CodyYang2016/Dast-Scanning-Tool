"""Adversarial tests for the exploration redactor (open question 3).

The exploration loop feeds live DOM/XHR data to the LLM, so nothing sensitive may leave the
boundary. Oracle: hand-built payloads embedding secrets/PII, asserting the secret bytes are gone
and the structural signal (keys, methods, paths) survives.
"""

from runner.redact import REDACTED, redact, redact_text

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123DEF-_"


def test_jwt_scrubbed_from_text():
    out = redact_text(f"Authorization: Bearer {_JWT}")
    assert _JWT not in out and REDACTED in out


def test_bearer_token_scrubbed():
    out = redact_text("Bearer sk-live-secrettoken12345")
    assert "secrettoken12345" not in out and "Bearer REDACTED" in out


def test_email_pii_scrubbed():
    assert "alice@example.com" not in redact_text("user alice@example.com logged in")


def test_secret_key_value_dropped_wholesale():
    obj = {"username": "alice", "password": "hunter2", "token": _JWT}
    out = redact(obj)
    assert out["username"] == "alice"          # non-secret preserved
    assert out["password"] == REDACTED
    assert out["token"] == REDACTED


def test_nested_structure_preserved_values_scrubbed():
    obj = {"api": [{"method": "POST", "url": "/rest/login",
                    "body": '{"email":"a@b.com","password":"p"}'}]}
    out = redact(obj)
    entry = out["api"][0]
    assert entry["method"] == "POST" and entry["url"] == "/rest/login"  # signal survives
    assert "a@b.com" not in entry["body"] and '"password":"REDACTED"' in entry["body"]


def test_token_field_in_json_text_scrubbed():
    out = redact_text('{"access_token":"abc.def.ghi","keep":"ok"}')
    assert '"access_token":"REDACTED"' in out and '"keep":"ok"' in out


def test_cookie_key_dropped():
    assert redact({"Cookie": "session=deadbeef"})["Cookie"] == REDACTED


def test_non_string_scalars_pass_through():
    assert redact({"n": 5, "b": True, "x": None}) == {"n": 5, "b": True, "x": None}


def test_structure_shape_is_unchanged():
    obj = {"url": "/x", "links": ["/a", "/b"], "forms": [{"selector": "#f", "fields": ["email"]}]}
    out = redact(obj)
    assert set(out) == set(obj) and out["links"] == ["/a", "/b"]
    assert out["forms"][0]["fields"] == ["email"]  # field NAMES are signal, not secrets
