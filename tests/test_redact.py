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


# ---- W5-5: the redactor must be linear in its input ------------------------------------
#
# The exploration loop redacts every page and response body before it reaches the model, and
# the normalizer redacts evidence lifted from the target — so the input length is chosen by the
# application under test. Measured before this fix: 200 KB took ~44 s through the email pattern,
# and the JWT pattern was quadratic too on input like "eyJeyJeyJ…". Both retried a match from
# every position inside a long run of word characters.

import random
import re
import time

import pytest

from runner import redact as R

# The patterns as they were before the fix — kept here as the ORACLE the fix is checked against,
# so "faster" can never quietly become "redacts less".
_OLD_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_OLD_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

_HOSTILE = {
    "long run, no @": "x" * 200_000,
    "many JWT starts, no dots": "eyJ" * 67_000,
    "many @, no domain": "a@" * 100_000,
    "long domain, no TLD": "a@" + "b." * 100_000,
    "mixed": ("eyJabc" + "x" * 50 + "@" + "y" * 50) * 2_000,
}


@pytest.mark.parametrize("name", list(_HOSTILE))
def test_hostile_input_is_redacted_in_linear_time(name):
    t = time.perf_counter()
    redact_text(_HOSTILE[name])
    assert time.perf_counter() - t < 1.0, f"{name}: redaction is not linear"


def _spans(rx, s):
    return [m.span() for m in rx.finditer(s)]


def _redacted_chars(spans):
    return {i for a, b in spans for i in range(a, b)}


def _fuzz_strings(n=20000, seed=20260930):
    # The alphabet needs short TLD-like fragments next to digits ("io", "9"): an earlier, narrower
    # alphabet passed a version of the fix that a wider fuzz then broke.
    rng = random.Random(seed)
    alphabet = ["a", "b", "x", "Z", "9", ".", "-", "_", "@", "eyJ", "e", "y", "J", " ", "=",
                "com", "io", "hb", "%", "+", "\n"]
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40))) for _ in range(n)]


def test_email_redaction_is_unchanged_by_the_fix():
    # Exactly the old pattern's output, on 20,000 random strings.
    for s in _fuzz_strings():
        assert R._redact_emails(s, "X") == _OLD_EMAIL.sub("X", s), s


@pytest.mark.parametrize("s", [
    # Found by fuzzing an earlier version of this fix, which forbade a match from starting
    # mid-run. Each has an address whose local part begins right where the previous address's
    # TLD stopped — inside the same run — and that version left it unredacted.
    "y%.99@eyJZJ.ay9J@eyJe..bxeyJ.ioeZ=eyJ",
    "bZ.Zcomcom+.comeaeyJ.%Z.Z_%.9@-beyJio-.xeyJZ+xiox@comeyJJxio.eyJ=Z@",
    "eyJ.io% ._\n\nio Zcom-eyJ.ioJax@eyJ.xxJ9Z@ee.Jcomx9a=Jio9%-xZ+xaZio=\n@eyJe\n",
    "alice@corp.io9bob@corp.io",
])
def test_an_address_starting_where_the_last_one_ended_is_still_redacted(s):
    assert R._redact_emails(s, "X") == _OLD_EMAIL.sub("X", s)


def test_jwt_redaction_never_covers_less_than_before():
    # The fix redacts the whole token run, so a JWT glued to a preceding word character now loses
    # its prefix as well. Stricter, never weaker: every character the old pattern redacted, the
    # new one redacts too.
    for s in _fuzz_strings():
        assert _redacted_chars(_spans(_OLD_JWT, s)) <= _redacted_chars(_spans(R._JWT, s)), s


def test_a_jwt_glued_to_a_word_leaves_no_token_text():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    for text in (f"token={jwt}", f"x{jwt}", f"{jwt} tail", f"Bearer {jwt}"):
        out = redact_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in out and "c2lnbmF0dXJl" not in out, out


def test_ordinary_emails_are_still_redacted():
    for text in ("contact a.b+c@example.co.uk now", "user@x.io", "id=victim@corp.com&x=1"):
        assert "@" not in redact_text(text), text


# ---- W1-3 prerequisite: headers and form bodies -----------------------------------------
#
# Reproducible findings mean storing whole request/response pairs, and redact_text did not scrub
# a Cookie or Authorization header LINE, or a form-encoded password. A real Juice Shop attack
# request, fetched from ZAP, carried the test account's password in its body and a Cookie header.

_REAL_ATTACK = (
    "POST http://juice:3000/rest/user/login HTTP/1.1\r\n"
    "host: juice:3000\r\n"
    "Content-Type: application/json\r\n"
    "Cookie: language=en; token=abc123SESSIONvalue; welcomebanner_status=dismiss\r\n"
    "Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n"
    "\r\n"
    '{"email":"\'","password":"Dast-POC-passw0rd!"}'
)


@pytest.mark.parametrize("header", ["Cookie", "cookie", "Set-Cookie", "Authorization",
                                    "Proxy-Authorization", "X-Auth-Token", "X-API-Key"])
def test_a_sensitive_header_keeps_its_name_and_loses_its_value(header):
    out = redact_text(f"{header}: secretvalue123; more=stuff")
    assert out.lower().startswith(header.lower() + ":") and "secretvalue123" not in out


def test_an_ordinary_header_is_left_alone():
    assert redact_text("Content-Type: application/json") == "Content-Type: application/json"


def test_the_real_attack_request_leaks_nothing():
    out = redact_text(_REAL_ATTACK)
    for raw in ("abc123SESSIONvalue", "YWRtaW46cGFzc3dvcmQ=", "Dast-POC-passw0rd!"):
        assert raw not in out, raw
    assert out.startswith("POST http://juice:3000/rest/user/login")   # still replayable


@pytest.mark.parametrize("body, raw", [
    ("username=admin&password=hunter2&Login=Login", "hunter2"),
    ("password=hunter2", "hunter2"),
    ("a=1&token=tok999xyz", "tok999xyz"),
    ("q=x&api_key=k-555&z=1", "k-555"),
    ("GET /cb?session=s3ss10n&next=/ HTTP/1.1", "s3ss10n"),
])
def test_form_encoded_secrets_are_redacted(body, raw):
    out = redact_text(body)
    assert raw not in out and "REDACTED" in out


def test_form_fields_that_are_not_secret_survive():
    assert redact_text("username=admin&Login=Login") == "username=admin&Login=Login"


def test_a_secret_word_inside_another_word_is_not_a_field():
    # "mypassword=" is not the field "password"; over-matching would mangle ordinary text.
    assert redact_text("mypassword=x") == "mypassword=x"


@pytest.mark.parametrize("hostile", [
    "Cookie: " + "a" * 200_000,
    "password=" + "x" * 200_000,
    ("&token=" * 30_000),
    ("Authorization:" * 15_000),
], ids=["cookie", "password", "token", "authorization"])
def test_the_new_rules_are_linear_too(hostile):
    t = time.perf_counter()
    redact_text(hostile)
    assert time.perf_counter() - t < 1.0
