"""Redact secrets/PII from an exploration observation BEFORE it reaches the LLM (open question 3).

`record` today is secret-free by construction (it captures names/URLs, not values). The exploration
loop is different: it feeds live DOM text and XHR bodies to the model, so an explicit, thorough
redactor is a hard requirement — nothing sensitive may leave the boundary. This generalizes the
HAR redaction in runner/evidence.py (JWTs, token/password fields, sensitive headers) to arbitrary
nested observation data, and adds bearer tokens, common secret field names, cookies, and emails.

Keeps the *shape* of the observation (keys, structure, methods, paths, statuses) so the LLM still
has enough to reason about — only values are scrubbed. Pure and unit-tested with adversarial cases.
"""

from __future__ import annotations

import re

REDACTED = "REDACTED"

# Value patterns (scrubbed anywhere they appear in a string).
#
# Both the JWT and email patterns must be LINEAR in their input (W5-5). The text comes from the
# application under test — every page and response body the exploration loop sends the model,
# and every evidence string the normalizer keeps — so its length is not ours to choose. The
# original patterns retried a match from every position inside a long run of word characters:
# 200 KB took ~44 s through the email pattern and ~14 s through the JWT one; both are now a few ms.
#
# The fix is the same for both: a match may only START at the beginning of a run, via a negative
# lookbehind on the run's own character class. That turns n retries per run into one.
#
# JWT: the whole run is matched and a lookahead requires "eyJ" plus at least one more token
# character somewhere in it — exactly what the old pattern demanded of its first segment. (A bare
# "eyJ" run does not qualify: accepting one shifted which three segments were matched, and a fuzz
# test against the old pattern caught the new one redacting less.) Whether a candidate succeeds
# depends only on what follows the run, so one attempt per run decides it.
# This redacts slightly MORE than before — a JWT glued to a preceding word character now loses
# that prefix too — and never less; tests/test_redact.py checks that against the old pattern.
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*?eyJ[A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")

# Email is scanned from each "@" rather than matched by one pattern. The previous pattern,
# [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}, retried from every position in a long run. The
# obvious regex fix — a lookbehind so a match only starts at the beginning of a run — is NOT
# equivalent: a TLD can stop partway through a run ("…@a.io9bob@x.com" ends the first match at
# "io"), and the old pattern then started the next address mid-run. A fuzz test against the old
# pattern found that case; Python's re has no \G to say "or where the last match ended". So the
# scan does it directly, and reproduces the old pattern's output exactly. It is linear because
# neither the local part nor the domain can contain "@", so the stretches it walks between one
# "@" and the next partition the string.
_EMAIL_LOCAL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")
_EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _redact_emails(text: str, replacement: str) -> str:
    out, last = [], 0
    at = text.find("@")
    while at != -1:
        start = at
        while start > last and text[start - 1] in _EMAIL_LOCAL:
            start -= 1
        domain = _EMAIL_DOMAIN.match(text, at + 1) if start < at else None
        if domain:
            out.append(text[last:start])
            out.append(replacement)
            last = domain.end()
            at = text.find("@", last)
        else:
            at = text.find("@", at + 1)
    out.append(text[last:])
    return "".join(out)

# Field/key names whose VALUE must be dropped regardless of content (case-insensitive).
_SECRET_KEYS = {
    "password", "passwordrepeat", "pass", "pwd",
    "token", "access_token", "refresh_token", "id_token", "auth", "authorization",
    "cookie", "set-cookie", "session", "sessionid", "jsessionid",
    "csrf", "csrf_token", "csrftoken", "xsrf", "authenticity_token", "_csrf",
    "api_key", "apikey", "secret", "client_secret", "private_key",
    "ssn", "creditcard", "credit_card", "card_number", "cvv",
}

# Headers whose VALUE is a credential. Shared with runner/evidence.py's HAR redaction so there is
# one list, not two that drift apart. A secret in a header with an unrecognised custom name is not
# caught by this; extend the list here.
SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization",
                               "x-auth-token", "x-api-key"})

# A header LINE: the name survives so a stored request still reads as one, the value does not.
# Anchored at a line start so prose that happens to say "Cookie:" mid-sentence is left alone.
# Linear: one attempt per line, and the value runs to the end of the line without backtracking.
_HEADER_LINE = re.compile(
    r"(?im)^([ \t]*)(" + "|".join(sorted((re.escape(h) for h in SENSITIVE_HEADERS),
                                          key=len, reverse=True)) + r")([ \t]*:[ \t]*)[^\r\n]*"
)

# Secret-ish key VALUES inside JSON-like text: "token": "...."  ->  "token": "REDACTED"
_TOKEN_FIELD = re.compile(
    r'("(?:' + "|".join(sorted(_SECRET_KEYS, key=len, reverse=True)) + r')"\s*:\s*")[^"]*(")',
    re.IGNORECASE,
)


# A form-encoded or query-string field whose name is secret: password=hunter2 -> password=REDACTED.
# The name must start at a field boundary, so "mypassword=" is not mistaken for "password=". The
# value stops at the next delimiter, so each match is a single forward pass.
_FORM_FIELD = re.compile(
    r"(?i)(^|[?&;\s])((?:" + "|".join(sorted((re.escape(k) for k in _SECRET_KEYS),
                                              key=len, reverse=True)) + r")=)[^&\s;#\"']*"
)


def redact_text(text):
    """Scrub secret/PII patterns from a string. Non-strings pass through unchanged."""
    if not isinstance(text, str) or not text:
        return text
    text = _HEADER_LINE.sub(rf"\1\2\3{REDACTED}", text)
    text = _FORM_FIELD.sub(rf"\1\2{REDACTED}", text)
    text = _JWT.sub(REDACTED, text)
    text = _BEARER.sub("Bearer " + REDACTED, text)
    text = _TOKEN_FIELD.sub(rf"\1{REDACTED}\2", text)
    text = _redact_emails(text, REDACTED)
    return text


def _is_secret_key(key) -> bool:
    return isinstance(key, str) and key.strip().lower() in _SECRET_KEYS


def redact(obj):
    """Recursively redact a nested observation (dict/list/str). Keys are preserved; a value under a
    secret-named key is dropped wholesale; all other strings are pattern-scrubbed."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _is_secret_key(k):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return redact_text(obj)
