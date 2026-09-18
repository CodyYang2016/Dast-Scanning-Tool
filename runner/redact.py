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
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Field/key names whose VALUE must be dropped regardless of content (case-insensitive).
_SECRET_KEYS = {
    "password", "passwordrepeat", "pass", "pwd",
    "token", "access_token", "refresh_token", "id_token", "auth", "authorization",
    "cookie", "set-cookie", "session", "sessionid", "jsessionid",
    "csrf", "csrf_token", "csrftoken", "xsrf", "authenticity_token", "_csrf",
    "api_key", "apikey", "secret", "client_secret", "private_key",
    "ssn", "creditcard", "credit_card", "card_number", "cvv",
}

# Secret-ish key VALUES inside JSON-like text: "token": "...."  ->  "token": "REDACTED"
_TOKEN_FIELD = re.compile(
    r'("(?:' + "|".join(sorted(_SECRET_KEYS, key=len, reverse=True)) + r')"\s*:\s*")[^"]*(")',
    re.IGNORECASE,
)


def redact_text(text):
    """Scrub secret/PII patterns from a string. Non-strings pass through unchanged."""
    if not isinstance(text, str) or not text:
        return text
    text = _JWT.sub(REDACTED, text)
    text = _BEARER.sub("Bearer " + REDACTED, text)
    text = _TOKEN_FIELD.sub(rf"\1{REDACTED}\2", text)
    text = _EMAIL.sub(REDACTED, text)
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
