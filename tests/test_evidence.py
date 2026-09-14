"""Objective tests for HAR redaction (FR-E1 hard requirement).

Redaction is safety-critical: a published HAR must never leak auth. Oracle: after redaction,
independently scan the serialized HAR and assert NO secret material survives (bearer tokens,
JWTs, cookies, passwords), while non-sensitive data is preserved.
"""

import json

from runner.evidence import evidence_relpath, redact_har

RAW_HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "request": {
                    "headers": [
                        {"name": "Authorization", "value": "Bearer eyJabc.def123.ghi456"},
                        {"name": "Accept", "value": "application/json"},
                    ],
                    "cookies": [{"name": "token", "value": "sekret-cookie"}],
                    "postData": {"text": '{"email":"a@b.c","password":"hunter2"}'},
                },
                "response": {
                    "headers": [
                        {"name": "Set-Cookie", "value": "token=abc123; HttpOnly"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "cookies": [{"name": "token", "value": "abc123"}],
                    "content": {"text": '{"authentication":{"token":"eyJxxx.yyy.zzz"}}'},
                },
            }
        ],
    }
}

SECRETS = ["eyJabc.def123.ghi456", "eyJxxx.yyy.zzz", "sekret-cookie", "hunter2", "abc123"]


def test_no_secret_survives_redaction():
    redacted = json.dumps(redact_har(RAW_HAR))
    for secret in SECRETS:
        assert secret not in redacted, f"leaked: {secret}"


def test_authorization_header_redacted_accept_preserved():
    entry = redact_har(RAW_HAR)["log"]["entries"][0]
    hdrs = {h["name"]: h["value"] for h in entry["request"]["headers"]}
    assert hdrs["Authorization"] == "REDACTED"
    assert hdrs["Accept"] == "application/json"  # non-sensitive preserved


def test_set_cookie_redacted_content_type_preserved():
    entry = redact_har(RAW_HAR)["log"]["entries"][0]
    hdrs = {h["name"]: h["value"] for h in entry["response"]["headers"]}
    assert hdrs["Set-Cookie"] == "REDACTED"
    assert hdrs["Content-Type"] == "application/json"


def test_original_har_not_mutated():
    before = json.dumps(RAW_HAR, sort_keys=True)
    redact_har(RAW_HAR)
    assert json.dumps(RAW_HAR, sort_keys=True) == before  # redaction returns a copy


def test_evidence_relpath_matches_contract_shape():
    # requirements §7.2 example: evidence/<scan_id>/active-scan.har
    assert evidence_relpath("20260101T000000Z") == "evidence/20260101T000000Z/active-scan.har"
