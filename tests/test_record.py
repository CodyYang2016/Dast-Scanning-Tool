"""TEST-FIRST suite for the record CLI's pure serialization (FR-R1/R3).

Frozen before authoring/record.py exists. The live crawl is validated by running it; here we
pin build_trace(): raw captured events -> a trace that conforms to contracts/trace.schema.json.
Oracle: the committed schema (third-party validator) + ground-truth about the input events.
"""

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from authoring.record import build_trace

ROOT = Path(__file__).resolve().parent.parent
TRACE_SCHEMA = ROOT / "contracts" / "trace.schema.json"

EVENTS = [
    {"type": "goto", "url": "http://juice:3000/#/login"},
    {"type": "form", "url": "http://juice:3000/#/login", "fields": ["email", "password"]},
    {"type": "fill", "selector": "#email", "field": "email"},
    {"type": "click", "selector": "#loginButton"},
    {"type": "request", "method": "GET", "url": "http://juice:3000/rest/user/whoami"},
    {"type": "goto", "url": "http://juice:3000/#/basket"},
]


def _trace():
    return build_trace("juice-shop", "http://juice:3000", EVENTS)


def test_trace_validates_against_schema():
    validator = Draft202012Validator(json.loads(TRACE_SCHEMA.read_text()))
    errors = sorted(validator.iter_errors(_trace()), key=lambda e: list(e.path))
    assert not errors, [e.message for e in errors]


def test_hosts_derived_from_events():
    assert "juice" in _trace()["hosts"]


def test_index_lists_visited_routes():
    index = _trace()["index"]
    assert any("/#/login" in p for p in index)
    assert any("/#/basket" in p for p in index)


def test_api_calls_captured():
    api = _trace()["api"]
    assert any(a["url"].endswith("/rest/user/whoami") and a["method"] == "GET" for a in api)


def test_forms_captured():
    forms = _trace()["forms"]
    assert forms and forms[0]["fields"] == ["email", "password"]


def test_interactions_preserve_order():
    types = [i["type"] for i in _trace()["interactions"]]
    # login sequence present and in order: goto -> fill -> click
    assert types.index("goto") < types.index("fill") < types.index("click")
