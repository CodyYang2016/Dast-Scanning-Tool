"""A coverage denominator (W6-4): what SHOULD have been tested, so "tested 80 routes" has a
"of N". From an OpenAPI/Swagger spec when the app has one; otherwise from the routes the
authoring walk discovered — labelled, so it is never mistaken for ground truth.
"""

from detections import inventory
from detections.fingerprint import endpoint_pattern

OAS3 = {"openapi": "3.0.0", "servers": [{"url": "http://app/api/v2"}],
        "paths": {"/Users/{id}": {"get": {}, "put": {}, "parameters": []},
                  "/Products": {"get": {}, "post": {}},
                  "/orders/{orderId}/items": {"delete": {}}}}
SWAGGER2 = {"swagger": "2.0", "basePath": "/b2b/v2", "paths": {"/orders": {"post": {}}}}


def test_openapi3_operations_carry_the_server_path_prefix():
    ops = inventory.from_openapi(OAS3)
    assert ("PUT", "/api/v2/users/{id}") in ops
    assert ("POST", "/api/v2/products") in ops
    assert ("DELETE", "/api/v2/orders/{id}/items") in ops
    assert not any(m == "PARAMETERS" for m, _ in ops)       # not an operation


def test_swagger2_uses_basepath():
    assert inventory.from_openapi(SWAGGER2) == [("POST", "/b2b/v2/orders")]


def test_spec_patterns_line_up_with_observed_endpoints():
    (_, pattern), = [o for o in inventory.from_openapi(OAS3) if o[0] == "GET" and "users" in o[1]]
    assert pattern == endpoint_pattern("http://app/api/v2/Users/42")


def test_the_trace_fallback_uses_what_the_walk_discovered():
    trace = {"index": ["http://app/index.php", "http://app/a/?x=1"],
             "api": [{"method": "POST", "url": "http://app/api/Users/7"}]}
    routes = inventory.from_trace(trace)
    assert routes == ["/a", "/api/users/{id}", "/index.php"]


def test_summary_gives_a_percent_and_names_what_was_missed():
    s = inventory.summarize(["/a", "/b", "/c", "/d"], {"routes": ["/a", "/b", "/x"]}, "openapi")
    assert (s["declared"], s["exercised"], s["percent"]) == (4, 2, 50)
    assert s["missing"] == ["/c", "/d"] and s["source"] == "openapi"


def test_excluded_routes_count_on_neither_side():
    cov = {"routes": ["/a"], "excluded": ["(?i).*/admin.*"]}
    s = inventory.summarize(["/a", "/admin/reset"], cov, "openapi")
    assert (s["declared"], s["exercised"], s["percent"]) == (1, 1, 100)
    assert s["excluded"] == 1


def test_an_empty_denominator_has_no_percent():
    assert inventory.summarize([], {"routes": ["/a"]}, "trace")["percent"] is None


def test_a_spec_can_be_read_from_json_or_yaml(tmp_path):
    import json
    import yaml
    (tmp_path / "s.json").write_text(json.dumps(SWAGGER2))
    (tmp_path / "s.yaml").write_text(yaml.safe_dump(SWAGGER2))
    assert inventory.parse_spec((tmp_path / "s.json").read_text()) == SWAGGER2
    assert inventory.parse_spec((tmp_path / "s.yaml").read_text()) == SWAGGER2


# ---- the runner: load the spec, seed ZAP with it, record the declared routes ---------------

def test_a_url_spec_is_imported_by_url(monkeypatch):
    from runner import scan as scan_mod
    calls = []
    monkeypatch.setattr(scan_mod, "_api", lambda z, p, params=None, timeout=30.0: calls.append((p, params)) or {})
    out = scan_mod.import_openapi("http://zap", "http://app/openapi.json", "http://app")
    assert calls == [("/JSON/openapi/action/importUrl/", {"url": "http://app/openapi.json"})]
    assert out == {"imported": True}


def test_a_file_spec_is_imported_only_where_zap_can_read_it(monkeypatch, tmp_path):
    from runner import scan as scan_mod
    calls = []
    monkeypatch.setattr(scan_mod, "_api", lambda z, p, params=None, timeout=30.0: calls.append((p, params)) or {})
    out = scan_mod.import_openapi("http://zap", "security/dast/app/openapi.json", "http://app")
    assert not calls and out["imported"] is False and "DAST_ZAP_SPEC_DIR" in out["note"]
    out = scan_mod.import_openapi("http://zap", "security/dast/app/openapi.json", "http://app",
                                  zap_spec_dir="/zap/specs")
    assert calls == [("/JSON/openapi/action/importFile/",
                      {"file": "/zap/specs/app/openapi.json", "target": "http://app"})]


def test_declared_routes_are_recorded_from_a_spec(monkeypatch, tmp_path):
    import json
    from runner import main as rm
    f = tmp_path / "spec.json"; f.write_text(json.dumps(SWAGGER2))
    d = rm.declared_surface(str(f), "http://zap", fetch_text=None)
    assert d == {"source": "openapi", "spec": str(f), "operations": 1, "routes": ["/b2b/v2/orders"]}
