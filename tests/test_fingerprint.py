"""Fingerprint unit tests (FR-N2) — the contract's frozen worked examples must reproduce."""

from detections.fingerprint import endpoint_pattern, fingerprint, payload_family

# The two worked examples frozen in contracts/README.md, with their published digests.
SQLI_DIGEST = "ece130214d0131cf2c0d71334a6719a0442d794cc6dfe9faababed15c7fcf3db"
HEADERS_DIGEST = "6c668292549821d6f3742016bf4371a07524016924cae5a57735ba0ca71cf35f"


def test_readme_example_1_sqli():
    assert fingerprint("40018", "/rest/products/search", "q", "sqli") == SQLI_DIGEST


def test_readme_example_2_headers_empty_param():
    # empty parameter -> two adjacent pipes in the preimage
    assert fingerprint("10038", "/", "", "headers") == HEADERS_DIGEST


def test_fingerprint_is_stable():
    a = fingerprint("40018", "/rest/products/search", "q", "sqli")
    b = fingerprint("40018", "/rest/products/search", "q", "sqli")
    assert a == b


def test_empty_case_sentinels_applied():
    # endpoint "" -> "/", family "" -> "none"; must equal explicit sentinels
    assert fingerprint("1", "", "", "") == fingerprint("1", "/", "", "none")


def test_pipe_is_stripped_from_inputs():
    # a stray "|" must never change the field boundaries
    assert fingerprint("1", "/a|b", "p", "sqli") == fingerprint("1", "/ab", "p", "sqli")


def test_endpoint_pattern_drops_query_and_lowercases():
    assert endpoint_pattern("http://juice:3000/REST/Products/Search?q=apple'") == "/rest/products/search"


def test_endpoint_pattern_collapses_numeric_segments():
    assert endpoint_pattern("http://h/rest/user/42/reviews") == "/rest/user/{id}/reviews"


def test_endpoint_pattern_collapses_uuid_segments():
    u = "http://h/api/order/9f2c1e7a-1b2c-4d5e-8f90-0a1b2c3d4e5f"
    assert endpoint_pattern(u) == "/api/order/{id}"


def test_endpoint_pattern_root_and_trailing_slash():
    assert endpoint_pattern("http://h/") == "/"
    assert endpoint_pattern("http://h/rest/products/") == "/rest/products"


def test_payload_family_mapping_and_fallback():
    assert payload_family("40018") == "sqli"
    assert payload_family("10038") == "headers"
    assert payload_family("99999") == "misc"  # unmapped -> fallback
