"""The gap between what an application exposes and what a scan actually sent (W6-12)."""

from detections import reachability

TRACE = {"base_url": "http://app", "forms": [
    {"url": "http://app/sqli/", "method": "GET", "fields": ["id", "Submit"]},
    {"url": "http://app/xss_r/", "method": "GET", "fields": ["name"]},
]}


def test_exposed_parameters_are_keyed_by_canonical_route():
    # Same endpoint_pattern as coverage and as finding identity, or the two cannot be compared.
    assert reachability.exposed_params(TRACE) == {"/sqli": ["Submit", "id"], "/xss_r": ["name"]}


def test_a_trailing_slash_does_not_make_a_second_route():
    t = {"forms": [{"url": "http://app/sqli/", "method": "GET", "fields": ["id"]},
                   {"url": "http://app/sqli", "method": "GET", "fields": ["Submit"]}]}
    assert reachability.exposed_params(t) == {"/sqli": ["Submit", "id"]}


def test_post_form_parameters_are_not_counted_as_exposed():
    # Coverage reads GET parameters from ZAP's URL list; a POST body never appears there, so
    # reporting one as "never sent" would be a gap nobody could ever close.
    t = {"forms": [{"url": "http://app/login", "method": "POST", "fields": ["user", "pass"]}]}
    assert reachability.exposed_params(t) == {}


def test_a_form_event_without_a_method_is_treated_as_get():
    t = {"forms": [{"url": "http://app/x", "fields": ["a"]}]}
    assert reachability.exposed_params(t) == {"/x": ["a"]}


# ---- the gap ---------------------------------------------------------------------------

def test_a_parameter_never_sent_is_reported():
    cov = {"routes": ["/sqli", "/xss_r"], "route_params": {"/sqli": [], "/xss_r": ["name"]}}
    assert reachability.unexercised(reachability.exposed_params(TRACE), cov) == {
        "/sqli": ["Submit", "id"]}


def test_nothing_is_reported_when_everything_was_sent():
    cov = {"routes": ["/sqli", "/xss_r"],
           "route_params": {"/sqli": ["Submit", "id"], "/xss_r": ["name"]}}
    assert reachability.unexercised(reachability.exposed_params(TRACE), cov) == {}


def test_an_excluded_route_is_not_reported_as_a_gap():
    # It is a declared exclusion, already reported as route_excluded — not an accident.
    cov = {"routes": [], "route_params": {}, "excluded": [r"(?i).*sqli.*"]}
    got = reachability.unexercised({"/sqli": ["id"]}, cov)
    assert got == {}


def test_coverage_predating_parameter_recording_reports_no_gap():
    # Without route_params there is no evidence either way; inventing a gap would be noise.
    assert reachability.unexercised({"/sqli": ["id"]}, {"routes": ["/sqli"]}) == {}


def test_a_route_the_scan_never_reached_at_all_is_still_a_gap():
    cov = {"routes": ["/other"], "route_params": {"/other": []}}
    assert reachability.unexercised({"/sqli": ["id"]}, cov) == {"/sqli": ["id"]}


def test_the_summary_counts_exercised_against_exposed():
    cov = {"routes": [], "route_params": {"/sqli": [], "/xss_r": ["name"]}}
    s = reachability.summarize(reachability.exposed_params(TRACE), cov)
    assert s["exposed"] == 3 and s["exercised"] == 1 and s["routes_with_gaps"] == 1
