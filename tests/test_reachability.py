from detections.reachability import exposed_params, summarize, unexercised


def test_exposed_get_parameters_are_canonicalized():
    trace = {"forms": [{"method": "GET", "url": "http://app.test/sqli", "fields": ["id", "Submit"]},
                       {"method": "POST", "url": "http://app.test/login", "fields": ["password"]}]}
    assert exposed_params(trace) == {"/sqli": ["Submit", "id"]}


def test_unexercised_parameters_are_reported():
    exposed = {"/sqli": ["Submit", "id"], "/search": ["q"]}
    coverage = {"route_params": {"/sqli": ["id"], "/search": []}}
    assert unexercised(exposed, coverage) == {"/sqli": ["Submit"], "/search": ["q"]}


def test_summary_is_conservative_without_parameter_coverage():
    assert summarize({"/sqli": ["id"]}, {"routes": ["/sqli"]})["gaps"] == {}
