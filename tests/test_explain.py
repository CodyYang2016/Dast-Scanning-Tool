from detections.explain import explain_one, summarize


BASE = {"routes": ["/sqli"], "rules": ["40018"],
        "route_params": {"/sqli": ["id"]},
        "rule_outcomes": {"40018": {"requests": 100, "state": "Complete"}}}
RECORD = {"fingerprint": "f1", "endpoint": "/sqli", "parameter": "id",
          "rule_id": "40018", "severity": "high", "title": "SQL injection"}


def test_unexercised_parameter_is_explained():
    coverage = {**BASE, "route_params": {"/sqli": []}}
    assert explain_one(RECORD, coverage, {})["reason"] == "parameter_not_exercised"


def test_missing_route_is_explained():
    assert explain_one(RECORD, {"routes": [], "rules": []}, {})["reason"] == "route_not_covered"


def test_disabled_rule_is_explained():
    coverage = {"routes": ["/sqli"], "rules": []}
    assert explain_one(RECORD, coverage, {})["reason"] == "rule_not_enabled"


def test_summary_counts_reasons():
    explanations = [explain_one(RECORD, {"routes": [], "rules": []}, {})]
    assert summarize(explanations) == {"route_not_covered": 1}
