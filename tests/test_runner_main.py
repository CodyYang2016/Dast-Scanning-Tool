

def test_the_per_rule_budget_comes_from_the_policy():
    from runner.main import resolve_max_rule_min
    assert resolve_max_rule_min(None, {"max_rule_min": 5}) == 5


def test_an_explicit_per_rule_budget_wins():
    from runner.main import resolve_max_rule_min
    assert resolve_max_rule_min(2, {"max_rule_min": 5}) == 2


def test_no_policy_gives_the_historical_per_rule_default():
    from runner.main import resolve_max_rule_min
    assert resolve_max_rule_min(None, None) == 1


def test_the_recorded_policy_reports_the_budget_that_was_used():
    # coverage.json previously hardcoded 1, so it agreed with the config while both
    # contradicted what the scan actually ran.
    from runner.scan import resolved_policy
    assert resolved_policy({"max_rule_min": 5}, 10, 5)["max_rule_min"] == 5
