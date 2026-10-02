

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


# ---- W4-7: a target on ZAP's own port is refused -------------------------------------------
# Measured onboarding WebGoat on 8080: ZAP answered every proxied request as an API call
# (`No enum constant …Format.WEBGOAT`), the app never saw one, and the scan "succeeded".

def test_a_target_on_zaps_port_is_refused():
    import pytest
    from runner.main import refuse_zap_port
    from runner.scan import ScanScopeError
    with pytest.raises(ScanScopeError, match="8080"):
        refuse_zap_port("http://webgoat:8080/WebGoat", "http://zap:8080")


def test_other_ports_and_default_ports_are_fine():
    from runner.main import refuse_zap_port
    refuse_zap_port("http://webgoat:8083/WebGoat", "http://zap:8080")
    refuse_zap_port("http://dvwa", "http://zap:8080")


def test_a_default_port_target_collides_with_a_zap_on_80():
    import pytest
    from runner.main import refuse_zap_port
    from runner.scan import ScanScopeError
    with pytest.raises(ScanScopeError):
        refuse_zap_port("http://dvwa", "http://zap:80")
