"""Environment verification (W4-6): the declared environment_class is checked, not trusted.

Against real hostnames one typo in a hand-typed string was the whole safety story. Production
hostnames are refused whatever the scope says, a registered host must agree with the declared
class, and a shared (test/staging) host must be registered at all.
"""

import pytest

from runner.env_registry import Registry, load
from runner.preflight import PreflightError, check_scope

REG = Registry(prod_host_patterns=["*.prod.*", "prod-*"],
               hosts={"orders.test.internal": "test", "*.stage.internal": "staging",
                      "juice": "dev"})


def _scope(env, *allow):
    return {"app_id": "a", "environment_class": env, "target_fqdn": "x",
            "fqdn_allow_list": list(allow)}


@pytest.mark.parametrize("host", ["https://orders.prod.internal", "prod-api.example",
                                  "https://PROD-api.example:8443"])
def test_a_production_host_is_refused_whatever_the_class_says(host):
    with pytest.raises(PreflightError, match="production"):
        check_scope(_scope("dev", host), registry=REG)


def test_a_registered_host_must_agree_with_the_declared_class():
    with pytest.raises(PreflightError, match="registered as 'test'"):
        check_scope(_scope("staging", "https://orders.test.internal"), registry=REG)


def test_an_unregistered_shared_host_is_refused_with_the_line_to_add():
    with pytest.raises(PreflightError, match=r"new\.test\.internal: test"):
        check_scope(_scope("test", "https://new.test.internal"), registry=REG)


def test_registered_shared_hosts_pass_including_by_pattern():
    check_scope(_scope("test", "https://orders.test.internal"), registry=REG)
    check_scope(_scope("staging", "https://web.stage.internal"), registry=REG)


def test_dev_hosts_need_not_be_registered():
    check_scope(_scope("dev", "dvwa"), registry=REG)


def test_a_dev_host_registered_as_shared_is_refused_as_dev():
    with pytest.raises(PreflightError, match="registered as 'test'"):
        check_scope(_scope("dev", "orders.test.internal"), registry=REG)


def test_lookup_is_exact_before_patterns_and_case_insensitive():
    assert REG.lookup("ORDERS.test.internal") == "test"
    assert REG.lookup("web.stage.internal") == "staging"
    assert REG.lookup("unknown") is None


def test_the_shipped_registry_loads_and_denies_prod_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("DAST_ENV_REGISTRY", raising=False)
    reg = load()
    assert reg.is_production("api.prod.example.com")
    assert not reg.is_production("dvwa")


def test_the_registry_path_can_be_overridden(tmp_path, monkeypatch):
    f = tmp_path / "envs.yaml"
    f.write_text("prod_host_patterns: ['live-*']\nhosts:\n  app.qa: test\n")
    monkeypatch.setenv("DAST_ENV_REGISTRY", str(f))
    reg = load()
    assert reg.is_production("live-web") and reg.lookup("app.qa") == "test"


def test_a_missing_override_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("DAST_ENV_REGISTRY", str(tmp_path / "nope.yaml"))
    with pytest.raises(FileNotFoundError):
        load()


def test_preflight_consults_the_registry(tmp_path, monkeypatch):
    import json
    from runner.preflight import preflight
    f = tmp_path / "envs.yaml"
    f.write_text("prod_host_patterns: []\nhosts: {}\n")
    monkeypatch.setenv("DAST_ENV_REGISTRY", str(f))
    s = tmp_path / "scope.json"
    s.write_text(json.dumps(_scope("test", "https://new.test.internal")))
    with pytest.raises(PreflightError, match="not registered"):
        preflight(str(s))
