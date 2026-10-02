"""Authentication failure is a clean abort, not a traceback (W5-4).

Measured today: Chromium went missing and the run died with forty lines of Playwright stack. An
operator — or a UI — needs one line saying what failed and what to do about it.
"""

import pytest

from runner.replay import AuthenticationError, AuthProofError, classify_login_failure


class PlaywrightError(Exception):
    pass


class TimeoutError_(Exception):
    pass


TimeoutError_.__name__ = "TimeoutError"


def test_a_missing_browser_says_how_to_install_it():
    exc = PlaywrightError("BrowserType.launch: Executable doesn't exist at /Users/x/Library/Caches/"
                          "ms-playwright/chromium_headless_shell-1234/chrome-headless-shell")
    e = classify_login_failure(exc, "http://dvwa")
    assert "browser could not start" in str(e) and "playwright install chromium" in e.hint


def test_a_selector_that_is_not_on_the_page_is_named():
    exc = TimeoutError_('Page.fill: Timeout 30000ms exceeded.\nCall log:\n  - waiting for '
                        'locator("input[name=usernme]")')
    e = classify_login_failure(exc, "http://dvwa")
    assert "login page element not found: input[name=usernme]" in str(e)
    assert "auth.selectors" in e.hint


def test_a_failed_proof_says_login_happened_but_was_not_proven():
    e = classify_login_failure(AuthProofError("authentication not proven (route): redirected"),
                               "http://dvwa")
    assert "not proven" in str(e) and "credentials" in e.hint


def test_an_unreachable_target_is_said_plainly():
    exc = PlaywrightError("Page.goto: net::ERR_PROXY_CONNECTION_FAILED at http://dvwa/login.php")
    e = classify_login_failure(exc, "http://dvwa")
    assert "could not reach http://dvwa through ZAP" in str(e)


def test_anything_else_is_still_one_line():
    e = classify_login_failure(ValueError("strange\nmultiline\nthing"), "http://dvwa")
    assert str(e).startswith("ValueError: strange")
    assert "\n" not in str(e)


def test_main_prints_one_abort_line_and_exits_2(monkeypatch, capsys, tmp_path):
    from runner import main as rm

    def fake_run(*a, **k):
        raise AuthenticationError("login page element not found: #email", hint="check it")
    monkeypatch.setattr(rm, "run", fake_run)
    rc = rm.main(["--scope", str(tmp_path / "s.json"), "--flow", "f.py", "--base-url", "http://x"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "RUNNER ABORT: authentication failed — login page element not found: #email" in err
    assert "Traceback" not in err


def test_login_errors_are_wrapped_but_scope_violations_pass_through():
    from runner.main import _login
    from runner.scope_guard import ScopeViolation

    def boom():
        raise PlaywrightError("Executable doesn't exist at /x")
    with pytest.raises(AuthenticationError):
        _login(boom, "http://dvwa")

    def crossed():
        raise ScopeViolation("1 out-of-scope request")
    with pytest.raises(ScopeViolation):
        _login(crossed, "http://dvwa")


def test_missing_credentials_abort_before_the_browser_for_a_provisioned_identity(monkeypatch):
    from runner.main import require_credentials
    cfg = {"auth": {"identity": "provisioned",
                    "credentials": {"email_env": "DVWA_USER", "password_env": "DVWA_PASS"}}}
    monkeypatch.delenv("DVWA_USER", raising=False); monkeypatch.setenv("DVWA_PASS", "x")
    with pytest.raises(AuthenticationError, match="credentials not in the environment: DVWA_USER"):
        require_credentials(cfg)
    require_credentials({"auth": {"identity": "self-register"}})      # makes its own


def test_the_generated_flows_proof_failure_reads_as_unproven():
    # Measured with a wrong DVWA password: the generated flow raises RuntimeError("auth check …").
    e = classify_login_failure(RuntimeError("auth check redirected to http://dvwa/login.php"),
                               "http://dvwa")
    assert str(e).startswith("the login was submitted, but authentication was not proven")
