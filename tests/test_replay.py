"""Pure unit tests for the replay flow loader.

The browser/proxy path in runner/replay.py is validated LIVE (see runner_design.md §9), not
here. These cover the flow-loading contract, which needs neither Playwright nor a network.
"""

from pathlib import Path

import pytest

from runner import replay
from runner.replay import load_flow

ROOT = Path(__file__).resolve().parent.parent
FLOW = ROOT / "security" / "dast" / "juice-shop" / "flow.py"


def test_load_flow_exposes_run():
    module = load_flow(str(FLOW))
    assert callable(module.run)


def test_load_flow_rejects_missing_run(tmp_path):
    bad = tmp_path / "bad_flow.py"
    bad.write_text("x = 1\n")  # no run()
    with pytest.raises(RuntimeError):
        load_flow(str(bad))


# ---- wait_for_auth: one live proof for every configured mode (W2-11) --------------------
# record and seed drive a real login, then must wait for proof that it worked. The three
# proof modes have to behave identically here and in the generated flow, or an app onboards
# in one path and fails in the other — exactly the split this suite exists to prevent.
# Oracle: fake pages whose answers are known by construction.

import pytest

from runner.replay import AuthProofError, wait_for_auth

BASE = "http://app:8080"


class FakePage:
    def __init__(self, *, landed="/index.php", status=200, truthy=True, selector_count=1):
        self._landed, self._status = landed, status
        self._truthy, self._count = truthy, selector_count
        self.waited_function = self.waited_selector = None

    def wait_for_function(self, expr, timeout=None):
        self.waited_function = expr
        if not self._truthy:
            raise TimeoutError("no token")

    def wait_for_selector(self, sel, timeout=None, state=None):
        self.waited_selector = sel
        if not self._count:
            raise TimeoutError("not present")

    def goto(self, url, wait_until=None):
        self._landed = url if url.startswith("http") else BASE + url
        return type("Resp", (), {"status": self._status})()

    @property
    def url(self):
        return self._landed


def test_js_proof_waits_on_the_expression():
    page = FakePage()
    wait_for_auth(page, BASE, {"js": "window.t"})
    assert "window.t" in page.waited_function


def test_js_proof_raises_when_the_expression_never_becomes_truthy():
    with pytest.raises(AuthProofError):
        wait_for_auth(FakePage(truthy=False), BASE, {"js": "window.t"})


def test_selector_proof_waits_for_the_logged_in_marker():
    page = FakePage()
    wait_for_auth(page, BASE, {"selector": "nav .logout"})
    assert page.waited_selector == "nav .logout"


def test_selector_proof_raises_when_the_marker_never_appears():
    with pytest.raises(AuthProofError):
        wait_for_auth(FakePage(selector_count=0), BASE, {"selector": "nav .logout"})


def test_route_proof_accepts_an_authenticated_page():
    page = FakePage(status=200, landed=BASE + "/index.php")
    wait_for_auth(page, BASE, {"route": {"path": "/index.php",
                                         "forbid_redirect_to": "login.php"}})


def test_route_proof_rejects_a_bounce_back_to_the_login_form():
    # The cookie-session failure that a token check cannot see: the page loads 200, but it is
    # the login page.
    page = FakePage(status=200)
    page.goto = lambda url, wait_until=None: (
        setattr(page, "_landed", BASE + "/login.php") or type("R", (), {"status": 200})())
    with pytest.raises(AuthProofError):
        wait_for_auth(page, BASE, {"route": {"path": "/index.php",
                                             "forbid_redirect_to": "login.php"}})


def test_route_proof_rejects_a_non_2xx_status():
    with pytest.raises(AuthProofError):
        wait_for_auth(FakePage(status=403), BASE, {"route": {"path": "/index.php"}})


def test_route_proof_honours_an_exact_expected_status():
    with pytest.raises(AuthProofError):
        wait_for_auth(FakePage(status=204), BASE,
                      {"route": {"path": "/index.php", "expect_status": 200}})


def test_an_unknown_proof_mode_fails_closed():
    with pytest.raises(AuthProofError):
        wait_for_auth(FakePage(), BASE, {"psychic": True})


# ---- a logged-in marker counts even when it is not visible ------------------------------
# Observed on WebGoat: its logout link is authenticated-only but sits inside a collapsed
# dropdown, so a visibility-based wait timed out on a session that was in fact established.
# Presence in the DOM is the honest signal for a PROOF; requiring visibility would fail every
# app whose marker lives in a nav menu.

class HiddenMarkerPage(FakePage):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.waited_state = None

    def wait_for_selector(self, sel, timeout=None, state=None):
        self.waited_state = state
        if state == "visible" and self._count == 0:
            raise TimeoutError("hidden")
        self.waited_selector = sel


def test_selector_proof_accepts_a_marker_that_is_present_but_hidden():
    page = HiddenMarkerPage(selector_count=0)      # present in the DOM, not visible
    wait_for_auth(page, BASE, {"selector": "a[href*='logout']"})
    assert page.waited_state == "attached"


# ---- handing the scan's own session to the state probes --------------------------------

class _FakeContext:
    def __init__(self, cookies): self._c = cookies
    def cookies(self): return self._c


def test_the_scans_session_is_collected_for_this_host():
    ctx = _FakeContext([{"name": "PHPSESSID", "value": "abc", "domain": "app", "path": "/"}])
    assert replay._context_cookies(ctx, "http://app") == {"PHPSESSID": "abc"}


def test_another_hosts_cookies_are_not_collected():
    ctx = _FakeContext([{"name": "PHPSESSID", "value": "abc", "domain": "app"},
                        {"name": "ad", "value": "x", "domain": "ads.example"}])
    assert replay._context_cookies(ctx, "http://app") == {"PHPSESSID": "abc"}


def test_a_context_that_cannot_report_cookies_is_not_fatal():
    class Broken:
        def cookies(self): raise RuntimeError("closed")
    assert replay._context_cookies(Broken(), "http://app") == {}
