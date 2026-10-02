"""Detect a session that dies mid-scan (W5-1).

Liveness was proven once, before a scan that runs for many minutes. If the session expired or was
destroyed partway, the rest of the scan attacked a logged-out application while the run still
reported `authenticated: true` — and its silence read as a clean bill of health.

Oracles are the two real signals measured on the onboarded apps: Juice Shop's /rest/user/whoami
answers {"user":{}} without a session, and DVWA redirects to login.php.
"""

from runner.liveness import SessionMonitor

ANON = (200, '{"user":{}}', "http://juice:3000/rest/user/whoami")
AUTHED = (200, '{"user":{"id":25,"email":"x"}}', "http://juice:3000/rest/user/whoami")
TO_LOGIN = (200, "<form>please log in</form>", "http://dvwa/login.php")


class FakeZap:
    """Answers the probe from a script: what the anonymous and the session fetch return."""
    def __init__(self, anon, sequence):
        self.anon, self.sequence, self.calls = anon, list(sequence), 0
    def __call__(self, url, cookies):
        if not cookies:
            return self.anon
        self.calls += 1
        return self.sequence.pop(0) if len(self.sequence) > 1 else self.sequence[0]


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def _monitor(fetch, clock=None, login="/login.php"):
    return SessionMonitor("http://juice:3000/rest/user/whoami", {"token": "t"}, login_path=login,
                          fetch=fetch, clock=clock or Clock(), interval_s=60)


def test_a_session_that_holds_is_alive_throughout():
    clock = Clock(); m = _monitor(FakeZap(ANON, [AUTHED]), clock)
    m.start()
    for t in (61, 122, 183):
        clock.t = t; m.check()
    r = m.result()
    assert r["method"] == "probe" and r["alive_throughout"] is True and r["checks"] == 3


def test_a_session_that_reverts_to_the_anonymous_answer_is_lost():
    clock = Clock(); m = _monitor(FakeZap(ANON, [AUTHED, AUTHED, ANON]), clock)
    m.start()
    for t in (61, 122):
        clock.t = t; m.check()
    r = m.result()
    assert r["alive_throughout"] is False and r["lost_after_s"] == 122


def test_a_redirect_to_the_login_page_is_lost():
    clock = Clock(); m = _monitor(FakeZap(TO_LOGIN, [(200, "<h1>Welcome</h1>", "http://dvwa/index.php"),
                                                     TO_LOGIN]), clock)
    m.start(); clock.t = 61; m.check()
    assert m.result()["alive_throughout"] is False


def test_a_401_or_403_is_lost():
    for status in (401, 403):
        clock = Clock(); m = _monitor(FakeZap(ANON, [AUTHED, (status, "nope", "http://a/x")]), clock)
        m.start(); clock.t = 61; m.check()
        assert m.result()["alive_throughout"] is False, status


def test_once_lost_it_stays_lost():
    clock = Clock(); m = _monitor(FakeZap(ANON, [AUTHED, ANON, AUTHED]), clock)
    m.start()
    for t in (61, 122):
        clock.t = t; m.check()
    assert m.result()["alive_throughout"] is False


def test_checks_are_rate_limited():
    clock = Clock(); fz = FakeZap(ANON, [AUTHED]); m = _monitor(fz, clock)
    m.start()
    for t in (5, 10, 30, 59):
        clock.t = t; m.check()
    assert m.result()["checks"] == 0 and fz.calls == 1        # only the start-of-scan fetch


def test_a_probe_that_cannot_tell_the_difference_is_unknown_not_alive():
    # If the logged-in and logged-out answers are the same, a "pass" proves nothing.
    m = _monitor(FakeZap(ANON, [ANON]))
    m.start()
    r = m.result()
    assert r["method"] == "unknown" and r["alive_throughout"] is None


def test_a_session_already_dead_at_the_start_is_lost_immediately():
    m = _monitor(FakeZap(TO_LOGIN, [TO_LOGIN]))
    m.start()
    assert m.result()["alive_throughout"] is False


def test_no_probe_configured_is_unknown():
    r = SessionMonitor.unavailable("no liveness_path, route proof or state probe configured")
    assert r["method"] == "unknown" and "liveness_path" in r["reason"]


def test_a_failing_probe_is_not_mistaken_for_a_lost_session():
    clock = Clock()
    def flaky(url, cookies):
        if not cookies:
            return ANON
        if flaky.n == 0:
            flaky.n += 1; return AUTHED
        raise RuntimeError("zap busy")
    flaky.n = 0
    m = _monitor(flaky, clock); m.start(); clock.t = 61; m.check()
    r = m.result()
    assert r["alive_throughout"] is True and r["probe_errors"] == 1


# ---- the gate --------------------------------------------------------------------------

def test_a_lost_session_fails_the_health_gate():
    from runner.main import evaluate_gate
    cov = {"routes": ["/a"], "session": {"method": "probe", "alive_throughout": False}}
    g = evaluate_gate(True, True, [], cov)
    assert g["passed"] is False and g["session_alive"] is False


def test_an_unknown_session_does_not_fail_it_but_is_reported():
    from runner.main import evaluate_gate
    cov = {"routes": ["/a"], "session": {"method": "unknown", "alive_throughout": None}}
    g = evaluate_gate(True, True, [], cov)
    assert g["passed"] is True and g["session_alive"] is None


def test_choosing_the_probe_path():
    from runner.liveness import probe_path
    assert probe_path({"scan": {"liveness_path": "/rest/user/whoami"}}) == "/rest/user/whoami"
    assert probe_path({"auth": {"proof": {"route": {"path": "/index.php"}}}}) == "/index.php"
    assert probe_path({"scan": {"state_probes": ["/security.php"]}}) == "/security.php"
    assert probe_path({}) is None


# ---- measured on DVWA: sessions destroyed mid-scan, and the monitor said "alive" ----------
#
# The only mid-scan probe errored under scan load and was counted as harmless; with every request
# then bouncing to the login page the scan finished before the next probe slot, and nothing
# checked at the end. "Never confirmed" was reported as "alive throughout".

def test_a_final_check_runs_regardless_of_the_rate_limit():
    clock = Clock(); fz = FakeZap(ANON, [AUTHED, ANON]); m = _monitor(fz, clock)
    m.start(); clock.t = 5                  # well inside the 60 s interval
    m.finish()
    r = m.result()
    assert r["alive_throughout"] is False and r["checks"] == 1


def test_a_session_never_confirmed_after_the_start_is_unverified_not_alive():
    clock = Clock()
    def busy(url, cookies):
        if not cookies:
            return ANON
        if busy.first:
            busy.first = False; return AUTHED
        raise TimeoutError("ZAP busy")
    busy.first = True
    m = _monitor(busy, clock); m.start()
    clock.t = 61; m.check(); m.finish()
    r = m.result()
    assert r["alive_throughout"] is None and r["probe_errors"] == 2
    assert "TimeoutError" in r["last_error"]


def test_a_confirmed_session_with_some_errors_is_still_alive():
    clock = Clock()
    def flaky(url, cookies):
        if not cookies:
            return ANON
        flaky.n += 1
        if flaky.n == 2:
            raise TimeoutError("busy once")
        return AUTHED
    flaky.n = 0
    m = _monitor(flaky, clock); m.start()
    clock.t = 61; m.check(); m.finish()
    r = m.result()
    assert r["alive_throughout"] is True and r["probe_errors"] == 1 and r["checks"] == 1


def test_an_unverified_session_does_not_fail_the_gate_but_is_reported():
    from runner.main import evaluate_gate
    cov = {"routes": ["/a"], "session": {"method": "probe", "alive_throughout": None}}
    g = evaluate_gate(True, True, [], cov)
    assert g["passed"] is True and g["session_alive"] is None


# ---- W5-2: re-authenticate when the session is lost ------------------------------------------
# Detection alone ends a long scan unhealthy. With a re-login hook the monitor pauses the scan,
# logs in again, checks the new session works, and resumes; every loss is still recorded and
# the scan is degraded (alive_throughout false), but it can finish healthy (alive_at_end).

class Server:
    """A login server: one valid token at a time; `kill()` invalidates it, `login()` issues one."""
    def __init__(self):
        self.valid, self.n = "t", 0
    def kill(self): self.valid = None
    def login(self):
        self.n += 1; self.valid = f"t{self.n}"; return {"token": self.valid}
    def fetch(self, url, cookies):
        if cookies and cookies.get("token") == self.valid:
            return AUTHED
        return ANON


def _reauth_monitor(server, clock, events, max_reauth=3, login=None):
    def pause(): events.append("pause")
    def resume(): events.append("resume")
    def reauth():
        events.append("login")
        return (login or server.login)()
    return SessionMonitor("http://juice:3000/rest/user/whoami", {"token": "t"},
                          login_path="/login.php", fetch=server.fetch, clock=clock, interval_s=60,
                          reauth=reauth, pause=pause, resume=resume, max_reauth=max_reauth)


def test_a_lost_session_is_re_established_and_the_scan_continues():
    server, clock, events = Server(), Clock(), []
    m = _reauth_monitor(server, clock, events)
    m.start()
    server.kill(); clock.t = 61
    assert m.check() is False                      # do not stop: recovered
    assert events == ["pause", "login", "resume"]
    clock.t = 122; m.check(); m.finish()
    r = m.result()
    assert r["alive_throughout"] is False and r["alive_at_end"] is True
    assert r["losses"] == [{"at_s": 61, "recovered": True}]
    assert r["lost_after_s"] == 61 and r["checks"] >= 3


def test_the_new_session_is_what_later_checks_use():
    server, clock, events = Server(), Clock(), []
    m = _reauth_monitor(server, clock, events)
    m.start(); server.kill(); clock.t = 61; m.check()
    assert m.cookies["token"] == "t1"


def test_a_re_login_that_does_not_work_stops_the_scan():
    server, clock, events = Server(), Clock(), []
    m = _reauth_monitor(server, clock, events, login=lambda: {"token": "wrong"})
    m.start(); server.kill(); clock.t = 61
    assert m.check() is True                       # stop: everything after is logged out
    m.finish()
    r = m.result()
    assert r["alive_at_end"] is False
    assert r["losses"][0]["recovered"] is False and "still logged out" in r["losses"][0]["reason"]


def test_a_re_login_that_raises_stops_the_scan_and_says_why():
    server, clock, events = Server(), Clock(), []
    def boom(): raise RuntimeError("login form changed")
    m = _reauth_monitor(server, clock, events, login=boom)
    m.start(); server.kill(); clock.t = 61
    assert m.check() is True
    assert "login form changed" in m.result()["losses"][0]["reason"]
    assert events[-1] == "resume"                  # never leave ZAP paused


def test_re_authentication_is_bounded():
    server, clock, events = Server(), Clock(), []
    m = _reauth_monitor(server, clock, events, max_reauth=2)
    m.start()
    stops = []
    for i in range(3):
        server.kill(); clock.t = 61 * (i + 1); stops.append(m.check())
    assert stops == [False, False, True]
    r = m.result()
    assert [x["recovered"] for x in r["losses"]] == [True, True, False]
    assert "limit" in r["losses"][2]["reason"]


def test_without_a_re_login_hook_a_loss_stops_the_scan():
    clock = Clock(); m = _monitor(FakeZap(ANON, [AUTHED, ANON]), clock)
    m.start(); clock.t = 61
    assert m.check() is True
    m.finish()
    assert m.result()["alive_at_end"] is False


def test_the_gate_passes_a_recovered_session_and_fails_an_unrecovered_one():
    from runner.main import evaluate_gate
    ok = {"routes": ["/a"], "session": {"alive_throughout": False, "alive_at_end": True}}
    bad = {"routes": ["/a"], "session": {"alive_throughout": False, "alive_at_end": False}}
    assert evaluate_gate(True, True, [], ok)["passed"] is True
    assert evaluate_gate(True, True, [], ok)["session_degraded"] is True
    assert evaluate_gate(True, True, [], bad)["passed"] is False
