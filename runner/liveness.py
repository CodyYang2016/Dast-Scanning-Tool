"""Is the scan still logged in? Checked DURING the scan, not just before it (W5-1).

Liveness used to be proven once, before an active scan that runs for many minutes. If the session
expired or was destroyed partway — a timeout, a logout the scanner tripped, an app restart — the
rest of the scan attacked a logged-out application while the run still said `authenticated: true`.
Its silence about everything behind the login then read as a clean bill of health.

A probe URL is fetched through ZAP twice at the start — without a session (the logged-out answer)
and with the scan's session — and again with the session at most once a minute while ZAP scans.
The session is LOST when the probe redirects to the login page, answers 401/403, or gives exactly
the logged-out answer. If the logged-in and logged-out answers are already the same, the probe
cannot tell them apart, and liveness is recorded as unknown rather than assumed.

With a re-login hook (W5-2) a loss is answered: the scan is paused, the application logged into
again, the new session proven, and the scan resumed — and the loss is still recorded, so the scan
is marked degraded and cannot resolve findings. Without one, or when the re-login fails, the scan
is stopped: everything after the loss would attack a logged-out application.
"""

from __future__ import annotations

import time
import urllib.parse


def probe_path(cfg: dict) -> str | None:
    """The URL path to probe: an explicit `scan.liveness_path`, else the route proof, else the
    first state probe. None when the config gives nothing to probe."""
    scan = (cfg or {}).get("scan", {})
    if scan.get("liveness_path"):
        return scan["liveness_path"]
    route = (((cfg or {}).get("auth") or {}).get("proof") or {}).get("route") or {}
    if route.get("path"):
        return route["path"]
    probes = scan.get("state_probes") or []
    return probes[0] if probes else None


class SessionMonitor:
    def __init__(self, url: str, cookies: dict, login_path: str | None, fetch,
                 clock=time.monotonic, interval_s: float = 60.0, reauth=None, pause=None,
                 resume=None, max_reauth: int = 3):
        """`fetch(url, cookies) -> (status, body, final_url)`; injected so this stays testable.

        With `reauth` (W5-2) a loss is answered rather than only recorded: `pause()` the scan,
        `reauth() -> cookies` logs in again, the new session is probed, and `resume()` — always,
        even when the re-login fails, so ZAP is never left paused. At most `max_reauth` times.
        """
        self.url, self.cookies, self.fetch, self.clock = url, dict(cookies or {}), fetch, clock
        self.login_path = (urllib.parse.urlsplit(login_path).path if login_path else "") or ""
        self.interval_s = interval_s
        self.reauth, self.pause, self.resume = reauth, pause, resume
        self.max_reauth = max_reauth
        self._anon_body = None
        self._started = self._last = None
        self._alive = False                  # the session as of the latest probe
        self._state = {"method": "probe", "probe": url, "checks": 0, "probe_errors": 0,
                       "alive_throughout": None, "lost_after_s": None, "last_error": None,
                       "losses": []}

    @staticmethod
    def unavailable(reason: str) -> dict:
        return {"method": "unknown", "reason": reason, "alive_throughout": None}

    def _logged_out_signal(self, status, final_url) -> bool:
        """An explicit signal: refused (401/403) or sent to the login page."""
        if status in (401, 403):
            return True
        login = self.login_path.rstrip("/")
        return bool(login.strip("/")) and \
            urllib.parse.urlsplit(final_url or "").path.rstrip("/").endswith(login)

    def _lost(self, status, body, final_url) -> bool:
        return self._logged_out_signal(status, final_url) or body == self._anon_body

    def start(self) -> None:
        self._started = self._last = self.clock()
        _s, self._anon_body, _u = self.fetch(self.url, None)
        status, body, final_url = self.fetch(self.url, self.cookies)
        if self._logged_out_signal(status, final_url):
            self._state.update(alive_throughout=False, lost_after_s=0)   # dead before it began
        elif body == self._anon_body:
            # Same answer with and without the session: a pass would prove nothing.
            self._state = {**self.unavailable(
                "the probe answers the same with and without the session, so it cannot tell "
                "logged-in from logged-out"), "probe": self.url}
        else:
            self._state["alive_throughout"] = True
            self._alive = True

    def check(self, force: bool = False) -> bool:
        """Called from the scan's polling loop; probes at most once per interval unless forced.
        Returns True when the scan should STOP: the session is gone and could not be restored,
        so everything ZAP sends from here on attacks a logged-out application."""
        if self._state.get("method") != "probe" or not self._alive:
            return False                     # unknown, or already lost: nothing more to learn
        now = self.clock()
        if not force and now - self._last < self.interval_s:
            return False
        self._last = now
        try:
            status, body, final_url = self.fetch(self.url, self.cookies)
        except Exception as exc:
            # A busy ZAP is not a lost session — but it is not a confirmed one either.
            self._state["probe_errors"] += 1
            self._state["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
            return False
        self._state["checks"] += 1
        if not self._lost(status, body, final_url):
            return False
        at = round(now - self._started)
        self._state["alive_throughout"] = False
        if self._state["lost_after_s"] is None:
            self._state["lost_after_s"] = at
        from runner import events
        events.emit("session_lost", at_s=at, probe=self.url)
        loss = {"at_s": at, "recovered": self._recover()}
        if not loss["recovered"]:
            loss["reason"] = self._why_not
            self._alive = False
            events.emit("session_not_recovered", at_s=at, reason=self._why_not)
        else:
            events.emit("session_reestablished", at_s=at)
        self._state["losses"].append(loss)
        return not loss["recovered"]

    def _recover(self) -> bool:
        """Log in again and prove the new session works (W5-2)."""
        if self.reauth is None:
            self._why_not = "re-authentication is not configured"
            return False
        if len(self._state["losses"]) >= self.max_reauth:
            self._why_not = f"re-authentication limit reached ({self.max_reauth})"
            return False
        if self.pause:
            self.pause()
        try:
            self.cookies = {**self.cookies, **(self.reauth() or {})}
            status, body, final_url = self.fetch(self.url, self.cookies)
            self._state["checks"] += 1
            if self._lost(status, body, final_url):
                self._why_not = "still logged out after logging in again"
                return False
            return True
        except Exception as exc:
            self._why_not = f"re-login failed: {type(exc).__name__}: {exc}"[:200]
            return False
        finally:
            if self.resume:
                self.resume()

    def finish(self) -> None:
        """A forced check after the active scan. Opportunistic checks can all be skipped — a scan
        that loses its session often ends quickly, everything bouncing to the login page — and a
        dead session stays dead, so the end of the scan is the one moment that always catches it.

        If no check after the start ever succeeded, liveness was never confirmed DURING the scan:
        that is recorded as unverified, not as alive.
        """
        self.check(force=True)
        if self._state.get("method") != "probe":
            return
        self._state["alive_at_end"] = self._alive if self._state["alive_throughout"] is not None \
            else None
        if self._state["alive_throughout"] is True and self._state["checks"] == 0:
            self._state.update(alive_throughout=None, alive_at_end=None,
                               reason="never confirmed after the scan started: every probe failed")

    def result(self) -> dict:
        return dict(self._state)
