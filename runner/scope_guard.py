"""Request-boundary scope enforcement (FR-S4, NFR-4) — the second safety layer (D2).

Where preflight validates config before any traffic, the scope guard enforces the boundary on
every in-flight request during the scan: block any host not in fqdn_allow_list (or matching
fqdn_deny_list), log the decision (NFR-4), and fail the scan if any violation occurred (D4).

Conforms to the frozen spec in docs/junior_engineer/runner_design.md §8 and the test-first
suite tests/test_scope_guard.py. Matching is host-based (D5/D6): scheme and port are ignored;
allow-list is exact host (case-insensitive); deny-list is wildcard (fnmatch); deny wins.
Fails closed — a request with no parseable host is blocked.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

log = logging.getLogger("dast.scope_guard")


class ScopeViolation(Exception):
    """Raised when the scan contacted (or attempted) an out-of-scope host (FR-S4 'fail')."""


@dataclass
class Decision:
    allowed: bool
    url: str
    host: str | None
    reason: str


def host_of(url: str) -> str | None:
    """Return the lowercased hostname (port stripped), or None if the URL has no host.

    Never raises: urlparse rejects some malformed inputs (e.g. a bracket in the netloc ->
    "Invalid IPv6 URL"); those read as "no host", which every caller treats as fail-closed.
    """
    try:
        return urlparse(url).hostname  # already lowercased and port-stripped by urlparse
    except ValueError:
        return None


_DEFAULT_PORT = {"http": 80, "https": 443}


def _parts(url: str):
    """(scheme, host, port) with the default port filled in, or None if unparseable."""
    try:
        p = urlparse(url)
        if not p.hostname or not p.scheme:
            return None
        return p.scheme.lower(), p.hostname, p.port or _DEFAULT_PORT.get(p.scheme.lower())
    except ValueError:
        return None


def origin_of(url: str) -> str | None:
    """`scheme://host[:port]`, lowercased, default port dropped — the form an allow-list origin
    entry is written in."""
    parts = _parts(url)
    if parts is None:
        return None
    scheme, host, port = parts
    return f"{scheme}://{host}" if port == _DEFAULT_PORT.get(scheme) else f"{scheme}://{host}:{port}"


def is_origin(entry: str) -> bool:
    return "://" in str(entry)


def path_exclusion_regex(pattern: str) -> str:
    """A regex for "this path and everything beneath it", from an operator's path pattern (W4-5).

    `/api/payments` covers /api/payments, /api/payments/42 and /api/payments?x — never
    /api/paymentsx, and never a URL that merely mentions it in a query string. `*` matches within
    one path segment. Case-insensitive, because excluding too much is the safe direction.

    Matches a full URL (what ZAP sees) and a bare path (the routes in coverage and records), and
    stays within the regex subset Java and Python agree on, since ZAP evaluates it too.
    """
    import re
    pattern = str(pattern).strip()
    if not pattern.startswith("/"):
        raise ValueError(f"exclusion {pattern!r} must be a path starting with /")
    body = pattern.rstrip("/")
    if not body.strip("*/"):
        raise ValueError(f"exclusion {pattern!r} would cover the whole application")
    path_rx = "[^/?#]*".join(re.escape(part) for part in body.split("*"))
    return f"(?i)^(?:[a-z][a-z0-9+.-]*://[^/?#]+)?{path_rx}(?:[/?#].*)?$"


def path_excluded(url: str, patterns) -> bool:
    import re
    return any(re.match(path_exclusion_regex(p), url) for p in patterns or [])


def entry_matches(url: str, entry: str) -> bool:
    """Does `url` fall under one allow/deny entry? (W4-2)

    An ORIGIN entry (`https://app.internal:8443`) must match scheme, host and port exactly, with
    default ports normalised. A BARE HOST entry keeps its original meaning — that host on any
    scheme and any port — which is why shared environments may not use it (preflight).
    """
    entry = str(entry).strip()
    if is_origin(entry):
        want, got = _parts(entry), _parts(url)
        return want is not None and got is not None and want == got
    return host_of(url) == entry.lower()


def in_scope(url: str, allow_entries) -> bool:
    """True when any allow-list entry admits `url`. The single matcher every reader uses, so an
    origin entry cannot be honoured in one place and silently widened to its host in another."""
    return any(entry_matches(url, e) for e in (allow_entries or []))


class ScopeGuard:
    def __init__(self, scope: dict, mode: str = "enforce"):
        """mode:
          - "enforce"   (default): out-of-scope requests are blocked AND the scan fails
            (finalize/raise_if_violated raises) — the active-scan policy (D4/FR-S4).
          - "discovery": out-of-scope requests are still blocked and logged, but do NOT fail
            the run (block-and-continue) — the exploration policy (open question 5 / KI4).
        Blocking + logging is identical in both modes; only the terminal failure differs.
        """
        if mode not in ("enforce", "discovery"):
            raise ValueError(f"unknown scope-guard mode: {mode!r}")
        self.mode = mode
        self._allow = [h.strip() for h in scope.get("fqdn_allow_list", [])]
        self._deny = [p.strip().lower() for p in scope.get("fqdn_deny_list", [])]
        self._exclude = list(scope.get("exclude_paths") or [])
        # Login-only origins (an SSO identity provider): reachable, never attacked.
        self._traverse = [t.strip() for t in scope.get("traverse_list") or []]
        self._decisions: list[Decision] = []
        self.excluded: list[str] = []    # in scope, but declared off-limits (W4-5): refused

    def _evaluate(self, url: str) -> Decision:
        host = host_of(url)
        if host is None:
            return Decision(False, url, None, "no parseable host (fail closed)")
        # Deny takes precedence over allow.
        for pattern in self._deny:
            if fnmatch.fnmatch(host, pattern):
                return Decision(False, url, host, f"deny-list match: {pattern}")
        if in_scope(url, self._allow):
            return Decision(True, url, host, "allow-list match")
        if in_scope(url, self._traverse):
            return Decision(True, url, host, "traverse (login-only host): reached, never attacked")
        return Decision(False, url, host, "not in allow-list (host, or scheme/port for an "
                                          "origin entry)")

    def check(self, url: str) -> Decision:
        """Evaluate a URL, record + log the decision, and track violations. Returns Decision."""
        d = self._evaluate(url)
        self._decisions.append(d)
        from runner import events
        if d.allowed:
            log.debug("scope allow: host=%s url=%s", d.host, d.url)
            if d.reason.startswith("traverse"):
                events.emit("scope_decision", decision="traverse", url=d.url, host=d.host)
        else:
            log.warning("scope BLOCK: host=%s url=%s reason=%s", d.host, d.url, d.reason)
            events.emit("scope_decision", decision="block", url=d.url, host=d.host,
                        reason=d.reason, mode=self.mode)
        return d

    @property
    def decisions(self) -> list[Decision]:
        return list(self._decisions)

    @property
    def violations(self) -> list[Decision]:
        return [d for d in self._decisions if not d.allowed]

    @property
    def ok(self) -> bool:
        return not self.violations

    def raise_if_violated(self) -> None:
        """Fail the scan if any out-of-scope request occurred (FR-S4 'fail')."""
        v = self.violations
        if v:
            raise ScopeViolation(
                f"{len(v)} out-of-scope request(s) blocked; scan failed. "
                f"First: {v[0].url} ({v[0].reason})"
            )

    def finalize(self) -> None:
        """Phase-split terminal check: raise in 'enforce' mode, block-and-continue in 'discovery'.

        Discovery still blocked + logged every out-of-scope request (route.abort in route_handler);
        it just doesn't fail the run, so a stray request can't abort the whole crawl (KI4)."""
        if self.mode == "enforce":
            self.raise_if_violated()

    def attach(self, page) -> None:
        """Guard a Playwright page: every first request through page.route (blocked if out of
        scope), and every redirect hop through the context's request events.

        page.route never sees a redirect hop — measured: a 302 to another origin was followed
        with the route handler called only for the original request. Blocking the hop means
        answering the first request from inside the handler, and the browser did not follow a
        redirect answered that way when tried, so a hop is checked as it is issued and an
        off-scope one fails the scan (D4).
        """
        page.route("**/*", lambda route: self.route_handler(route))
        page.context.on("request", self.on_request)

    def on_request(self, request) -> None:
        """Check a redirect hop. First requests are page.route's job and are not re-counted."""
        source = getattr(request, "redirected_from", None)
        if source is None:
            return
        d = self._evaluate(request.url)
        if d.allowed:
            return
        d = Decision(False, d.url, d.host,
                     f"redirect from {source.url}: {d.reason} — followed by the browser before "
                     f"it could be blocked")
        self._decisions.append(d)
        log.warning("scope BLOCK (redirect): host=%s url=%s reason=%s", d.host, d.url, d.reason)
        from runner import events
        events.emit("scope_decision", decision="block", url=d.url, host=d.host,
                    reason=d.reason, mode=self.mode, redirect_from=source.url)

    def route_handler(self, route) -> None:
        """Playwright page.route handler: continue allowed requests, abort blocked ones."""
        d = self.check(route.request.url)
        if d.allowed and path_excluded(route.request.url, self._exclude):
            # An endpoint the application team declared off-limits (W4-5). Refused, and logged,
            # but not a scope violation: nobody crossed a boundary, a decision was honoured.
            # Answered here with a 403 rather than aborted: an aborted navigation throws, and a
            # recorded walk that visits the page would crash. Nothing reaches ZAP or the app.
            self.excluded.append(route.request.url)
            log.info("excluded path refused: %s", route.request.url)
            from runner import events
            events.emit("scope_decision", decision="excluded", url=route.request.url)
            route.fulfill(status=403, content_type="text/plain",
                          body="refused by the DAST runner: this path is in scope.exclude (W4-5)")
        elif d.allowed:
            route.continue_()
        else:
            route.abort()
