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
    """Return the lowercased hostname (port stripped), or None if the URL has no host."""
    return urlparse(url).hostname  # already lowercased and port-stripped by urlparse


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
        self._allow = {h.strip().lower() for h in scope.get("fqdn_allow_list", [])}
        self._deny = [p.strip().lower() for p in scope.get("fqdn_deny_list", [])]
        self._decisions: list[Decision] = []

    def _evaluate(self, url: str) -> Decision:
        host = host_of(url)
        if host is None:
            return Decision(False, url, None, "no parseable host (fail closed)")
        # Deny takes precedence over allow.
        for pattern in self._deny:
            if fnmatch.fnmatch(host, pattern):
                return Decision(False, url, host, f"deny-list match: {pattern}")
        if host not in self._allow:
            return Decision(False, url, host, "host not in allow-list")
        return Decision(True, url, host, "allow-list match")

    def check(self, url: str) -> Decision:
        """Evaluate a URL, record + log the decision, and track violations. Returns Decision."""
        d = self._evaluate(url)
        self._decisions.append(d)
        if d.allowed:
            log.debug("scope allow: host=%s url=%s", d.host, d.url)
        else:
            log.warning("scope BLOCK: host=%s url=%s reason=%s", d.host, d.url, d.reason)
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

    def route_handler(self, route) -> None:
        """Playwright page.route handler: continue allowed requests, abort blocked ones."""
        d = self.check(route.request.url)
        if d.allowed:
            route.continue_()
        else:
            route.abort()
