"""Make ZAP's own requests carry the CURRENT session (W5-2).

ZAP's active scan replays the requests it has seen with the cookies they were recorded with. So
when a session dies and the runner logs in again, the attacks would go on sending the dead
session: a fresh login alone changes nothing. ZAP's bundled Replacer add-on rewrites a request
header on every request from chosen initiators; these rules set `Cookie` (and, for applications
that authenticate with a bearer token, `Authorization`) to the session the runner holds now.

Initiators are the active scanner (2) and the spider (3) only. The liveness probe's anonymous
baseline is sent through the API (a manual request) and must stay anonymous.
"""

from __future__ import annotations

from runner import zapapi

COOKIE_RULE = "dast-session-cookie"
BEARER_RULE = "dast-session-bearer"
INITIATORS = "2,3"          # HttpSender: ACTIVE_SCANNER_INITIATOR, SPIDER_INITIATOR


def _api(zap_api: str, path: str, params: dict | None = None, timeout: float = 30.0) -> dict:
    return zapapi.call(zap_api, path, params, timeout)


def rules(jar: dict, bearer_cookie: str | None = None, initiators: str | None = None) -> list[dict]:
    """`initiators` "" means every request through ZAP — used for the DOM-XSS pass, whose
    browsers reach ZAP as proxied traffic rather than as the active scanner (W6-3)."""
    init = INITIATORS if initiators is None else initiators
    out = [{"description": COOKIE_RULE, "enabled": "true", "matchType": "REQ_HEADER",
            "matchRegex": "false", "matchString": "Cookie",
            "replacement": "; ".join(f"{k}={v}" for k, v in sorted(jar.items())),
            "initiators": init}]
    if bearer_cookie and jar.get(bearer_cookie):
        out.append({"description": BEARER_RULE, "enabled": "true", "matchType": "REQ_HEADER",
                    "matchRegex": "false", "matchString": "Authorization",
                    "replacement": f"Bearer {jar[bearer_cookie]}", "initiators": init})
    return out


def remove(zap_api: str) -> None:
    for name in (COOKIE_RULE, BEARER_RULE):
        try:
            _api(zap_api, "/JSON/replacer/action/removeRule/", {"description": name})
        except Exception:
            pass                             # absent is fine


def install(zap_api: str, jar: dict, bearer_cookie: str | None = None,
            initiators: str | None = None) -> None:
    """Set the rules to `jar`, replacing whatever was there. Also how they are updated."""
    remove(zap_api)
    for rule in rules(jar, bearer_cookie, initiators):
        _api(zap_api, "/JSON/replacer/action/addRule/", rule)
