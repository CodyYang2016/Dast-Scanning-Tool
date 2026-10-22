"""Who may talk to the UI, and how (UI-N2).

The UI listens on loopback only, but a browser on the same machine will happily send requests to
it on behalf of any website it has open. So, in order:

1. The Host header must be the UI's own (127.0.0.1:<port> or localhost:<port>). This defeats DNS
   rebinding, where an attacker's name resolves to 127.0.0.1.
2. The launch token printed by `dast ui` works once, at /auth, and becomes an HttpOnly,
   SameSite=Strict session cookie. It is never accepted anywhere else.
3. Every /api call needs that session; every page needs it too.
4. Every state-changing call needs the session's CSRF token in X-CSRF-Token.
5. No CORS headers, ever, and a Content-Security-Policy with no inline script or style.
"""
from __future__ import annotations

import hmac
import secrets
import threading

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

COOKIE = "dast_session"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class Sessions:
    def __init__(self, launch_token: str):
        self._launch = launch_token
        self._used = False
        self._sessions: dict[str, str] = {}          # session id -> csrf token
        self._lock = threading.Lock()

    def redeem(self, token: str) -> str | None:
        with self._lock:
            if self._used or not self._launch or not hmac.compare_digest(token or "", self._launch):
                return None
            self._used = True
            sid = secrets.token_urlsafe(32)
            self._sessions[sid] = secrets.token_urlsafe(32)
            return sid

    def csrf(self, sid: str | None) -> str | None:
        return self._sessions.get(sid or "")


def _deny(status: int, message: str, fix: str | None = None) -> Response:
    return JSONResponse({"detail": {"message": message, "fix": fix}}, status_code=status)


def _headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    for h in [h for h in resp.headers if h.lower().startswith("access-control-")]:
        del resp.headers[h]
    return resp


def install(app, config, sessions: Sessions):
    allowed_hosts = {f"127.0.0.1:{config.port}", f"localhost:{config.port}"}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "").lower() not in allowed_hosts:
            return _headers(_deny(400, "This UI only answers on its own address."))
        path = request.url.path
        if path == "/auth":
            sid = sessions.redeem(request.query_params.get("token", ""))
            if sid is None:
                return _headers(_deny(401, "That link has already been used or isn't valid.",
                                      "Restart `python -m dast ui` for a new link."))
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(COOKIE, sid, httponly=True, samesite="strict", path="/",
                            secure=False)        # plain http on loopback; SameSite does the work
            return _headers(resp)
        sid = request.cookies.get(COOKIE)
        csrf = sessions.csrf(sid)
        if csrf is None:
            if path.startswith("/api/") or path == "/api":
                return _headers(_deny(401, "Not signed in.",
                                      "Open the link printed by `python -m dast ui`."))
            return _headers(HTMLResponse(
                "<!doctype html><title>DAST</title><p>Open the link printed by "
                "<code>python -m dast ui</code> to use this UI.</p>", status_code=401))
        if request.method in WRITE_METHODS:
            sent = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(sent, csrf):
                return _headers(_deny(403, "This request is missing its CSRF token."))
        request.state.csrf = csrf
        return _headers(await call_next(request))
