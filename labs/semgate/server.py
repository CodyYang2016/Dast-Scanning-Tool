"""A target whose forms reject nonsense: the experiment deterministic crawling cannot pass.

WebGoat and DVWA answer any input, so a crawler that types the operator's approved value gets
through and the deterministic-vs-assisted comparison is a tie by construction. The failure class
that actually costs money in authenticated DAST is different: a form that validates its input
server-side, where the surface behind it is unreachable unless the request *means* something.
Insurance workflows are full of them -- a quote reference, a policy number, a date in range.

So this lab reduces that class to its smallest honest form. `/gate` asks a question that is
generated per page load and signed, so no value can be approved in advance and no recorded value
can be replayed; answer it and three pages appear that are 403 otherwise. Nothing here is
deliberately vulnerable -- it is a coverage experiment, not a vulnerable app, and it is the gate
that is under test, not the application.

Stdlib only, no image, no network: both the operator and CI can run it.

    python -m labs.semgate.server --port 8099
"""

from __future__ import annotations

import argparse
import hmac
import html
import os
import random
import sys
from hashlib import sha256
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# A per-process key: the challenge is signed so the server need not remember it, and a restart
# invalidates every outstanding one. Not a security control -- there is nothing here to protect.
_KEY = os.urandom(16)


def credentials() -> tuple[str, str]:
    """The account the lab accepts, from the environment. No default, deliberately: a committed
    default would be a credential in the repository, and the operator already exports these for
    `dast author` (SEMGATE_USER / SEMGATE_PASS)."""
    return os.environ.get("SEMGATE_USER", ""), os.environ.get("SEMGATE_PASS", "")


_PAGE = """<!doctype html><html><head><title>{title}</title></head><body>
<h1>{title}</h1>{body}</body></html>"""

VAULT_PAGES = {
    "/vault/policy": "Policy summary",
    "/vault/claims": "Claims history",
    "/vault/billing": "Billing schedule",
}


def sign(payload: str) -> str:
    """A tag binding a challenge to this process, so the answer is checked without server state."""
    return hmac.new(_KEY, payload.encode(), sha256).hexdigest()[:16]


def challenge() -> tuple[str, str, str]:
    """A fresh question, its signed token, and the expected answer.

    Generated per request on purpose: an operator cannot pre-approve the answer in `test_data`
    and a previous run's answer cannot be replayed, which is the whole point of the lab.
    """
    a, b = random.randint(2, 9), random.randint(2, 9)
    token = f"{a}:{b}:{sign(f'{a}:{b}')}"
    return f"What is {a} plus {b}?", token, str(a + b)


def expected(token: str) -> str | None:
    """The answer a token demands, or None if the token was not issued by this process. Pure-ish."""
    parts = (token or "").split(":")
    if len(parts) != 3:
        return None
    a, b, tag = parts
    if not hmac.compare_digest(tag, sign(f"{a}:{b}")):
        return None
    try:
        return str(int(a) + int(b))
    except ValueError:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "semgate/1.0"

    # ---- plumbing ----

    def _cookies(self) -> dict:
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return {k: v.value for k, v in jar.items()}

    def _send(self, status: int, title: str, body: str, cookie: str | None = None,
              location: str | None = None) -> None:
        page = _PAGE.format(title=html.escape(title), body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        if cookie:
            self.send_header("Set-Cookie", cookie + "; Path=/")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *args):  # quiet: the operator is reading dast output, not this
        pass

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _authed(self) -> bool:
        return self._cookies().get("sid") == "ok"

    # ---- pages ----

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler's interface)
        path = urlsplit(self.path).path
        if path == "/signin":
            return self._send(200, "Sign in", """
<form method="POST" action="/signin">
<input id="email" name="user" placeholder="user">
<input id="password" name="pass" type="password" placeholder="password">
<button id="submit" type="submit">Sign in</button></form>""")
        if not self._authed():
            return self._send(401, "Not signed in", '<a href="/signin">sign in</a>')
        if path in ("/", "/home"):
            return self._send(200, "Home", """
<p id="whoami">signed in</p>
<ul><li><a href="/profile">Profile</a></li>
<li><a href="/gate">Quote reference check</a></li></ul>""")
        if path == "/profile":
            return self._send(200, "Profile", '<p>nothing here</p><a href="/home">home</a>')
        if path == "/gate":
            question, token, _answer = challenge()
            return self._send(200, "Quote reference check", f"""
<form method="POST" action="/gate">
<p id="challenge">{html.escape(question)}</p>
<input type="hidden" name="token" value="{html.escape(token)}">
<label for="answer">{html.escape(question)}</label>
<input id="answer" name="answer" placeholder="your answer">
<label for="note">Note for the adviser</label>
<input id="note" name="note" placeholder="note">
<button id="continue" type="submit">Continue</button></form>""")
        if path in VAULT_PAGES:
            if self._cookies().get("gate") != "ok":
                return self._send(403, "Refused", "<p>the quote reference check was not passed</p>")
            others = "".join(f'<li><a href="{p}">{html.escape(t)}</a></li>'
                             for p, t in VAULT_PAGES.items() if p != path)
            return self._send(200, VAULT_PAGES[path], f"<ul>{others}</ul>")
        return self._send(404, "Not found", "")

    def do_POST(self):  # noqa: N802
        path = urlsplit(self.path).path
        form = self._body()
        if path == "/signin":
            user, password = credentials()
            if user and form.get("user") == user and form.get("pass") == password:
                return self._send(200, "Home", '<p id="whoami">signed in</p>'
                                  '<ul><li><a href="/gate">Quote reference check</a></li></ul>',
                                  cookie="sid=ok")
            return self._send(401, "Sign in failed", '<a href="/signin">try again</a>')
        if not self._authed():
            return self._send(401, "Not signed in", '<a href="/signin">sign in</a>')
        if path == "/gate":
            want = expected(form.get("token", ""))
            if want is None:
                return self._send(400, "Refused", "<p>that check was not issued here</p>")
            if (form.get("answer") or "").strip() != want:
                # The deterministic arm lands here: a value nobody could approve in advance.
                return self._send(400, "Refused", "<p>that is not the right answer</p>"
                                  '<a href="/gate">try again</a>')
            links = "".join(f'<li><a href="{p}">{html.escape(t)}</a></li>'
                            for p, t in VAULT_PAGES.items())
            return self._send(200, "Reference accepted", f"<ul>{links}</ul>", cookie="gate=ok")
        return self._send(404, "Not found", "")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Semantic-gate lab target (coverage experiment).")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8099)
    args = p.parse_args(argv)
    user, password = credentials()
    if not user or not password:
        print("SEMGATE ABORT: export SEMGATE_USER and SEMGATE_PASS first (no default account)",
              file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"semgate listening on http://{args.host}:{args.port} "
          f"(user {user}; /gate guards {len(VAULT_PAGES)} pages)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
