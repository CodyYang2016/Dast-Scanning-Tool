"""The lab target is only an experiment if its gate really cannot be passed by guessing.

Everything the semantic-gate comparison concludes rests on three properties of this server: the
question is different every time (so no value can be approved in advance or replayed), a wrong
answer gets nothing, and the pages behind it are refused until a right one arrives. Those are
asserted here over a real socket, because a stub of the server would be asserting the stub.

Oracle: the arithmetic in the question the server itself issues.
"""

import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from labs.semgate import server as semgate

USER, PASSWORD = "lab-user", "lab-pass"


@pytest.fixture()
def target(monkeypatch):
    """The server on an ephemeral port, with a session cookie jar, torn down after the test."""
    monkeypatch.setenv("SEMGATE_USER", USER)
    monkeypatch.setenv("SEMGATE_PASS", PASSWORD)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), semgate.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    cookies: dict[str, str] = {}

    def request(path: str, data: dict | None = None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(base + path, data=body)
        if cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
        try:
            resp = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()
        for raw in resp.headers.get_all("Set-Cookie") or []:
            name, _, value = raw.split(";")[0].partition("=")
            cookies[name] = value
        return resp.status, resp.read().decode()

    try:
        yield request
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _gate_form(page: str) -> tuple[str, str]:
    """The token and expected answer from a /gate page, as a client would read them."""
    token = page.split('name="token" value="')[1].split('"')[0]
    question = page.split('<p id="challenge">')[1].split("</p>")[0]
    left, right = question.replace("What is ", "").replace("?", "").split(" plus ")
    return token, str(int(left) + int(right))


def test_the_question_changes_between_page_loads(target):
    target("/signin", {"user": USER, "pass": PASSWORD})
    tokens = {_gate_form(target("/gate")[1])[0] for _ in range(8)}
    assert len(tokens) > 1  # a single fixed question would be approvable in test_data


def test_a_wrong_answer_is_refused_and_opens_nothing(target):
    target("/signin", {"user": USER, "pass": PASSWORD})
    token, _answer = _gate_form(target("/gate")[1])
    status, page = target("/gate", {"token": token, "answer": "1", "note": "dast-test"})
    assert status == 400 and "not the right answer" in page
    assert target("/vault/policy")[0] == 403


def test_the_right_answer_opens_the_pages_behind_the_gate(target):
    target("/signin", {"user": USER, "pass": PASSWORD})
    token, answer = _gate_form(target("/gate")[1])
    status, page = target("/gate", {"token": token, "answer": answer, "note": "dast-test"})
    assert status == 200 and "/vault/policy" in page
    assert [target(path)[0] for path in semgate.VAULT_PAGES] == [200, 200, 200]


def test_a_token_this_process_did_not_issue_is_refused(target):
    """Otherwise a recorded answer from an earlier run would replay, and the lab would prove
    nothing about reasoning."""
    target("/signin", {"user": USER, "pass": PASSWORD})
    status, page = target("/gate", {"token": "4:7:deadbeefdeadbeef", "answer": "11"})
    assert status == 400 and "not issued here" in page
    assert semgate.expected("4:7:deadbeefdeadbeef") is None
    assert semgate.expected("nonsense") is None


def test_nothing_is_reachable_before_signing_in(target):
    assert target("/home")[0] == 401
    assert target("/gate")[0] == 401
    assert target("/signin", {"user": USER, "pass": "wrong"})[0] == 401


def test_the_lab_refuses_to_start_without_an_account(monkeypatch, capsys):
    """No committed default credential: the operator exports one or the lab does not run."""
    monkeypatch.delenv("SEMGATE_USER", raising=False)
    monkeypatch.delenv("SEMGATE_PASS", raising=False)
    assert semgate.main(["--port", "0"]) == 2
    assert "SEMGATE ABORT" in capsys.readouterr().err
