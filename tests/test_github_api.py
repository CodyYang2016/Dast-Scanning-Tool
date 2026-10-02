"""GitHub API by token, `gh` as the fallback (W3-5).

The upload and the dismissals import shelled out to the `gh` CLI. A pipeline wants HTTP with a
token, and an organisation on GitHub Enterprise Server wants its own API URL. With no token the
`gh` path is unchanged, for local convenience. The token is a credential: it never appears in an
error.
"""

import io
import json
import urllib.error

import pytest

from detections import github_api


class FakeResp(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(json.dumps(body).encode())
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _capture(monkeypatch, responses):
    sent = []
    def urlopen(req, timeout=30):
        sent.append(req)
        return responses.pop(0)
    monkeypatch.setattr(github_api.urllib.request, "urlopen", urlopen)
    return sent


def test_a_token_request_carries_the_right_headers(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret123")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    sent = _capture(monkeypatch, [FakeResp({"id": "1"})])
    out = github_api.request("POST", "/repos/o/r/code-scanning/sarifs", {"a": 1})
    req = sent[0]
    assert out == {"id": "1"}
    assert req.full_url == "https://api.github.com/repos/o/r/code-scanning/sarifs"
    assert req.get_header("Authorization") == "Bearer ghs_secret123"
    assert req.get_header("Accept") == "application/vnd.github+json"
    assert json.loads(req.data) == {"a": 1} and req.get_method() == "POST"


def test_enterprise_server_uses_its_own_api_url(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "t"); monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_API_URL", "https://github.corp.example/api/v3/")
    sent = _capture(monkeypatch, [FakeResp({})])
    github_api.request("GET", "/repos/o/r")
    assert sent[0].full_url == "https://github.corp.example/api/v3/repos/o/r"


def test_errors_carry_status_and_message_but_never_the_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret123")
    def urlopen(req, timeout=30):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {},
                                     io.BytesIO(b'{"message":"Resource not accessible by integration ghs_secret123"}'))
    monkeypatch.setattr(github_api.urllib.request, "urlopen", urlopen)
    with pytest.raises(github_api.GitHubError) as e:
        github_api.request("GET", "/repos/o/r")
    assert "403" in str(e.value) and "not accessible" in str(e.value)
    assert "ghs_secret123" not in str(e.value)


def test_pagination_follows_link_headers(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    nxt = '<https://api.github.com/repos/o/r/alerts?page=2>; rel="next"'
    sent = _capture(monkeypatch, [FakeResp([{"n": 1}], {"Link": nxt}), FakeResp([{"n": 2}])])
    assert github_api.paginate("/repos/o/r/alerts?per_page=1") == [{"n": 1}, {"n": 2}]
    assert sent[1].full_url.endswith("page=2")


def test_without_a_token_it_falls_back_to_gh(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False); monkeypatch.delenv("GH_TOKEN", raising=False)
    calls = []
    monkeypatch.setattr(github_api, "_gh", lambda args, stdin=None: calls.append(args) or b'{"ok": true}')
    assert github_api.request("GET", "/repos/o/r") == {"ok": True}
    assert calls == [["/repos/o/r", "-X", "GET"]]


def test_the_upload_sends_the_same_payload_as_before(monkeypatch, tmp_path):
    from detections import github_upload
    seen = {}
    monkeypatch.setattr(github_api, "request",
                        lambda m, p, body=None: seen.update(m=m, p=p, body=body) or {"id": "9"})
    f = tmp_path / "r.sarif"; f.write_bytes(b'{"runs":[]}')
    out = github_upload.upload("o", "r", str(f), "a" * 40, "refs/heads/main")
    assert out == {"id": "9"} and seen["m"] == "POST"
    assert seen["p"] == "/repos/o/r/code-scanning/sarifs"
    assert seen["body"] == github_upload.build_payload(b'{"runs":[]}', "a" * 40, "refs/heads/main")
