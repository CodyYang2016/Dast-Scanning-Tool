"""ZAP's API must not be open to anyone who can reach it (W4-4).

It ran with `api.disablekey=true` and an address allow-list of `.*`: anything on the network could
start a scan against an allow-listed host, read every request and response ZAP had seen —
including live session cookies — or stop and reconfigure scans. Every call now carries the key,
and a scan records whether the API answered without one.
"""

import io
import json
import urllib.error

import pytest

from runner import zapapi


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.fixture
def sent(monkeypatch):
    seen = []
    def fake_urlopen(req, timeout=None):
        seen.append(req)
        return _Resp(json.dumps({"version": "2.17.0"}).encode())
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_the_key_is_sent_as_a_header(monkeypatch, sent):
    monkeypatch.setenv("ZAP_API_KEY", "k-123")
    zapapi.call("http://zap:8080", "/JSON/core/view/version/")
    assert sent[0].get_header("X-zap-api-key") == "k-123"


def test_the_key_is_never_put_in_the_url(monkeypatch, sent):
    # URLs end up in logs and proxies; a header does not.
    monkeypatch.setenv("ZAP_API_KEY", "k-123")
    zapapi.call("http://zap:8080", "/JSON/core/view/version/", {"a": "b"})
    assert "k-123" not in sent[0].full_url


def test_without_a_key_no_header_is_sent(monkeypatch, sent):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    zapapi.call("http://zap:8080", "/JSON/core/view/version/")
    assert sent[0].get_header("X-zap-api-key") is None


def test_a_refused_key_says_what_to_do(monkeypatch):
    def refuse(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b""))
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", refuse)
    with pytest.raises(zapapi.ZapAuthError, match="ZAP_API_KEY"):
        zapapi.call("http://zap:8080", "/JSON/core/view/version/")


def test_an_api_that_answers_without_a_key_is_open(sent):
    assert zapapi.is_open("http://zap:8080") is True
    assert sent[0].get_header("X-zap-api-key") is None       # the probe sends no key


def test_an_api_that_refuses_without_a_key_is_closed(monkeypatch):
    def refuse(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b""))
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", refuse)
    assert zapapi.is_open("http://zap:8080") is False


def test_an_unreachable_api_is_unknown_not_closed(monkeypatch):
    def down(req, timeout=None):
        raise urllib.error.URLError("refused")
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", down)
    assert zapapi.is_open("http://zap:8080") is None


@pytest.mark.parametrize("env", ["test", "staging", "TEST"])
def test_an_open_api_is_refused_for_shared_environments(env):
    with pytest.raises(zapapi.ZapAuthError, match="open"):
        zapapi.require_closed_for(env, is_open=True)


def test_an_open_api_is_allowed_in_dev_and_an_unknown_one_anywhere():
    zapapi.require_closed_for("dev", is_open=True)
    zapapi.require_closed_for("staging", is_open=None)
    zapapi.require_closed_for("staging", is_open=False)


# ---- every caller goes through the keyed client -----------------------------------------

def test_every_zap_caller_sends_the_key(monkeypatch, sent):
    monkeypatch.setenv("ZAP_API_KEY", "k-123")
    from runner import coverage, exchange, scan
    from runner import main as runner_main
    scan._api("http://zap:8080", "/JSON/core/view/version/")
    coverage._api("http://zap:8080", "/JSON/core/view/version/")
    try:
        exchange.fetch_message("http://zap:8080", 1)
    except KeyError:
        pass                                    # the fake response has no "message"; header is what matters
    runner_main._zap_can_reach("http://zap:8080", "http://app")
    runner_main._zap_up("http://zap:8080")
    assert len(sent) == 5
    assert all(r.get_header("X-zap-api-key") == "k-123" for r in sent)


# ---- how ZAP 2.17.0 ACTUALLY refuses: it hangs up ----------------------------------------
#
# Verified against a keyed ZAP 2.17.0: a missing or wrong key gets no 401/403 at all — ZAP accepts
# the connection and closes it without a response. Recognising only 401/403 left a keyed ZAP
# reported as "unknown" rather than closed, and a wrong key waited out the whole readiness timeout
# looking like "ZAP is not up yet".

import http.client


def _hang_up(req, timeout=None):
    raise http.client.RemoteDisconnected("Remote end closed connection without response")


def _refuse_connection(req, timeout=None):
    raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))


def test_a_hang_up_is_zaps_refusal(monkeypatch):
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", _hang_up)
    with pytest.raises(zapapi.ZapAuthError, match="ZAP_API_KEY"):
        zapapi.call("http://zap:8080", "/JSON/core/view/version/")


def test_a_keyed_zap_is_reported_closed_not_unknown(monkeypatch):
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", _hang_up)
    assert zapapi.is_open("http://zap:8080") is False


def test_nothing_listening_is_still_unknown(monkeypatch):
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", _refuse_connection)
    assert zapapi.is_open("http://zap:8080") is None


def test_a_wrong_key_fails_readiness_at_once_instead_of_timing_out(monkeypatch):
    from runner import main as runner_main
    monkeypatch.setattr(zapapi.urllib.request, "urlopen", _hang_up)
    with pytest.raises(zapapi.ZapAuthError):
        runner_main.wait_ready("http://zap:8080", "http://app", timeout=60, interval=0.01)
