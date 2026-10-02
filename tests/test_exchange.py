"""Reproducible findings: the request ZAP sent and what came back (W1-3).

Oracle: a real exchange fetched from ZAP's /JSON/core/view/message/ during a Juice Shop scan —
the High SQL injection on /rest/user/login. It carried the test account's password and a Cookie
header, which is exactly what must never reach a stored file or GitHub.
"""

import pytest

from runner import exchange

MESSAGE = {
    "requestHeader": ("POST http://juice:3000/rest/user/login HTTP/1.1\r\n"
                      "host: juice:3000\r\nContent-Type: application/json\r\n"
                      "Cookie: language=en; token=abc123SESSIONvalue\r\n\r\n"),
    "requestBody": '{"email":"\'","password":"Dast-POC-passw0rd!"}',
    "responseHeader": ("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n"
                       "Set-Cookie: sid=s3cr3tSID; Path=/\r\n\r\n"),
    "responseBody": "<html>" + "x" * 5000 + "SQLITE_ERROR: near \"'\": syntax error" + "y" * 5000,
}
SECRETS = ("Dast-POC-passw0rd!", "abc123SESSIONvalue", "s3cr3tSID")


def test_the_request_line_is_what_a_developer_replays():
    assert exchange.request_line(MESSAGE) == "POST /rest/user/login"


def test_a_query_string_is_kept_but_redacted():
    m = {**MESSAGE, "requestHeader": "GET http://a/cb?q=apple'&token=tok999 HTTP/1.1\r\n\r\n"}
    line = exchange.request_line(m)
    assert line.startswith("GET /cb?q=apple'") and "tok999" not in line


def test_the_response_status_is_read_from_the_status_line():
    assert exchange.response_status(MESSAGE) == 500
    assert exchange.response_status({"responseHeader": ""}) is None


def test_the_stored_exchange_leaks_nothing():
    text = exchange.exchange_text(MESSAGE, evidence="SQLITE_ERROR")
    for raw in SECRETS:
        assert raw not in text, raw
    assert "POST http://juice:3000/rest/user/login" in text and "500 Internal Server Error" in text


def test_the_response_body_is_cut_to_a_window_around_the_evidence():
    text = exchange.exchange_text(MESSAGE, evidence="SQLITE_ERROR")
    assert "SQLITE_ERROR" in text
    assert len(text) < 3000          # not the whole 10 KB page
    assert "[…" in text              # and it says it was cut


def test_without_findable_evidence_the_body_starts_at_the_top():
    text = exchange.exchange_text(MESSAGE, evidence="not-in-the-body")
    assert "<html>" in text and len(text) < 3000


# ---- attaching exchanges to records -----------------------------------------------------

def _alert(i, risk="High", mid="7"):
    return {"messageId": mid, "riskcode": {"High": "3", "Medium": "2", "Low": "1"}[risk],
            "risk": risk, "evidence": "SQLITE_ERROR"}


def _record(i, sev="high"):
    return {"fingerprint": f"{i:064x}", "severity": sev}


def test_high_and_medium_findings_get_an_exchange(tmp_path):
    alerts = [_alert(0), _alert(1, "Medium"), _alert(2, "Low")]
    recs = [_record(0), _record(1, "medium"), _record(2, "low")]
    n = exchange.attach(alerts, recs, tmp_path, "evidence/S", fetch=lambda mid: MESSAGE)
    assert n["attached"] == 2
    assert recs[0]["request_line"] == "POST /rest/user/login"
    assert recs[0]["response_status"] == 500
    assert recs[0]["exchange_path"] == f"evidence/S/messages/{recs[0]['fingerprint']}.txt"
    assert (tmp_path / "messages" / f"{recs[0]['fingerprint']}.txt").exists()
    assert "request_line" not in recs[2]          # low: not fetched


def test_a_fetch_that_fails_does_not_break_the_scan(tmp_path):
    recs = [_record(0)]
    def boom(mid):
        raise RuntimeError("zap went away")
    n = exchange.attach([_alert(0)], recs, tmp_path, "evidence/S", fetch=boom)
    assert n["attached"] == 0 and n["failed"] == 1 and "request_line" not in recs[0]


def test_the_number_fetched_is_capped_and_says_so(tmp_path):
    alerts = [_alert(i) for i in range(5)]
    recs = [_record(i) for i in range(5)]
    n = exchange.attach(alerts, recs, tmp_path, "evidence/S", fetch=lambda mid: MESSAGE, cap=3)
    assert n["attached"] == 3 and n["capped"] is True


def test_findings_sharing_a_fingerprint_share_one_file(tmp_path):
    recs = [_record(0), _record(0)]
    exchange.attach([_alert(0), _alert(1)], recs, tmp_path, "evidence/S", fetch=lambda m: MESSAGE)
    assert len(list((tmp_path / "messages").iterdir())) == 1
    assert recs[1]["exchange_path"] == recs[0]["exchange_path"]


def test_mismatched_inputs_are_refused(tmp_path):
    with pytest.raises(ValueError):
        exchange.attach([_alert(0)], [], tmp_path, "evidence/S", fetch=lambda m: MESSAGE)


def test_the_cap_spends_itself_on_the_most_severe_findings_first(tmp_path):
    # Measured on Juice Shop: ~520 mediums came before the highs in ZAP's order, used up the
    # 500-fingerprint cap, and 2 of the 3 highs got no exchange. The cap must work top-down.
    alerts = [_alert(i, "Medium") for i in range(4)] + [_alert(4), _alert(5)]
    recs = [_record(i, "medium") for i in range(4)] + [_record(4), _record(5)]
    n = exchange.attach(alerts, recs, tmp_path, "evidence/S", fetch=lambda m: MESSAGE, cap=3)
    assert n["capped"] is True
    assert "request_line" in recs[4] and "request_line" in recs[5]     # both highs
    assert sum("request_line" in r for r in recs[:4]) == 1              # one medium fits


def test_critical_comes_before_high():
    import tempfile, pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    alerts = [_alert(0), _alert(1)]
    recs = [_record(0, "high"), _record(1, "critical")]
    exchange.attach(alerts, recs, d, "evidence/S", fetch=lambda m: MESSAGE, cap=1)
    assert "request_line" in recs[1] and "request_line" not in recs[0]
