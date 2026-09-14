"""Pure unit tests for the scan safety pre-check.

The live ZAP orchestration (spider/ascan/export) is validated by driving the real containers
(see runner_design.md). Here we cover the one pure, safety-critical branch: scan() must refuse
an out-of-scope target BEFORE touching ZAP (NFR-2). If it raised only after calling ZAP, a
misconfig could send traffic — so this asserts the refusal happens with no network.
"""

import pytest

from runner.scan import ScanScopeError, scan

# A ZAP API that would explode if used — proves scan() never touches the network on refusal.
EXPLODING_API = "http://zap.invalid:1"


def test_scan_refuses_out_of_scope_target():
    with pytest.raises(ScanScopeError):
        scan(EXPLODING_API, "http://evil.example.com/", allow_hosts=["juice"])


def test_scan_refuses_target_with_no_host():
    with pytest.raises(ScanScopeError):
        scan(EXPLODING_API, "/relative/path", allow_hosts=["juice"])


def test_scan_scope_check_is_case_insensitive():
    # 'JUICE' host normalizes to 'juice' which is allow-listed -> passes the check and then
    # tries to reach ZAP (which fails on the bogus API). We only assert it did NOT raise
    # ScanScopeError, i.e. the safety check let an in-scope host through.
    with pytest.raises(Exception) as exc:
        scan(EXPLODING_API, "http://JUICE:3000/", allow_hosts=["juice"])
    assert not isinstance(exc.value, ScanScopeError)
