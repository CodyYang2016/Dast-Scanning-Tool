"""Objective tests for the SARIF upload payload builder (FR-X2, pure part).

The network upload itself is validated live (alerts appearing in the Security tab); here we
objectively check the encoding, using an independent decode path (base64 + gzip round-trip)
as the oracle — not our own encoder.
"""

import base64
import gzip
import json

from detections.github_upload import build_payload, encode_sarif


def test_encode_sarif_roundtrips_via_independent_decode():
    original = b'{"version":"2.1.0","runs":[]}'
    encoded = encode_sarif(original)
    # Decode with the stdlib directly (independent of our encoder's internals).
    decoded = gzip.decompress(base64.b64decode(encoded))
    assert decoded == original


def test_encode_output_is_ascii_base64():
    encoded = encode_sarif(b"anything")
    assert encoded == encoded.encode("ascii").decode("ascii")  # pure ascii
    base64.b64decode(encoded)  # decodes without error


def test_build_payload_has_required_fields():
    sarif = b'{"version":"2.1.0","runs":[]}'
    payload = build_payload(sarif, "deadbeef" * 5, "refs/heads/main")
    assert set(payload) >= {"commit_sha", "ref", "sarif"}
    assert payload["commit_sha"] == "deadbeef" * 5
    assert payload["ref"] == "refs/heads/main"
    # the embedded sarif must decode back to exactly the input
    assert gzip.decompress(base64.b64decode(payload["sarif"])) == sarif


def test_build_payload_is_json_serializable():
    payload = build_payload(b'{"runs":[]}', "a" * 40, "refs/heads/main")
    assert json.loads(json.dumps(payload)) == payload


def test_tool_name_optional():
    assert "tool_name" not in build_payload(b"{}", "a" * 40, "refs/heads/main")
    assert build_payload(b"{}", "a" * 40, "refs/heads/main", tool_name="ZAP")["tool_name"] == "ZAP"


# ---- W1-8: an alert must be attributed to the deployment that was scanned ----------------
#
# GitHub stores every alert against a ref and a commit and shows them as "Affected branches".
# The upload used to default the commit to `git rev-parse HEAD` in the DAST TOOL's working tree
# and the ref to refs/heads/main. Verified on alert #1329: a Juice Shop SQL injection recorded
# against a commit of the scanner's own repository. The scanner cannot know which build was
# deployed, so it must be told — and refuse to publish when it is not.

import pytest

from detections import github_upload as gu

SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def no_network(monkeypatch, tmp_path):
    from detections import github_api
    calls = []
    # The network boundary (W3-5): everything GitHub-bound goes through github_api.request.
    monkeypatch.setattr(github_api, "request",
                        lambda method, path, body=None: calls.append(path) or {"id": "x"})
    for var in ("DAST_TARGET_COMMIT", "DAST_TARGET_REF"):
        monkeypatch.delenv(var, raising=False)
    sarif = tmp_path / "r.sarif"; sarif.write_text("{}")
    return calls, str(sarif)


def test_the_scanners_own_commit_is_never_used(monkeypatch, no_network):
    def refuse(cmd, *a, **k):
        raise AssertionError(f"shelled out to {cmd}: the scanner's checkout is not the target")
    import subprocess
    monkeypatch.setattr(subprocess, "run", refuse)
    calls, sarif = no_network
    assert gu.main([sarif, "--owner", "o", "--repo", "r", "--ref", "refs/heads/main"]) == 2
    assert calls == [] and not hasattr(gu, "_git_head")


def test_no_commit_refuses_to_publish(no_network, capsys):
    calls, sarif = no_network
    assert gu.main([sarif, "--owner", "o", "--repo", "r", "--ref", "refs/heads/main"]) == 2
    assert calls == []
    assert "DAST_TARGET_COMMIT" in capsys.readouterr().err


def test_no_ref_refuses_to_publish(no_network, capsys):
    calls, sarif = no_network
    assert gu.main([sarif, "--owner", "o", "--repo", "r", "--commit", SHA]) == 2
    assert calls == [] and "DAST_TARGET_REF" in capsys.readouterr().err


def test_the_deployment_can_come_from_the_pipeline(monkeypatch, no_network):
    calls, sarif = no_network
    monkeypatch.setenv("DAST_TARGET_COMMIT", SHA)
    monkeypatch.setenv("DAST_TARGET_REF", "refs/heads/release")
    assert gu.main([sarif, "--owner", "o", "--repo", "r"]) == 0
    assert len(calls) == 1


def test_an_explicit_flag_beats_the_environment(monkeypatch, no_network):
    calls, sarif = no_network
    seen = {}
    monkeypatch.setattr(gu, "upload", lambda o, r, s, c, ref: seen.update(c=c, ref=ref) or {})
    monkeypatch.setenv("DAST_TARGET_COMMIT", "f" * 40)
    monkeypatch.setenv("DAST_TARGET_REF", "refs/heads/env")
    gu.main([sarif, "--owner", "o", "--repo", "r", "--commit", SHA, "--ref", "refs/heads/cli"])
    assert seen == {"c": SHA, "ref": "refs/heads/cli"}


@pytest.mark.parametrize("bad", ["f0a32c9", "not-a-sha", "G" * 40, ""])
def test_a_commit_that_is_not_a_full_sha_is_refused(no_network, bad):
    calls, sarif = no_network
    assert gu.main([sarif, "--owner", "o", "--repo", "r", "--ref", "refs/heads/main",
                    "--commit", bad]) == 2
    assert calls == []


def test_a_bare_branch_name_is_refused_with_the_right_form(no_network, capsys):
    calls, sarif = no_network
    assert gu.main([sarif, "--owner", "o", "--repo", "r", "--ref", "main", "--commit", SHA]) == 2
    assert "refs/heads/main" in capsys.readouterr().err


def test_encode_sarif_is_byte_for_byte_deterministic():
    # gzip stamps the current time unless told otherwise; an upload retried a second later
    # must carry the same payload.
    assert encode_sarif(b'{"runs":[]}') == encode_sarif(b'{"runs":[]}')
    assert base64.b64decode(encode_sarif(b"x"))[4:8] == b"\x00\x00\x00\x00"
