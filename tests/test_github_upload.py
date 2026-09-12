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
