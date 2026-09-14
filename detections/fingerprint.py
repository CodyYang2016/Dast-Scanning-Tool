"""Stable detection fingerprint (FR-N2).

This is the backbone of the lifecycle diff (FR-L2): two scans of an unchanged app must
produce byte-identical fingerprints, or "resolved" labels are wrong. The formula and all
derivation rules are FROZEN in `contracts/README.md` — this module is the executable copy of
that contract. If you change anything here, change the contract in the same reviewed PR.

    fingerprint = sha256( rule_id | endpoint_pattern | parameter | payload_family )
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

# ZAP pluginId -> coarse payload family. Pinned from the real fixture
# (contracts/sample_zap_output.json); see the mapping table in contracts/README.md.
# Anything not listed falls through to the "misc" bucket.
_PAYLOAD_FAMILY: dict[str, str] = {
    "40018": "sqli",     # SQL Injection
    "10038": "headers",  # CSP Header Not Set
    "10055": "headers",  # CSP: Failure to Define Directive with No Fallback
    "10098": "headers",  # Cross-Domain Misconfiguration
    "10096": "headers",  # Timestamp Disclosure (info-leak passive)
    "90022": "headers",  # Application Error Disclosure (info-leak passive)
    "10104": "misc",     # User Agent Fuzzer
    "10109": "misc",     # Modern Web Application
}
_FAMILY_FALLBACK = "misc"     # rule present but unmapped
_FAMILY_EMPTY = "none"        # empty-case sentinel (see contract)

# Path segments that vary per-request and must collapse to {id} so the fingerprint tracks the
# endpoint, not the specific object.
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_LONG_HEX = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)  # hashes / opaque ids


def payload_family(plugin_id: str) -> str:
    """Map a ZAP pluginId to its coarse payload family (contract-pinned)."""
    return _PAYLOAD_FAMILY.get(str(plugin_id), _FAMILY_FALLBACK)


def _is_variable_segment(seg: str) -> bool:
    return bool(_NUMERIC.match(seg) or _UUID.match(seg) or _LONG_HEX.match(seg))


def endpoint_pattern(url: str) -> str:
    """Derive the stable endpoint pattern from a ZAP alert url.

    Path only (query string dropped), lowercased, per-request id-ish segments collapsed to
    {id}, trailing slash stripped except root. Empty path -> "/". (contracts/README.md.)
    """
    path = urlparse(url).path
    if not path:
        return "/"
    out = []
    for seg in path.split("/"):
        if seg == "":
            out.append(seg)
        elif _is_variable_segment(seg):
            out.append("{id}")
        else:
            out.append(seg.lower())
    pattern = "/".join(out).rstrip("/")
    return pattern or "/"


def fingerprint(rule_id: str, endpoint_pattern: str, parameter: str, payload_family: str) -> str:
    """Compute the frozen sha256 fingerprint. Mirrors the reference impl in the contract.

    Empty-case sentinels are applied here so callers can pass raw/empty values safely:
    endpoint -> "/", parameter -> "" (literal, yields adjacent pipes), family -> "none".
    A literal "|" can never appear in an input, so it is stripped before joining.
    """
    parts = [
        rule_id,
        endpoint_pattern or "/",
        parameter or "",
        payload_family or _FAMILY_EMPTY,
    ]
    preimage = "|".join(p.replace("|", "") for p in parts)
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
