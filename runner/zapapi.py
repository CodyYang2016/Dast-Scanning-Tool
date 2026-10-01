"""The one way this tool talks to ZAP's API — always with the key (W4-4).

ZAP used to run with `api.disablekey=true` and an address allow-list of `.*`, so anything that
could reach the daemon could start a scan against an allow-listed host, read every request and
response ZAP had seen (live session cookies included), or stop and reconfigure scans. The key now
comes from $ZAP_API_KEY and travels as the `X-ZAP-API-Key` header — never in the URL, which ends
up in logs and proxies.

There used to be four separate urlopen() calls into ZAP. Routing them all through `call()` is what
makes "every call carries the key" a property of the code rather than a hope.
"""

from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.parse
import urllib.request

_SHARED_ENVIRONMENTS = {"test", "staging"}


class ZapAuthError(RuntimeError):
    """ZAP refused the key, or its API is open where that is not acceptable."""


def api_key() -> str | None:
    return os.environ.get("ZAP_API_KEY") or None


def call(zap_api: str, path: str, params: dict | None = None, timeout: float = 30.0,
         key: str | None = "", ) -> dict:
    """GET a ZAP API path and decode the JSON. `key=""` means "use $ZAP_API_KEY"; `key=None`
    sends no key at all (only `is_open` does that, on purpose)."""
    url = zap_api.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    use = api_key() if key == "" else key
    if use:
        req.add_header("X-ZAP-API-Key", use)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ZapAuthError(
                f"ZAP refused the API call ({exc.code}). Set ZAP_API_KEY to the key ZAP was started "
                f"with (-config api.key=...).") from exc
        raise
    except http.client.RemoteDisconnected as exc:
        # How ZAP 2.17.0 actually refuses a missing or wrong key: it accepts the connection and
        # hangs up without a response — no 401/403 (verified against a keyed daemon). "Connection
        # refused" means nothing is listening; this means something is, and it said no.
        raise ZapAuthError(
            "ZAP closed the connection without answering — how it refuses an API call with a "
            "missing or wrong key. Set ZAP_API_KEY to the key ZAP was started with "
            "(-config api.key=...).") from exc


def is_open(zap_api: str) -> bool | None:
    """Does ZAP's API answer WITHOUT a key? True = open to anyone who can reach it, False =
    closed, None = could not tell (ZAP unreachable). Probes a read-only view only."""
    try:
        call(zap_api, "/JSON/core/view/version/", key=None, timeout=10.0)
        return True
    except ZapAuthError:
        return False
    except Exception:
        return None


def require_closed_for(environment_class: str, is_open: bool | None) -> None:
    """Refuse a scan of a shared environment through an open ZAP API.

    In `dev` — a disposable container on a private network — an open API is recorded and warned
    about. In `test` or `staging` it would hand the scanner, and everything it has captured, to
    anyone on that network. Unknown is not refused: the scan's own calls will fail if ZAP is down.
    """
    if is_open and str(environment_class).strip().lower() in _SHARED_ENVIRONMENTS:
        raise ZapAuthError(
            f"refusing to scan a {environment_class} environment: ZAP's API is open — it answers "
            f"without a key. "
            f"Start ZAP with -config api.key=<secret> (not api.disablekey=true) and export "
            f"ZAP_API_KEY.")
