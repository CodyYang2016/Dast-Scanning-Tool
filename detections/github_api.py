"""GitHub's REST API, by token — with the `gh` CLI as the fallback (W3-5).

The upload and the dismissals import used to shell out to `gh api`, which a pipeline has to
install and authenticate. With `$GITHUB_TOKEN` (or `$GH_TOKEN`) set, requests go over HTTP
directly; `$GITHUB_API_URL` points them at GitHub Enterprise Server. With no token, `gh` is used
exactly as before, for local convenience.

The token is a credential: it is read at call time, sent only in the Authorization header, and
scrubbed from any error text.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request

_DEFAULT_API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


def _token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def _base() -> str:
    return (os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")


def _scrub(text: str, token: str | None) -> str:
    return text.replace(token, "***") if token else text


def _gh(args: list[str], stdin: bytes | None = None) -> bytes:
    return subprocess.run(["gh", "api", *args], input=stdin, capture_output=True,
                          check=True).stdout


def _http(method: str, url: str, body, token: str):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return (json.loads(raw) if raw else {}), dict(resp.headers or {})
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read() or b"{}").get("message", "")
        except ValueError:
            message = ""
        raise GitHubError(_scrub(f"GitHub API {method} {url} → {exc.code}: {message}",
                                 token)) from None
    except urllib.error.URLError as exc:
        raise GitHubError(_scrub(f"GitHub API {method} {url} unreachable: {exc.reason}",
                                 token)) from None


def request(method: str, path: str, body=None):
    """One API call. `path` starts with `/`. Returns the decoded JSON."""
    token = _token()
    if not token:
        args = [path, "-X", method] + (["--input", "-"] if body is not None else [])
        out = _gh(args, stdin=json.dumps(body).encode() if body is not None else None)
        return json.loads(out) if out.strip() else {}
    data, _headers = _http(method, _base() + path, body, token)
    return data


def paginate(path: str) -> list:
    """Every item of a list endpoint, following `Link: rel="next"`."""
    token = _token()
    if not token:
        out = _gh(["--paginate", path]).decode().strip()
        decoder, pos, items = json.JSONDecoder(), 0, []
        while pos < len(out):           # --paginate concatenates JSON arrays
            chunk, pos = decoder.raw_decode(out, pos)
            items.extend(chunk)
            while pos < len(out) and out[pos].isspace():
                pos += 1
        return items
    items, url = [], _base() + path
    while url:
        data, headers = _http("GET", url, None, token)
        items.extend(data if isinstance(data, list) else [data])
        link = headers.get("Link") or headers.get("link") or ""
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None
    return items
