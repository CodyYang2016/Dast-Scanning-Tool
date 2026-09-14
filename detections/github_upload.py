"""Upload a SARIF log to GitHub code scanning so detections show in the Security tab (FR-X2).

GitHub's code-scanning API wants the SARIF gzip-compressed then base64-encoded, plus the
commit sha and ref it applies to. This module builds that payload (pure, unit-tested) and
POSTs it via the authenticated `gh` CLI, then polls processing status.

  POST /repos/{owner}/{repo}/code-scanning/sarifs   -> {id, url}
  GET  {url}                                         -> {processing_status, ...}
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import subprocess
import sys


def encode_sarif(sarif_bytes: bytes) -> str:
    """gzip then base64 the raw SARIF bytes — the exact encoding GitHub expects."""
    return base64.b64encode(gzip.compress(sarif_bytes)).decode("ascii")


def build_payload(sarif_bytes: bytes, commit_sha: str, ref: str,
                  tool_name: str | None = None) -> dict:
    """Build the code-scanning upload payload. Required: commit_sha, ref, sarif."""
    payload = {"commit_sha": commit_sha, "ref": ref, "sarif": encode_sarif(sarif_bytes)}
    if tool_name:
        payload["tool_name"] = tool_name
    return payload


def _gh_api(args: list[str], stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["gh", "api", *args], input=stdin, capture_output=True, check=True
    ).stdout


def _git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, check=True, text=True
    ).stdout.strip()


def upload(owner: str, repo: str, sarif_path: str, commit_sha: str, ref: str) -> dict:
    """Upload a SARIF file; returns GitHub's {id, url} response."""
    with open(sarif_path, "rb") as fh:
        payload = build_payload(fh.read(), commit_sha, ref)
    out = _gh_api(
        [f"/repos/{owner}/{repo}/code-scanning/sarifs", "-X", "POST", "--input", "-"],
        stdin=json.dumps(payload).encode(),
    )
    return json.loads(out)


def processing_status(owner: str, repo: str, sarif_id: str) -> dict:
    out = _gh_api([f"/repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}"])
    return json.loads(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Upload SARIF to the GitHub Security tab (FR-X2).")
    p.add_argument("sarif", help="Path to the SARIF file to upload")
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--ref", default="refs/heads/main")
    p.add_argument("--commit", default=None, help="Commit sha (default: git HEAD)")
    args = p.parse_args(argv)

    commit = args.commit or _git_head()
    resp = upload(args.owner, args.repo, args.sarif, commit, args.ref)
    print(f"uploaded: id={resp.get('id')}")
    print(f"status url: {resp.get('url')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
