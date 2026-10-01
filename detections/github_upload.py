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
import os
import re
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


_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def target_deployment(commit: str | None, ref: str | None) -> tuple[str, str]:
    """The commit and ref of the BUILD THAT WAS SCANNED, or ValueError explaining what is missing.

    GitHub stores every alert against a ref and a commit and shows them as "Affected branches".
    For a DAST finding the only meaningful values are those of the deployment in the scanned
    environment, which a scanner cannot work out for itself. This used to default the commit to
    `git rev-parse HEAD` in the DAST tool's own working tree and the ref to refs/heads/main — so
    alert #1329, a Juice Shop SQL injection, was recorded against a commit of the scanner's
    repository (W1-8). Attributing findings to the wrong code is worse than not publishing them,
    so there is no default: the caller says, or the pipeline that deployed the build does.
    """
    commit = (commit or os.environ.get("DAST_TARGET_COMMIT") or "").strip().lower()
    ref = (ref or os.environ.get("DAST_TARGET_REF") or "").strip()
    if not commit:
        raise ValueError("which build was scanned? pass --commit <sha of the deployed build>, or "
                         "set DAST_TARGET_COMMIT (normally from the pipeline that deployed it). "
                         "There is no default: the scanner's own checkout is not the target.")
    if not _FULL_SHA.match(commit):
        raise ValueError(f"--commit must be a full 40-character commit SHA, got {commit!r}")
    if not ref:
        raise ValueError("which branch is deployed? pass --ref refs/heads/<branch>, or set "
                         "DAST_TARGET_REF.")
    if not ref.startswith("refs/"):
        raise ValueError(f"--ref must be a full ref such as refs/heads/{ref}, got {ref!r}")
    return commit, ref


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Upload SARIF to the GitHub Security tab (FR-X2).")
    p.add_argument("sarif", help="Path to the SARIF file to upload")
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--ref", default=None,
                   help="Ref of the DEPLOYED build, e.g. refs/heads/main (or $DAST_TARGET_REF)")
    p.add_argument("--commit", default=None,
                   help="Full SHA of the DEPLOYED build that was scanned (or $DAST_TARGET_COMMIT). "
                        "No default: the scanner's own checkout is not the target")
    args = p.parse_args(argv)

    try:
        commit, ref = target_deployment(args.commit, args.ref)
    except ValueError as exc:
        print(f"refusing to upload: {exc}", file=sys.stderr)
        return 2
    resp = upload(args.owner, args.repo, args.sarif, commit, ref)
    print(f"uploaded: id={resp.get('id')}  (attributed to {ref} @ {commit[:12]})")
    print(f"status url: {resp.get('url')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
