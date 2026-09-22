# GitHub SARIF Upload — Design & Verification (FR-X2)

Push a SARIF log to GitHub code scanning so detections appear in the repo's **Security tab**
(proof point #3). Unlike the pure-logic components, this is **IO/integration**, so it is not
built strictly test-first: the pure part (payload encoding) is unit-tested; the upload itself
is validated **live** by confirming alerts render via the API.

## Flow

```
detection records ──(sarif_export)──▶ .sarif ──(github_upload)──▶ code-scanning API ──▶ Security tab
```

1. Build the payload: **gzip then base64** the SARIF (GitHub's required encoding), plus
   `commit_sha` (must exist on the remote) and `ref` (e.g. `refs/heads/main`).
2. `POST /repos/{owner}/{repo}/code-scanning/sarifs` via the authenticated `gh` CLI → `{id, url}`.
3. Poll `GET {url}` until `processing_status == "complete"`.
4. Confirm alerts via `GET /repos/{owner}/{repo}/code-scanning/alerts`.

## Why the fingerprint + security-severity work matters here
- `partialFingerprints` (set in the exporter) is what lets GitHub track "the same" alert across
  uploads — so re-uploading after a fix removes the resolved alert, matching our lifecycle diff.
- `security-severity` is why the SQLi shows as **High** in the tab instead of a generic warning.

## Objective test (pure part)
`tests/test_github_upload.py` — encodes a SARIF, then decodes it with an **independent** path
(`gzip` + `base64` directly) and asserts round-trip equality, plus required-field presence.
No network.

## How to run
```bash
python -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop \
  | python -m detections.sarif_export --driver-version 2.17.0 -o out.sarif
python -m detections.github_upload out.sarif --owner CodyYang2016 --repo Dast-Scanning-Tool
# then poll the returned status url until "complete"
```

## Verified (2026-09-12)
Uploaded the fixture-derived SARIF to `CodyYang2016/Dast-Scanning-Tool`:
- processing_status: **complete**, no errors
- **38 alerts** rendered in the Security tab
- severity distribution matched the SARIF exactly: **1 high** (SQL Injection, alert #38),
  14 medium, 11 low, 12 note — confirming the `security-severity` mapping.
- Security tab: https://github.com/CodyYang2016/Dast-Scanning-Tool/security/code-scanning

## Requirements / gotchas
- Token needs `security_events` (private repos) or `public_repo`/`repo` (public). Ours has `repo`.
- `commit_sha` must be pushed to the remote, or GitHub rejects the upload.
- DAST locations are URL endpoints (e.g. `/rest/products/search`), not source files — alerts
  show with the endpoint as location; they don't link to repo source lines (expected for DAST).
