# Evidence hosting (FR-E1, FR-X2) — gap analysis

*Analysis first run against `NationwideDevin/ssd-dast-tool-poc`, branch `parallel-poc-branch` at
`0dc9593`. Re-verified on 2026-10-16 against this repository's `main` at `82caf5d`, which has that
branch merged in (PR #9). Where `main` differs from the original analysis, it says so below.*

> **Status, 2026-10-22:** the redaction holes (items 1–3 of the suggested scope) are fixed on
> branch `fix/evidence-redaction`, test first (`tests/test_evidence_redaction.py`, RED-1..RED-9):
> `redact_har` now delegates to `runner.redact`; HARs are redacted the moment the browser writes
> them, including after a failed login and in `python -m runner.replay`; screenshots mask password
> fields; `python -m runner.evidence --check DIR` finds any evidence still holding a secret, and
> `dast report --upload|--issues` and the self-test workflow refuse to publish if it finds one.
> Items 4–5 (a scan workflow for internal apps, resolvable SARIF links) still wait on the
> self-hosted-runner decision.

## Verdict: not done

The building blocks exist. Durable hosting, links that resolve, and redaction that has been
verified do not. None of the story's three acceptance criteria is met as written.

**The most urgent part is redaction, not hosting.** As the code stands, a form-login application
leaves its test account's password in the saved evidence. That is true today, on the operator's
disk, before anything is published.

## What the story asks for

When the scanner reports a finding, it keeps evidence that the finding is real:

- a recording of the browser traffic (a HAR file);
- a screenshot;
- the exact request and response that triggered it.

The story requires three things of that evidence:

| Acceptance criterion | Status on `main` | Evidence |
|---|---|---|
| Evidence (HAR + screenshot) persists beyond a single container run | **Partly met** | `compose.yaml` and the demo scripts mount `./out:/app/out` and pass `--evidence-dir=/app/out/evidence`, so the files survive teardown on the host. But `demo_full_scan.sh` writes to a fixed `out/evidence`, so each scan overwrites the last. **Differs from the original analysis:** `main` has `.github/workflows/dast-selftest.yml`, which uploads each self-test's `out/` with `actions/upload-artifact` (30-day retention) and passes `--evidence-url` with the run's URL. It covers only the bundled Juice Shop target on GitHub-hosted runners, so internal applications still have no durable hosting. The README's known gaps still list durable evidence hosting |
| SARIF results link to that scan's evidence, and the link resolves | **Not met** | `detections/sarif_export.py` `_result_for` sets `attachments[].artifactLocation.uri` to the record's relative `evidence_path`, which resolves nowhere on GitHub. `publish.evidence_url`, `$DAST_EVIDENCE_URL` and `--evidence-url` (W1-4) exist and are URL-validated (`check_evidence_url`), but `_evidence()` only adds a link to the message text, and only when the record has an `exchange_path`. Those are stored for high/medium findings (W1-3). It never links the HAR or the screenshot. No `app.yaml` sets `publish.evidence_url`, and `demo_full_scan.sh` doesn't pass `--evidence-url`. A run-page link reaches the zip artifact, not the file inside it |
| Redaction is verified before publication on the hosting path | **Not met** | There is no hosting path for internal apps to verify yet, and the redaction that exists has the holes below |

## Redaction holes (verified 2026-10-16)

### 1. The HAR redactor is weaker than the shared one

`runner/evidence.py` has its own `_redact_text`: JWTs and a short list of JSON keys. It shares only
the sensitive-header list with `runner/redact.py`, whose `redact_text` is the one used for stored
exchanges and the normalizer. Running `runner.evidence.redact_har` on a sample HAR:

| Secret in the HAR | After `redact_har` |
|---|---|
| Form-encoded password in `postData.text` (`user=…&pass=…&password=…`) | **left in** |
| Form-encoded password in `postData.params[]` | **left in** |
| Token in the query string of `request.url` (`access_token=…`) | **left in** |
| Token in `request.queryString[]` | **left in** |
| `X-CSRF-Token` header | **left in** |
| JSON `sessionId`, `apikey` | **left in** |
| `Authorization: Bearer …` inside a response body | **left in** |
| `Cookie` header (control) | removed |

Juice Shop logs in with a JSON body, so the demo looks clean. A form-login application, such as
`labs/semgate` or most enterprise apps, would leave the password in the HAR.

### 2. A failed login leaves the raw HAR on disk

`runner.replay` writes the HAR when its browser context closes, in a `finally`. The HAR is
documented there as unredacted, and the caller must redact it. `runner/main.py` redacts it only
after `_login(...)` returns. When authentication fails, `_login` raises, and the raw HAR, with the
typed password and session cookies, stays in `out/evidence/`.

### 3. The replay demo never redacts

`demo_replay_flow.sh` runs `python -m runner.replay --evidence-dir /app/out/replay-evidence`.
`runner.replay` leaves redaction to its caller, and nothing on that path calls it.

### 4. Screenshots are not redacted

`runner/replay.py` saves full-page screenshots with no masking, so they can show personal or
account data. Options: mask selectors through Playwright's `screenshot(mask=…)`, configured per
app, or exclude screenshots from anything published.

### 5. No check before publication

Nothing scans the evidence directory for secrets before it would be uploaded.

## What already exists and can be reused

- Per-scan run directories, `out/<app>/scans/<scan_id>/`, created by `dast scan`. Each has a
  `settings.json` that records the evidence URL and where that setting came from.
- `check_evidence_url` (http/https only, refuses hostile characters) and `{scan_id}`/`{path}`
  templating.
- `runner/redact.py`: linear-time patterns, form and query fields, header lines, bearer tokens,
  emails. Already used for stored exchanges.
- GitHub Issues bodies deliberately carry no payloads or responses. They point to the scan's
  artifacts instead.
- The self-test workflow's upload step (`dast-selftest.yml`), which a scan workflow for internal
  apps can copy.

## Suggested scope to close the story (about one session)

1. **✅ Make `evidence.redact_har` delegate to `runner.redact`,** and also scrub `request.url`,
   `queryString[]` and `postData.params[]`. Add tests using the fixtures above: form login,
   query token, CSRF header, extra JSON keys, bearer in a body.
2. **✅ Redact on every path.** Redact in `replay()`'s `finally`, or in `main.py`'s error path, so a
   failed login never leaves a raw HAR. Make the `runner.replay` command line redact too.
3. **✅ Add a check before publication.** Re-run the redactor over the evidence directory and fail
   if anything would change. Add screenshot masking through app config, or exclude screenshots
   from publication.
4. **Add a scan workflow for internal applications,** on a self-hosted runner inside the
   Nationwide network (GitHub-hosted runners are blocked by the IP allow list). It uploads
   `out/<app>/scans/<scan_id>/` with `actions/upload-artifact`, using a retention period and the
   scan id in the name, and sets `DAST_EVIDENCE_URL` to the run URL.
5. **Make the SARIF links resolve.** Replace the relative `attachments[].uri` with the resolved
   evidence URL, and link the HAR and the screenshot as well as the exchange.
6. **Update** the README's known gaps and `docs/nationwide_test_checklist.md`.

Items 1–3 don't depend on any decision, and they close a password leak that exists today.

## Open dependency

**Issue 1, the evidence-hosting decision.** The code assumes GitHub Actions artifacts are where
evidence lives. Whether Nationwide can provide a self-hosted runner decides whether item 4 is
feasible there. If it can't, evidence needs another governed store, and items 4 and 5 change
shape. Items 1–3 don't.
