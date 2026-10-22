# DAST tool UI — acceptance criteria and API contract

*Stage 0 of the UI build (test first). Written and reviewed **before** any UI code. Every criterion
below becomes an automated test that is committed failing ("red") and then frozen: the
implementation has to meet these tests, never the other way round. Requirements are in
[`ui_requirements.md`](ui_requirements.md); the visual reference is
[style 2](style-2/index.html).*

## How the tests stay honest

1. **They test public surfaces only:** HTTP (§3), the `dast` command line, files on disk, and the
   rendered UI through the `data-testid` hooks in §4. No test imports a private function of the UI.
2. **Their answers come from somewhere other than the UI.** Each test checks against an
   independent source of truth: the JSON schemas in `contracts/`, byte comparisons and hashes of
   files, counts the test computes itself from fixture data, `git log` and `git blame` run by the
   test, the real `dast` CLI, and the tool's own `summary.md`.
3. **Fixtures are real output.** Scan artifacts come from a real self-test run of the tool
   (GitHub Actions run 39255076068, trimmed), and app configs are the real ones in
   `security/dast/`.
4. **They are frozen.** `tests/ui/FROZEN.sha256` records a hash of every test file **and every
   fixture** written at this stage (changing a fixture to make a test pass is the same thing as
   changing the test), and `tests/ui/test_frozen.py` fails if any of them changes. A frozen test can only change
   in a separate commit titled `spec change: …`, approved by the project owner. Implementation may
   add tests; it may not weaken these.

**Layers.** **API**: pytest, through FastAPI's test client, real subprocesses and real files.
**CMP**: vitest component tests. **E2E**: Playwright against a real `python -m dast ui` process.
**LIVE**: E2E that also needs Docker/ZAP or an AI key; run locally and by a manually started
workflow, not on every push.

## 1. Core changes the UI depends on

| ID | Pass when | Layer |
|---|---|---|
| CORE-1 | With `DAST_APPS_DIR` set, `appconfig.app_config_path`, `load_app_config` and `suppressions_path` all resolve under that directory, and the `dast` CLI reads app configs from there. Unset, nothing changes | API |
| CORE-2 | `dast onboard <app> --config-out PATH` writes the config to `PATH` and does not create `<apps dir>/<app>/app.yaml` | API |
| CORE-3 | `appconfig.validate_app_config(cfg)` raises for a config that fails `contracts/app.schema.json` and accepts one that passes; `load_app_config` behaves as before | API |
| CORE-4 | With `DAST_ACTOR` set, every line a run writes to `events.jsonl` carries `"actor"` equal to it | API |

## 2. Acceptance criteria

### Security (local, but attackable through the browser)

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| SEC-1 | `python -m dast ui` listens on 127.0.0.1 only: connecting through the machine's other addresses is refused | UI-N2 | API (process) |
| SEC-2 | Every `/api/*` request without the session cookie gets 401 | UI-N2 | API |
| SEC-3 | `GET /auth?token=<launch token>` works once (303 and a session cookie); a second use gets 401. The launch token is never accepted as an API credential (header or query) | UI-N2 | API |
| SEC-4 | A request whose Host header is not `127.0.0.1:<port>` or `localhost:<port>` is refused with 400, even with a valid session (DNS rebinding) | UI-N2 | API |
| SEC-5 | Every POST/PUT/PATCH/DELETE without an `X-CSRF-Token` header equal to the session's token gets 403, and so does one with a wrong value | UI-N2 | API |
| SEC-6 | No response, including an `OPTIONS` preflight from another origin, carries any `Access-Control-Allow-*` header | UI-N2 | API |
| SEC-7 | Every HTML page carries a `Content-Security-Policy` whose `script-src` and `style-src` have no `unsafe-inline` or `unsafe-eval`, and which sets `frame-ancestors 'none'` | UI-N2 | API |
| SEC-8 | With the referenced secret variables set to sentinel values, no sentinel appears in any API response, job log, UI audit entry or `events.jsonl` line, even when the job prints it. The API reports only whether each is set | UI-4 | API |
| SEC-9 | The session cookie is `HttpOnly`, `SameSite=Strict` and `Path=/` | UI-N2 | API |

### Settings and tiers

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| CFG-1 | Saving one tier B change alters only that value's line: every other line of `app.yaml`, comments included, is byte-identical | UI-1 | API |
| CFG-2 | The diff returned by preview equals the real difference between the file before and after the save | UI-1 | API |
| CFG-3 | A change to any tier C path gets 403 and the file's hash is unchanged | UI-6 | API |
| CFG-4 | A change to a non-editable tier D path gets 403 and the file is unchanged | UI-6 | API |
| CFG-5 | A change that fails `contracts/app.schema.json` (checked in the test with `jsonschema`) gets 422 and the file is unchanged | UI-N3 | API |
| CFG-6 | Each field of the fixture apps comes back with the tier given in `ui_requirements.md` §4, resolved for that app (for example `scope.exclude` is A for durable data and B for disposable) | §4 | API |
| CFG-7 | A field in `app.yaml` that the tier mapping doesn't know is reported as tier C, not editable | UI-N7 | API |
| CFG-8 | With a different tier mapping file supplied, the API reports the new tier for that field, with no code change | UI-N7 | API |
| CFG-9 | If `app.yaml` changed on disk after it was read, a save with the old `etag` gets 409 and nothing is written | UI-1 | API |
| CFG-10 | A file saved through the UI loads with `appconfig.load_app_config` to the same dict as the same edit made by hand | UI-1 | API |
| CFG-11 | Referenced secrets come back as `{name, set}` only | UI-4 | API |

### Runs and jobs

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| RUN-1 | Starting a scan runs exactly `<python> -m dast scan <app>`, with `DAST_ACTOR` equal to the current identity, and the job's `command` is the string `python -m dast scan <app>` | UI-2, N4 | API |
| RUN-2 | A second job for an app that has one running gets 409 | UI-7 | API |
| RUN-3 | Each line appended to a run's `events.jsonl` reaches the live stream in order within 2 s | UI-7 | API |
| RUN-4 | Stopping a job ends its process, runs `dast stop <app>`, marks the job and its run `stopped` (not `failed`), and records who stopped it | UI-7 | API |
| RUN-5 | When a run ends with an `abort` event, the job carries `refusal: {kind, message, fix}` in plain words, and no API response contains `Traceback` | UI-8 | API, LIVE |
| RUN-6 | Runs are listed newest first; a run directory with no `records.json` and no job running is listed as `aborted`, not hidden | UI-7 | API |
| RUN-7 | With ZAP unreachable, starting a scan or author job gets 422 with a plain message, and no process is started | UI-8 | API |

### Results, triage and publishing

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| RES-1 | Severity and lifecycle counts equal those the test computes from the run's `labeled.json` | UI-9 | API |
| RES-2 | `coverage.routes_tested`, `rules` and `truncated_rules` equal the tool's own `summary.md` and `coverage.json` | UI-9 | API |
| RES-3 | `not_scanned` findings are listed and counted, and the results page shows them | UI-9 | API, CMP |
| RES-4 | A finding's detail carries parameter, attack, evidence, solution, references and a replay line, each taken from the record; the page shows each one | UI-9 | API, CMP |
| RES-5 | An author job that ran with the AI reports `summary.steps_by_source` from the command's own output | UI-12 | API |
| TRI-1 | A proposal without `reason` or `justification` gets 422; `accepted_risk` without `expires` gets 422 | UI-10 | API |
| TRI-2 | A proposal is written to the app's `suppressions.yaml` with `status: proposed` and `proposed_by`, and the file validates against `contracts/suppressions.schema.json` | UI-10 | API |
| TRI-3 | `triage.apply` ignores `proposed` entries: no record changes status | UI-10 | API |
| TRI-4 | Approving sets `status: approved`, `approved_by` and `decided_at`; the real `dast report` then labels that finding `suppressed` | UI-10 | API |
| TRI-5 | An expired suppression is reported and shown as expired | UI-10 | API, CMP |
| TRI-6 | A `suppressions.yaml` entry with no `status` is applied as approved | UI-10 | API |
| TRI-7 | `triage.from_github` produces entries with `status: proposed` | §8 Q4 | API |
| PUB-1 | Publishing without a deployed commit, or with the token variable unset, gets 422 and starts nothing | UI-11 | API |
| PUB-2 | The preview's `count` equals the latest run's `labeled.json` length and its `category` is `dast/<app>` | UI-11 | API |
| PUB-3 | Publishing runs `dast report <app> --upload --owner … --repo … --ref … --commit …` (or `--issues` for issues) with exactly those values; the token reaches the process only as `GITHUB_TOKEN` in its environment, never in arguments or logs | UI-11, 4 | API |

### Onboarding

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| ONB-1 | Across all wizard steps the only inputs are the tier A onboarding fields (§4 below) | UI-3 | E2E |
| ONB-2 | A test or staging host missing from the environment registry is refused at the check step (422, `{message, fix}`) | UI-3, 8 | API, E2E |
| ONB-3 | A host matching the registry's production patterns is refused at the check step, whatever class was chosen | UI-3 | API |
| ONB-4 | With an AI provider available, onboarding runs `dast onboard <app> --discover` with the given base URL, class, auth mode and login URL and a `--config-out` staging path; `<apps dir>/<app>/app.yaml` does not exist until the proposal is confirmed; after confirming it exists, validates, and names the chosen secret variables | UI-3 | API |
| ONB-5 | With no AI provider available, onboarding runs `dast onboard` without `--discover` and the response says the login must be filled in by hand | UI-3 | API |
| ONB-6 | Onboarding an existing app id gets 409 unless `overwrite: true` is sent | UI-3 | API |
| ONB-7 | The wizard asks for secret **names**, shows whether each is set, and has no input for a value | UI-4 | E2E |
| ONB-8 | The semgate lab onboarded through the UI then passes `python -m dast author semgate` | UI-3 | LIVE |
| ONB-9 | For SSO (`auth: seeded`), the sign-in job runs `dast author <app> --explore --headed` | UI-5 | API |

### Governance and automation

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| GOV-1 | Each tier C value carries `approved_by` and `approved_at` equal to `git blame`'s author and date for that line, run by the test in a fixture repository | UI-6, 13 | API |
| GOV-2 | The gaps list includes every `scan.policy.disabled_rules` entry and `scope.exclude` path of every app, and every undecided posture in the tier mapping | UI-13 | API |
| GOV-3 | No API route accepts POST, PUT, PATCH or DELETE for the environment registry | UI-13 | API |
| GOV-4 | The audit trail merges every app's `events.jsonl` and the UI's own actions, newest first; every entry has an `actor` (runs started outside the UI show `outside the UI`) | UI-13, N4 | API |
| CI-1 | The generated workflow parses as YAML, runs `dast author`, `dast scan` and `dast report` for the app in that order, passes the app's credential variables from `secrets.<NAME>`, and contains no secret value | UI-14 | API |

### General

| ID | Pass when | Proves | Layer |
|---|---|---|---|
| GEN-1 | `python -m dast ui` with no built front end exits 2 and prints the command that builds it | — | API |
| GEN-2 | Every screen renders with no console errors and no broken links | all | E2E |
| GEN-3 | axe-core finds no serious or critical violations on any screen, and every visible control is reachable with Tab | UI-N5 | E2E |
| GEN-4 | Every write the UI makes (save, propose, approve, start, stop, publish, onboard) adds an entry with the actor to the UI audit log | UI-N4 | API |
| GEN-5 | No file under `webui/` names an onboarded application | — | API |
| GEN-6 | Every screen that starts an action shows its equivalent command; running that command by hand produces the same kind of artifacts | UI-2 | E2E, LIVE |

## 3. API contract

All paths are under one origin. JSON unless stated. Errors use `{"detail": {"message": str,
"fix": str | null}}` with the status shown.

**Test harness.** `webui.app.create_app(config: webui.config.UIConfig) -> FastAPI`. `UIConfig`
fields: `repo_root`, `apps_dir`, `out_dir`, `registry_path`, `tiers_path` (default: the bundled
mapping), `dist_dir`, `audit_log`, `port`, `launch_token`, `actor`, `python` (the interpreter jobs
run with), `zap_api`. Jobs inherit `DAST_APPS_DIR`, `DAST_OUT`, `DAST_ENV_REGISTRY` and
`DAST_ACTOR` from these.

**Command line.** `python -m dast ui [--port N] [--no-open]` serves the built front end from
`$DAST_UI_DIST` (default `webui/frontend/dist`), binds 127.0.0.1 only, and prints one line
containing `http://127.0.0.1:<port>/auth?token=<launch token>`. With no build it exits 2 and prints
`npm run build` with the directory to run it in.

**Tier mapping (UI-N7).** `webui/tiers.yaml`: `fields:` is a list of
`{path, tier, editable?, label, help, owner, when?}`, where `when` is a list of
`{environment_class?: [..], data_policy?: [..], tier}` overrides tried in order. `postures:` is a
list of `{id, title, decided, paths}`. A field the mapping doesn't list is tier C, not editable.

**Audit log (UI-N4).** One JSON line per UI write in `UIConfig.audit_log`:
`{ts, actor, app_id, event, detail}`, with `event` one of `settings.save`, `suppression.propose`,
`suppression.approve`, `job.start`, `job.stop`, `publish`, `onboard.start`, `onboard.confirm`.

### Session

| Method and path | Request | Response |
|---|---|---|
| `GET /auth?token=` | launch token | 303 to `/` with `Set-Cookie: dast_session=…`; 401 if reused or wrong |
| `GET /api/session` | — | `{actor, csrf_token}` |
| `GET /api/system` | — | `{zap: {url, reachable}, ai: {provider, available}}` |

Every state-changing call sends `X-CSRF-Token: <csrf_token>`.

### Apps and settings

| Method and path | Request | Response |
|---|---|---|
| `GET /api/apps` | — | `[{app_id, environment_class, base_url, latest_run: {scan_id, status} \| null}]` |
| `GET /api/apps/{app}/settings` | — | `{app_id, etag, command, fields: [{path, value, tier: "A"\|"B"\|"C"\|"D", editable, label, help, owner, secret?: {name, set}}]}` |
| `POST /api/apps/{app}/settings/preview` | `{etag, changes: {path: value}}` | `{diff}` (unified diff of `app.yaml`); 403 tier, 409 etag, 422 schema |
| `PUT /api/apps/{app}/settings` | `{etag, changes}` | `{etag, diff}`; same errors |

`path` is dotted (`scan.budgets.max_scan_min`). Lists and free-form maps are one field
(`auth.steps`, `explore.test_data`).

### Jobs and runs

| Method and path | Request | Response |
|---|---|---|
| `POST /api/apps/{app}/jobs` | `{command: "author"\|"scan"\|"report", options: {explore?, headed?, no_llm?}}` | 201 `{job_id, command, status}`; 409 one running; 422 ZAP down |
| `GET /api/jobs/{job_id}` | — | `{job_id, app_id, command, status: "running"\|"succeeded"\|"failed"\|"stopped", exit_code, actor, started_at, ended_at, scan_id, refusal?: {kind, message, fix}, summary?: {steps_by_source}}` |
| `GET /api/jobs/{job_id}/log` | — | `text/plain`, secret values masked |
| `POST /api/jobs/{job_id}/stop` | — | `{status: "stopped"}` |
| `GET /api/apps/{app}/runs` | — | `[{scan_id, status: "running"\|"complete"\|"stopped"\|"aborted", started_at}]`, newest first |
| `GET /api/apps/{app}/runs/{scan_id}` | — | `{scan_id, status, counts: {high, medium, low, info}, lifecycle: {new, open, resolved, not_scanned, suppressed}, coverage: {routes_tested, rules, truncated_rules, excluded, declared, exercised}}` |
| `GET /api/apps/{app}/runs/{scan_id}/events` | — | `text/event-stream`; one `data: <events.jsonl line>` per event, then new lines as they are appended |
| `GET /api/apps/{app}/runs/{scan_id}/findings` | — | `[{fingerprint, severity, rule_id, title, endpoint, parameter, status, suppression?: {reason, status, expires, expired}}]` |
| `GET /api/apps/{app}/runs/{scan_id}/findings/{fingerprint}` | — | the list item plus `{attack, evidence, solution, references, request_line, replay}`; `evidence` is the record's `evidence_excerpt`, `attack` is `null` when the record has none |

### Triage and publishing

| Method and path | Request | Response |
|---|---|---|
| `GET /api/apps/{app}/suppressions` | — | `[{fingerprint, reason, justification, status, expires, expired, proposed_by, approved_by, decided_at}]` |
| `POST /api/apps/{app}/suppressions` | `{fingerprint, reason, justification, expires?}` | 201 the entry (`status: proposed`) |
| `POST /api/apps/{app}/suppressions/{fingerprint}/approve` | — | the entry (`status: approved`) |
| `POST /api/apps/{app}/publish/preview` | `{destination: "code-scanning"\|"issues", owner, repo, ref, commit, token_env}` | `{destination, count, category, scan_id}` |
| `POST /api/apps/{app}/publish` | same | 201 job |

### Onboarding

| Method and path | Request | Response |
|---|---|---|
| `POST /api/onboard/check` | `{app_id, base_url, environment_class}` | `{ok, host, registry}`; 422 not registered or prod-like; 409 exists |
| `POST /api/onboard` | `{app_id, base_url, environment_class, auth: "form"\|"seeded", login_url, user_env, pass_env, overwrite?}` | 201 `{job_id, mode: "discover"\|"skeleton", message}` |
| `GET /api/onboard/{app}/proposal` | — | `{steps, proof, authenticated_routes, mode}` from the staged config |
| `POST /api/onboard/{app}/confirm` | `{proof_confirmed: true, authenticated_routes?}` | 201 `{app_id, path}` |
| `POST /api/onboard/{app}/sign-in` | — | 201 job (`dast author <app> --explore --headed`) |

### Governance and automation

| Method and path | Request | Response |
|---|---|---|
| `GET /api/governance` | — | `{approvals: [{app_id, path, value, approved_by, approved_at}], gaps: [{app_id, kind: "disabled_rule"\|"exclude"\|"posture", item, decided}], registry: {hosts, prod_patterns}, audit: [{ts, actor, app_id, event, detail}]}` |
| `GET /api/apps/{app}/workflow` | — | `{path, content}` |

## 4. Front-end contract

**Routes.** `/` Overview · `/onboard` · `/apps/:app/settings` · `/apps/:app/runs/:scanId/progress` ·
`/apps/:app/runs/:scanId/results` · `/apps/:app/runs/:scanId/findings/:fingerprint` ·
`/governance` · `/apps/:app/automate`. `src/App.tsx` exports `AppRoutes` (the routes, no router)
so tests can mount it inside a `MemoryRouter`. Data comes only from the API above, through
`fetch`.

**Tier A onboarding fields (ONB-1).** `app_id`, `base_url`, `environment_class`, `scope.allow`,
`scope.exclude` (when data is durable), `auth.mode`, `auth.login_url`,
`auth.credentials.email_env`, `auth.credentials.password_env`, `record.authenticated_routes`.

**`data-testid` hooks.**

| Hook | On |
|---|---|
| `nav-overview`, `nav-onboard`, `nav-apps`, `nav-runs`, `nav-findings`, `nav-governance`, `nav-automation` | app bar links |
| `onboard-step`, `onboard-field-<path>`, `onboard-secret-status-<path>`, `onboard-continue`, `onboard-refusal`, `proof-confirm` | onboarding |
| `tier-band-A`, `tier-band-B`, `tier-band-C`, `tier-band-D`, `setting-<path>`, `diff-preview`, `save-settings` | settings |
| `run-stage-preflight`, `run-stage-auth`, `run-stage-scan`, `run-stage-normalize`, `run-stage-coverage` (each with `data-state` = `todo`, `now` or `done`), `stop-run`, `refusal` | run progress |
| `count-<severity>`, `lifecycle-<state>`, `findings-row`, `status-<state>` | results |
| `finding-parameter`, `finding-attack`, `finding-evidence`, `finding-solution`, `finding-references`, `finding-replay` | finding detail |
| `suppression-status`, `suppression-expired`, `propose-suppression`, `approve-suppression` | triage |
| `gaps-row`, `audit-row`, `approval-row` | governance |
| `workflow-yaml` | automation |
| `equivalent-command` | every screen that starts an action |
