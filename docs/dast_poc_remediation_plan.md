# DAST PoC — remediation plan: onboard a second application, then make it complete

The actionable plan derived from the three feedback documents (`archive/dast_poc_review.md`,
`dast_first_internal_app_readiness.md`, `archive/Authenticated-Application-Discovery-DAST-Design-Proposal.md`)
plus what we found running the pipeline ourselves.

**The one goal above all others:** make this tool easy enough to use that a second application
— one nobody wrote code for — can be onboarded from configuration alone. Everything in Phase 0
serves that; everything after it is sequenced behind it. The rest of the register is real work
the review identified, but it is not what this programme is judged on first.

**How to read this.** §1 is the operating principle every item below is subordinate to. §2 is the
concrete configuration contract that principle implies. §3 is the issue register — every issue,
its evidence in the code, who it fails, and the proposed fix. §4 sequences them. §5 lists the
decisions only humans can make. Sizes are in *sessions* (≈ one focused engineering day for
someone already in this codebase), matching the readiness plan's unit.

---

## 1. The operating principle: configuration is the product surface

The review's sharpest structural finding is not a missing feature — it is that **every persona
meets this tool through its configuration, and the configuration is code**:

| Persona | Today's entry point | Verdict |
|---|---|---|
| Security engineer (SEC) | A 900+ line runbook, two terminals, platform cards, exported creds, an LLM backend, an authenticated `gh` | Served, heavily |
| App developer (DEV) | A GitHub alert with a rule id and a URL path, no remediation text. *Since 2026-09-30 (W1-1/W1-2): the alert names the parameter, the payload, the evidence and ZAP's confidence, and carries the fix and references* | Partly served — not yet reproducible (W1-3) and no triage state (W1-5) |
| DevOps (OPS) | Nothing — no workflow, no usable exit-code contract, no structured logs | Not served |
| Governance (GOV) | A hand-typed `environment_class` string and logs from one module | Not served |

Onboarding a second application currently means editing `authoring/record.py` and
`authoring/generate.py`. That single fact caps adoption, invalidates the onboarding-cost question
every reviewer asks, and is the reason the demo needs a rehearsal.

> **Primary goal.** Onboard a second application with **zero diff to `authoring/` or `runner/`**,
> and publish the elapsed time. Phase 0 is not finished until that is true and enforced in CI.
> This is the claim a funding audience can check in one minute, and the one we currently cannot
> make.

### The rule we adopt from here on

> **Config in, contracts out, one command, one artifact.**
> No new capability ships if using it requires editing Python, remembering a command sequence, or
> reading a runbook to interpret its output.

### Definition of done — applies to every change in this plan

A change is not done until all five are true:

1. **Config, not code.** Anything app-specific lives in `security/dast/<app>/app.yaml`. A diff to
   `authoring/` or `runner/` to onboard an app is a bug.
2. **One command.** The capability is reachable as `dast <verb> <app>`, not a multi-flag module
   invocation. The runbook may explain *why*; it must not be required to type *what*.
3. **Observable.** It emits a structured JSON log line carrying `scan_id`, and it writes its
   output as a named artifact under `out/<app>/<scan_id>/`.
4. **Explains itself.** Its output states what it did, what it refused, and what it did not reach
   — no reader should need the source to interpret a result.
5. **Tested and documented** in the same change, with the doc updated in the same commit.

### Target experience (the measurable goal of Phase 1)

```bash
dast onboard my-app --base-url https://my-app.dev.example --auth form   # writes app.yaml skeleton
dast author  my-app          # seed -> explore -> generate -> validate, one command
dast scan    my-app          # preflight -> replay -> ZAP -> normalize -> coverage
dast report  my-app          # lifecycle diff -> SARIF -> upload -> evidence artifact
```

**Success measure:** a security engineer who has never seen this repo onboards a new application
and gets a scan report in **under one hour**, touching one YAML file and four commands. That
number is the headline we report at the next gate — not a detection count.

---

## 2. The configuration contract

One file per application, replacing the hard-coded constants and the four scattered inputs
(`scope.json`, `seed.json`, credentials, policy). It is an *input*: the frozen contracts
(`scope.schema.json`, `detection.schema.json`, the fingerprint formula, `journey.schema.json`)
are unchanged and are still what the runner consumes — `generate` emits them from this file, so
the safety argument and every existing test survive intact.

```yaml
# security/dast/<app>/app.yaml
app_id: juice-shop
environment_class: dev            # verified against the app registry where one exists (W4-6)
base_url: http://juice:3000       # the target as ZAP resolves it

scope:
  allow:    [juice]               # may traverse AND attack
  traverse: [login.idp.example]   # may reach, must NEVER be attacked (W4-1)
  deny:     ["*.google-analytics.com"]

auth:
  mode: form                      # form | seeded
  login_url: /#/login
  # Either the three-selector shorthand (below) or an explicit `steps:` list for multi-step and
  # username-based logins — see W2-10. The shorthand desugars to the same step list.
  selectors: {email: "#email", password: "#password", submit: "#loginButton"}
  # How we PROVE we are authenticated. Exactly one mode; no default (W2-11, fail closed).
  proof:
    js: "window.localStorage.getItem('token')"        # SPA with a JS-visible token
    # route: {path: /account, expect_status: 200, forbid_redirect_to: /login}   # cookie session
    # selector: "nav a[href='/logout']"                                          # logged-in marker
  identity: provisioned           # provisioned (default) | self-register  (W2-12)
  bootstrap:  {method: POST, path: /api/Users/, body: register.json}   # only when self-register
  credentials: {email_env: AUTH_EMAIL, password_env: AUTH_PASSWORD}
  storage_state: secret://dast/juice-shop/storageState     # or .secrets/… in local dev

ui:
  dismiss_selectors:              # cookie banners / modals; EMPTY by default, not Juice Shop's (W2-9)
    - "button[aria-label='Close Welcome Banner']"
    - "a[aria-label='dismiss cookie message']"

explore:
  seed_routes: ["/#/basket", "/#/order-history", "/#/search?q=apple"]
  deny_actions: [logout, delete-account, purchase, change-password]
  safe_forms:  []                 # per-app write allow-list (SP-1) — empty = read-only scan
  budgets: {max_pages: 12, max_depth: 4, max_minutes: 8}

api:
  patterns: ["/rest/", "/api/"]   # replaces the hard-coded substring heuristic
  openapi: ./openapi.json         # optional; drives discovery, scope and coverage denominator

scan:
  policy:  {attack_strength: medium, alert_threshold: medium, disabled_rules: [40026]}
  budgets: {max_scan_min: 4, max_rule_min: 1, requests_per_second: 10}

report:
  github: {owner: Nationwide, repo: ssd-dast-tool-poc, ref: refs/heads/main}
```

This one file closes the bundle gap as a side effect: `zap-policy.yaml`, `auth.json` and
`manifest.json` stop being write-only artifacts because `app.yaml` gives them a single consumer
path (W2-4).

---

## 3. Issue register

Persona: **DEV** app developer · **SEC** security engineer · **OPS** platform/DevOps · **GOV**
governance/approver. Size in sessions.

### W1 — Actionable findings (unblocks DEV; prerequisite for every demo and the benchmark)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W1-1 | ZAP's remediation content is discarded at normalization. Verified on our fixture: `description` 38/38, `confidence` 38/38, `solution` 32/38, `reference` 27/38, `evidence` 26/38 — all dropped | `detections/normalizer.py`; `contracts/detection.schema.json` has 11 properties, `additionalProperties: false` | DEV | Extend the detection contract with `description`, `solution`, `confidence`, `reference`, `evidence`; carry them through `normalize()`. Bump the contract version; fingerprint inputs unchanged so no lifecycle churn ✅ done — the normalizer carries `description`, `solution`, `references` (split from ZAP's newline-separated field), `confidence`, and `evidence_excerpt`/`attack` **redacted at normalisation and capped at 500 chars**, as optional fields on the contract. None feed the fingerprint; a test pins the fixture's fingerprints to their pre-change hash. | 1 |
| W1-7 | **Two applications published to one repository overwrite each other's alerts.** GitHub keys a code-scanning analysis by (tool name, category, ref). `sarif_export.to_sarif()` emitted `runs[0]` with only `tool` and `results` — no `automationDetails` — and `DRIVER_NAME` is one constant for every app, so all three onboarded applications competed for a single slot in the Security tab and the newest upload deleted the previous app's findings. Nothing in the tool said so | observed 2026-09-28, `detections/sarif_export.py` | SEC, GOV, DEV | ✅ done — `to_sarif(..., category=)` writes `runs[].automationDetails.id`, which is where a category lives (the REST API has no such field; it is what the CodeQL action's `category` input sets). `dast report` passes **`dast/<app_id>` by default**, so the collision is fixed with no configuration; `publish.github.category` overrides it. Verified on real artifacts: dvwa → `dast/dvwa`, webgoat → `dast/webgoat` | 0.5 |
| W2-17 | **Where results go was the one thing not driven by config.** The artifact root was a hard-coded `out/`, and the publish destination existed only as CLI flags — so an operator could not put artifacts on another volume or in a CI workspace, and a future UI had no setting to render | observed 2026-09-28 | OPS, DEV, GOV | ✅ done — `output.dir` and `publish.github` in `app.schema.json`, resolved `--out`/`$DAST_OUT` > config > default, with `~` and `${VAR}` expansion so a **committed** app.yaml stays portable. Each run writes `settings.json` recording the resolved value *and which rung produced it*, so a layered precedence can explain itself instead of appearing to ignore the operator. Two traps closed on the way: six `path.relative_to(ROOT)` prints that raise `ValueError` for any path outside the repo (every command would have died at its closing line after doing all the work), and the module-level `OUT` global, replaced by a per-invocation `Paths` object because a global keyed to "the current app" cannot serve a long-running process handling several | 1 |
| W1-2 | SARIF carries no remediation, so a developer receives a rule id, a severity and a path | `detections/sarif_export.py` — no `help`, `fullDescription`, `helpUri` | DEV | Map the new fields to SARIF `help.markdown`, `fullDescription`, `helpUri`; keep `partialFingerprints` untouched ✅ done — rule `fullDescription`, `help` (how to fix + references, with hard line breaks so ZAP's one-instruction-per-line text does not collapse) and `helpUri`; the result **message** now names the parameter, the payload, the evidence and the confidence, because GitHub renders the message and does not render `properties` — which is why the parameter had been invisible in the Security tab all along. Target-controlled evidence is fenced so it cannot inject markdown into the alert. Fixture SARIF: 38 results, 8 rules, 6 KB gzipped; a projection to GitHub's 25,000-result ceiling stays under its 10 MB limit. | 0.5 |
| W1-3 | No request/response pair in the finding, so nothing is reproducible | ZAP alerts carry only `messageId`; `/JSON/core/view/message/` is never called | DEV | Fetch the message for high/medium findings, redact it through `runner/redact.py`, attach an excerpt | 1 |
| W1-4 | Evidence path is unresolvable — SARIF references `evidence/<scan_id>/…` under a gitignored app dir; compose mounts only `./out` | `compose.yaml:46-47`; `runner/evidence.py` | DEV, GOV | Write evidence under `out/<app>/<scan_id>/`, retain as a CI artifact, reference by absolute URL | 1 |
| W1-5 | No triage model: no dedup, no suppression, no accepted-risk state; GitHub dismissals are invisible to the diff so a dismissed finding returns as `open` forever | `detections/lifecycle_diff.py` | SEC, DEV | Per-app suppression file keyed by fingerprint; reconcile GitHub alert state on upload | 1.5 |
| W1-6 | No scan summary — 1,400+ records with no grouping or ranking | — | SEC, GOV | One Markdown/HTML report per scan: counts by severity/rule/route, top 10, coverage, lifecycle deltas | 1 |

### W2 — Configuration and onboarding (Phase 0 — the primary goal) — ✅ all complete

*Status 2026-09-27: W2-1 … W2-13 delivered. W2-7's acceptance ran twice — DVWA (needed code, see
§4) and WebGoat (zero code). The `dast` CLI (W2-6) and the image change (W2-8) shipped with them.*

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W2-1 | Login flow is hard-coded to Juice Shop: registration call, selectors, token check, post-login route | `authoring/record.py:98-111`; `authoring/generate.py:32,63-65` | SEC | Read all of it from `app.yaml` `auth:`; keep the current values as the Juice Shop config | 2 |
| W2-2 | `emit_scope()` hard-codes `environment_class: "dev"` and the deny-list | `authoring/generate.py:49,52` | SEC, GOV | Source from `app.yaml`; fail loudly if absent rather than defaulting to `dev` | 0.5 |
| W2-3 | API detection is a two-substring heuristic (`/rest/`, `/api/`), missing `/v1/`, `/graphql`, versioned hosts | `authoring/record.py:18`; same pattern in `explore.py` | SEC | `api.patterns` from config; default to the current pair | 0.5 |
| W2-4 | `zap-policy.yaml`, `auth.json`, `manifest.json`, `lock` are generated but no code consumes them; `configure_policy()` takes only two time budgets and a hard-coded disabled scanner | `runner/scan.py:49-53` (`_SLOW_SCANNERS = "40026"`) | SEC, OPS | Load the policy in `configure_policy()` (attack strength, alert threshold, rule set); record the resolved policy into the coverage artifact; fail the scan if the enabled rule set differs from the pinned policy | 1.5 |
| W2-5 | Four inputs, four formats, no single place to look | — | SEC | `app.yaml` loader + schema + `dast onboard` skeleton generator | 1 |
| W2-6 | Every capability is a bare module invocation with 6–8 flags | the runbook exists because of this | SEC, OPS | `dast` console script: `onboard`/`author`/`scan`/`report`. Modules keep their current entry points so tests are untouched | 1 |
| W2-7 | **Proof:** onboarding a second app is unmeasured | — | SEC, GOV | Onboard **DVWA** with config only, zero diff to `authoring/`/`runner/`, as a CI job; publish the elapsed time | 1 |
| W2-8 | `Containerfile` does not copy `authoring/`, so the authoring half has no deployable form and `runner.main --seed` fails in-container | `Containerfile` | OPS | Copy `authoring/` into the image; add `dast` as the entry point | 0.5 |
| W2-9 | Juice Shop's cookie-banner selectors are emitted into **every** generated `flow.py` — they are baked into the code generator, not config | `authoring/generate.py:125-126` (`Close Welcome Banner`, `dismiss cookie message`, `.cc-btn`) | SEC | `ui.dismiss_selectors` from `app.yaml`; default empty so a new app inherits nothing | 0.5 |
| W2-10 | The journey contract assumes a **single-step email+password** login. A username field, a two-step login (email → Next → password) or an SSO redirect cannot be expressed | `contracts/journey.schema.json` — `login.required = [url, email_selector, password_selector, submit_selector]` | SEC | Additive, versioned schema change: `login` accepts either the current shorthand **or** a `steps[]` list of typed actions (`goto`/`fill`/`click`/`press`/`wait_for`). Shorthand desugars to steps, so existing plans, bundles and tests stay valid | 1.5 |
| W2-11 | Auth proof is mandatory and **JS-token-shaped**: the generated flow always waits on a JS expression and raises if it is falsy. An app with an **HttpOnly session cookie** can never satisfy it. Note the asymmetry — the seeded path already tolerates no token | `authoring/generate.py:143-146`; cf. `runner/replay.py:57` | SEC | `auth.proof` with three modes — `js`, `route` (status + no login redirect, reusing `prove_auth_live`'s logic), `selector`. Shared helper between generated flow and seeded replay; no default, fail closed if unset | 1.5 |
| W2-12 | Self-registration is assumed — `record` POSTs the app's signup endpoint to create its own user. Real apps do not permit this | `authoring/record.py:98` | SEC, GOV | `auth.identity: provisioned` is the default; `bootstrap` runs only when `self-register` is configured. Juice Shop keeps self-register | 0.5 |
| W2-16 | **Writing the `auth:` block by hand was the largest remaining human task in onboarding.** Finding a usable authenticated-only marker on WebGoat took a throwaway script that tried nine candidate selectors — mechanical work with a crisp oracle | observed during the WebGoat onboarding | SEC | `dast onboard --discover`: the model proposes login steps and candidate proofs; deterministic code verifies by logging in, accepting a proof only if it holds logged-in and fails logged-out, each candidate in a fresh session, session-ending candidates refused before evaluation. Falls back to the skeleton with reasons. ✅ done — DVWA in 11s | 1 |
| W2-14 | **A committed bundle did not record whether a model authored it.** `plan_source` was printed by the CLI and persisted nowhere, so the question could only be answered from scrollback or by diffing against a freshly generated deterministic plan — in a project whose safety argument is "the LLM emits only a schema-validated plan, and here is that artifact" | observed 2026-09-28 | GOV, SEC | `manifest.json` records `plan_source` (`llm`/`fallback`) and the model id when one was used. ✅ done | 0.2 |
| W2-13 | Nothing prevents app-specific code creeping back into the core | — | SEC | Guard test: fail the suite if any module under `authoring/` or `runner/` contains an app-identifying token (`juice`, `dvwa`, `#loginButton`, `PHPSESSID`, …). This is how DoD rule 1 is enforced rather than remembered | 0.5 |

### W3 — Unattended operation and audit (unblocks OPS)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W3-1 | Nothing runs unattended; no `.github/workflows/` exists | verified | OPS, GOV | One scheduled workflow: scan → diff → SARIF upload → evidence artifact retention | 1 |
| W3-2 | The gate is inverted for CI — `evaluate_gate()` passes only when a high/medium finding exists, so a clean app *fails* | `runner/main.py:80-88` | OPS | Split: `--assert-findings` (demo/self-test, current behaviour) vs. a policy gate (fail on *new* findings at/above a threshold against a baseline). Document that the current exit code must not be consumed by CI | 1 |
| W3-3 | NFR-4 unmet — `runner/scope_guard.py` is the only module that logs; no timestamps, no scan correlation id elsewhere | verified by grep | GOV, OPS | Structured JSON logging across all stages with `scan_id`; emit auth, scan-progress, refusal and export events | 1 |
| W3-4 | `out/state.json` holds every record of the last scan and is the de facto database | `detections/lifecycle_diff.py` | OPS | Per-scan artifacts + a compact state (fingerprints + coverage only, not full records); SQLite or blob-per-scan before app #3 | 1 |
| W3-5 | Manual `gh` CLI dependency for upload | `detections/github_upload.py` | OPS | Token-based API path usable from CI, `gh` kept as the local convenience | 0.5 |

### W4 — Safety for a shared, real environment (blocks the first internal scan)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W4-1 | ZAP itself is unbounded: no context, no include/exclude regex. Our two safety layers cover **browser-originated** requests only; the spider and active scan are bounded solely by the seed URL | `/JSON/context/` never called; `runner/scan.py:65,71` use `recurse=true` | GOV, SEC | Create a ZAP context per scan from `scope:`; set include/exclude regex; split `allow` (attack) from `traverse` (reach, never attack) so an IdP is never scanned | 1.5 |
| W4-2 | Scope matching is host-only — an allow-listed host is authorised on every port and scheme (KI2) | `runner/scope_guard.py` | GOV | Extend to (scheme, host, port) tuples; handle redirect chains | 1 |
| W4-3 | No throttling and no kill switch — a scan can only be stopped with Ctrl-C | — | OPS, GOV | `requests_per_second` in config → ZAP thread/delay options; a documented stop procedure and a `dast stop <app>` | 1 |
| W4-4 | ZAP API is unauthenticated (`api.disablekey=true`, `api.addrs.addr.regex=.*`) | `compose.yaml` | GOV | Enable the API key, bind the daemon to the runner | 0.5 |
| W4-7 | **`api.addrs.addr.name=.*` makes ZAP hijack any target on its own port.** Onboarding WebGoat (port 8080), every proxied request was answered by ZAP's API — `No enum constant …Format.WEBGOAT` — and the app was never reached. Silent: the scan "succeeds" against nothing | observed 2026-09-27; `docker logs zap` | SEC, OPS | Narrow `api.addrs` to the runner's address (folds into W4-4), and have preflight refuse a `base_url` whose port equals the ZAP proxy port rather than letting the scan run empty. Internal Java apps commonly listen on 8080, so this will recur in the pilot | 0.5 |
| W4-5 | Destructive/integration endpoints are not excluded per app — an active scan can trigger mail, SMS, payments or partner test systems | — | GOV, App team | Per-app exclusion list in `app.yaml`, enforced in the ZAP context *and* the action policy | 0.5 |
| W4-6 | Preflight trusts a hand-typed `environment_class` — against real hostnames one typo is the whole safety story | `runner/preflight.py` | GOV | Verify against the app registry where available; deny prod hostname patterns outright | 1 |

### W5 — Session integrity (the most likely cause of a bad pilot result)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W5-1 | Mid-scan session expiry is undetected: liveness is proven once, before a multi-minute scan. The scan can silently degrade to unauthenticated while still reporting `authenticated: true` | `runner/replay.py::prove_auth_live` called once | SEC, GOV | Post-scan liveness re-check; mark the scan **degraded**; a degraded scan may never produce `resolved` labels | 1 |
| W5-2 | No ZAP session-management or re-authentication rules, no anti-CSRF token handling. A write-enabled scan logs the scanner out and then attacks a login page (readiness SP-5) | — | SEC | Configure ZAP session management + re-auth in the context created by W4-1 | 1.5 |
| W5-3 | `storageState` is a live credential sitting in a working tree with no TTL | `.secrets/storageState.json` | GOV | Secret store reference (`secret://…`) with TTL and a documented re-seed cadence | 1 |
| W5-4 | Authentication failure surfaces as a raw Playwright traceback, not a clean abort | `runner/main.py` catches only `PreflightError`, `ScanScopeError`, `ScopeViolation` | SEC | Catch auth failure and exit with `RUNNER ABORT: authentication failed` | 0.2 |
| W5-5 | **The redactor is quadratic.** `runner/redact.py`'s `_EMAIL` pattern (`[A-Za-z0-9._%+\-]+@…`) retries from every start position inside a long run with no `@`. Measured: 1k chars 1 ms, 8k 72 ms, **200 KB 44 s**. It runs on every observation the exploration loop sends to the model (DOM text and XHR bodies), so a target with large responses makes `explore` crawl — and the input length is chosen by the target | observed 2026-09-30 while building W1-1 | SEC, DEV | ✅ done — **both** the email and the JWT patterns were quadratic (the JWT one on input like `eyJeyJeyJ…`, ~14 s at 200 KB); both are now a few milliseconds. JWT: a lookbehind so a match starts only at the beginning of a run, plus a lookahead requiring `eyJ` and one more token character — it redacts slightly *more* than before (a JWT glued to a preceding word character loses that prefix too) and never less. Email: scanned from each `@` instead of one regex, because the obvious lookbehind fix is *not* equivalent — a fuzz test found addresses starting where the previous TLD stopped mid-run that it would have left unredacted — and the scan reproduces the old output exactly. Checked against the old patterns on 1,000,000 fuzzed strings with zero counterexamples. The normalizer's interim pre-cap is removed, so a secret crossing the 500-character cap is now redacted whole | 0.2 |

### W6 — Scan posture and benchmark honesty (settle *before* the first internal scan)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W6-1 | Write paths are default-denied, so injection/authz/business-logic classes are never tested (SP-1) | `runner/action_policy.py` | SEC, GOV | Keep the guardrail; populate `safe_forms` per app; agree data reset with the app team. Note write-enabled scans are not idempotent — budget the reset or the lifecycle diff gets noisy | 1 |
| W6-2 | Scan cap with no truncation signal — "no finding" is indistinguishable from "never reached" (SP-2). Per-app budgets shipped with W2-4; the signal did not | `runner/scan.py` | SEC, GOV | Record **per-rule outcome** from ZAP's `ascan/view/scanProgress` into coverage: state, requests sent, alerts raised. This answered in seconds a question that had taken an hour — 40018 read `Complete, 660 requests, 0 alerts`, which ruled out budget and pointed at app state instead | 0.5 |
| W6-8 | **Findings depend on application state that is neither controlled nor recorded.** Measured: the same bundle and policy produced 5 highs, then 0, with the SQL-injection rule completing 660 requests and raising nothing — while the app was exploitable by hand minutes later. DVWA's security level rides in a cookie; the tool never set it and never noticed it changed. An autonomous run had also emptied the admin password earlier | observed 2026-09-27/28 | SEC, GOV | Two halves: **set** required state (`auth.cookies` seeded into the scanning context, so it is configuration rather than an accident) and **record** it (hash a few probe responses into coverage, so two scans can be compared for "was the app even in the same condition?"). ✅ done — **and the recording half shipped broken and was re-fixed**: probes were fetched with no session, so every one digested the login page to `sha256("")` and two scans differing by five highs compared as identical. Probes now carry the scan's own session, collected from the browser and never written to an artifact; `authenticated` records which kind of probe it was | 1 |
| W6-10 | **Coverage is route-level, so a parameter never exercised looks covered.** Measured: `/vulnerabilities/sqli` was visited without `?id=`, the route appears in coverage and rule 40018 ran to completion — so `dast explain` would attribute the two missing findings on that parameter as `fixed`, which is false. `resolved` inherits the same flaw | observed 2026-09-28 | SEC, GOV | Record the (route, **parameter**) pairs ZAP actually attacked, not just routes, and require the parameter to match before a fix can be claimed. ✅ done (`f75d3d5`) — `coverage.route_params` from ZAP's URL list, `resolved` gated on the finding's own parameter, and a `parameter_not_exercised` reason in `explain`. Fired on real data at once: `/vulnerabilities/brute` was visited but never with `password`. Limit: GET parameters only — a POST-body parameter cannot be shown as exercised, so it reads `not_scanned`, which is the conservative direction | 1 |
| W6-11 | **The scanner was attacking the application's own controls, and destroying the state its own findings depended on.** `scope.avoid_actions` (`logout`, `setup`, `phpinfo`, `captcha`) was enforced during exploration only; ZAP was never told. Measured over one 10-minute DVWA scan: **~325 submissions of the "Create / Reset Database" form** and **~1,000 POSTs to the login form**, after which roughly **half** of all `/vulnerabilities/*` responses were redirects to the login page. The scan was resetting the database and logging itself out while scanning. This — not model variance, and not only the security cookie — was the dominant cause of findings appearing and vanishing between runs | observed 2026-09-28 | SEC, GOV, DEV | ✅ done (`0fe329c`) — `exclusion_regexes()` turns the existing config into URL patterns and `apply_exclusions()` gives them to both spider and active scan (after `new_session`, since exclusions are session-scoped); the login page is excluded whether or not it was named. **Coverage subtracts them**, or every finding on an excluded route would resolve itself the moment the exclusion was added; `explain` names the pattern (`route_excluded`). Measured: 996 records/1 high → **617 records/5 highs**, with rule 40018 going from 868 requests/0 alerts to 468/2 — five times the highs for half the requests. Two consecutive scans then produced identical output (267 fingerprints, 80 routes, same 5 highs, `nothing disappeared`) | 1 |
| W6-12 | **A reached route is not a tested route.** `/vulnerabilities/sqli` is in the journey and in coverage, but the authored walk visits it bare, so `route_params` is empty and the two findings on `?id=` are unreachable by any scan built from that bundle. Hand-picked authoring listed `?id=1&Submit=Submit` explicitly; autonomous authoring does not always submit the form | observed 2026-09-28, scan `20260928T044609Z` | SEC | ✅ done (`ce43e27`) — the cause was ordering, not the model: seed routes were walked **before** the exploration loop began, so only the last one was ever observed and `untried_form()` (which judges only the current page) never saw the others. DVWA's seeds end with `xss_r`, exactly the page whose form was submitted. Seed routes are now queued through the loop and forms seen on pages the model leaves are remembered and drained, filtered by the same policy that would submit them. `detections/reachability.py` compares exposed against exercised parameters and `dast report` prints the shortfall. Measured: journey parameterised targets **1 → 7**, `route_params["/vulnerabilities/sqli"]` `[] → ['Submit','id']`, highs **5 → 7**, and **all 5 of the original hand-picked highs found autonomously with zero supplied routes** | 1–1.5 |
| W6-13 | **The W6-11 fix excluded all of Juice Shop from its own scan.** It derived the login exclusion from the login URL's path; Juice Shop's login is a hash route, `/#/login`, whose path is `/`, so the pattern became `(?i).*/.*` — every URL. The scan still passed its gate: 60 passive findings instead of ~1,400, and coverage reporting **0 routes**. Uploaded, it would have closed ~1,400 alerts as fixed. Missed because the tests only used `/login.php` and live checks ran on DVWA only; DVWA and WebGoat were never affected, and nothing was published while it was live | introduced `0fe329c`, found 2026-09-30 on the first Juice Shop scan since | SEC, GOV | ✅ done (`b9d6492`) — no login exclusion when the path is empty or `/` (a hash route never reaches the server), and `refuse_exclusions_covering()` refuses any scan where an exclusion matches the target's root, before ZAP is touched. After: 1,353 records over 372 routes, 2 highs. Caught only because coverage subtracts excluded routes — `0 routes` is impossible to miss | 0.3 |
| W6-9 | **The lifecycle diff says a finding is gone but never why.** `resolved` vs `not_scanned` is the honest label; the operator still has to do the forensics by hand — as happened here, by curling ZAP and reading container logs | `detections/lifecycle_diff.py` | DEV, SEC, GOV | `dast explain <app>`: for every finding that disappeared between two scans, attribute it — route excluded · route not covered · parameter not exercised · rule not enabled · rule skipped or truncated · app state differed · scan changed the app · genuinely gone. Turns an hour of detective work into a line of output. ✅ done | 1 |
| W6-3 | DOM-XSS rule 40026 disabled by default — the class that matters most for SPAs (SP-3) | `runner/scan.py:26` | SEC | Re-enable with browser config and a longer budget, or disclose on the scorecard | 1 |
| W6-4 | Coverage has no denominator: "12 pages" is meaningless without a route inventory (SP-4) | `runner/coverage.py` | GOV, SEC | OpenAPI import where a spec exists; report coverage as a percentage of declared routes; treat crawl breadth as a measured output | 1.5 |
| W6-5 | OAST (blind SSRF/XSS/injection) absent by construction (SP-6) | — | GOV | Decide in or out. Out ⇒ record as a disclosed exclusion, not a detection deficit | decision |
| W6-6 | Authorization testing (IDOR/BOLA) impossible with one identity (SP-7) | — | GOV | Fund multi-identity scanning as a distinct capability, or exclude explicitly | decision |
| W6-7 | The evaluation could reduce to a finding count, where the PoC *is* ZAP and the outcome is predetermined | readiness scorecard | GOV | Agree the weighted scorecard and must-win criteria **before** the first scan; report unique findings, FP rate from a ~30-finding manual sample, and every posture exclusion | 0.5 |

### W7 — Discovery depth and the D9 question

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W7-1 | **D9 contradiction.** `decisions_and_known_issues.md` records "LLM-primary with deterministic fallback" as ADOPTED; the discovery proposal argues deterministic-first with LLM escalation, also as adopted text | both docs | all | Write a superseding decision (**D11**) — do not leave three documents disagreeing. Recommended content: deterministic-primary, LLM invoked only at a measured blocker, applies to authoring only (the scan loop keeps R1: no LLM, ever) ✅ done — D11 written (`f0a32c9`): seed + explore is the default authoring path, the LLM acts at three authoring points behind one boundary, and the two risks that deferred it turned out to be our defects (W6-11, W6-12). KI4 marked resolved by it. | 0.5 |
| W7-2 | `explore` calls the model on every step even when a deterministic choice exists | `authoring/explore.py:190-204` | SEC | Invert `next_action()`: `propose_fallback` first, escalate to the model only when it returns `stop` or a form needs a semantic value | 1 |
| W7-3 | The loop `break`s on the first non-executable proposal — no frontier queue, no backtracking, no depth/time budget (only `max_pages`) | `authoring/explore.py:297-304` | SEC | Frontier queue + depth/time budgets from config; degrade gracefully instead of stopping | 1 |
| W7-4 | The LLM's value is unproven either way. Our comparison (deterministic 15 pages/30 API vs. LLM 12/27) is one run against a link-rich, form-poor app — exactly where deterministic wins and the model has nothing to contribute | our runs, 2026-09-19/20 | GOV | Run the proposal's §19 experiment on three apps against a manual ground-truth inventory; let measured blockers define the model's job. Do not claim "AI discovery" until that number exists | 2 |
| W7-5 | Discovery emits routes, not requests — ZAP cannot attack parameters it never saw | `trace.json` shape | SEC | Adopt the proposal's authenticated *request corpus* (method, URL pattern, params, body shape, content type, auth context) as the discovery artifact | 2 |

### W8 — Evidence, story and demo

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W8-1 | **Our two strongest pieces of evidence exist only in run logs** — the no-LLM comparison and the live false-"fixed" incident. Neither is in the repository, so the docs undersell the work | reviewer's finding, confirmed | GOV | Commit `docs/evidence/`: both SARIF files, the GitHub alert states before/after, the labeled records, the three explore traces and their runner gates | 0.5 |
| W8-2 | The project's own definition of done — fix → re-scan → `resolved` (requirements §9 step 4) — has never been demonstrated | — | GOV | Execute it on Juice Shop, capture it, then the `not_scanned` counter-case | 1 |
| W8-3 | Zero screenshots or recordings in the repo; the 22–26 minute live runbook is a rehearsal risk | — | GOV | A 3-minute recorded highlight reel plus Security-tab screenshots | 1 |
| W8-4 | No build-vs-buy position; competitors are never named in any document | — | GOV | One page: what this layer adds on top of ZAP/Burp/StackHawk, and what it deliberately will not do | 0.5 |
| W8-5 | Demo is organised around architecture, not around a user | review §9 | GOV | Re-cut around a finding's life: onboard → refusal → one finding end-to-end → fix/re-scan → unattended → the AI boundary last | 1 |

### W9 — Repository hygiene and convergence

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W9-1 | **Two repositories have diverged.** Upstream (`Nationwide/ssd-dast-tool-poc`) has 228 tests, `authoring/llm_backend.py` (Copilot backend), the demo deck and helper scripts; this checkout has 213 tests and none of them. The runbook here now documents `LLM_PROVIDER`/`COPILOT_GITHUB_TOKEN` and four helper scripts that do not exist here | verified | all | **This repo is canonical (decision 1).** Port upstream's additions in — Copilot backend behind `LLM_PROVIDER`, demo deck, helper scripts — reconcile the README test count, and make the runbook match this checkout. Enterprise packaging consumes this repo rather than forking it | 1 |
| W9-2 | Stray files upstream: a 17 KB file named `-`, `runner/capture_zap_fixture copy.sh`, an empty committed `nw-ca-all.pem` referenced by two runbooks | review §4 (upstream only) | OPS | Delete; source the CA bundle at runtime | 0.2 |
| W9-3 | No linter, no pre-commit, no CI running the suite | — | OPS | ruff + pre-commit + the test suite in the same workflow as W3-1 | 0.5 |
| W9-4 | `payload_family` is a pure function of `rule_id`, so the "four-dimension" fingerprint has three effective dimensions | `detections/fingerprint.py:42-44` | SEC | Documentation fix, not a code change — restate the formula honestly in `contracts/README.md`. Changing it is a contract change and is not proposed | 0.2 |

---

## 4. Sequencing

Five phases. Phase 0 is the primary goal and everything else is sequenced behind it; nothing in
Phase 0 or 1 requires a real target application, so both start immediately and run in parallel
with target selection.

### Phase 0 — Onboard a second application (≈ 11 sessions) — ✅ **COMPLETE 2026-09-27**
**W2-1 … W2-13**: move every app-specific input to `app.yaml` (selectors, bootstrap, token check,
API patterns, environment class, deny-list, banner selectors), generalise the two contracts that
assume Juice Shop's login shape (W2-10 step list, W2-11 pluggable auth proof), default to a
provisioned identity (W2-12), ship the `dast` CLI (W2-6), consume the generated policy (W2-4),
copy `authoring/` into the image (W2-8), and lock it all down with the guard test (W2-13).

**Acceptance target: DVWA.** Chosen because it runs locally in a container with no approvals and
breaks three of our assumptions at once — a **username** field rather than email, a **PHPSESSID
session cookie** rather than a JS token, and **no self-registration**. Its one-time database
setup also exercises the "app needs a bootstrap step we don't control" case. If DVWA onboards
config-only, the first internal Nationwide application becomes a network-and-identity problem
rather than a code problem.

*Exit (all four, or the phase is not done):*
1. `security/dast/dvwa/` contains **configuration only** — no `.py`.
2. `git diff --stat authoring/ runner/` is **empty** for the onboarding commit, and W2-13's guard
   test enforces it from then on.
3. A CI job runs `dast onboard → author → scan → report` against a DVWA container end to end.
4. The elapsed wall-clock time for a first-time operator is measured and published.

#### What happened (all items delivered; commits `622650c`, `e9c41c5`, `1a02492`, `27f4d8f`, `dda5427`, `2e0c082`)

| Criterion | Result |
|---|---|
| App directory is configuration only | ✅ `security/dast/dvwa/app.yaml`, `security/dast/webgoat/app.yaml` — one file each, no `.py` |
| Zero diff to `authoring/` and `runner/` | ⚠️ **not on DVWA** (see below) · ✅ **yes on WebGoat**, app #3 |
| End-to-end through the CLI | ✅ `dast onboard → author → scan → report` on both, gates passed |
| Onboarding time measured and published | ✅ **DVWA 4m20s, WebGoat 4m32s** (config + four commands; excludes environment prep) |
| CI job | ❌ **deferred to Phase 2 (W3-1)** — no workflow exists yet, so the loop is proven by hand, not on a schedule |

**The honest reading.** DVWA was *not* a zero-code onboarding: it required finishing the live
half of W2-11 (`wait_for_auth`, step-driven login in `record`/`seed`, a configured proof in
`prove_auth_live`). The claim was only tested by **app #3**. WebGoat — Spring Boot, JSESSIONID
cookie, `selector` proof, `/service/` API pattern — onboarded in 4m32s with `git status` showing
exactly one new path and no diff to any module. Three applications now cover three different
stacks, three login shapes, three session mechanics and all three proof modes.

**What the exercise cost, and what it bought.** Each onboarding found real defects that reading
the code had not: DVWA exposed the unfinished live proof path; WebGoat exposed that a
`selector` proof required a *visible* element (fixed: presence is the proof) and that **ZAP
hijacks any target on its own port** (W4-7 — silent, and likely in the pilot, since internal
Java apps commonly listen on 8080). Onboarding real applications is the cheapest defect-finding
activity available to this project.

**Not claimed:** environment prep is excluded from both timings. DVWA needed its database
created, WebGoat a registered account (its passwords cap at 10 characters). That is the same
category of work as standing up the container, but an operator's clock includes it, so quote
"config-only onboarding under 5 minutes; environment prep varies."

See `docs/onboarding_a_new_application.md` for the procedure these numbers describe.

### Phase 1 — Make a finding worth receiving (≈ 5 sessions)
**W1-1 … W1-4** (rich records, SARIF `help`, request/response excerpt, resolvable evidence) +
**W5-4** (clean auth abort) + **W7-1** (D11 supersession) + **W8-1** (commit the evidence we
already have).

*Status 2026-09-30:* W1-1 and W1-2 ✅ (`a7b8fec`), W7-1 ✅ (D11, `f0a32c9`). Remaining: W1-3
(request/response pair), W1-4 (resolvable evidence), W5-4, W8-1.

*Exit:* a developer on either pilot app can read one alert and know what is wrong, where, why it
matters and how to fix it, without asking the tool team.

### Phase 2 — Make it run itself (≈ 5 sessions)
**W3-1 … W3-5** (workflow, gate split, structured logs, durable state, token upload) + **W9-1,
W9-3** (converge the repos, lint/CI) + **W1-6** (scan report) + **W8-2** (fix-and-rescan evidence).

*Exit:* a scheduled scan runs with nobody watching, its alerts land in the target repo, its
evidence is retained, and its log answers "what did you touch, and what did you refuse?".

### Phase 3 — Make it safe for someone else's environment (≈ 8 sessions)
**W4-1 … W4-6** (ZAP context, traverse-vs-attack, scheme/host/port, throttle + kill switch, API
key, registry-verified environment class) + **W5-1 … W5-3** (post-scan liveness, ZAP session
management, secret store).

*Exit:* a deliberate misconfiguration suite passes — wrong environment class, off-scope host,
off-scope port, IdP host, excluded destructive endpoint — each refused, logged and provable after
the fact.

### Phase 4 — Make the comparison fair (≈ 7 sessions + decisions)
**W6-1 … W6-7** (postures settled and written down, coverage denominator, scorecard agreed) +
**W7-2 … W7-5** (deterministic-first, frontier, request corpus, the three-app experiment) +
**W8-3 … W8-5** (recording, build-vs-buy, re-cut demo).

*Exit:* the benchmark run completes with every posture exclusion disclosed, and the LLM's
measured increment is a number rather than a claim.

**Dependency notes.** Phase 0 comes first because every later item lands as a field in
`app.yaml` once it exists, and as another flag to remember if it does not. W1 must land before any
real app receives findings (W6-2's longer scans otherwise just produce more unactionable noise).
W4 and W5 gate the first internal scan. W6-4 (coverage denominator) and W7-4 (the experiment) are
the only items that produce the numbers the funding decision needs, and both depend on Phases 0–1
being finished.

> **These phases are ordered by dependency, not by severity.** The most serious defects in this
> register are not in Phase 1: **W4-1** (ZAP's own spider and active scan are unbounded — our two
> documented safety layers cover browser-originated requests only) and **W5-1/W5-2** (a scan can
> silently degrade to unauthenticated and still report `authenticated: true`). They sit in Phase 3
> for two reasons only: neither can bite until we point the scanner at a real shared environment,
> and that is gated on target selection (readiness Gate 0), which is a human decision with the
> longest lead time in the programme. Phases 0–1 are what we do *while* that decision is being
> made, and they make every later fix cheaper — config-driven onboarding means each Phase 3 and 4
> control lands as a field in `app.yaml` rather than as another flag to remember.
>
> **If a target application is selected sooner than expected, reorder: pull W4 and W5 ahead of
> Phase 1**, keeping Phase 0's config loader (W2-1/W2-5/W2-10/W2-11) in front of them, since the
> new safety controls should be configured from `app.yaml` rather than retrofitted into it. No
> internal scan should run before Phase 3's misconfiguration suite passes, regardless of how much
> of Phases 0–1 is finished.

---

## 5. Decisions required (not engineering)

| # | Decision | Why it blocks | Recommendation |
|---|---|---|---|
| 1 | ~~**Canonical repository**~~ — **settled 2026-09-27: this repository** | We are maintaining two diverging copies; the runbook here already documents code that only exists upstream | Work proceeds here. This inverts W9-1: port *upstream's* additions **into** this repo (the `llm_backend.py` Copilot backend, the demo deck, the four helper scripts the runbook already references), and reconcile the 213-vs-228 test count. The enterprise Nationwide packaging is a consumer of this repo, not a fork of it |
| 2 | **Supersede D9** (deterministic-first vs. LLM-primary) | Three documents currently disagree, in a repo whose credibility rests on documentation discipline | Adopt D11 as in W7-1; keep R1 (no LLM in the scan loop) explicit and unchanged |
| 3 | **First *internal* target application** | Sizes Phases 3–4; longest lead time. (The Phase 0 acceptance target is settled: **DVWA**, local, no approvals) | An app with real SSO — it is the capability actually under test — accepting a longer identity gate |
| 4 | **Build vs. buy underneath** | Changes what W2, W4 and W6 are worth building | Decide at this gate; the differentiated value (governed authoring, honest lifecycle) survives on top of a commercial scanner |
| 5 | **What is parity, and who declares it** | Without a threshold agreed beforehand, the comparison produces a table nobody can act on | Agree must-win vs. acceptable-to-lose criteria before the first scan (W6-7) |
| 6 | **OAST and authorization testing in or out** | Both are capability projects, not settings | Explicitly out for the pilot, disclosed on the scorecard |
| 7 | **Who runs scans** — central service or app-team self-service | Decides whether multi-tenancy/RBAC is needed now | Central service for the pilot |

---

## 6. Explicitly not doing (and why)

- **Changing the fingerprint formula** (KI1 id-collapsing, W9-4). It is a frozen contract; changing
  it invalidates lifecycle history. Document the limitation; revisit only with a version bump.
- **Rebuilding as the proposal's 12-component platform.** That is a funded product build, not the
  next phase of a prototype. This plan borrows its principles (deterministic-first, request corpus,
  observed coverage, controlled mutation) without committing to its org chart.
- **Multi-app scale-out** (queue, scheduler, RBAC, tenancy). Not before app #3, and only after the
  build-vs-buy decision.
- **GraphQL and WebSocket support.** State as a non-goal for the pilot unless the chosen target
  needs it.

---

## 7. How we will know this worked

Measured 2026-09-27 unless stated. "Start" is where this plan was written.

| Measure | Start | **Now** | Target |
|---|---|---|---|
| Apps onboarded config-only | 0 | **2** (DVWA, WebGoat — WebGoat with zero code diff) | ✅ met |
| Time to onboard a new app | Unmeasured; required editing Python | **4m32s** (WebGoat; DVWA 4m20s), excluding environment prep | ✅ well under the 1-hour target |
| Files to edit to onboard | 2 Python modules + 2 JSON files | **1** (`app.yaml`) | ✅ met |
| Commands to a report from scratch | ~12, across two terminals | **4** (`onboard`/`author`/`scan`/`report`) | ✅ met |
| Login shapes supported | email + password only | **3**: email, username, and arbitrary step lists (`fill`/`click`/`press`/`wait_for`) | ✅ met |
| Proof-of-authentication modes | JS token only | **3**: `js`, `route` (cookie sessions), `selector` — all three exercised live | ✅ met |
| Generated artifacts the runner consumes | 2 of 7 | **4 of 7** (`flow.py`, `scope.json`, `zap-policy.yaml`, and the scope's budgets) | `auth.json`, `manifest.json`, `lock` remain informational |
| Scan posture | hard-coded constants | **per-app config**, resolved policy pinned into `coverage.json` | ✅ met |
| Tests | 213 | **559** (2026-09-30) | grows with the register |
| Scans run with nobody watching | 0 | **0** | ≥ 2 consecutive scheduled runs (W3-1, Phase 2) |
| A developer can act on a finding unaided | No | **Mostly** (2026-09-30) — verified on GitHub alert #1329: parameter, payload, evidence, confidence, the fix and references. Not yet reproducible: no request/response pair | Phase 1 remainder (W1-3, W1-4) |
| Coverage expressed as a percentage | No denominator | **No denominator** | % of declared routes (W6-4) |
| Measured LLM increment over deterministic | One Juice Shop run, inconclusive | **Still one run** | A number from three applications (W7-4) |
| Posture exclusions disclosed on the scorecard | Not agreed | **Two recorded with evidence**: DOM-XSS 40026 (OOM-killed the daemon), write paths unexercised | All of SP-1…SP-7, agreed before the first internal scan |

**One number worth quoting on its own.** On DVWA, moving scan posture into configuration and
widening the recorded surface by four parameterised GETs took the same scan from **0
high-severity findings to 5** (reflected XSS ×3, MySQL injection ×2) with no code change. The
missing findings were never an engine problem: ZAP had only ever seen `/vulnerabilities/sqli/`
without parameters, so there was nothing to inject into — the readiness plan's SP-4 point,
demonstrated rather than argued.
