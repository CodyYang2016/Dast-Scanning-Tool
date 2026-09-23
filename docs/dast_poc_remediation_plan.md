# DAST PoC — remediation plan: make it configurable, then make it complete

The actionable plan derived from the three feedback documents (`dast_poc_review.md`,
`dast_first_internal_app_readiness.md`, `Authenticated-Application-Discovery-DAST-Design-Proposal.md`)
plus what we found running the pipeline ourselves.

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
| App developer (DEV) | A GitHub alert with a rule id and a URL path, no remediation text | Not served |
| DevOps (OPS) | Nothing — no workflow, no usable exit-code contract, no structured logs | Not served |
| Governance (GOV) | A hand-typed `environment_class` string and logs from one module | Not served |

Onboarding a second application currently means editing `authoring/record.py` and
`authoring/generate.py`. That single fact caps adoption, invalidates the onboarding-cost question
every reviewer asks, and is the reason the demo needs a rehearsal.

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
  selectors: {email: "#email", password: "#password", submit: "#loginButton"}
  token_check: "window.localStorage.getItem('token')"
  bootstrap:  {method: POST, path: /api/Users/, body: register.json}   # optional, app-specific
  credentials: {email_env: AUTH_EMAIL, password_env: AUTH_PASSWORD}
  storage_state: secret://dast/juice-shop/storageState     # or .secrets/… in local dev

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
| W1-1 | ZAP's remediation content is discarded at normalization. Verified on our fixture: `description` 38/38, `confidence` 38/38, `solution` 32/38, `reference` 27/38, `evidence` 26/38 — all dropped | `detections/normalizer.py`; `contracts/detection.schema.json` has 11 properties, `additionalProperties: false` | DEV | Extend the detection contract with `description`, `solution`, `confidence`, `reference`, `evidence`; carry them through `normalize()`. Bump the contract version; fingerprint inputs unchanged so no lifecycle churn | 1 |
| W1-2 | SARIF carries no remediation, so a developer receives a rule id, a severity and a path | `detections/sarif_export.py` — no `help`, `fullDescription`, `helpUri` | DEV | Map the new fields to SARIF `help.markdown`, `fullDescription`, `helpUri`; keep `partialFingerprints` untouched | 0.5 |
| W1-3 | No request/response pair in the finding, so nothing is reproducible | ZAP alerts carry only `messageId`; `/JSON/core/view/message/` is never called | DEV | Fetch the message for high/medium findings, redact it through `runner/redact.py`, attach an excerpt | 1 |
| W1-4 | Evidence path is unresolvable — SARIF references `evidence/<scan_id>/…` under a gitignored app dir; compose mounts only `./out` | `compose.yaml:46-47`; `runner/evidence.py` | DEV, GOV | Write evidence under `out/<app>/<scan_id>/`, retain as a CI artifact, reference by absolute URL | 1 |
| W1-5 | No triage model: no dedup, no suppression, no accepted-risk state; GitHub dismissals are invisible to the diff so a dismissed finding returns as `open` forever | `detections/lifecycle_diff.py` | SEC, DEV | Per-app suppression file keyed by fingerprint; reconcile GitHub alert state on upload | 1.5 |
| W1-6 | No scan summary — 1,400+ records with no grouping or ranking | — | SEC, GOV | One Markdown/HTML report per scan: counts by severity/rule/route, top 10, coverage, lifecycle deltas | 1 |

### W2 — Configuration and onboarding (unblocks SEC; the cornerstone)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W2-1 | Login flow is hard-coded to Juice Shop: registration call, selectors, token check, post-login route | `authoring/record.py:98-111`; `authoring/generate.py:32,63-65` | SEC | Read all of it from `app.yaml` `auth:`; keep the current values as the Juice Shop config | 2 |
| W2-2 | `emit_scope()` hard-codes `environment_class: "dev"` and the deny-list | `authoring/generate.py:49,52` | SEC, GOV | Source from `app.yaml`; fail loudly if absent rather than defaulting to `dev` | 0.5 |
| W2-3 | API detection is a two-substring heuristic (`/rest/`, `/api/`), missing `/v1/`, `/graphql`, versioned hosts | `authoring/record.py:18`; same pattern in `explore.py` | SEC | `api.patterns` from config; default to the current pair | 0.5 |
| W2-4 | `zap-policy.yaml`, `auth.json`, `manifest.json`, `lock` are generated but no code consumes them; `configure_policy()` takes only two time budgets and a hard-coded disabled scanner | `runner/scan.py:49-53` (`_SLOW_SCANNERS = "40026"`) | SEC, OPS | Load the policy in `configure_policy()` (attack strength, alert threshold, rule set); record the resolved policy into the coverage artifact; fail the scan if the enabled rule set differs from the pinned policy | 1.5 |
| W2-5 | Four inputs, four formats, no single place to look | — | SEC | `app.yaml` loader + schema + `dast onboard` skeleton generator | 1 |
| W2-6 | Every capability is a bare module invocation with 6–8 flags | the runbook exists because of this | SEC, OPS | `dast` console script: `onboard`/`author`/`scan`/`report`. Modules keep their current entry points so tests are untouched | 1 |
| W2-7 | **Proof:** onboarding a second app is unmeasured | — | SEC, GOV | Onboard DVWA (or an internal dev app) with config only, no diff to `authoring/`/`runner/`; publish the elapsed time | 1 |
| W2-8 | `Containerfile` does not copy `authoring/`, so the authoring half has no deployable form and `runner.main --seed` fails in-container | `Containerfile` | OPS | Copy `authoring/` into the image; add `dast` as the entry point | 0.5 |

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
| W4-5 | Destructive/integration endpoints are not excluded per app — an active scan can trigger mail, SMS, payments or partner test systems | — | GOV, App team | Per-app exclusion list in `app.yaml`, enforced in the ZAP context *and* the action policy | 0.5 |
| W4-6 | Preflight trusts a hand-typed `environment_class` — against real hostnames one typo is the whole safety story | `runner/preflight.py` | GOV | Verify against the app registry where available; deny prod hostname patterns outright | 1 |

### W5 — Session integrity (the most likely cause of a bad pilot result)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W5-1 | Mid-scan session expiry is undetected: liveness is proven once, before a multi-minute scan. The scan can silently degrade to unauthenticated while still reporting `authenticated: true` | `runner/replay.py::prove_auth_live` called once | SEC, GOV | Post-scan liveness re-check; mark the scan **degraded**; a degraded scan may never produce `resolved` labels | 1 |
| W5-2 | No ZAP session-management or re-authentication rules, no anti-CSRF token handling. A write-enabled scan logs the scanner out and then attacks a login page (readiness SP-5) | — | SEC | Configure ZAP session management + re-auth in the context created by W4-1 | 1.5 |
| W5-3 | `storageState` is a live credential sitting in a working tree with no TTL | `.secrets/storageState.json` | GOV | Secret store reference (`secret://…`) with TTL and a documented re-seed cadence | 1 |
| W5-4 | Authentication failure surfaces as a raw Playwright traceback, not a clean abort | `runner/main.py` catches only `PreflightError`, `ScanScopeError`, `ScopeViolation` | SEC | Catch auth failure and exit with `RUNNER ABORT: authentication failed` | 0.2 |

### W6 — Scan posture and benchmark honesty (settle *before* the first internal scan)

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W6-1 | Write paths are default-denied, so injection/authz/business-logic classes are never tested (SP-1) | `runner/action_policy.py` | SEC, GOV | Keep the guardrail; populate `safe_forms` per app; agree data reset with the app team. Note write-enabled scans are not idempotent — budget the reset or the lifecycle diff gets noisy | 1 |
| W6-2 | 4-minute scan cap with no truncation signal — "no finding" is indistinguishable from "never reached" (SP-2) | `runner/scan.py:49` | SEC, GOV | Per-app budget; record truncation explicitly in the coverage artifact | 0.5 |
| W6-3 | DOM-XSS rule 40026 disabled by default — the class that matters most for SPAs (SP-3) | `runner/scan.py:26` | SEC | Re-enable with browser config and a longer budget, or disclose on the scorecard | 1 |
| W6-4 | Coverage has no denominator: "12 pages" is meaningless without a route inventory (SP-4) | `runner/coverage.py` | GOV, SEC | OpenAPI import where a spec exists; report coverage as a percentage of declared routes; treat crawl breadth as a measured output | 1.5 |
| W6-5 | OAST (blind SSRF/XSS/injection) absent by construction (SP-6) | — | GOV | Decide in or out. Out ⇒ record as a disclosed exclusion, not a detection deficit | decision |
| W6-6 | Authorization testing (IDOR/BOLA) impossible with one identity (SP-7) | — | GOV | Fund multi-identity scanning as a distinct capability, or exclude explicitly | decision |
| W6-7 | The evaluation could reduce to a finding count, where the PoC *is* ZAP and the outcome is predetermined | readiness scorecard | GOV | Agree the weighted scorecard and must-win criteria **before** the first scan; report unique findings, FP rate from a ~30-finding manual sample, and every posture exclusion | 0.5 |

### W7 — Discovery depth and the D9 question

| ID | Issue | Evidence | Persona | Proposed fix | Size |
|---|---|---|---|---|---|
| W7-1 | **D9 contradiction.** `decisions_and_known_issues.md` records "LLM-primary with deterministic fallback" as ADOPTED; the discovery proposal argues deterministic-first with LLM escalation, also as adopted text | both docs | all | Write a superseding decision (**D11**) — do not leave three documents disagreeing. Recommended content: deterministic-primary, LLM invoked only at a measured blocker, applies to authoring only (the scan loop keeps R1: no LLM, ever) | 0.5 |
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
| W9-1 | **Two repositories have diverged.** Upstream (`Nationwide/ssd-dast-tool-poc`) has 228 tests, `authoring/llm_backend.py` (Copilot backend), the demo deck and helper scripts; this checkout has 213 tests and none of them. The runbook here now documents `LLM_PROVIDER`/`COPILOT_GITHUB_TOKEN` and four helper scripts that do not exist here | verified | all | Declare one canonical repo, port the missing commits both ways (our coverage-aware export + explore hardening upstream; their backend + scripts here), and reconcile the test count in the README | 1 |
| W9-2 | Stray files upstream: a 17 KB file named `-`, `runner/capture_zap_fixture copy.sh`, an empty committed `nw-ca-all.pem` referenced by two runbooks | review §4 (upstream only) | OPS | Delete; source the CA bundle at runtime | 0.2 |
| W9-3 | No linter, no pre-commit, no CI running the suite | — | OPS | ruff + pre-commit + the test suite in the same workflow as W3-1 | 0.5 |
| W9-4 | `payload_family` is a pure function of `rule_id`, so the "four-dimension" fingerprint has three effective dimensions | `detections/fingerprint.py:42-44` | SEC | Documentation fix, not a code change — restate the formula honestly in `contracts/README.md`. Changing it is a contract change and is not proposed | 0.2 |

---

## 4. Sequencing

Four phases. Phase 1 exists to make Phases 2–4 cheap; nothing in it requires a target application,
so it starts immediately and in parallel with target selection.

### Phase 1 — Make it configurable and actionable (≈ 9 sessions)
**W2-1 … W2-8** (config contract, `dast` CLI, policy consumption, container) + **W1-1 … W1-4**
(rich findings, SARIF help, evidence) + **W5-4** (clean auth abort) + **W7-1** (D11 supersession)
+ **W8-1** (commit the evidence).

*Exit:* a new app is onboarded with one YAML file and four commands, its findings tell a developer
what to fix, and the onboarding cost is published in hours.

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

**Dependency notes.** W1 must land before any real app receives findings (W6-2's longer scans
otherwise just produce more unactionable noise). W4 and W5 gate the first internal scan. W6-4
(coverage denominator) and W7-4 (the experiment) are the only items that produce the numbers the
funding decision needs, and both depend on Phase 1 being finished.

> **These phases are ordered by dependency, not by severity.** The most serious defects in this
> register are not in Phase 1: **W4-1** (ZAP's own spider and active scan are unbounded — our two
> documented safety layers cover browser-originated requests only) and **W5-1/W5-2** (a scan can
> silently degrade to unauthenticated and still report `authenticated: true`). They sit in Phase 3
> for two reasons only: neither can bite until we point the scanner at a real shared environment,
> and that is gated on target selection (readiness Gate 0), which is a human decision with the
> longest lead time in the programme. Phase 1 is what we do *while* that decision is being made,
> and it makes every later fix cheaper — config-driven onboarding means each Phase 3 and 4 control
> lands as a field in `app.yaml` rather than as another flag to remember.
>
> **If a target application is selected sooner than expected, reorder: pull W4 and W5 ahead of the
> rest of Phase 1**, keeping only W2-1/W2-5 (the config loader) in front of them, since the new
> safety controls should be configured from `app.yaml` rather than retrofitted into it. No
> internal scan should run before Phase 3's misconfiguration suite passes, regardless of how much
> of Phase 1 is finished.

---

## 5. Decisions required (not engineering)

| # | Decision | Why it blocks | Recommendation |
|---|---|---|---|
| 1 | **Canonical repository** | We are maintaining two diverging copies; the runbook here already documents code that only exists upstream | Upstream `Nationwide/ssd-dast-tool-poc`; port our commits there this week |
| 2 | **Supersede D9** (deterministic-first vs. LLM-primary) | Three documents currently disagree, in a repo whose credibility rests on documentation discipline | Adopt D11 as in W7-1; keep R1 (no LLM in the scan loop) explicit and unchanged |
| 3 | **First target application** | Sizes everything; longest lead time | An app with real SSO — it is the capability actually under test — accepting a longer identity gate |
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

| Measure | Today | Target at the next gate |
|---|---|---|
| Time to onboard a new app | Unmeasured; requires editing Python | < 1 hour, one YAML file, published number |
| Files to edit to onboard | 2 Python modules + 2 JSON files | 1 (`app.yaml`) |
| Commands to a report from scratch | ~12, across two terminals | 4 (`onboard`/`author`/`scan`/`report`) |
| Scans run with nobody watching | 0 | ≥ 2 consecutive scheduled runs |
| A developer can act on a finding unaided | No | Yes — description, solution, reproduction, evidence link |
| Coverage expressed as a percentage | No denominator | % of declared routes (OpenAPI) or of a ground-truth inventory |
| Measured LLM increment over deterministic | One Juice Shop run, inconclusive | A number from three applications |
| Posture exclusions disclosed on the scorecard | Not agreed | All of SP-1…SP-7, agreed before the scan |
