# DAST PoC review: product, architecture, implementation, and demo

An evidence-based funding review of NationwideDevin/ssd-dast-tool-poc at commit c3bac3b, covering requirements traceability, design-vs-code gaps, DAST maturity, UX, scan quality, and the demo story, with an addendum on the new discovery design proposal and the D9 architecture reversal.

## Verdict first

**This PoC is a credible, unusually well-engineered *safety and plumbing* prototype around OWASP ZAP + Playwright — and it is not yet a DAST product.** The parts that are genuinely differentiated (two-layer fail-closed scope enforcement, a deterministic LLM boundary, and a coverage-aware lifecycle diff that refuses to claim a fix it did not test) are real, in code, and under test. The parts a DAST buyer judges a product by — onboarding a second application, actionable findings, developer workflow, CI/CD, reporting, durable storage — are either absent or exist only as a one-app hard-coded path.

**Maturity:** Prototype — Late-stage; not MVP

**Readiness (1–10):** 4 — Safety 8 · product 2

**Storytelling (1–10):** 7 — Strong engineering story, weak user story

**Tests verified:** 228 pass — 0.32 s · all unit; README says 213

> **The funding question is not "does it work?" — it does, on Juice Shop.** It is "is the thing that was built the thing that is hard?" ZAP already scans; Playwright already authenticates. The defensible custom value here is *governed authoring + honest lifecycle*. Fund that thesis explicitly, or fund a commercial scanner and keep only the safety/lifecycle layer.

Evidence base: repository `NationwideDevin/ssd-dast-tool-poc`, re-synced from its upstream `Nationwide/ssd-dast-tool-poc` and re-read at commit `c3bac3b` ("adding review documents"); the code is unchanged since `7c16c01`, which this review read in full (all 15 Python modules, 21 test files, 18 docs, contracts, compose/Containerfile, demo scripts). Test suite executed locally. No live ZAP/Juice Shop run was performed in this review, so runtime numbers are the project's own measurements — either documented in the repository or, where marked, reported by the team from runs whose artifacts are not committed.

## Addendum at `c3bac3b` — the discovery proposal, D9, and two corrections

Two commits arrived after the original review. They change no code: `nw-ca-all.pem` is deleted (closing the empty-CA-bundle hygiene item), two of this review's own documents are committed as Markdown, and one substantive new document appears — `docs/Authenticated-Application-Discovery-DAST-Design-Proposal.md`. Every implementation finding below still stands against the code at `c3bac3b`.

### The proposal is the strongest document in the repository

It answers several criticisms in this review directly: deterministic exploration by default with the LLM demoted to an escalation path (§5.3), measured against a manual ground-truth inventory before any agent is built (§15 Phase 0, §19); an *authenticated request corpus* rather than a route list (§8), which is precisely the constraint that limits what ZAP can attack today; explicit ZAP context, scope and session-handling configuration (§7.6), which the current code never performs; observed coverage with a recorded stopping reason instead of coverage claims (§9); and controlled mutation as an approved action class with a cleanup plan (§10), which resolves the write-path decision sensibly.

### Three things to settle before it is presented

- **It is a platform, not the PoC's next phase.** Twelve components (§12) including an onboarding API/UI, a human-assistance service and worker pools. That is a funded product build, and leadership should be asked for it in those terms rather than as "Phase 3/4" of a prototype.
- **The gaps that lose a tool comparison are deferred or absent.** Authorization/BOLA testing sits in Phase 4; out-of-band (OAST) detection of blind SSRF, blind XSS and blind injection is not mentioned anywhere in the proposal; and there is still no build-vs-buy position against the commercial tools under evaluation.
- **Actionable findings remain late.** The cheapest, highest-value fix in this review appears only as a "findings normalizer" component (§12) and Phase 4 triage assistance. In a deliberately evidence-led, deterministic-first plan it belongs in Phase 1, alongside ZAP ingestion.

> **D9 should be superseded, not contradicted.** `docs/decisions_and_known_issues.md` records D9 as "generate is LLM-primary with a deterministic fallback", while the proposal argues deterministic-first with LLM escalation. Both are ADOPTED text in the same repository. Record a new superseding decision rather than leaving three documents disagreeing — that contradiction is currently the largest unresolved item in the document set.
>
> On the merits the reversal is right: deterministic-first is idempotent, auditable, cheaper, and removes the nondeterminism objection at the point security engineering cares about. It also reframes the story from "AI discovery", which invites the one question the PoC cannot win, to "deterministic discovery with governed AI assist, and here is the measured increment the assist adds" — a stronger claim, not a weaker one.
>
> **But the evidence does not yet settle the LLM's value.** The team's live comparison (deterministic proposer 15 pages / 30 API calls / 1,581 detections vs. Claude 12 / 27 / 1,490) is reported from runs whose artifacts are not in the repository. Detection count is also the wrong yardstick: most of that volume is passive rules re-firing per page, so a 6% delta is noise. The informative figure is the surface reached (15/30 vs. 12/27) — and it comes from one run against Juice Shop, a link-rich, form-poor application needing no business semantics, which is exactly where deterministic crawling should win and an LLM has nothing to contribute. It shows the LLM is not earning its cost *here*; the three-application experiment in §19 is what decides whether it earns it on an app with a policy-number search box.

### Corrections to the original review

- **The GitHub upload has now been run live, twice** (team-reported, 2026-09; artifacts not committed). The original review described it as usually narrated rather than executed, following `docs/dast_poc_phase2_demo_runbook.md` line 433. That is now out of date, and the correction strengthens the case: the second live upload is what closed 13 findings as "fixed" that had not been fixed, which makes the coverage-aware export a *reproduced defect and remedy* rather than an anecdote. It is the single strongest item in the proposed demo, and it should lead it.
- **The runbook still contradicts this** — line 96 instructs the operator to narrate the command when the GHAS and push preconditions are not met. Update it, and commit the evidence: both SARIF files and the GitHub alert states before and after.

A pattern worth fixing: the project's two strongest pieces of evidence — the no-LLM comparison and the live false-"fixed" incident — exist only in run logs. Neither is in the repository at `c3bac3b`. The documentation currently undersells the work, because the evidence for its two biggest claims is not written down.

## 1. The vision, as the repository actually states it

- **Problem:** Authenticated, non-prod web apps are effectively untested by DAST because a scanner cannot log in, and the file that tells it how to log in and what to click (`flow.py`) is hand-typed per app — "that walk is the ceiling on how much of the app ever gets tested" (`docs/dast_poc_phase2_demo_deck.md`, Act 1).
- **Thesis:** Use an LLM at *authoring time only* to produce scan configuration, keep every scan deterministic, and publish findings into a surface the org already consumes (GitHub Security tab) with fingerprint-based lifecycle tracking (`README.md` lines 1–18).
- **Users named in the docs:** An **operator** (the demo persona), and by implication the security engineer who owns scope files. Application developers and DevOps engineers appear only as SARIF consumers; neither has a named workflow, doc, or artifact anywhere in the repo.
- **Intended workflow:** `record` (or `seed` + `explore`) → `generate` → `validate` → commit bundle → `runner.main` → `lifecycle_diff` → `sarif_export` → `github_upload`.
- **Hard boundary:** Never production, never unbounded: `runner/preflight.py` rejects missing/prod `environment_class` or an empty allow-list before any traffic; `runner/scope_guard.py` blocks per-request at the browser boundary.

The documentation set is exceptional for a PoC: a 424-line requirements doc with numbered acceptance criteria, a 408-line architecture overview, per-component frozen designs, a decisions/known-issues log (D1–D10, KI1–KI4), and a 969-line field-verified demo runbook. The team documents its own gaps honestly — including in the demo script's Q&A ("Not yet — `zap-policy.yaml` … not wired into the runner. Tracked gap, not a demo simplification", `docs/dast_poc_phase2_demo_script.md` line 123). That candor is a genuine asset and should be preserved, not polished away.

## 2. Storytelling assessment — 7/10

The Phase 2 deck tells a tight *engineering* story: problem (hand-typed flow), architecture (LLM confined to authoring), safety argument (model emits data, code decides), proof with numbers, and one hard-won lesson (GitHub wrongly closed 13 findings; coverage-aware labeling fixed it). The Act 5 false-closure story is the single best moment in the whole demo — it is the only part that proves product judgment rather than plumbing.

### What works

- **Alignment with requirements is high.** The four README proof points map 1:1 onto the requirements' definition of done (`docs/dast_poc_requirements.md` §9).
- **The safety argument is constructive, not promissory** — it names the mechanism (`journey.schema.json` validation, `render_flow`, `ast.parse`, action policy, scope guard) for each guarantee.
- **Quantified coverage win:** record 3 pages / 22 API calls vs. explore 12 pages / 27 API calls; 1,214 vs. 1,490 detections (deck Act 4, project-measured 2026-09-19).

### What weakens it

- **The protagonist is the pipeline, not a person.** No developer ever appears: nobody receives a finding, understands it, fixes it, or sees it close. Requirements §9 step 4 (fix → re-scan → resolved) is the emotional payoff and it is deferred to "Phase 3" in the deck's closing slide.
- **"1,490 detections" is told as a win.** To a security leader that is alert volume, not coverage; with no dedup, ranking, or exploitability signal it reads as a future triage bill. The deck never shows one finding end-to-end.
- **The headline benefit is admittedly not exercised.** The team's own design doc says so: Juice Shop's login is trivially automatable, so "the headline benefit — seeding a hard SSO/MFA/CAPTCHA login — *will not be exercised by Juice Shop*" (`docs/seeded_session_exploration_design.md`, open question 6). The demo therefore proves breadth, not the enterprise blocker.
- **No differentiation slide.** ZAP, Burp Enterprise, StackHawk and Invicti are never mentioned in any document. A funding audience will ask "why not buy?" and the deck has no answer prepared.
- **Demo artifacts are text only.** There are no screenshots, images, or recordings in the repository — every "demo artifact" is Markdown plus Mermaid. The GitHub upload, the most stakeholder-legible moment, is still written as a "one-way door … so today I'm showing" narration in `docs/dast_poc_phase2_demo_runbook.md` (lines 96 and 433) — although the team has since run it live twice, unrecorded in the repository. See the addendum above.
- **Operator burden leaks into the story.** A 969-line runbook, two terminals, platform-specific cards, a warm-up throwaway recording, and a "if something breaks live — don't debug on stage" section (§9) signal fragility to exactly the audience being asked for money.

### Questions stakeholders will ask (and the honest answers today)

| Question | Honest answer from the code |
| --- | --- |
| How long to onboard app #2? | Today it requires code edits, not config: `authoring/record.py::crawl()` hard-codes Juice Shop's registration call, `#email`/`#password`/`#loginButton` selectors and `/#/basket`; `authoring/generate.py::journey_from_trace()` hard-codes the same login block and a `localStorage.getItem('token')` check. |
| Where does a developer see this? | GitHub Security tab only, with no remediation text, no code location and no PR annotation (see §4 reporting). |
| What runs this nightly? | Nothing. There is no `.github/workflows/` directory in the repo; upload is a manual `gh` CLI call. |
| What is the false-positive rate? | Unmeasured. No confidence field survives normalization and there is no suppression/triage mechanism. |
| Who owns the scope file? | Undefined — no registry, approval, or governance model (explicitly out of PoC scope, §3.2). |

## 3. Requirements traceability matrix

Statuses use the requested vocabulary. "Implementation" was assessed by reading the module named in each row; "demo" by the Phase 2 runbook/deck/script. Requirement IDs are from `docs/dast_poc_requirements.md` §6–§8.

| Requirement | Design coverage | Implementation coverage | Demo coverage | Status |
| --- | --- | --- | --- | --- |
| FR-R1 crawl + trace/index | `authoring_clis_design.md` | `record.py::crawl/build_trace`; walk is Juice-Shop-specific, not a crawler | Part D, headed browser | Partially implemented |
| FR-R2 authenticated flow recording | Yes | Yes, but the login sequence is hard-coded, not discovered | Part D | Partially implemented |
| FR-R3 forms + API capture | Yes | `record.py` captures XHR matching `/rest/` or `/api/` only | Shown in `trace.json` | Partially implemented |
| FR-G1 LLM → runnable flow | `D8`, deck Act 3 | `generate.py::plan_from_llm → render_flow`, `ast.parse` gate; template supports 3 verbs (goto/click/api_get) | Part E, live LLM | Fully implemented (narrow vocabulary) |
| FR-G2 scope.json emission | Yes | `emit_scope`; `environment_class` always `"dev"`, deny-list a hard-coded constant | Part E | Partially implemented |
| FR-G3 zap-policy / manifest / lock | Yes | Files emitted (`emit_zap_policy/manifest/lock`) but **no consumer exists**; `runner/scan.py::configure_policy` takes only a time budget and a hard-coded disabled scanner `40026` | Disclosed on stage as a gap | Designed but not implemented |
| FR-G4 idempotency | Yes | Deterministic path only; the LLM path is not idempotent by construction | Byte-diff of two `--no-llm` runs | Partially implemented |
| FR-V1 auth replay | Yes | `validate.py::_replay_auth` | Part F | Fully implemented |
| FR-V2 allow-list coverage | Yes | `check_allowlist`; checks only `base_url` host + absolute journey targets | Part F/6a fail-closed case | Fully implemented (host-scope caveat) |
| FR-V3 report + non-zero exit | Yes | `build_report`, exit 2 | Part F | Fully implemented |
| FR-S1 ZAP proxy replay | `runner_design.md` | `replay.py::replay/replay_seeded` | Part G | Fully implemented |
| FR-S2 bounded active scan | Yes | `scan.py`: accessUrl → spider → ascan → alerts; bound = wall-clock, not policy | Part G | Fully implemented (crude bounding) |
| FR-S3 refuse prod/invalid | Yes, test-first | `preflight.py`, case-insensitive prod denylist | Part C/6a | Fully implemented |
| FR-S4 block in-flight out-of-scope | `D2/D6` | `scope_guard.py` at `page.route`; covers **browser-originated** requests only — ZAP's own spider/active scan is not bounded by a ZAP context (no `/JSON/context/` call anywhere) | Part C | Partially implemented |
| FR-S5 <15 min | Yes | Default `--max-scan-min 4` | 2m39s / 2m54s measured | Fully implemented |
| FR-N1 normalized records | Yes | `normalizer.py`; drops ZAP `description`, `solution`, `reference`, `evidence`, `attack`, `confidence` — `detection.schema.json` is `additionalProperties: false` with no such fields | Part B fixture run | Partially implemented |
| FR-N2 stable fingerprint | Frozen in `contracts/README.md` | `fingerprint.py`; note `payload_family` is a pure function of `rule_id`, so the formula has 3 effective dimensions, not 4 | Part B, external `shasum` oracle | Fully implemented |
| FR-X1 SARIF 2.1.0 | `sarif_exporter_design.md` | `sarif_export.py`; valid, carries `partialFingerprints` and `security-severity` | Part B | Fully implemented |
| FR-X2 GitHub Security tab | `github_upload_design.md` | `github_upload.py` shells out to `gh api`; no token/API path, no automation | **Run live twice** (team-reported; the runbook still says narrate, and no artifacts are committed) | Partially implemented |
| FR-L1 state persistence | Yes | `lifecycle_diff.py::save_state`; single local JSON holding every record of the last scan per app | Part H | Fully implemented (not durable/governed) |
| FR-L2 open/new/resolved | Yes + R2 extension | `diff()` with coverage-aware `not_scanned` | Part H, single scan | Implemented; the requirements' fix-and-rescan acceptance run is not demoed |
| FR-E1 HAR + screenshot referenced from SARIF | Yes | Captured and redacted (`evidence.py`), referenced as a *relative path* in `result.attachments` to a gitignored dir that compose does not mount out | Mentioned | Partially implemented |
| NFR-1 reproducibility | Yes | `versions.lock`, images pinned by digest in `compose.yaml` | Referenced | Fully implemented |
| NFR-2 safety | Yes | Two fail-closed layers; strongest part of the codebase | Part C | Fully implemented |
| NFR-3 no hardcoded secrets | Yes | Generated flow reads env; but the committed `security/dast/juice-shop/flow.py` hard-codes `TEST_EMAIL`/`TEST_PASSWORD`, as does `record.py`'s default | Stated | Partially implemented |
| NFR-4 structured timestamped logs | Stated | Barely — `runner/scope_guard.py` is the only module that uses `logging`; every other stage prints unstructured text or JSON blobs to stdout/stderr with no timestamps, no scan correlation id, and no auth/scan-progress/export events | Not shown | Partially implemented |
| NFR-5 containerized single command | Yes | `compose.yaml` + `Containerfile` for the *runner* only; the image does not `COPY authoring/`, so Phase 2 authoring cannot run in the container and `runner.main --seed` would fail there on `from authoring.seed import load_seed` | Option A in README | Partially implemented |
| Coverage-aware lifecycle (R2) | `seeded_session_exploration_design.md` | `runner/coverage.py` + `diff(covered=)` + `not_scanned` in schema and SARIF filter | Act 5 of the deck | Demoed but not requirements-driven (a genuine addition beyond the spec) |
| LLM exploration loop (`explore`) | Design doc + D9/D10 | `authoring/explore.py`, `action_policy.py`, `redact.py` | Part D2 | Demoed but not requirements-driven |
| Copilot backend (Nationwide path) | Mentioned in docs only | `authoring/llm_backend.py`, CLI shell-out, file-based output capture | Runbook §1.7 | Implemented but not documented in the requirements |
| CI/CD integration | Not designed (out of §3.2 scope) | None | None | Missing |
| Developer remediation workflow | Not designed | None | None | Missing |

## 4. Design vs. implementation gap analysis

- **Intended:** A generated `zap-policy` selects scan intensity (FR-G3); the runner performs a bounded, policy-driven active scan.
- **Designed:** Bundle = `flow.py` + `scope.json` + `auth.json` + `zap-policy.yaml` + `manifest.json` + `lock`, all consumed by the runner (requirements §5 diagram).
- **Actual:** Only `flow.py` and `scope.json` are consumed. `configure_policy()` sets `setOptionMaxScanDurationInMins`, `setOptionMaxRuleDurationInMins`, and disables scanner `40026` from a module constant. Attack strength and alert threshold — the two knobs that actually govern DAST depth and noise — are never set.
- **Missing:** Policy loader; per-app intensity; rule include/exclude; reproducible policy in the lock file; no ZAP context/include-exclude regex; no AJAX spider for SPA crawling.
- **Risk:** Scan depth is an accident of a wall-clock budget, so two scans of the same app can exercise different rule sets — which directly undermines the lifecycle diff the project is most proud of. Coverage is captured, so this degrades to `not_scanned` rather than a false fix; the failure mode is silent coverage decay, not a wrong "fixed".
- **Next:** Wire `zap-policy.yaml` into `configure_policy()` (attack strength, alert threshold, explicit rule set), record the resolved policy into the scan's coverage artifact, and fail the scan if the enabled rule set differs from the bundle's pinned policy.

- **Intended:** D10: OpenAPI-first discovery, crawl fallback, recorded walk as a floor. KI4 acknowledges the surface is bounded by a human walk.
- **Actual:** Three mechanisms: a hard-coded 4-step Juice Shop walk (`record.py`), ZAP's traditional spider (`spider(recurse=true)`), and the LLM loop (`explore.py`) which only ever follows hrefs and XHR URLs already present in the observation. There is no OpenAPI import (`/JSON/openapi/` is never called), no AJAX spider, and no GraphQL introspection anywhere in the repo.
- **Missing:** Spec-driven discovery, depth/budget controls beyond `max_pages`, stateful form traversal (state-changing verbs are default-denied, so anything behind a POST is unreachable by design), unvisited-branch backtracking (the loop `break`s on the first non-executable action).
- **Risk:** Coverage is unmeasured against any denominator. "12 pages" is only meaningful against a known route inventory, which does not exist. For API-first or heavily POST-driven apps, effective coverage may be very low while the tool still reports success.
- **Next:** Implement the OpenAPI-first half of D10 (ZAP's OpenAPI add-on import is a small integration and would immediately generalize beyond SPAs); report coverage as a percentage of a declared route inventory; add ZAP's AJAX spider behind a flag.

- **Intended:** ZAP does detection; the runner's exit code is a gate.
- **Actual:** `runner/main.py::evaluate_gate()` passes only when `authenticated and scope_ok and has_high_or_medium`. A scan of a *clean* app fails the gate.
- **Risk:** This is a demo assertion masquerading as a CI gate. Reused as-is in a pipeline it inverts the intended semantics; any future CI integration must not consume this exit code.
- **Next:** Split into `--assert-findings` (demo/self-test) and a real policy gate (fail on new findings at or above a severity threshold, with a documented baseline).

- **Intended:** Detections visible in the Security tab "with severity, description, and a link to evidence" (FR-X2).
- **Actual:** A SARIF result carries `ruleId`, level, `security-severity`, the endpoint path as `artifactLocation.uri`, the fingerprint, and an `attachments` entry pointing at `evidence/<scan_id>/active-scan.har`. There is no `region`, no `helpUri`, no `fullDescription`, no `help` markdown, and no remediation text — because the normalizer never carries ZAP's `solution`/`description` fields and `detection.schema.json` forbids extra properties.
- **Missing:** Remediation guidance in the alert; a resolvable evidence URL (the referenced HAR is gitignored, and `compose.yaml` mounts only `./out`, so evidence written under `security/dast/juice-shop/evidence/` is discarded with the container — acknowledged in README "Known gaps"); durable scan history beyond one local `state.json` that stores every record of the last scan inline.
- **Risk:** A URL path in `artifactLocation.uri` is not a repository file, so alerts are unlikely to link to code or annotate pull requests (behavior of GitHub code scanning — inference, worth verifying in the pilot repo before the next demo). Combined with missing remediation text, a developer receiving one of these alerts has a rule name, a severity, and a path — and nothing to act on.
- **Next:** Extend the detection contract with `description`, `solution`, `confidence`, `request/response excerpt`; map them to SARIF `help`/`fullDescription`; publish evidence as a retained CI artifact and reference it by absolute URL.

- **Intended:** Explicitly out of PoC scope (§3.2 excludes schedulers, triggers, PR automation) — so this is a scope gap, not a broken promise.
- **Actual:** No `.github/workflows/`. Every stage is a hand-typed command; the loop from records to the Security tab is three separate manual invocations (`lifecycle_diff` → `sarif_export` → `github_upload`), and upload requires an interactively authenticated `gh` CLI in the operator's shell.
- **Risk:** This is the single largest credibility gap for an engineering-leadership audience: nothing about the current artifact suggests it can run unattended. It is also the cheapest gap to close.
- **Next:** One workflow file that runs the compose scan on a schedule, uploads SARIF with `github/codeql-action/upload-sarif` or the token API, and retains evidence as an artifact. This is hours of work and converts the whole story from "a demo" to "a service".

- **Intended:** Human seeds auth once (SSO/MFA/CAPTCHA); scans replay a seeded `storageState`; never scan unauthenticated.
- **Actual:** Well built: `prove_auth_live()` checks login redirect, status, and token presence before scanning, and `SessionDeadError` forces a fail-closed fallback. `seed.json` points at a gitignored `.secrets/storageState.json`.
- **Missing:** Mid-scan session expiry — the team's own open question 2 — is unresolved: liveness is proven once, before a multi-minute active scan during which the token can expire and silently downgrade the surface. No re-auth, no periodic check, no post-scan auth assertion. Also no secret store for the seeded session (a live credential sitting in a developer's working tree) and no session rotation.
- **Next:** Add a post-scan liveness re-check and mark a scan `degraded` (not `resolved`-eligible) if auth was lost; move `storageState` into a real secret store with TTL.

- **Intended:** Multi-application support is explicitly out of scope; streaming interfaces (D1) keep the pipeline memory-bounded.
- **Actual:** The detection pipeline honors the streaming convention (`normalize()` yields; `write_json_array` streams). But `iter_alerts()` still `json.load`s the whole report (documented swap point), `to_sarif()` materializes all results (accepted carve-out), and `lifecycle_diff` loads the entire previous scan's records into memory and re-serializes them into `state.json` — at ~1,500 records/scan/app that file is the de facto database.
- **Risk:** Fine for one pilot app; nothing here survives 50 apps or concurrent scans. There is no queue, no scheduler, no per-app isolation, no concurrency control on the single ZAP daemon.
- **Next:** Treat state as a real store (even SQLite or a blob per scan) before app #3, and define one scan = one ZAP instance.

- **Strengths:** Redaction happens before the LLM sees anything (`runner/redact.py`, recursive, adversarially tested) and before a HAR hits disk (`evidence.py::redact_har`). The action policy default-denies state-changing verbs and rejects embedded off-scope URLs (open-redirect style) — a genuinely thoughtful control. Secrets are gitignored and `auth.json` stores env var *names* only.
- **Weaknesses:** ZAP runs with `api.disablekey=true` and `api.addrs.addr.regex=.*` — any process that can reach the daemon can drive a scanner; acceptable on an isolated compose network, unacceptable the moment this runs on shared infrastructure. Scope matching ignores scheme, port, path, and IP-literal forms (KI2), so `juice` in the allow-list authorizes every port on that host. Structured logging exists only in `scope_guard.py` (NFR-4 otherwise unmet), so "prove what this tool did to that environment" cannot currently be answered.
- **Next:** Enable the ZAP API key, bind the daemon to the runner only, add structured JSON logging with a scan correlation id, and extend scope tuples to (scheme, host, port).

> **Repository hygiene (small, but it will be noticed in a funding review):** a stray 17 KB file literally named `-` is committed at the repo root, alongside `runner/capture_zap_fixture copy.sh` (a duplicate with a space in the name) and a committed corporate CA bundle `nw-ca-all.pem`. There is no linter config, no `.pre-commit-config.yaml`, and no CI to catch any of it. Also: the README advertises "213 tests" while the suite is now 228.

## 5. DAST maturity assessment

Compared with Burp Suite Enterprise, Invicti, Acunetix, StackHawk, Detectify and plain ZAP, this PoC is not a scanner competitor — it wraps one of them. The right comparison is as an *orchestration and governance layer*, and on that axis it has two capabilities that are genuinely uncommon and one glaring absence.

### Real differentiators

- **Coverage-aware lifecycle.** Most tools (and GitHub itself) treat "absent from the latest scan" as "fixed". `not_scanned` is an honest fourth state, derived from ZAP's actual accessed URLs and enabled rule ids. StackHawk and Burp Enterprise both track findings across scans, but a coverage-conditioned fix claim is not a standard feature.
- **Fail-closed, two-layer, non-prod-only safety.** Preflight plus a per-request browser-boundary guard, both refusing by default, with production rejection duplicated outside the schema. For a regulated enterprise running DAST near real data, this is the part worth keeping regardless of which scanner wins.
- **A defensible LLM boundary.** Constrained JSON, schema validation, deterministic rendering, AST compile, deterministic fallback, and redaction before the model. This is how to answer a security-architecture review about AI in the loop, and it is fully implemented rather than aspirational.

### Missing foundations

- No multi-app registry, scheduler, or queue; no UI or console of any kind.
- No triage model: no confidence, no dedup, no suppression, no owner assignment, no SLA.
- No remediation content — the thing every commercial tool sells hardest.
- No CI/CD integration, no PR feedback, no ticketing.
- No API/GraphQL-native scanning (spec import, schema-aware fuzzing) — StackHawk's core differentiator.
- No RBAC, tenancy, audit trail, or retention policy.
- No coverage measurement against a route inventory; no FP/FN benchmarking (e.g. against OWASP Benchmark or WAVSEP).

**Classification: Prototype (late-stage), not MVP.** The MVP bar is "a second team could use it to find and fix a real bug without the authors present". This misses it on three counts: onboarding app #2 requires editing Python (hard-coded Juice Shop selectors and registration call in `record.py` and `generate.py`), nothing runs unattended, and a finding is not actionable when it arrives. It clears the Prototype bar emphatically — end-to-end on real data, containerized, 228 tests, documented decisions.

| Enterprise blocker | Why it blocks |
| --- | --- |
| Per-app code changes to onboard | Cost scales linearly with apps; no self-service. |
| No unattended execution | No scheduled assurance, so no compliance value. |
| Non-actionable findings | Developers will reject the tool after the first 1,400-alert upload. |
| No audit trail (NFR-4 largely unmet) | Cannot evidence what the scanner did to which environment. |
| Unauthenticated ZAP API | Fails a platform security review outside an isolated network. |
| Local state file as system of record | No history, no multi-runner, no recovery. |

## 6. User experience review

### Security engineer — the only persona the tool actually serves

- **Onboarding/setup:** the best-documented path in the repo, and still heavy — the Phase 2 runbook needs a container runtime, a venv, Chromium, two terminals, platform-specific cards, exported credentials, an LLM backend, and an authenticated `gh`. §11 "Gotchas" lists failures already hit on the demo machine, including Juice Shop exiting 133 between sessions (KI3).
- **Running scans:** good — `docker compose up` is a genuine single command, and the runner waits for readiness through ZAP itself (a nice detail: `_zap_can_reach` checks from ZAP's perspective, not the host's).
- **Understanding results:** weak — `records.json` with ~1,500 entries, no grouping, no ranking beyond severity, no counts by rule.
- **Triage:** absent — no suppression, no accepted-risk state, no confidence. The only states are `new/open/resolved/not_scanned`, all machine-assigned.
- **Reporting:** the Security tab only; no scan summary, no trend, no per-app posture.

### Application developer — not served at all

- No entry point exists for a developer: no PR comment, no local `scan-my-branch` command, no ownership mapping, no remediation text, no reproduction request/response in the alert. The alert names a ZAP rule and a URL path.
- The fastest credibility win in the entire backlog is making one finding fully actionable end-to-end (description + solution + the offending request + a link to retained evidence).

### DevOps engineer — not served at all

- Nothing to integrate: no workflow, no exit-code contract usable as a gate (the gate *requires* findings to pass), no artifact retention, no metrics/health endpoint, and structured logs only from the scope guard.
- The container is runner-only (`authoring/` is not copied in), so the authoring half of the product has no deployable form at all.

| Priority | Improvement | Why it is high impact |
| --- | --- | --- |
| 1 | Carry ZAP `description`/`solution`/`confidence`/evidence into the record and SARIF `help` | Turns 1,500 labels into fixable findings; unlocks the developer persona; ~1 day of work. |
| 2 | One GitHub Actions workflow: scheduled scan → lifecycle diff → SARIF upload → evidence artifact | Converts "a demo" into "a service"; removes the "one-way door" narration from the demo. |
| 3 | Extract the Juice-Shop-specific login/registration into per-app config (selectors, token check, seed routes) | Makes "onboard app #2" a config PR instead of a code change — the question every reviewer will ask. |
| 4 | Findings summary: counts by severity/rule/route, top 10 by risk, and a one-page HTML/Markdown scan report | Gives security engineers and leadership something to read in 30 seconds. |
| 5 | Structured JSON logging with a scan id (NFR-4) | Only `scope_guard.py` logs today; needed for audit evidence and for debugging live demos. |
| 6 | Split the runner gate from the demo assertion | Prevents the inverted gate semantics from leaking into any future pipeline. |

## 7. Scan quality assessment

| Dimension | Current state | Gap | Recommendation |
| --- | --- | --- | --- |
| Coverage completeness | Recorded walk + ZAP spider + LLM exploration; 12 pages / 27 API calls measured on the pilot | No denominator, no route inventory, no coverage percentage; POST-gated surface unreachable by design (state-changing verbs default-denied) | Import OpenAPI (D10) and report coverage against declared routes; allow explicit safe-form allow-lists per app |
| False-positive handling | None. ZAP `confidence` is dropped in `normalizer.py`; no suppression or accepted-risk state | Every alert is equal weight; GitHub dismissals are invisible to the diff, so a dismissed finding keeps returning as `open` | Carry confidence; add a per-app suppression file keyed by fingerprint; reconcile GitHub dismissal state |
| False-negative risk | High and structurally invisible: 4-minute scan cap, 1-minute per-rule cap, DOM-XSS (`40026`) disabled by default, no attack-strength setting | Nothing distinguishes "not vulnerable" from "not tested for"; the honest `not_scanned` state exists for findings but never for *never-found* gaps | Publish a per-scan "rules run × routes exercised" report; run a deep nightly profile alongside the bounded one |
| Authentication | Strong: form login, seeded `storageState`, liveness proof, fail-closed on dead session | No mid-scan expiry handling (open question 2); no OIDC/SAML/MFA path exercised; the pilot cannot demonstrate the headline benefit | Post-scan auth re-check; pilot against one real SSO app — that is the credibility test for this whole thesis |
| SPA support | Real browser drives the SPA; hash routes normalized (`normalize_href` handles Angular `#/` and `./` forms — a detail that shows field experience) | No AJAX spider; discovery limited to hrefs and observed XHR; client-side-only routes never linked are invisible | Enable ZAP's AJAX spider for SPA targets; consider route extraction from the SPA router |
| API support | Endpoints observed opportunistically when a URL contains `/rest/` or `/api/` (`record.py`, `explore.py`) | Substring heuristic misses every other convention (`/v1/`, `/graphql`, versioned hosts); GET-only; no body/param fuzzing of APIs | Spec-driven API scanning is the highest-value missing capability for a modern portfolio |
| GraphQL | Not supported anywhere in the codebase | No introspection, no query generation, no single-endpoint handling — a GraphQL app would appear as one route | Add ZAP's GraphQL add-on if any pilot candidate uses it; otherwise state it as an explicit non-goal |
| Rate limiting / blast radius | Explicitly out of scope (§3.2). No throttling, concurrency, or circuit breaker | Any non-prod environment shared with other testers can be saturated by an active scan | Add ZAP thread/delay options to the policy before scanning any shared environment |
| Crawl depth | `max_pages` (12 on the pilot) and the spider's defaults | No depth, breadth, or time budget in `explore`; the loop `break`s on the first non-executable proposal instead of backtracking | Add depth/time budgets and a frontier queue so exploration degrades gracefully rather than stopping |
| Context awareness | `endpoint_pattern` collapses numeric/UUID/long-hex segments so findings aggregate per route (KI1) | Heuristic: `/user/42` and `/user/settings` behave differently by accident of segment shape; no per-app route config; no business-criticality or data-classification input to prioritization | Per-app route patterns (or OpenAPI paths) instead of the heuristic; add app criticality to the record so prioritization can exist |

> **The most under-communicated quality risk:** volume. 1,490 detections on a pilot app, with no dedup, confidence, or ranking, and no remediation text, is the profile of a tool that gets switched off after its first real upload. Fix the finding *quality* story before scaling the finding *quantity* story.

## 8. Enhancements

### Near-term (next 1–3 working sessions each; realistic for this codebase)

1. **Rich findings:** extend `detection.schema.json` with `description`, `solution`, `confidence`, `request_excerpt`; map to SARIF `help`/`fullDescription`/`helpUri`.
2. **CI workflow:** scheduled compose scan → diff → SARIF upload → evidence artifact retention; remove the manual `gh` dependency.
3. **Per-app config:** move login selectors, token check, registration bootstrap, banner dismissal and seed routes out of Python into the app directory; prove it by onboarding a second target (DVWA or any internal dev app).
4. **Wire the generated bundle:** consume `zap-policy.yaml` in `configure_policy()` and `auth.json`/`manifest.json` in the runner, closing the most visible design/implementation gap the team already discloses on stage.
5. **Scan report artifact:** one HTML/Markdown summary per scan (counts, top findings, coverage, lifecycle deltas) — makes every future demo and every stakeholder update self-service.
6. **Structured logging across all stages (NFR-4)** with a scan correlation id — extend the pattern `scope_guard.py` already uses — plus fingerprint-keyed suppression.
7. **Fix-and-rescan demo evidence:** actually execute requirements §9 step 4 and capture it — it is the acceptance criterion the project defined for itself and has not yet shown.
8. **Hygiene:** delete the stray `-` file and the " copy.sh" duplicate, add ruff + pre-commit + the test suite to CI, and correct the README's test count.

### Strategic (what would make this an enterprise platform)

1. **Spec-driven discovery and API/GraphQL scanning** (the OpenAPI-first half of D10) — the difference between scanning SPAs and scanning a portfolio.
2. **Application registry + scheduler + queue** with per-app owners, criticality, environments, and scan cadence; one ZAP instance per scan.
3. **Risk-based prioritization:** severity × confidence × exploitability × app criticality × data classification, so the top 10 is defensible.
4. **Incremental/differential scanning:** scan the routes a change touches, using the coverage artifact already captured — this project is unusually well positioned for it.
5. **Developer feedback loop:** PR annotations, ticket creation with dedup by fingerprint, ownership routing, and an SLA clock.
6. **AI-assisted remediation at the right boundary:** the existing D8 pattern (model emits validated data, code acts) extends naturally to remediation guidance and suggested patches — and it is the one place an LLM adds value a commercial scanner does not already provide.
7. **Authentication recording as a product feature:** a guided "seed a session" tool for SSO/MFA apps with encrypted storage and TTL — this is the real enterprise blocker and currently the weakest-evidenced claim.
8. **Governance:** audit log, RBAC, scope-change approval, retention, and an evidence store that satisfies an auditor rather than a demo.
9. **Quality benchmarking:** measure FP/FN against a known-vulnerability benchmark so scan quality becomes a number the team can defend and improve.

## 9. A stronger Phase 2/3 demo

The current demo is organized around the *architecture* (fixture pipeline → safety → record → explore → generate → validate → runner → SARIF). Reorganize it around *a finding's life*. Same components, same runbook steps, radically better story — and it makes the coverage-aware lifecycle the climax instead of an appendix.

### Cold start: onboard an app in 3 minutes

*Status: Needs per-app config first*

Start with an app the audience has not seen. Drop in a scope file and seed routes, run `seed` + `explore` headed, and let them watch the surface get discovered. Open on the question leadership actually asks — "what does it cost me to add my app?"

### Safety, as a refusal

*Status: Already works*

30 seconds, two commands: flip `environment_class` to `prod` and watch it abort before traffic; point the plan at an out-of-scope host and watch `validate` reject it. Show the guard *saying no* — never narrate it.

### One finding, all the way down

*Status: Needs richer records*

Pick the SQL injection. Show the ZAP alert, the normalized record, the fingerprint, the redacted HAR proving it, and the GitHub alert with severity and remediation text. This is the slide that sells the product — and today it cannot be shown, because remediation content is dropped in normalization.

### Fix it, re-scan, watch it close

*Status: Requirements §9 step 4, still undemoed*

Fix one weakness in the pilot, re-scan, show the finding flip to `resolved` while the rest stay `open`. Then the honest twist: disable the SQLi rule, re-scan, and show it become `not_scanned` rather than "fixed" — with the real story of the 13 findings GitHub wrongly closed. Trust is won here, not on the architecture slide.

### Unattended

*Status: No workflow exists*

Show a scheduled run that already happened: the workflow log, the uploaded SARIF, the retained evidence artifact. One screenshot replaces the entire "one-way door, so I'll narrate it" moment.

### The AI boundary, on one slide

*Status: Keep as-is*

Keep the existing Act 3 material but move it to the end as the answer to "is the AI safe?", not as the thesis. The thesis is coverage and honest lifecycle; the LLM is how it is achieved.

### Missing artifacts worth producing before the next showing

- Screenshots: the GitHub Security tab with alerts, one alert detail page, a `not_scanned` carry-forward, a scheduled workflow run. The repo currently contains **zero** images.
- A 3-minute recorded highlight reel (the 22–26 minute live runbook is a rehearsal risk, not a demo).
- A one-page before/after coverage chart and a "cost to onboard app N" slide.
- A "why not buy Burp Enterprise / StackHawk" slide naming what this layer adds on top of a commercial scanner.

## 10. Executive summary

### Top five strengths

1. **Safety is real and fail-closed** — two independent layers, production refusal duplicated outside the schema, written test-first (`preflight.py`, `scope_guard.py`).
2. **Coverage-aware lifecycle** — `not_scanned` derived from ZAP's actual accessed routes and enabled rules; a defensible product insight, not plumbing (`coverage.py`, `lifecycle_diff.py`).
3. **A disciplined LLM boundary** — constrained JSON, schema validation, deterministic rendering, AST compile, deterministic fallback, redaction before the model (`generate.py`, `explore.py`, `action_policy.py`, `redact.py`).
4. **Engineering rigor** — 228 passing tests anchored to independent oracles (external `shasum`, OASIS SARIF schema, CWE facts, sensitivity checks), frozen contracts, and a documented "the suite must bite" exercise.
5. **Institutional honesty** — D1–D10 / KI1–KI4 and a demo script that instructs the presenter to disclose unwired artifacts. This is the cultural asset that makes the rest trustworthy.

### Top five gaps

1. **Findings are not actionable** — no remediation text, confidence, request evidence, or usable evidence link; ~1,500 undifferentiated detections.
2. **Nothing runs unattended** — no CI workflow at all; SARIF upload is a manual `gh` call from an operator's authenticated shell (it has been run live, but never by anything other than a person).
3. **Onboarding app #2 needs code changes** — Juice Shop selectors, registration call and token check are hard-coded in `record.py` and `generate.py`.
4. **The headline auth benefit is unproven** — the pilot cannot exercise SSO/MFA seeding, as the team's own design doc states; mid-scan session expiry is unresolved.
5. **Operational foundations missing** — structured audit logging only in the scope guard (NFR-4 otherwise unmet), a local JSON file as system of record, unauthenticated ZAP API, evidence discarded by the compose runner.

### Top five investments, in order

1. **Make one finding excellent** (rich record → SARIF `help` → retained evidence link). Unlocks the developer persona and every future demo.
2. **Ship the unattended loop** (one workflow: scan → diff → upload → artifacts). Converts a demo into a service; cheapest credibility gain available.
3. **Config-driven app onboarding, proven on a second app** — ideally one with real SSO, which simultaneously tests the core thesis.
4. **Close the bundle gap** (`zap-policy.yaml`, `auth.json`, `manifest.json` consumed by the runner) plus policy pinned into coverage, so scan depth is reproducible.
5. **Operational hardening** — structured logs with scan ids, ZAP API key, durable state/evidence, split demo gate from policy gate.

> **Does it tell a compelling DAST product story today? Partly.** It tells a compelling *safety and AI-governance* story (that part is better than most vendor material) and an incomplete *product* story: no user receives value on screen, nothing runs by itself, and the differentiator versus buying a commercial scanner is never articulated. Storytelling 7/10; overall readiness 4/10.

### Prerequisites before presenting to engineering leadership for broader adoption

- One end-to-end unattended run, evidenced by a workflow log and a populated Security tab — not narrated.
- One finding shown as a developer would receive it: what, where, why it matters, how to fix it, proof.
- The fix-and-rescan lifecycle demo (the project's own definition of done) plus the `not_scanned` counter-case.
- A second application onboarded without code changes, with the onboarding cost stated in hours.
- An explicit build-vs-buy position: what this layer adds on top of ZAP/Burp/StackHawk, and what it deliberately will not do. The defensible form is *buy the engine, build the discovery* — nothing in the new proposal actually depends on ZAP, so the request corpus, session bootstrap and coverage-aware lifecycle survive a decision to buy a commercial scanner and can feed it instead.
- A one-page risk register carried forward from D1–D10 / KI1–KI4, including the unauthenticated ZAP API, mid-scan session expiry, and host-only scope matching.

Funding recommendation: continue, at Phase-3 scale, with the scope re-pointed from "more discovery" to "make the loop unattended and the findings actionable". The riskiest open question is not technical — it is whether the differentiated value (governed authoring, honest lifecycle) is large enough to justify building around a free scanner rather than buying one and keeping only the safety and lifecycle layers. It need not be answered as either/or: because the discovery layer is engine-agnostic, the durable question is "what do we build regardless of which scanner we buy", and that framing survives losing a vendor comparison. Decide it explicitly at the next gate, not by deferral.

---

Sources: NationwideDevin/ssd-dast-tool-poc, re-synced from upstream Nationwide/ssd-dast-tool-poc and read at commit c3bac3b (code unchanged since 7c16c01); repository documentation, contracts, and tests; local test run (228 passing). Runtime figures are the project's own measurements — those marked team-reported come from runs whose artifacts are not committed and were not independently reproduced. Judgements are the reviewer's.
