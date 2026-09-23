# First internal application: DAST readiness and benchmark plan

Gates, scan-posture decisions, and a comparison scorecard for the first authenticated scan of a real internal application in a non-production environment.

## How to read this

A sequenced path from the current PoC (verified end-to-end on OWASP Juice Shop; re-synced from the upstream repository and re-checked at commit `c3bac3b`, where the code is unchanged since `7c16c01`) to a first authenticated scan of a real internal Nationwide application in a **non-production** environment. Production remains out of scope and `runner/preflight.py` should keep refusing it.

> **Stated purpose of the pilot:** to establish whether this PoC's findings and user experience can reach parity with the commercial DAST tools currently under evaluation. That makes the pilot a benchmark, not just an infrastructure milestone — so sections 8 to 10 (scan posture decisions, the residual detection gap, and the scorecard) matter as much as the gates, and several of them must be settled *before* the first scan rather than discovered during it.

Gates are ordered by dependency, not importance: each one's exit criteria are the entry condition for the next. Roughly half the work is not scanner engineering — it is target selection, approval, and network/identity plumbing, and that half has the longest lead times, so Gate 0 starts on day one in parallel with everything else.

- **Effort unit:** One "session" ≈ one focused engineering day for someone already familiar with this codebase. Estimates cover implementation and tests, not review latency, approvals, or waiting on another team.
- **Owner roles:** **Tool** = the PoC engineers. **Platform** = whoever owns the runner host, network egress, and secrets. **App** = the target application's team. **Gov** = security architecture / governance approver.
- **Basis:** Every item traces to a specific gap found in the code review; file references are given so each can be picked up directly.

> **Architecture direction changed while this plan was being written.** `docs/Authenticated-Application-Discovery-DAST-Design-Proposal.md` (new at `c3bac3b`) proposes deterministic-first discovery with the LLM demoted to an escalation path, which contradicts the adopted D9 ("generate is LLM-primary with a deterministic fallback"). See “Architecture direction” below: that decision precedes these gates, because it changes what Gate 1 is building.

> **Decide Gate 0 before funding the rest.** Target choice determines most of the remaining work: an app with form login and an OpenAPI spec is a fraction of the effort of an SSO+MFA SPA with no spec. Pick the target first, then re-estimate.

## Architecture direction — the decision that precedes the gates

The new design proposal is the strongest document in the repository, and it reverses the current architecture. It puts deterministic exploration in the common path and calls the LLM only for measured semantic blockers (§5.3), after a ground-truth baseline establishes what deterministic discovery achieves alone (§15 Phase 0, §19). It also introduces three things this plan depends on: an authenticated *request corpus* rather than a route list (§8), explicit ZAP context and session-handling configuration (§7.6), and controlled mutation as an approved, cleanup-planned action class (§10).

> **AD-1 — Supersede D9, or reaffirm it.** D9 (`docs/decisions_and_known_issues.md`) and the proposal are both adopted text and they disagree. Recommendation: supersede D9 with a new numbered decision stating deterministic-first with bounded LLM escalation. Consequence: the Phase 2 story becomes “deterministic discovery with governed AI assist” rather than “AI discovery” — which is the more defensible claim, is idempotent and auditable, and retires D9’s own non-idempotency caveat. Do not leave the contradiction standing across three documents.

> **Do not over-read the supporting data.** The team’s live comparison — deterministic proposer 15 pages / 30 API calls / 1,581 detections against Claude’s 12 / 27 / 1,490 — is not committed to the repository, and detection count is the wrong yardstick: most of that volume is passive rules re-firing per page, so a 6% delta is noise. The meaningful figure is surface reached (15/30 vs. 12/27), from a single run against Juice Shop — link-rich, form-poor, and needing no business semantics, so exactly where deterministic crawling should win and an LLM contributes nothing. It shows the LLM is not earning its cost *on this application*. The three-application experiment in §19 is what decides the general case.

> **AD-2 — Scope the proposal honestly when it is presented.** Twelve components including an onboarding API/UI, a human-assistance service and worker pools (§12) is a funded platform build, not the next iteration of a prototype. Two gaps that decide a tool comparison are also deferred or absent: authorization/BOLA testing sits in Phase 4, and out-of-band (OAST) detection is not mentioned at all. Actionable findings — the cheapest high-value work — appears only as a “findings normalizer” component and Phase 4 triage; move it into Phase 1 beside ZAP ingestion.

> **Two of the project’s strongest facts are not written down.** The no-LLM comparison above, and the live SARIF uploads — run twice, the second of which closed 13 findings as “fixed” that were not fixed, producing the evidence for coverage-aware export. Neither exists in the repository at `c3bac3b`, and `docs/dast_poc_phase2_demo_runbook.md` still tells the operator to narrate the upload rather than run it. Commit the artifacts (both SARIF files and the GitHub alert states before and after), update the runbook, and lead the demo with the incident: it is reproduced defect-and-remedy evidence, which is rarer and more persuasive than a clean run.

## Effort at a glance

**Engineering effort by gate (sessions; excludes approval and lead times)**

| Gate | Low estimate (sessions) | High estimate (sessions) |
| --- | --- | --- |
| G0 | 1 | 2 |
| G1 | 3 | 5 |
| G2 | 4 | 6 |
| G3 | 3 | 6 |
| G4 | 2 | 4 |
| G5 | 2 | 4 |
| G6 | 2 | 3 |
| G7 | 4 | 8 |

G0 target and approval · G1 app-agnostic · G2 safety hardening · G3 real authentication · G4 actionable findings · G5 unattended and audit · G6 first scan ladder · G7 scan posture tuning and the benchmark run (SP-1 to SP-5: write paths, scan bounds, DOM XSS, specification import, session handling). Total 21–38 engineering sessions. G7 excludes OAST (SP-6) and multi-identity authorization testing (SP-7), which are separate capabilities rather than tuning. Calendar time will be dominated by Gate 0 approvals and Gate 3 identity access, not by the code. Gates 1, 4 and 5 can run in parallel with Gate 0; Gates 2 and 3 need the target known.

## Gate 0 — Choose the target and get permission

### Target selection and approval

*Status: Start immediately — longest lead time*

Nothing else can be sized until the target is known. Bias the first target toward "boring": a non-prod environment the app team controls, with test data only, no partner integrations that send real messages, and ideally a published API spec.

- **Selection criteria:** Non-prod, isolated test data, an engaged app team, a GitHub repo with Advanced Security enabled (needed for SARIF), known auth mechanism, and a named owner who can approve an active scan.
- **Deliverables:** Signed-off target record: environment URL(s), environment class verified against the app registry (not hand-typed), auth method, downstream integrations that must be excluded, scan window, notification list, and a named kill-switch contact.
- **Owners:** Gov (approval), App (environment facts), Tool (feasibility).
- **Exit criteria:** Written approval to run an authenticated active scan in that environment, plus an agreed rollback/stop procedure.
- **Effort:** 1–2 sessions of tool-team time; calendar time driven by approvals.

> **Do not let the target be chosen by convenience.** Picking a hard SSO app first proves the thesis but risks the pilot stalling on identity access; picking a trivial app de-risks delivery but proves nothing Juice Shop has not already proven. If only one pilot is funded, choose an app with real SSO — that is the capability under test.

## Gate 1 — Make the tool app-agnostic

Blocker: today onboarding a second app means editing Python. Can run in parallel with Gate 0 using Juice Shop plus one second throwaway target (DVWA) as proof.

| Task | Where | Owner | Sessions |
| --- | --- | --- | --- |
| Move login selectors, token check and bootstrap out of code into per-app config | `authoring/record.py::crawl()`, `authoring/generate.py::journey_from_trace()` (`#email`, `#loginButton`, `/api/Users/`, `localStorage.getItem('token')`) | Tool | 2 |
| Stop hard-coding `environment_class: "dev"` and the deny-list in `emit_scope()` | `authoring/generate.py` | Tool | 0.5 |
| Generalise API detection beyond the `/rest/` + `/api/` substring heuristic | `authoring/record.py`, `authoring/explore.py` | Tool | 0.5 |
| Prove it: onboard a second app with config only, and record the elapsed time | new `security/dast/<app>/` | Tool | 1 |
| Optional but high value if the target is API-heavy: OpenAPI import (the D10 direction) | `runner/scan.py` + ZAP OpenAPI add-on | Tool | 1–2 |

**Exit criteria:** a new application is onboarded by adding one directory of configuration, with no diff to `authoring/` or `runner/`, and the onboarding cost is stated in hours.

## Gate 2 — Safety hardening for a shared environment

The PoC's safety model was designed for a disposable container on an isolated network. A shared internal environment breaks three of its assumptions.

| Task | Why | Owner | Sessions |
| --- | --- | --- | --- |
| Split scope into "may traverse" and "may attack" | An SSO login must be reachable but must never be scanned; today `fqdn_allow_list` authorises both | Tool | 1 |
| Bound ZAP itself with a context and include/exclude regex | `/JSON/context/` is never called; the spider and active scan are bounded only by the seed URL, so the two documented safety layers cover browser-originated requests only | Tool | 1 |
| Extend scope matching to (scheme, host, port) and handle redirects | KI2: host-only matching authorises every port and scheme on an allow-listed host | Tool | 1 |
| Add throttling and a kill switch | Rate limiting was explicitly descoped; there is no way to stop a scan today except Ctrl-C | Tool | 1 |
| Exclude destructive and integration endpoints per app | Active scanning a shared environment can trigger mail, SMS, payments or partner test systems | Tool + App | 0.5 |
| Verify `environment_class` against the app registry; deny prod hostname patterns | Preflight trusts a hand-typed string — against real hostnames one typo is the entire safety story | Tool + Gov | 1 |
| Enable the ZAP API key and bind the daemon to the runner | Currently `api.disablekey=true` with `api.addrs.addr.regex=.*` | Platform | 0.5 |

**Exit criteria:** a deliberate misconfiguration test suite passes — wrong environment class, off-scope host, off-scope port, IdP host, and an excluded destructive endpoint are each refused, logged, and provable after the fact.

## Gate 3 — Authenticate the real application

The seeded-session design already exists and is the right one; what is missing is everything around the credential.

| Task | Detail | Owner | Sessions |
| --- | --- | --- | --- |
| Corporate TLS and egress | ZAP is a MITM proxy: the Nationwide CA chain must be trusted by Chromium and ZAP, and both need proxy settings. Note `nw-ca-all.pem` is committed **empty** (0 bytes) while two runbooks reference it — source it at runtime, do not commit it. | Platform | 1–2 |
| Seed an SSO/MFA session for real | Human logs in once through `authoring/seed.py`; capture what breaks (conditional access, device trust, session binding to IP or user agent) | Tool + App | 1–2 |
| Put `storageState` in a secret store with a TTL | Today it is a live credential in a working tree at `.secrets/storageState.json` | Platform | 1 |
| Handle mid-scan session expiry | Liveness is proven once before a multi-minute scan. Add a post-scan re-check and mark the scan *degraded* so no finding can be labelled `resolved` from a scan that lost its session | Tool | 1 |
| Agree a test identity | A dedicated non-privileged service identity with no access to real customer data, and a documented re-seed cadence | App + Gov | — |

**Exit criteria:** an authenticated page of the real app is reachable through the ZAP proxy, proven by `prove_auth_live()`, with the session sourced from the secret store and no credential on local disk.

## Gate 4 — Make the findings worth delivering

Confirmed against the committed ZAP fixture (38 alerts): the content already exists in ZAP's output and is discarded during normalization. Fill rates — `description` 38/38, `confidence` 38/38, `solution` 32/38, `reference` 27/38, `evidence` 26/38.

| Task | Where | Owner | Sessions |
| --- | --- | --- | --- |
| Extend the detection contract with `description`, `solution`, `confidence`, `reference`, `evidence` | `contracts/detection.schema.json` (currently `additionalProperties: false`), `detections/normalizer.py` | Tool | 1 |
| Map them into SARIF `help`, `fullDescription`, `helpUri` | `detections/sarif_export.py` | Tool | 0.5 |
| Optionally fetch the request/response pair | ZAP alerts carry only `messageId`; the full pair needs `/JSON/core/view/message/`, which the runner does not call today | Tool | 1 |
| Retain evidence somewhere resolvable, with a retention policy | Compose mounts only `./out`, so evidence written under the app directory is discarded; SARIF references a relative path | Tool + Platform | 1 |
| Review redaction against real data | The redactor is heuristic and its surface is a known open question; real-app HARs will contain real-shaped test data | Tool + Gov | 0.5 |

**Exit criteria:** a developer on the target app can read one alert and know what is wrong, where, why it matters, and how to fix it — without asking the tool team.

## Gate 5 — Unattended execution and audit

| Task | Detail | Owner | Sessions |
| --- | --- | --- | --- |
| One scheduled workflow | scan → `lifecycle_diff` → `sarif_export` → upload → retain evidence. No `.github/workflows/` exists today and upload is a manual `gh` call | Tool | 1 |
| Split the demo assertion from the policy gate | `evaluate_gate()` passes only when a high/medium finding exists, so a clean app fails — this must not be consumed as a CI gate | Tool | 0.5 |
| Structured logging with a scan id (NFR-4) | Only `runner/scope_guard.py` logs today; you will be asked to evidence what the scanner did to that environment | Tool | 1 |
| Durable state | `out/state.json` holds every record of the last scan and is the de facto database | Tool | 1 |
| Confirm GitHub Advanced Security on the target repo | SARIF upload will not surface alerts without it | App | — |

**Exit criteria:** a scan runs on a schedule with nobody watching, its alerts appear in the target repo, its evidence is retained, and its log answers "what did you touch, when, and what did you refuse?".

## Gate 6 — The first scan, as a ladder

Do not point a full active scan at a real environment on day one. Climb, and stop at the first surprise. Each rung is a scheduled window with the app team on notice.

1. **Connectivity and refusal.** Preflight and scope guard only: prove the tool refuses prod, refuses off-scope hosts, and can reach the target through the proxy. No scanning.
2. **Authenticated walk, passive only.** Seed, explore, capture coverage. Produces a route inventory and passive findings with zero attack traffic.
3. **Bounded active scan on one low-risk route,** off-hours, throttled, with the app team watching logs and error rates.
4. **Full bounded active scan** of the authenticated surface, still off-hours and throttled.
5. **Second scan for lifecycle:** fix one finding, re-scan, show it flip to `resolved` while an unvisited route's findings correctly show `not_scanned`. This is the project's own definition of done and has still not been demonstrated.
6. **Benchmark run.** With the SP-1 to SP-5 postures settled and written down, run the scan that the commercial tools will be compared against, under the protocol below.

**Exit criteria:** two consecutive scans complete unattended with no environment incident, the app team accepts the findings as useful, and the benchmark run is complete with every posture exclusion recorded.

## Scan posture decisions

The PoC's current scan configuration was tuned for a repeatable stage demo against a disposable container. Every one of those settings suppresses detection, and each is a deliberate choice that must now be re-made for a benchmark against commercial tools — which do not operate under these constraints. These are not defects to fix silently; they are postures to choose, minute, and disclose on the scorecard.

> **SP-1. Write paths: keep the default-deny, or exercise them?**
>
> *Current state:* `runner/action_policy.py` default-denies POST, PUT, PATCH and DELETE unless the target appears on the `safe_forms` allow-list. The effect is that write requests are never observed, so they never enter ZAP's site tree and are never attacked.
>
> *What the comparison tools do:* they attack forms and write methods in scope by default, and manage risk through disposable environments, endpoint exclusions and data restoration.
>
> *Consequence of doing nothing:* injection, authorization and business-logic classes go untested, and the vendors' extra findings will read as better detection when the real difference is safety posture.
>
> *Recommendation:* exercise write paths in test environments, but by populating `safe_forms` per application rather than removing the policy — keep the guardrail that an LLM never decides a mutation is safe, since governed authoring is a differentiator, not overhead. Agree with the app team which write paths are in play, what data they touch, and how the environment is restored. Note that write-enabled scans are not idempotent: test data drifts between runs, so budget a data reset or the lifecycle diff gets noisy.

> **SP-2. Scan duration bounds.**
>
> *Current state:* `configure_policy()` in `runner/scan.py` sets a 4-minute cap on the whole active scan and 1 minute per rule. When the cap is hit, ZAP stops where it is and returns what it has — and nothing in the output distinguishes a truncated scan from a completed one.
>
> *Consequence:* missing findings for reasons unrelated to the engine, and coverage claims that cannot be defended in a comparison.
>
> *Recommendation:* raise the cap to suit the target's size, and record scan truncation explicitly so "no finding here" never silently means "never reached". Caveat: longer scans against the current pipeline mostly produce more unactionable low-severity output, so Gate 4 must land first or the improvement reads as noise.

> **SP-3. DOM-based XSS rule (ZAP plugin 40026).**
>
> *Current state:* disabled in `configure_policy()`; the code comment says it "wedges the API" — it drives a real browser per payload, so it is slow. This is the repo's own note and has not been independently reproduced.
>
> *Consequence:* an entire client-side vulnerability class is untested, specifically the one that matters most for SPAs — awkward when the comparison tools do test it.
>
> *Recommendation:* re-enable with proper browser configuration and a longer budget, or disclose the exclusion on the scorecard.

> **SP-4. Attack surface: how does the scanner learn what to attack?**
>
> *Current state:* ZAP only attacks what it has seen. The site tree comes from the authenticated Playwright walk plus the classic spider — 12 pages and 27 API calls on the Phase 2 run. The classic spider finds very little on a modern SPA, and without a specification ZAP does not know an endpoint accepts fifteen parameters when the walk exercised three.
>
> *Consequence:* more scan time mostly re-attacks the same small surface. Surface is a harder constraint than duration.
>
> *Recommendation:* import an OpenAPI or GraphQL specification where one exists, and treat crawl breadth as a measured output of the pilot rather than an assumption.

> **SP-5. Session handling under a write-heavy scan.**
>
> *Current state:* no ZAP context, no session-management or re-authentication rules, no anti-CSRF token handling; liveness is proven once before the scan begins.
>
> *Consequence:* attacking forms logs the scanner out and regenerates CSRF tokens. A longer, write-enabled scan can therefore find *fewer* issues than a short one, because most of it runs unauthenticated against a login page — the single most likely way for the pilot to produce a misleadingly poor result.
>
> *Recommendation:* configure ZAP session management and re-authentication before the first full scan, and pair it with the post-scan liveness re-check in Gate 3.

> **SP-6. Out-of-band (OAST) detection — in or out of the pilot?**
>
> *Current state:* absent. Blind SSRF, blind XSS, blind injection and deserialization are detected by watching for a callback to infrastructure the scanner controls.
>
> *What the comparison tools do:* Burp Collaborator and the Invicti equivalent ship this, and it features prominently in vendor demonstrations.
>
> *Consequence:* these classes are invisible to the PoC, by construction.
>
> *Recommendation:* decide now. Closing it means standing up a callback host reachable from the target and getting network approval — a scoped project, not a setting. If it is out of scope for the pilot, record it as a known exclusion rather than letting it show up as a detection deficit.

> **SP-7. Authorization testing — in or out of the pilot?**
>
> *Current state:* one seeded session. Broken access control (IDOR, BOLA, privilege escalation) requires two identities and cross-session replay, so it is out of reach by construction.
>
> *Consequence:* the PoC cannot find the category that sits at the top of the OWASP Top 10.
>
> *Recommendation:* either fund multi-identity scanning as a distinct capability, or exclude it explicitly and state that this category is covered by another control.

## Residual detection gap after tuning

Settling SP-1 through SP-5 should bring the PoC close to credible on the common injection classes. It will not reach parity, and it is worth being precise with stakeholders about which part of the remaining gap is configurable and which is structural — before anyone reads a finding count as a verdict on the engine.

| Cause of missed findings | Closed by tuning? | What it actually takes |
| --- | --- | --- |
| Scan truncated at 4 minutes | Yes | Raise the cap; record truncation (SP-2) |
| Write paths never exercised | Yes | Per-app `safe_forms` allow-list and an agreed data reset (SP-1) |
| DOM XSS rule disabled | Yes | Re-enable 40026 with browser configuration (SP-3) |
| Unknown endpoints and parameters | Partly | Specification import; better crawl (SP-4) |
| Scanner loses its session mid-scan | Partly | ZAP context, re-authentication and anti-CSRF rules (SP-5) |
| Blind / out-of-band vulnerabilities | No | OAST infrastructure and network approval (SP-6) |
| Broken access control | No | Multi-identity scanning — a new capability (SP-7) |
| Rule depth and false-positive rate | No | Nothing: this is the ZAP engine, and it is where vendor research budgets go |

> **Do not let the evaluation reduce to a finding count.** On raw detection the PoC *is* OWASP ZAP — the engine the commercial tools benchmark themselves against. Scored on "who finds more", the outcome is predetermined and the PoC's actual value is never measured. Agree the scorecard and its weights with stakeholders before the first scan.

## Evaluation scorecard and comparison protocol

Run every tool against the same application, the same environment, the same authenticated session state, the same scope and the same window. Then have one engineer manually validate a random sample of roughly thirty findings per tool, so the false-positive rate is measured rather than asserted, and key findings on a common fingerprint so overlap and unique findings can be computed. Unique findings matter far more than totals.

| Criterion | How it is measured | Expected standing of the PoC |
| --- | --- | --- |
| True positives found | Validated findings on the shared target | Behind — ZAP rule set |
| Unique findings | Findings no other tool reported, after validation | Unknown; the most informative number in the exercise |
| False-positive rate | Manual validation of a ~30-finding sample per tool | Behind, and worse still before Gate 4 |
| Authenticated coverage of an SSO application | Routes reached while authenticated; did the session hold? | Competitive — vendors frequently struggle here, and the seeded-session design is genuinely differentiated |
| Lifecycle honesty | Fix one finding, re-scan; and check what each tool claims about a finding whose route was not revisited | Ahead — coverage-aware diffing in `detections/lifecycle_diff.py`, and the only claim here backed by a reproduced incident (a live upload wrongly closed 13 findings). Ask each vendor this question directly |
| Triage experience | Can a developer act on one finding unaided? | Behind today; Gate 4 is what makes this competitive, and it is most of what a side-by-side judges |
| Onboarding cost | Elapsed time to first authenticated scan of a new app | Behind — a vendor engineer does this in a day; measure and report the PoC's number honestly |
| Developer workflow fit | Findings in the team's existing tooling without a new console | Competitive — GitHub-native SARIF delivery |
| Data residency | Does scan traffic or evidence leave Nationwide? | Ahead |
| Unattended operation | Scheduled scan with nobody watching | Behind until Gate 5 — every commercial tool has this, so its absence will be scored |
| Total cost at fleet scale | Licence and run cost across the intended application estate | Ahead, but only credible once the engineering cost of the gates is included |

Disclose every posture exclusion agreed in SP-1 to SP-7 alongside the results. A scorecard that omits them turns a deliberate safety choice into an apparent detection weakness.

## Risk register for the first internal scan

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Active scan disrupts a shared non-prod environment | Medium | High | Ladder in Gate 6, throttling, endpoint exclusions, off-hours window, kill switch, app team on notice |
| Scan reaches an SSO/IdP or an integrated partner system | Medium | High | Traverse-vs-attack scope split and a ZAP context with explicit excludes (Gate 2) |
| Wrong environment scanned via a mistyped `environment_class` | Low | Severe | Registry-verified environment class plus prod hostname pattern denies |
| Real data captured in evidence | Medium | High | Redaction review against real traffic, retention policy, no evidence in repositories |
| Session expires mid-scan and coverage silently shrinks | High | Medium | Post-scan liveness re-check and a *degraded* scan state that blocks `resolved` |
| App team rejects the findings as noise | High | High | Gate 4 before Gate 6 — never deliver the first 1,000+ alert upload without remediation text and confidence |
| Identity access blocks the pilot for weeks | Medium | Medium | Start Gate 0 and the identity conversation on day one; keep Juice Shop as the regression target meanwhile |
| Scanner loses its session early in a write-heavy scan and the pilot records a misleadingly poor result | High | High | SP-5: configure ZAP session management, re-authentication and anti-CSRF handling before the first full scan |
| Evaluation reduces to a finding count and the PoC is judged on the ZAP engine alone | High | High | Agree the weighted scorecard before the first scan; report unique findings and posture exclusions, not totals |
| Write-enabled scanning damages or drifts shared test data | Medium | Medium | SP-1: per-app `safe_forms` allow-list, agreed destructive-endpoint exclusions, and a data reset between runs |

## Open decisions

> **1. Which target?** An SSO app tests the thesis but risks schedule; a form-login app de-risks delivery but proves little beyond the pilot. Recommendation: SSO, accepting a longer Gate 3.

> **2. Who runs the scan?** Central security team as a service, or the app team self-service? This decides whether Gate 5 needs multi-tenancy and RBAC now or later.

> **3. Build or buy underneath?** The differentiated value here is governed authenticated discovery and honest lifecycle, not scanning — and it is engine-agnostic. Nothing in the new design proposal actually requires ZAP: the request corpus, session bootstrap and coverage-aware lifecycle can feed a commercial scanner instead. The answerable form of this decision is therefore not “build or buy” but “what do we build regardless of which scanner we buy” — a position that survives losing the vendor comparison, and the one most likely to survive a funding review. Settle it at this gate rather than deferring again; it changes what Gates 1, 2 and 4 are worth building.

> **4. What is parity, and who declares it?** "On par with the tools we are evaluating" needs a threshold before the scan, not after: which criteria are must-win, which are acceptable to lose, and what result would end the PoC. Without it, the comparison produces a table nobody can act on.

> **5. Who signs the scorecard?** Weighted criteria agreed before the scan are worth little if only security engineering agrees them. Get the weights signed by whoever will actually make the tooling decision, and record the SP-1 to SP-7 posture exclusions on the scorecard in advance — otherwise a deliberate safety choice is read afterwards as a detection failure.

> **6. What does a finding oblige anyone to do?** Without an SLA, ownership routing, or a triage path, alerts accumulate and the pilot's second scan is less welcome than its first.

---

Sources: NationwideDevin/ssd-dast-tool-poc, re-synced from upstream and read at commit c3bac3b (code unchanged since 7c16c01), including the new Authenticated Application Discovery design proposal. Effort is in engineering sessions and excludes approval and access lead times. Team-reported run figures are not committed to the repository and were not independently reproduced. Recommendations are the reviewer's; open decisions remain unsettled.
