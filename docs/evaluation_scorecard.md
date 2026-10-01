# Evaluation scorecard — DRAFT for sign-off

> **Status: DRAFT (W6-7).** Nothing on this page is agreed. Its weights, its must-win list and the
> posture exclusions are proposals for the people who will make the tooling decision to change and
> sign **before the first benchmark scan**. A scorecard agreed after the results are in is a
> description of the results, not a test of them.

This turns the criteria in [the readiness doc](dast_first_internal_app_readiness.md#evaluation-scorecard-and-comparison-protocol)
into something that can be signed. It exists because of one risk in that doc's register: on raw
detection this PoC *is* OWASP ZAP, the engine commercial tools benchmark themselves against. If
the evaluation comes down to "who finds more", the result is decided in advance, and what the PoC
actually adds goes unmeasured.

## 1. Posture exclusions — disclosed before any result

Each of these is a deliberate choice that suppresses detection. All of them are listed here first,
so a reader sees them before any count. Each line records the posture **as the benchmark will run
it**. The "current" column is today's default, which the signatories can change.

| # | Posture | Current default | Benchmark posture (to agree) | What it hides if kept |
|---|---|---|---|---|
| SP-1 | Write paths during exploration | `write_mode: deny`. HTML forms are still submitted by ZAP's spider; script-driven writes are replayed only on `disposable` + `write_mode: allow` apps, with `scan.reset` (W6-1) | ☐ deny · ☐ per-app `safe_forms` allow-list · ☐ allow | Injection, authorization and business logic behind forms |
| SP-1a | ZAP's active scan attacks every write it has seen, **whatever `write_mode` says** (found during W5-1 work) | Unbounded | ☐ accept · ☐ exclude write endpoints from the active scan · ☐ disposable environment | If excluded: the same classes as SP-1. If accepted: test data drifts, and Juice Shop already shows one flaky High from it |
| SP-2 | Scan duration | Per-app `max_scan_min` / `max_rule_min`; rules that were cut short are recorded in `truncated_rules` | ☐ ___ min total / ___ min per rule | Findings that were not reached; the summary now names every rule that was cut short |
| SP-3 | DOM-XSS rule 40026 | Off unless `scan.dom_xss` is enabled. Then it runs as its own bounded pass (W6-3): on DVWA, 15 min full-site, ~5 GiB, 1 new class found | ☐ disabled · ☐ enabled with a longer budget | Client-side XSS, the class that matters most for SPAs |
| SP-4 | Attack surface source | Authenticated walk plus spider, reachability measured; `scan.openapi` imports a spec and gives a declared-route denominator (W6-4) | ☐ as is · ☐ OpenAPI/GraphQL import | Endpoints and parameters the walk never sent; the summary lists the gaps it measured |
| SP-5 | Session under load | Loss is **detected and fails the scan** (W5-1); no re-authentication | ☐ detect-and-fail · ☐ add re-authentication first | A long write-heavy scan that loses its session is reported as unhealthy, not as a clean app |
| SP-6 | Out-of-band (OAST) | Out | ☐ out (disclosed) · ☐ in (callback host plus network approval) | Blind SSRF, blind XSS, blind injection, deserialization |
| SP-7 | Authorization (multi-identity) | Out | ☐ out (covered by: ________) · ☐ in | IDOR / BOLA / privilege escalation, OWASP Top 10 #1 |

## 2. Criteria, weights and must-win

**Scoring.** Each criterion is scored 0–3 per tool against the anchors below, then multiplied by
its weight. Weights sum to 100, so the maximum is 300. **A must-win criterion the PoC loses ends
the PoC however the total comes out.** A tool that fails a gating criterion is out regardless of
its score.

| Criterion | Proposed weight | Must-win? | How it is measured | PoC's expected standing (as of this draft) |
|---|---:|---|---|---|
| Authenticated coverage of the target | 15 | **Must-win** | Routes reached while authenticated, and whether the session held for the whole scan | Competitive. Seeded sessions; mid-scan loss is now detected, not silent |
| Lifecycle honesty | 10 | **Must-win** | Fix one finding and re-scan; separately, ask what each tool claims about a finding whose route was not revisited | Ahead. Coverage-aware diff; `not_scanned` is never shown as fixed — demonstrated: [fix → re-scan evidence](proof/fix_rescan_resolved.md) |
| Unique validated findings | 15 | — | Findings no other tool reported, after manual validation | Unknown. This is the most informative number here |
| Triage experience | 15 | Must not score 0 | Can a developer act on one sampled finding unaided, using only the alert? | Improved. Remediation text, parameter/attack/evidence, a replay line, a linked request/response and suppressions have all shipped |
| False-positive rate | 10 | — | Manual validation of a random ~30-finding sample per tool | Behind; ZAP's rule set. Confidence is now shown on every alert |
| Onboarding cost | 10 | — | Elapsed time from "here is the app" to the first authenticated scan | Behind. Measure it and report the number honestly |
| True positives found | 5 | — | Validated findings on the shared target | Behind (the ZAP rule set). **Weighted low on purpose**: see the introduction |
| Data residency | 5 | **Gating** | Does scan traffic or evidence leave the organisation? | Ahead |
| Developer workflow fit | 5 | — | Findings arrive in the team's existing tooling, without a new console | Competitive. GitHub-native SARIF with per-scan summaries on the run page |
| Unattended operation | 5 | — | A scheduled scan with nobody watching, with failures visible | Partly. A weekly self-test in CI; not yet against an internal app |
| Total cost at fleet scale | 5 | — | Licence plus run cost across the intended estate, including the engineering cost of the gates | Ahead, once engineering cost is counted honestly |

**Score anchors (all criteria):** 0 = absent or unusable · 1 = present but needs expert help ·
2 = usable unaided, with gaps · 3 = as good as any tool in the comparison.

## 3. Protocol

1. **Same conditions for every tool:** the same application, environment, authenticated session
   state, scope and time window. Postures are fixed by §1 before any tool runs.
2. **Validation sample.** One engineer validates a random sample of about 30 findings per tool,
   drawn by severity in proportion to that tool's output. Each is marked true positive, false
   positive or unverifiable, and the sample is kept so the rate can be re-checked.
3. **Overlap.** Findings are keyed on (route, parameter, vulnerability class), so overlap and
   unique findings can be computed. A finding only one tool reports is validated before it
   counts as unique.
4. **Lifecycle check.** Fix one validated finding, then re-scan with every tool. Separately, leave
   one route unvisited and record what each tool says about that route's findings.
5. **Triage check.** Pick three sampled true positives per tool. A developer who did not run the
   scan tries to reproduce each one using only what the tool shows, and the time taken is
   recorded.
6. **Onboarding clock.** It starts when the app is named and stops at the first authenticated scan
   whose session held. Time spent waiting on access requests is recorded separately.
7. **Report.** The posture exclusions (§1) come first. After them: unique findings, false-positive
   rate and must-win results; totals last.

## 4. What result ends the PoC

Proposed:
- The PoC loses a must-win criterion.
- The PoC's false-positive rate is more than double that of the best tool in the comparison.
- The triage check fails for all three sampled findings.

To agree: whether a result that is behind on detection but ahead on lifecycle, coverage and
residency means **continue**, or **build the governed discovery/lifecycle layer over a bought
engine** (readiness doc, open decision 3).

## 5. Sign-off

Weights, must-win list and posture choices are agreed as amended above:

| Role | Name | Date | Signature / approval link |
|---|---|---|---|
| Tooling decision owner | | | |
| Application security lead | | | |
| Pilot application owner | | | |
| Platform / environment owner | | | |
