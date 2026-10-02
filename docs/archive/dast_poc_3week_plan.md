# DAST Platform — 3-Week POC / MVP Plan

## Assumptions (adjust if these are off)

* Team: 1–2 engineers. Where a step can be parallelized with a second engineer, it is noted.
* Scope: the **Step 1 authenticated non-prod loop only**. Step 2 (blackbox/production), Qualys migration, App Registry, scheduler, on-demand console, and Archer are all out of scope for the POC.
* Goal: prove the core value loop end-to-end on **one pilot app**, plus a demo narrative for stakeholders — not a productionized, multi-app, governed system.
* Pilot target: an intentionally-vulnerable app with real auth (OWASP Juice Shop or DVWA). This is safe to attack, has known vulnerabilities to detect, and removes the need to onboard a real Nationwide app during the POC.
* Trigger: run the scan manually or via a simple GitHub Action. Full Harness CD wiring is a stretch goal, not MVP.

## What the POC must prove

1. LLM-assisted authoring can turn a recording into working Playwright flow scripts and a scope file (the platform's core differentiator and highest technical risk).
2. Authenticated replay + ZAP active scan runs against a live non-prod target, bounded by an FQDN allow/deny list, producing at least one high/medium-severity alert on an authenticated endpoint. Pin the target weakness/endpoint/ZAP-fixture in advance, but do not make the pass/fail condition one specific alert — ZAP output varies with policy, timing, and app version.
3. Detections normalize into SARIF and render in the GitHub Security tab with evidence.
4. Fingerprint-based lifecycle diff correctly tracks open / new / resolved across two scans, at the **local state-file level**. GitHub's own alert-resolution behavior after a second SARIF upload is a separate observation, not a pass/fail condition, unless independently verified.

If those four work on one app, the concept is validated. Treat each as a **risk gate**: Week 1 closes the runner/auth/safety risk, Week 2 closes the deterministic-results and LLM-authoring risk, Week 3 closes the lifecycle risk. See `dast_poc_demo_plan.md` for the phase-by-phase gate criteria.

## Components to build (MVP set)

### Core scan pipeline (highest priority)
* DAST runner — orchestrates fetch artifacts, Playwright replay through the ZAP proxy, ZAP active scan, and export. This is the heart of the POC.
* Scope enforcement (minimal) — FQDN allow/deny via the ZAP proxy filter plus a Playwright request interceptor, and a single `environment_class` check. Skip the remaining defense-in-depth controls.
* Detection normalizer + fingerprint — convert raw ZAP JSON into normalized detections with a stable fingerprint hash (`rule_id + endpoint + parameter + payload_family`).
* Evidence capture — write HAR, a few screenshots, and raw ZAP output to local disk or an S3 bucket. Redact auth cookies, bearer tokens, passwords, and sensitive request bodies before evidence is published anywhere. A local file path does not become a clickable GitHub Security-tab link on its own — link evidence via a GitHub Actions artifact (preferred), a controlled repo location, or an approved stable URL.

### Authoring CLIs (the differentiator)
* `record` — a thin Playwright crawler that captures `trace.json` / `index.json` for the pilot app.
* `generate` — the LLM step: trace to Playwright flow script(s) + `scope.json` + `auth.json` + a `zap-policy.yaml` (start from a single medium template). Timebox prompt iteration; keep a semi-manual fallback. **Safety boundary:** `validate`'s auth/allow-list checks do not make generated Python safe to execute. Prefer having the LLM emit a constrained JSON journey plan that deterministic code renders into `flow.py`; if generating Python directly, enforce AST/syntax validation, a restricted import/API allow-list (no `subprocess`, filesystem writes, sockets, `eval`/`exec`), container-only execution, mandatory proxy use, timeouts, and redaction of credentials/cookies/tokens before any trace is sent to the LLM.
* `validate` — a smoke run that replays the generated flow, confirms auth succeeds, and checks the scope guardrails.

### Results surface
* SARIF upload to the GitHub Security tab via the code-scanning API or a GitHub Action.
* Lifecycle diff (minimal) — persist the previous scan's fingerprint set in a local JSON or SQLite file, diff against the current scan, and label open / new / resolved.

### Deliberately deferred (do NOT build in the POC)
* Step 2 blackbox / production scanning, prod-safe policies, circuit breaker, rate limiting.
* Databricks ingestion service, the landing-zone boundary, Power BI dashboards — use a flat parquet/CSV and a notebook chart if you want any metrics at all.
* Drift monitoring, App Registry, scheduler, on-demand console, API triggers, Archer feed.
* Full 7-control non-prod enforcement stack, CODEOWNERS, automated PR review gates, multi-app support.
* `testdata.json` form-input framework — hand-author minimal inputs for the one pilot app.

## Three-week schedule

| Week | Focus | Key tasks | Exit milestone |
|------|-------|-----------|----------------|
| Prep (day 0) | Setup | Pick pilot app; stand up ZAP daemon; get Claude API access; create POC repo and container skeleton | Toolchain installed and reachable |
| Week 1 | Scan core | Containerize runner; Playwright auth + flow replay routed through the ZAP proxy; capture HAR; ZAP active scan bounded by a hand-written `scope.json`; get raw detections out. In parallel, build the normalizer/fingerprint/SARIF exporter/lifecycle diff against `sample_zap_output.json` and prove a hand-made SARIF upload to the GitHub Security tab. | **Minimum-viable-scanner gate:** authenticated request visible in ZAP, ≥1 high/medium alert on an authenticated endpoint, zero target traffic on unsafe scope (missing/no-env/prod), and a deliberately out-of-scope request is blocked+logged+fails the scan. HAR/screenshot capture, containerization, and the 15-minute budget are secondary checks, not gate conditions. |
| Week 2 | Authoring + results pipeline | Build `record` (trace capture); build `generate` (LLM to flow + scope + policy) and iterate prompts until the generated flow replays; build `validate` smoke run; normalizer producing fingerprinted detections + SARIF | LLM-generated artifacts drive a real scan and emit SARIF |
| Week 3 | Results UX, lifecycle, demo | SARIF into the GitHub Security tab with evidence links; lifecycle diff across two scans using a local state store; optional minimal metrics; harden, add buffer, prepare demo and a written gaps/next-steps summary | Full loop demo on one app, including fingerprint lifecycle across two scans |

Sequencing rationale: Week 1 hand-authors the artifacts on purpose so the scan pipeline (the fiddliest integration) is de-risked before the LLM work begins. If the LLM step slips in Week 2, you still have a working scanner and a demoable pipeline.

## Success criteria / demo script

1. Onboard the pilot app with `record` then `generate` then `validate`, showing LLM-generated artifacts.
2. Run a scan; show scope enforcement blocking a request to a host outside the allow-list (proves the guardrail) — enforced at the proxy/request-interception boundary, not just ZAP's own scope config, with a deterministic block-log-fail policy.
3. Show detections in the GitHub Security tab as SARIF, with severity, CWE, and a redacted evidence link (GitHub Actions artifact).
4. "Fix" one issue in the pilot app and re-scan; show that detection flip to resolved via the **local fingerprint diff**, with the others staying open. Separately note (not as a pass/fail condition) whether GitHub's Security tab also reflects the second SARIF upload.

## Top risks and mitigations

* LLM flow generation is flaky. Mitigation: start from Playwright codegen output as LLM input; keep a hand-authored flow template as a fallback so the concept can still be demoed.
* ZAP-plus-Playwright session/auth handling is finicky. Mitigation: begin with the simplest login on the pilot app and timebox; this is why it is Week 1 work.
* LLM-generated `flow.py` is executable code and validate's checks alone don't make it safe. Mitigation: prefer a constrained JSON journey plan over direct Python generation; otherwise enforce AST validation, import restrictions, and container-only execution (see `generate` CLI above).
* Scope enforcement may not block every path (redirects, alternate ports, IP literals, IPv6, host aliases). Mitigation: for the POC, enforce a single deterministic rule — proxy every request, block/log/fail on any non-allow-listed host — and document the remaining edge cases as known gaps rather than building full coverage.
* Scope creep toward Step 2, dashboards, or Harness. Mitigation: treat the deferred list above as a hard boundary for the three weeks.
* Single-engineer capacity. Mitigation: if solo, drop Week 3 metrics entirely and protect the core loop, SARIF, and lifecycle diff.

## Team-size variants

* Solo: cut optional metrics and any Databricks landing; focus strictly on the four proof points.
* Two to three engineers: parallelize the authoring CLIs against the runner in Weeks 1–2, and add a basic Databricks Delta landing table in Week 3 as an early nod to the real ingestion boundary.

## Team split & integration checkpoints (1 junior + 1 senior)

The most important move for a two-person team is to **agree the data contracts on day 1, then let each engineer build against those contracts in isolation**, integrating only at defined checkpoints. This lets the junior work productively without deep DAST knowledge (their world is "JSON in, JSON out") and keeps the project moving even if the senior's high-risk work slips.

### Split principle

Assign by **risk and knowledge dependency, not by volume**:

* **Engineer 2 (senior)** takes components that need DAST/proxy/browser judgment and where the interfaces are still fuzzy — the scan runner, the ZAP + Playwright + auth-replay wiring, and scope enforcement. This is the critical path and the thing most likely to blow the timeline.
* **Engineer 1 (junior)** takes components with a **clear input → output contract testable against a saved fixture** — the normalizer, fingerprint, SARIF exporter, and lifecycle diff. None require a running scanner: they operate on a sample ZAP JSON file, so the junior is never blocked waiting on the runner.

### Component ownership

| Component | Owner | Why |
|-----------|-------|-----|
| Scan runner (orchestration) | Eng 2 | Hardest integration; needs ZAP/Playwright/auth judgment |
| ZAP + Playwright proxy + auth replay | Eng 2 | The core technical risk of the whole POC |
| Scope enforcement (allow/deny + env check) | Eng 2 | Safety-critical; sits inside the runner |
| `generate` CLI (LLM prompt + parsing) | Eng 2, pairing with Eng 1 | Prompt design + brittle output parsing; high teaching value |
| Normalizer + fingerprint | Eng 1 | Pure function on ZAP JSON → clear contract, easy to unit-test |
| SARIF exporter | Eng 1 | Well-specified format; testable against a schema |
| Lifecycle diff | Eng 1 | Simple set comparison of two fingerprint files |
| `record` CLI (thin) | Eng 1 | Small; drives the Playwright crawl, good ramp-up |
| `validate` CLI (thin) | Eng 1 | Small; replays flow + checks scope |

### When to build separately vs. integrate

* **Day 1 — integrate first (together).** Jointly nail down the three contracts the design leans on: `scope.json` shape, the **normalized detection record**, and the **exact fingerprint formula** (`rule_id + endpoint + parameter + payload_family`). Hand-run ZAP against the pilot app once and check in a real `sample_zap_output.json` — this single fixture unblocks all of the junior's work.
* **Week 1 — build separately.** Eng 2 runs the risky spike: ZAP + Playwright + auth replay against *hand-authored* artifacts (no LLM yet), producing raw ZAP output. Eng 1 builds normalizer → fingerprint → SARIF exporter → lifecycle diff against the fixture, and uploads a hand-made SARIF to the GitHub Security tab to prove that path independently. **Checkpoint (end of Week 1):** connect the real runner output into the normalizer — a wiring exercise, not a rewrite, because both coded to the same contract.
* **Week 2 — build separately, then integrate.** Eng 2 (pairing with Eng 1) builds the `generate` CLI — LLM call, prompt, output parsing — replacing the hand-authored artifacts. Eng 1 finishes the thin `record` and `validate` CLIs and hardens modules with tests. **Checkpoint (end of Week 2):** run the full chain `record → generate → validate → runner → normalizer → SARIF → GitHub` end-to-end for the first time.
* **Week 3 — integrate continuously (mostly together).** Join the pieces, run two consecutive scans to exercise the lifecycle diff (open → resolved → closed), fix the seams, and build the demo. Parallel work shrinks and shared debugging dominates — that is expected and correct.

### Two rules that make this work

1. **Contracts before code.** Every interface between the two engineers is a written schema plus a sample file. As long as both code to the schema, integration is assembly, not negotiation.
2. **Mock the neighbor, never wait for it.** The junior always builds against the checked-in `sample_zap_output.json`; the senior builds against a hand-written `scope.json` and flow. Neither blocks on the other between the three scheduled handshakes (end of Day 1, Week 1, Week 2), plus continuous integration in Week 3.

**Critical-path risk:** the senior's runner/auth-replay spike is the critical path. If it slips, the junior still has fully-testable work against fixtures so the *project* keeps moving, but the **end-to-end demo** cannot complete until the runner lands. Protect it by timeboxing the spike in Week 1 and escalating early if auth replay against the pilot app proves stubborn.

## What this POC intentionally does not answer

* Production safety (that is the entire point of Step 2 and should not be rushed into a POC).
* Scale behavior: fleet-wide scheduling, warehouse ingestion under load, and the state-store design are validated later.
* Governance: PR review standards, policy templates, and drift SLAs are Phase 1 hardening, not POC.
* Full scope-enforcement edge cases (IPv6 forms, host aliases, alternate ports, redirect chains, IP literals) — the POC uses one deterministic block/log/fail rule instead.
* Full fingerprint canonicalization across arbitrary ZAP output variants — only the stability cases needed for the single pinned pilot app/ZAP version are tested.
* Durable/governed evidence hosting beyond a GitHub Actions artifact link.
* Whether GitHub's own SARIF-driven alert resolution matches the local lifecycle diff — observed, not asserted.

## Contract-freeze checklist (resolve on Day 1, alongside `scope.json` / detection-record / fingerprint contracts)

* FR-S4 policy: does an out-of-scope request abort the scan or block-and-continue? (Default: block, log, fail.)
* Is `auth.json` a required `generate` output? (This plan already assumes yes — reconcile with the formal requirements doc.)
* Where does evidence live so SARIF links resolve? (Default: GitHub Actions artifact.)
* Is GitHub alert auto-resolution required, or is local lifecycle diff sufficient? (Default: local only.)
* Which weakness + endpoint + ZAP fixture constitutes the Week 1 detection gate?
