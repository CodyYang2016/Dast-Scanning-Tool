# DAST Platform — 3-Week POC / MVP Plan

## Assumptions (adjust if these are off)

* Team: 1–2 engineers. Where a step can be parallelized with a second engineer, it is noted.
* Scope: the **Step 1 authenticated non-prod loop only**. Step 2 (blackbox/production), Qualys migration, App Registry, scheduler, on-demand console, and Archer are all out of scope for the POC.
* Goal: prove the core value loop end-to-end on **one pilot app**, plus a demo narrative for stakeholders — not a productionized, multi-app, governed system.
* Pilot target: an intentionally-vulnerable app with real auth (OWASP Juice Shop or DVWA). This is safe to attack, has known vulnerabilities to detect, and removes the need to onboard a real Nationwide app during the POC.
* Trigger: run the scan manually or via a simple GitHub Action. Full Harness CD wiring is a stretch goal, not MVP.

## What the POC must prove

1. LLM-assisted authoring can turn a recording into working Playwright flow scripts and a scope file (the platform's core differentiator and highest technical risk).
2. Authenticated replay + ZAP active scan runs against a live non-prod target, bounded by an FQDN allow/deny list.
3. Detections normalize into SARIF and render in the GitHub Security tab with evidence.
4. Fingerprint-based lifecycle diff correctly tracks open / new / resolved across two scans.

If those four work on one app, the concept is validated.

## Components to build (MVP set)

### Core scan pipeline (highest priority)
* DAST runner — orchestrates fetch artifacts, Playwright replay through the ZAP proxy, ZAP active scan, and export. This is the heart of the POC.
* Scope enforcement (minimal) — FQDN allow/deny via the ZAP proxy filter plus a Playwright request interceptor, and a single `environment_class` check. Skip the remaining defense-in-depth controls.
* Detection normalizer + fingerprint — convert raw ZAP JSON into normalized detections with a stable fingerprint hash (`rule_id + endpoint + parameter + payload_family`).
* Evidence capture — write HAR, a few screenshots, and raw ZAP output to local disk or an S3 bucket.

### Authoring CLIs (the differentiator)
* `record` — a thin Playwright crawler that captures `trace.json` / `index.json` for the pilot app.
* `generate` — the LLM step: trace to Playwright flow script(s) + `scope.json` + `auth.json` + a `zap-policy.yaml` (start from a single medium template). Timebox prompt iteration; keep a semi-manual fallback.
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
| Week 1 | Scan core | Containerize runner; Playwright auth + flow replay routed through the ZAP proxy; capture HAR; ZAP active scan bounded by a hand-written `scope.json`; get raw detections out | End-to-end scan produces real ZAP detections on a live target, scope-bounded (artifacts hand-written, no LLM yet) |
| Week 2 | Authoring + results pipeline | Build `record` (trace capture); build `generate` (LLM to flow + scope + policy) and iterate prompts until the generated flow replays; build `validate` smoke run; normalizer producing fingerprinted detections + SARIF | LLM-generated artifacts drive a real scan and emit SARIF |
| Week 3 | Results UX, lifecycle, demo | SARIF into the GitHub Security tab with evidence links; lifecycle diff across two scans using a local state store; optional minimal metrics; harden, add buffer, prepare demo and a written gaps/next-steps summary | Full loop demo on one app, including fingerprint lifecycle across two scans |

Sequencing rationale: Week 1 hand-authors the artifacts on purpose so the scan pipeline (the fiddliest integration) is de-risked before the LLM work begins. If the LLM step slips in Week 2, you still have a working scanner and a demoable pipeline.

## Success criteria / demo script

1. Onboard the pilot app with `record` then `generate` then `validate`, showing LLM-generated artifacts.
2. Run a scan; show scope enforcement blocking a request to a host outside the allow-list (proves the guardrail).
3. Show detections in the GitHub Security tab as SARIF, with severity, CWE, and evidence.
4. "Fix" one issue in the pilot app and re-scan; show that detection flip to resolved via the fingerprint diff, with the others staying open.

## Top risks and mitigations

* LLM flow generation is flaky. Mitigation: start from Playwright codegen output as LLM input; keep a hand-authored flow template as a fallback so the concept can still be demoed.
* ZAP-plus-Playwright session/auth handling is finicky. Mitigation: begin with the simplest login on the pilot app and timebox; this is why it is Week 1 work.
* Scope creep toward Step 2, dashboards, or Harness. Mitigation: treat the deferred list above as a hard boundary for the three weeks.
* Single-engineer capacity. Mitigation: if solo, drop Week 3 metrics entirely and protect the core loop, SARIF, and lifecycle diff.

## Team-size variants

* Solo: cut optional metrics and any Databricks landing; focus strictly on the four proof points.
* Two to three engineers: parallelize the authoring CLIs against the runner in Weeks 1–2, and add a basic Databricks Delta landing table in Week 3 as an early nod to the real ingestion boundary.

## What this POC intentionally does not answer

* Production safety (that is the entire point of Step 2 and should not be rushed into a POC).
* Scale behavior: fleet-wide scheduling, warehouse ingestion under load, and the state-store design are validated later.
* Governance: PR review standards, policy templates, and drift SLAs are Phase 1 hardening, not POC.
