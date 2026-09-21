# ssd-dast-poc — Agentic DAST platform (POC)

Proof-of-concept for an authenticated, non-prod, LLM-assisted DAST loop: drive a real browser
through a login, scan the authenticated app with OWASP ZAP inside a hard safety boundary,
normalize the findings with stable fingerprints, and publish them to the GitHub Security tab
with lifecycle tracking across scans.

**Status: the full loop works end-to-end on real data**, including the Phase 2 authoring CLIs
(`record → generate → validate`). 213 automated tests pass; the containerized single-command
run is verified; and the **auto-generated `flow.py` drives a passing scan** end-to-end
(Week-2 checkpoint). The LLM path in `generate` runs with an `ANTHROPIC_API_KEY`; without one
it uses a deterministic fallback (verified here).

An optional **seeded-session + LLM exploration** authoring path is also built and verified: a
human seeds an authenticated session once (`seed`), an LLM-driven loop explores the authenticated
surface behind the same safety boundary (`explore`), and the lifecycle diff is **coverage-aware**
— it only labels a finding `resolved` if the scan actually exercised its route with its rule
enabled, else `not_scanned`. See `docs/junior_engineer/seeded_session_exploration_design.md`.

## The four proof points (definition of done)

| # | Proof point | Status |
|---|-------------|--------|
| 1 | Authenticated scan through ZAP | ✅ live-validated (`runner/`) |
| 2 | Scope enforcement blocks out-of-allow-list requests | ✅ live-validated (block/log/fail) |
| 3 | Detections in the GitHub Security tab (SARIF) | ✅ verified (38 alerts, SQLi = High) |
| 4 | Fingerprint lifecycle across two scans (open/new/resolved) | ✅ verified (fix → resolved) |

## Architecture

```
scope.json ─▶ preflight ─▶ replay (Chromium ─▶ ZAP proxy) ─▶ scope-enforced active scan ─▶ raw ZAP JSON
 (safety 1)   ABORT if      (auth login)   page.route block/    (bounded to allow-list)         │
             unsafe                          log/fail (safety 2)                                  ▼
                                                                          normalizer ─▶ fingerprint
   evidence: HAR (redacted) + screenshot ──────────────────────────────────────┐         │
                                                                                ▼         ▼
                                              lifecycle diff ◀── detection records ─▶ SARIF ─▶ GitHub Security tab
```

- **`authoring/`** — produce scan config from a login journey: `record` (browser crawl) **or**
  `seed` + `explore` (human-seeded session + LLM-driven exploration) → `trace.json`; `generate`
  (LLM → JSON plan → `flow.py` + config); `validate` (allow-list + auth replay).
- **`runner/`** — the scanner: `preflight` (never scan prod/unbounded), `replay`/`replay_seeded`
  (Playwright auth through the ZAP proxy, form-login or seeded session), `scope_guard` (per-request
  block/log/fail; phase-split enforce/discovery), `action_policy` + `redact` (exploration safety),
  `scan` (bounded ZAP active scan), `coverage` (route×rule surface exercised), `evidence` (redacted
  HAR + screenshot), `main` (one-command gate).
- **`detections/`** — the results pipeline: `normalizer`, `fingerprint`, `sarif_export`,
  `github_upload`, `lifecycle_diff` (coverage-aware: `new`/`open`/`resolved`/`not_scanned`).
  Pure, streaming, fixture-testable.
- **`contracts/`** — frozen shared contracts: `scope.json`/`scope.schema.json`,
  `detection.schema.json`, the fingerprint formula (`README.md`), the vendored SARIF schema,
  and the real ZAP fixture `sample_zap_output.json`.
- **`security/dast/<app>/`** — per-app flow + scope (+ gitignored `evidence/`).
- **`docs/junior_engineer/`** — design + decision docs (see below).

## Prerequisites

- Python 3.11+ (3.12 used; macOS ships 3.9 — `brew install python@3.12`)
- Docker (or Podman) — for ZAP + the pilot app (OWASP Juice Shop)
- `pip install -r requirements-dev.txt` then `python -m playwright install chromium`

## Run it

### Option A — one command (containerized, NFR-5)

```bash
docker compose up --build --abort-on-container-exit --exit-code-from runner
```

Builds the runner, starts Juice Shop + ZAP + the runner on one network, runs a safe
authenticated scan, and exits with the **Phase 1 gate** as its code (0 = pass). Detection
records land in `./out/records.json`. Images are pinned by digest (`versions.lock`).

### Option B — local dev loop

```bash
# 1. Start the pilot app + ZAP daemon on one network
docker network create dast
docker run -d --name juice --network dast -p 3000:3000 bkimminich/juice-shop
docker run -d --name zap  --network dast -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -silent \
  -config api.disablekey=true -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true

# 2. End-to-end runner (preflight → auth replay → scope-enforced scan → normalize)
python -m runner.main \
  --scope security/dast/juice-shop/scope.json \
  --flow  security/dast/juice-shop/flow.py \
  --base-url http://juice:3000 --records-out out/records.json
#   -> gate: {authenticated, scope_ok, has_high_or_medium, passed: true}  (exit 0)

# 3. Lifecycle across two scans, coverage-aware (fix a finding → "resolved"; unreached → "not_scanned")
python -m detections.lifecycle_diff out/records.json --app-id juice-shop --state out/state.json \
  --coverage out/coverage.json -o out/labeled.json        # coverage from `runner.main --coverage-out`

# 4. Publish to the GitHub Security tab (SARIF) from the LABELED set: the export drops only
#    `resolved` and carries `not_scanned` forward, so GitHub never auto-closes a finding the scan
#    did not reach (it marks anything absent from the newest upload "fixed").
python -m detections.sarif_export out/labeled.json -o out.sarif
python -m detections.github_upload out.sarif --owner <owner> --repo <repo>
```

The results pipeline also runs standalone against the committed fixture (no scanner needed):
```bash
python -m detections.normalizer contracts/sample_zap_output.json --app-id juice-shop | \
  python -m detections.sarif_export -o out.sarif
```

### Option C — seeded session + LLM exploration (authoring)

Removes the autonomous-login dependency: a human seeds an authenticated session once, then an
LLM-driven loop explores the authenticated surface (behind the same safety boundary) and emits the
same `trace.json` as `record`. The LLM runs only at **authoring** time; the committed trace/bundle
is what scans replay (deterministic — protects the lifecycle diff).

```bash
# 1. Seed a session once (human logs in; --assisted auto-logs-in the pilot). Saved gitignored.
python -m authoring.seed --base-url http://juice:3000 --zap-proxy http://localhost:8080 \
  --assisted --storage-state .secrets/storageState.json     # AUTH_EMAIL/AUTH_PASSWORD from env

# 2. Explore from a seed config (storage_state + seed_routes); LLM primary, deterministic fallback.
python -m authoring.explore --seed security/dast/juice-shop/seed.json \
  --scope security/dast/juice-shop/scope.json --zap-proxy http://localhost:8080 --out-dir rec/
#   --no-llm forces the deterministic fallback proposer

# 3. From here it rejoins the normal path: generate → validate → runner → detections (as above).

# Coverage-aware lifecycle: have the runner emit the (route×rule) surface it exercised, then feed
# it to the diff so 'resolved' is only claimed for exercised pairs (else 'not_scanned').
python -m runner.main --scope … --flow … --records-out out/records.json --coverage-out out/coverage.json
python -m detections.lifecycle_diff out/records.json --app-id juice-shop \
  --state out/state.json --coverage out/coverage.json
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # 213 tests
```

Testing philosophy is **objective / test-first**: expectations are anchored to independent
oracles (an external SHA tool, the official OASIS SARIF schema, published CWE facts, the raw
fixture, sensitivity checks), and the safety-critical modules were written test-first (tests
committed red, then implemented to green). See `docs/junior_engineer/validation_and_testing.md`.

## Safety (NFR-2 — the top guardrail)

Two independent layers, both fail-closed: **preflight** refuses to scan when `scope.json` is
missing/invalid, has no `environment_class`, is `prod` (explicit + case-insensitive), or has no
allow-list — *before any traffic*; and the **scope guard** blocks, logs, and fails on any
in-flight request to a non-allow-listed host. Evidence HARs are **redacted** (auth headers,
cookies, tokens, passwords) at capture, before anything could publish them.

The LLM exploration path adds matching guardrails: a **deterministic action policy** (default-deny
state-changing verbs + `avoid_action_list`; the LLM's own "non-destructive" label is never trusted),
a **phase-split scope guard** (block-and-continue during discovery, block/log/fail during the scan),
and a **redactor** that scrubs DOM/XHR bodies before anything reaches the model.

## Docs

| Doc (`docs/junior_engineer/`) | What |
|---|---|
| `architecture_overview.md` | **Start here** — front-to-back: how every part fits, the LLM's role, diagrams |
| `remaining_work_plan.md` | The 3-week scope + component inventory |
| `testing_and_running_roadmap.md` | How to run/test (both paths), verification checklist, containerization issues + fixes |
| `validation_and_testing.md` | Objective-testing method, catalogue, acceptance checklist |
| `reproducing_the_sample.md` | Regenerate the ZAP fixture from scratch |
| `sarif_exporter_design.md`, `github_upload_design.md`, `lifecycle_diff_design.md` | Results-pipeline component designs |
| `runner_design.md` | Full runner design + per-component frozen specs (§7–§13) |
| `authoring_clis_design.md` | Phase 2 record/generate/validate design + the LLM safety architecture |
| `seeded_session_exploration_design.md` | Seeded-session + LLM exploration loop (`seed`/`explore`), coverage-aware lifecycle (R1/R2) |
| `chromium_and_playwright_setup.md` | All Playwright/Chromium usage + gotchas |
| `decisions_and_known_issues.md` | Every design decision (D1–D10) + known gaps (KI1–KI4) |

Background specs: `docs/dast_poc_requirements.md`, `dast_poc_3week_plan.md`,
`dast_poc_demo_plan.md`, `dast_poc_day1_runbook.md`.

## Known gaps (documented, out of POC scope)

- `endpoint_pattern` id-collapsing is a heuristic (KI1) — per-app route config / OpenAPI later.
- Scope matching is host-based (KI2) — scheme/port/redirect/IPv6 edge cases deferred.
- Durable/governed evidence hosting beyond a local/CI artifact; evidence isn't volume-mounted
  out of the compose runner (add a volume to persist it).
