# DAST POC — Architecture Overview (front to back)

The single doc that explains **what's been built and how every part fits together** — the
authoring CLIs, the runner, the detections pipeline, the contracts, the safety model, and
exactly where (and how narrowly) the LLM is used. Start here; the per-component design docs
(`runner_design.md`, `authoring_clis_design.md`, `sarif_exporter_design.md`, …) go deeper.

---

## 1. What this is

An **authenticated, non-prod, LLM-assisted DAST loop**: record a login + a short journey
through a web app, use an LLM to turn that recording into scan config, run OWASP ZAP against the
authenticated app inside a hard safety boundary, normalize the findings with stable
fingerprints, and publish them to the GitHub Security tab with lifecycle tracking across scans.

Pilot app: **OWASP Juice Shop** (intentionally vulnerable, safe to attack). Scanner: **OWASP
ZAP**. Browser automation: **Playwright + Chromium**. LLM: **Claude** (Anthropic API).

**Status:** both halves built, tested (129 tests), and verified end-to-end on real data — the
full loop runs from a single containerized command, and the four proof points all pass.

---

## 2. The whole pipeline, front to back

```
        ┌──────────────── AUTHORING (once, per app) ────────────────┐   ┌──────────── SCANNING (every run) ────────────┐
        │                                                            │   │                                              │
 human  │  record ──▶ trace.json ──▶ generate ──▶ flow.py           │   │  preflight ──▶ replay ──▶ scope-enforced     │
 +creds │  (browser   (pages,        │  scope.json  auth.json       │   │  (safety 1)   (auth via   active scan        │
        │   crawl)     forms, API,   │  zap-policy.yaml manifest lock│   │              ZAP proxy)   (safety 2)          │
        │              hosts)        │                              │   │                    │                         │
        │                            ▼                              │   │                    ▼                         │
        │                     ┌─────────────┐                       │   │            raw ZAP alerts JSON               │
        │                     │  LLM call    │  trace → JSON journey │   │                    │                         │
        │                     │  (Claude)    │  plan (data, not code)│   │                    ▼                         │
        │                     └─────────────┘                       │   │   normalizer ─▶ fingerprint                  │
        │                            │  deterministic render        │   │        │                                     │
        │                            ▼                              │   │        ▼                                     │
        │                          flow.py  ◀── validate (allowlist  │   │  detection records ──▶ SARIF ──▶ GitHub      │
        │                                       + live auth replay)  │   │        │                        Security tab │
        └────────────────────────────────────────────────────────┘   │        ▼                                     │
                                                                       │  lifecycle diff (new/open/resolved)          │
        evidence: redacted HAR + screenshots ──────────────────────────┘   (state file across two scans)             │
                                                                       └──────────────────────────────────────────────┘
```

Two phases, and the seam between them is the generated `flow.py` + `scope.json`:

- **Authoring** (`authoring/`) turns a human's recording into scan config. The **LLM lives
  here and only here.**
- **Scanning** (`runner/` → `detections/`) executes a safe authenticated scan and processes the
  results. **No LLM runs during a scan.**

---

## 3. The three subsystems

### 3a. Authoring CLIs (`authoring/`) — produce the config

| CLI | FRs | What it does |
|-----|-----|--------------|
| `record.py` | R1/R2/R3 | Drives Chromium through register → login → an authenticated page; captures `trace.json` (interactions, forms, API/XHR, hosts) + `index.json` |
| `generate.py` | G1–G4 | **LLM** turns the trace into a JSON *journey plan*; deterministic code renders `flow.py`; also emits `scope.json`, `auth.json`, `zap-policy.yaml`, `manifest.json`, `lock` |
| `validate.py` | V1/V2/V3 | Checks every host the plan would contact is in the allow-list (FR-V2), replays the generated `flow.py` to confirm auth (FR-V1), writes `validation-report.json` + non-zero exit on failure (FR-V3) |

### 3b. Runner (`runner/`) — execute a safe scan

| Module | FRs | Role |
|--------|-----|------|
| `preflight.py` | S3, NFR-2 | **Safety layer 1** — refuse to scan before any traffic if scope is missing/`prod`/unbounded |
| `replay.py` | S1, R2 | Launch Chromium proxied through ZAP; run the flow so ZAP observes authenticated traffic |
| `scope_guard.py` | S4, NFR-4 | **Safety layer 2** — `page.route` interceptor; block/log/fail any out-of-allow-list request |
| `scan.py` | S1, S2 | Port of the capture-script choreography: spider + bounded active scan → raw ZAP JSON |
| `evidence.py` | E1 | Capture HAR + screenshot, **redact secrets**, reference from records/SARIF |
| `main.py` | all | Chain preflight → fresh ZAP session → replay → scan → normalize; exit code = the Phase 1 gate |

### 3c. Detections pipeline (`detections/`) — process the results

| Module | FRs | Role |
|--------|-----|------|
| `normalizer.py` | N1 | Raw ZAP alert → contract-shaped detection record (streaming) |
| `fingerprint.py` | N2 | Stable `sha256(rule_id \| endpoint_pattern \| parameter \| payload_family)` |
| `sarif_export.py` | X1 | Records → SARIF 2.1.0 (severity→level, `security-severity`, CWE tags, fingerprint in `partialFingerprints`) |
| `github_upload.py` | X2 | gzip+base64 the SARIF, POST to the code-scanning API |
| `lifecycle_diff.py` | L1/L2 | Compare two scans' fingerprint sets → label new/open/resolved; persist state |

### 3d. Contracts (`contracts/`) — the frozen interfaces

`scope.json`(+schema), `detection.schema.json`, the fingerprint formula (`README.md`),
`trace.schema.json`, `journey.schema.json`, the vendored `sarif-2.1.0.schema.json`, and the real
`sample_zap_output.json` fixture. Everything is written *to* these; they're the seams that let
each part be built and tested independently.

---

## 4. Where the LLM fits (and where it doesn't)

The LLM is a **single, stateless, authoring-time step**. It reads the recording and returns a
**constrained JSON journey plan** — *data*. Deterministic code turns that data into `flow.py`.
The model never authors executable code and never runs during a scan.

```
   trace.json (redacted: no creds)
        │
        ▼
   ┌───────────────────────────────┐
   │  authoring/generate.py         │
   │                                │
   │  plan_from_llm() ── Claude ──▶ │  { "login": {...selectors...},
   │     (one Messages API call)    │    "journey": [ {goto ...}, {api_get ...} ] }
   │         │                      │            │  validated against
   │         │  (on failure)        │            │  journey.schema.json
   │         ▼                      │            ▼
   │  journey_from_trace()  ← deterministic fallback (no key / bad output)
   │         │                      │
   │         ▼                      │
   │  render_flow(plan) ────────────┼──▶  flow.py   (templated Python, AST-checked)
   │  emit_scope / zap-policy / …   │      scope.json, auth.json, zap-policy.yaml, manifest, lock
   └───────────────────────────────┘
```

Key properties:
- **Data in, data out.** Input: a redacted trace (no credentials). Output: a JSON plan. The
  plan is schema-validated; deterministic `render_flow()` produces `flow.py`. → decision **D8**.
- **LLM-optional.** With `ANTHROPIC_API_KEY` set it's the primary path; otherwise a deterministic
  `trace → plan` fallback keeps the pipeline runnable. → decision **D9**.
- **Stateless, one-shot.** A single Anthropic Messages API request — no multi-turn conversation,
  no persistent agent, no connection to the target app or ZAP.
- **Out of the scan path.** After `generate`, the LLM is done. `validate`, `runner`, and every
  detection stage involve **no LLM**. Re-scanning reuses `flow.py` without calling the model.

### The two "sessions" — different things that share a word

```
   USER (APP) SESSION                          LLM (API) SESSION
   ------------------                          -----------------
   the authenticated login to Juice Shop       one call to the Claude API
   (JWT in localStorage after form login)

   where:  runner/replay.py (scan time)        where:  authoring/generate.py (authoring time)
   when:   established live, every scan         when:   once, before any scan
   state:  STATEFUL (JWT/cookies persist        state:  STATELESS (single request/response)
           so ZAP reaches auth endpoints)
   talks:  the target app, via the ZAP proxy    talks:  api.anthropic.com only
   holds:  REAL credentials + JWT               holds:  a REDACTED trace (no secrets)
   trust:  trusted (our creds, our target)      trust:  UNTRUSTED output — schema-validated,
                                                        rendered by deterministic code
```

The user session is the stateful authenticated connection **to the app being scanned** (what
makes the scan "authenticated"). The LLM session is a stateless config-authoring call that never
touches the app, ZAP, or any secret.

---

## 5. The safety model (NFR-2 — the top guardrail)

Two independent, fail-closed layers, so a bug in one can't send unsafe traffic:

```
   scope.json ──▶ preflight (layer 1)                    every browser request
                  ├─ missing / no environment_class ──▶ ABORT     │
                  ├─ environment_class == prod ─────────▶ ABORT     ▼
                  └─ empty allow-list ──────────────────▶ ABORT   scope_guard (layer 2)
                          │ (safe)                                 ├─ host in allow-list ─▶ continue ─▶ ZAP proxy
                          ▼                                        └─ else ──────────────▶ block + log + FAIL scan
                    launch browser / scan                                (FR-S4: block/log/fail)
```

Plus: evidence HARs are **redacted** (auth headers, cookies, tokens, passwords) at capture,
before anything could publish them; credentials come from env, never committed; the LLM only
ever sees a redacted trace.

---

## 6. Data & contract flow (one concrete example)

Following the High SQL Injection from raw scan to Security-tab alert:

```
ZAP alert                          → normalizer                 → detection record
{ pluginId:"40018",                  rule_id  "40018"             { rule_id:"40018",
  alert:"SQL Injection",             title    "SQL Injection"       title:"SQL Injection",
  risk:"High",                       severity High→"high"           severity:"high",
  url:".../rest/products/            endpoint /rest/products/       endpoint:"/rest/products/search",
       search?q=apple%27",                    search  (query dropped) parameter:"q",
  param:"q", cweid:"89" }            cwe      "CWE-89"              cwe_id:"CWE-89",
                                     fingerprint = sha256(          fingerprint:"ece130…",
                                       "40018|/rest/products/       status:"open" }
                                        search|q|sqli")
        │
        ▼  sarif_export
   SARIF result: level "error", security-severity "8.0", tag external/cwe/cwe-89,
                 partialFingerprints.dastFingerprint/v1 = "ece130…"
        │
        ▼  github_upload  →  GitHub Security tab: "SQL Injection" alert, High severity
        │
        ▼  lifecycle_diff (scan 2, after a fix): fingerprint "ece130…" gone from current
                          → labeled RESOLVED, others stay OPEN
```

The **fingerprint** is the thread that ties it all together: it's the stable identity SARIF
carries into GitHub (so re-uploads dedupe) and the key the lifecycle diff compares across scans.

For how `journey.schema` steps become `flow.py` and then authenticated requests ZAP records,
see §4 above + `authoring_clis_design.md`.

---

## 7. The four proof points (definition of done)

| # | Proof point | Delivered by |
|---|-------------|--------------|
| 1 | Authenticated scan | runner (`replay` through ZAP) — ZAP records `Authorization: Bearer` requests |
| 2 | Scope enforcement blocks out-of-list requests | `scope_guard` (block/log/fail), proven live |
| 3 | Detections in the GitHub Security tab | `sarif_export` + `github_upload` (38 alerts, SQLi = High) |
| 4 | Fingerprint lifecycle across two scans | `lifecycle_diff` (fix → resolved, others open) |

All four are demonstrable end-to-end on real data, and the **generated** `flow.py` (LLM path
verified) drives a passing runner gate — the Week-2 checkpoint.

---

## 8. How to run

**One command (containerized):**
```bash
docker compose up --build --abort-on-container-exit --exit-code-from runner
```

**Authoring + scan (local dev), with the LLM:**
```bash
export ANTHROPIC_API_KEY=…  AUTH_EMAIL=…  AUTH_PASSWORD=…  RUNNER_CHROMIUM_NO_SANDBOX=1
python -m authoring.record   --app-id juice-shop --base-url http://juice:3000 --zap-proxy http://localhost:8080 --out-dir rec/
python -m authoring.generate --trace rec/trace.json --out-dir rec/            # LLM → flow.py + config
python -m authoring.validate --plan rec/journey.json --scope rec/scope.json --flow rec/flow.py   # allow-list + live auth
python -m runner.main        --scope rec/scope.json --flow rec/flow.py --records-out rec/records.json
python -m detections.sarif_export rec/records.json -o out.sarif
python -m detections.github_upload out.sarif --owner <owner> --repo <repo>
```

Full run/verify guide (both paths, containerization gotchas, troubleshooting):
`testing_and_running_roadmap.md`.

---

## 9. Testing philosophy (why you can trust it)

Objective, **test-first** where it counts: expectations are anchored to **independent oracles**
— an external SHA tool, the official OASIS SARIF schema, published CWE facts, the raw fixture,
and sensitivity/negative checks — not to the code itself. Safety-critical and pure modules
(preflight, scope guard, fingerprint, lifecycle diff, the authoring transforms) were committed
**red first**, then implemented to green, and each suite was proven to *bite* via a
break/restore. Live/integration parts (the crawl, the LLM call, the auth replay, the ZAP scan)
are validated by running them. See `validation_and_testing.md`.

---

## 10. Repo map

```
contracts/       frozen interfaces: scope/detection/trace/journey schemas, fingerprint formula,
                 vendored SARIF schema, sample_zap_output.json fixture
authoring/       record.py · generate.py (LLM) · validate.py
runner/          preflight · replay · scope_guard · scan · evidence · main · capture_zap_fixture.sh
detections/      normalizer · fingerprint · sarif_export · github_upload · lifecycle_diff
security/dast/juice-shop/   hand-authored flow.py + app scope.json (+ gitignored evidence/)
tests/           objective suites (129 tests) — one per module + acceptance suites
docs/            requirements, 3-week plan, demo plan, day-1 runbook, phase-1 demo script
docs/junior_engineer/   this file + all design/decision docs
Containerfile · compose.yaml · versions.lock · requirements*.txt · pyproject.toml
```

## 11. Decisions & known gaps

Every design decision (D1–D9) and known limitation (KI1–KI3) is logged with rationale and a
"how to interrogate later" note in `decisions_and_known_issues.md` — including the LLM safety
boundary (D8), LLM-optional+fallback (D9), the two-layer safety model (D2), and the deferred
items (endpoint-pattern heuristic, scope edge cases, evidence hosting).
