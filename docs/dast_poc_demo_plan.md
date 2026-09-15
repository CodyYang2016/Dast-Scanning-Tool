# DAST POC — Demo Plan (Risk-Gated)

Companion to `dast_poc_requirements.md` and `dast_poc_3week_plan.md`. This plan reframes
the three milestones as **risk gates**, not feature showcases. Each phase closes the single
biggest remaining source of technical or safety risk before the next begins. Where the review
pushed toward production hardening, those items are captured as **known gaps** rather than build
work, to stay inside the scope boundary in requirements section 3.2.

## Guiding principle

> Phase 1 proves **safe authenticated scanning**. Phase 2 proves **deterministic result handling**
> before adding LLM variability. Phase 3 proves **lifecycle behavior** and the polished full loop.

Two structural rules carried over from the 3-week plan:
1. **Contracts before code.** Freeze `scope.json`, the normalized detection record, and the
   fingerprint formula on Day 1 (see the contract-freeze checklist at the end).
2. **Mock the neighbor, never wait for it.** The results pipeline is built against a checked-in
   `sample_zap_output.json` fixture **starting in Week 1**, in parallel with the runner spike — it
   does not wait for Week 2.

Engineer naming matches the 3-week plan: **Engineer 1 (junior)** owns the fixture-driven results
pipeline; **Engineer 2 (senior)** owns the runner/proxy/auth spike.

---

## Phase 1 — Safe deterministic scanner (Week 1)

**Goal:** prove the central integration and the safety boundary. Nothing else is allowed to make
this gate look like it failed.

### Primary gate — "minimum viable scanner"
> Given a hand-authored `flow.py` and `scope.json`, the runner authenticates through ZAP, performs
> an active scan, produces at least one expected detection, and refuses unsafe configuration before
> any traffic is sent.

Exit criteria (all required):
- An authenticated request is visible in ZAP (proxy + auth + replay works).
- At least one **high/medium** alert is produced on an **authenticated endpoint**
  (not one specific SQLi alert — see below).
- Unsafe scope cases (missing `scope.json`, no `environment_class`, `environment_class == prod`)
  produce **zero** target traffic.
- A deliberately injected out-of-allow-list request is **blocked, logged, and fails the scan**
  (deterministic block/log/fail policy).

### Secondary exit checks (desirable, not gate conditions)
- HAR + at least one screenshot captured.
- Containerized single-command run.
- Full scan completes within the 15-minute budget (FR-S5).

Treating evidence, container polish, and the time budget as secondary means a working proxy
integration is never masked by an incomplete peripheral feature.

### Detection assertion (avoid brittle pass/fail)
Pin the target, not a single alert:
- one expected Juice Shop weakness,
- one authenticated endpoint,
- one raw ZAP fixture (`sample_zap_output.json`),
- assertion: **"at least one high/medium alert on an authenticated endpoint."**

Record the exact **Juice Shop image tag** and **ZAP version** in the lock file (NFR-1).

**Requirements covered:** FR-S1–S5, FR-R2, FR-E1, NFR-2, NFR-5

### Current build status (as of latest `main`)

**Both phases are now built and verified.** The Phase 2 deterministic results pipeline
(`detections/` normalizer, fingerprint, SARIF export, GitHub upload, lifecycle diff) and the
**entire Phase 1 `runner/`** are implemented and tested (107 objective tests). The whole loop
runs from a single containerized command and passes the Phase 1 gate end-to-end.

| Phase 1 component | Status | Where / evidence |
|-------------------|--------|------------------|
| Hand-authored `flow.py` | ✅ done | `security/dast/juice-shop/flow.py` — register → form login → authenticated view |
| ZAP proxy integration | ✅ done | `runner/replay.py` routes Chromium through the ZAP proxy; ZAP records the traffic |
| Authentication & request replay | ✅ done | live-verified: ZAP saw the login POST + 8 `Authorization: Bearer` requests |
| Active scan | ✅ done | `runner/scan.py` (spider + bounded ascan, host-bounded) → raw ZAP JSON |
| Expected high/medium detection | ✅ done | live scan → normalizer produced high/medium detections (gate `has_high_or_medium`) |
| Unsafe-configuration preflight | ✅ done | `runner/preflight.py` — aborts on missing/no-env/prod/no-allow-list before traffic |
| Block, log, fail on out-of-scope | ✅ done | `runner/scope_guard.py` — `page.route` block/log/fail; injected off-list host blocked live |
| Pinned Juice Shop/ZAP versions | ✅ done | `versions.lock` (images pinned by digest) |
| `sample_zap_output.json` fixture | ✅ done | 38 alerts, 1 High SQLi — committed |
| HAR & screenshots | ✅ done | `runner/evidence.py` — HAR + screenshot per scan, **redacted**, referenced from records/SARIF |
| Containerized single-command run | ✅ done | `Containerfile` + `compose.yaml`; `docker compose up …` → gate passed, `out/records.json` |
| 15-minute performance target | ✅ met | measured runner wall-clock ≈ 3m36s |

**Gate result (verified):** `docker compose up --build --abort-on-container-exit --exit-code-from
runner` → `{authenticated: true, scope_ok: true, has_high_or_medium: true, detections: 1351,
passed: true}`, exit 0. Details in `docs/junior_engineer/testing_and_running_roadmap.md`.

### Completion plan for Phase 1

Steps 1 and 3 are pure-Python and testable without a live scan — do them first to lock the safety
contract. Step 2 (auth replay) is the schedule risk; if it slips, Steps 1/3/4 still demonstrate the
guardrail and the ZAP data path independently.

1. **`runner/preflight.py`** — load + schema-validate `scope.json`; abort with a clear message and
   non-zero exit on missing / no `environment_class` / `environment_class == prod`, before any
   traffic (FR-S3, NFR-2). Gates everything.
2. **Hand-authored `flow.py` + auth replay** — `security/dast/juice-shop/flow.py` logs into Juice
   Shop and hits one authenticated endpoint; `runner/replay.py` launches Chromium with its proxy
   set to the ZAP daemon so ZAP observes authenticated traffic (FR-S1, FR-R2). Time-box this.
3. **Request-boundary scope enforcement** — a Playwright `page.route` interceptor that blocks any
   host not in `fqdn_allow_list` (or in the deny-list), logs each decision (NFR-4), and fails the
   scan (deterministic block/log/fail). Include the injected out-of-scope request as a test (FR-S4).
4. **Active-scan orchestration** — `runner/scan.py` ports the capture script's spider + bounded
   active-scan calls, bounded to allow-listed hosts, emitting raw ZAP JSON into the existing
   normalizer (FR-S1/S2). Closes the live ZAP→Norm path.
5. **Evidence capture** — HAR + ≥1 screenshot per scan under
   `security/dast/juice-shop/evidence/<scan-id>/`, referenced by the record's `evidence_path`
   (FR-E1).
6. **Packaging + version pins** — Containerfile bundling ZAP + Chromium + runner with one
   documented command (NFR-5); a lock file pinning the Juice Shop image tag + ZAP + Playwright
   versions (NFR-1). Then measure end-to-end < 15 min (FR-S5).
7. **Wire the gate** — `runner/main.py` chaining preflight → replay → scope-enforced scan →
   normalizer, then verify the minimum-viable-scanner gate criteria above.

### Checkpoint — end of Week 1
Per the 3-week plan's team-split checkpoints: wire the real runner output into Engineer 1's
already-built normalizer. This is a wiring exercise, not a rewrite, because both engineers coded to
the same `scope.json` / detection-record / fingerprint contracts frozen on Day 1. By this point
Engineer 1 has also already uploaded a hand-made SARIF to the GitHub Security tab to prove that
path independently (see Phase 2 below — it runs concurrently with this phase, not after it).

---

## Phase 2 — Contracted results pipeline + generated artifacts (Week 1–2)

> **Build status — DONE (verified).** The results pipeline (`detections/`) and the authoring
> CLIs (`authoring/record`, `generate`, `validate`) are built and tested (129 tests). The LLM
> emits a schema-validated JSON journey plan and deterministic code renders `flow.py` (safety
> boundary, D8); `generate` is LLM-primary with a deterministic fallback (D9), and `auth.json`
> is emitted (the FR-G3 "fourth file"). **Verified live (fallback path):** `record → generate →
> validate` (allow-list + live auth replay) → the generated `flow.py` drove `runner.main` to a
> **passing gate** (1212 detections) — the Week-2 checkpoint. LLM path verified separately with
> `ANTHROPIC_API_KEY`. See `docs/junior_engineer/authoring_clis_design.md`.

**Goal:** prove deterministic result handling and the external GitHub path **before** introducing
LLM variability. The deterministic half is **not** a Week 2 activity — per the 3-week plan's team
split, Engineer 1 builds it starting Day 1/Week 1, in parallel with Engineer 2's Phase 1 spike, so
it is proven and stable before the LLM step begins in Week 2.

### Parallel ownership (matches 3-week plan team split)
- **Engineer 2 (senior):** ZAP/Playwright runner and safety (Phase 1) — Week 1.
- **Engineer 1 (junior):** schemas, normalizer, fingerprinting, SARIF, lifecycle fixtures — all
  against `sample_zap_output.json`, no running scanner required — **starting Week 1**.

Only after those contracts are stable (end of Week 1): LLM generation and generated-flow
integration begin, owned by Engineer 2 pairing with Engineer 1.

### Demonstration sequence
1. Deterministic path first: fixture -> normalized record -> SARIF -> **GitHub Security tab**.
   Do this **in Week 1**, alongside the runner spike, so GitHub Advanced Security enablement,
   token scopes, and SARIF rendering are proven as external-integration risks, not discovered in
   the final demo.
2. Show `record` (trace capture) — Week 2.
3. Show `generate` — Week 2.
4. Show `validate` — Week 2.
5. Run the generated bundle through the already-proven Phase 1 scanner — Week 2.

### Checkpoint — end of Week 2
Per the 3-week plan: run the full chain `record → generate → validate → runner → normalizer →
SARIF → GitHub` end-to-end for the first time.

### LLM safety boundary (new, required)
An LLM-generated `flow.py` is executable code; `validate`'s auth + allow-list checks do **not** make
it safe. Preferred design:

> The LLM emits a **constrained JSON journey plan**; deterministic code renders that plan into
> `flow.py`. This also makes FR-G4 idempotency nearly free.

If the POC must generate Python directly, `generate`/`validate` must enforce:
- syntax compilation (AST parse),
- restricted imports/APIs — no `subprocess`, filesystem writes, sockets, `eval`, or `exec`,
- execution only inside the runner container,
- mandatory proxy use,
- timeout and resource limits,
- redaction of credentials, cookies, tokens, and secrets **before** any trace is sent to the LLM.

### Evidence linking (pick one, lightest first)
A local path (`evidence/scan-id/active-scan.har`) is not a clickable GitHub URL. For the POC:
- **preferred:** upload redacted evidence as a GitHub Actions artifact and link to the run;
- alternatives: commit sanitized evidence to a controlled location, or host at an approved URL.

**Redaction of auth cookies, bearer tokens, passwords, and sensitive request bodies before
publishing HAR is a hard requirement, not polish.** Note: redaction and the Actions-artifact
evidence link are additions beyond the 3-week plan's original scope (that plan is silent on
redaction) — confirm they fit the Week 2 budget rather than treating them as already-planned work.

**Requirements covered:** FR-R1/R3, FR-G1–G4, FR-V1–V3, FR-N1/N2, FR-X1/X2

---

## Phase 3 — Lifecycle and hardening (Week 3)

**Goal:** prove lifecycle behavior and deliver the polished full loop.

Deliver:
- two-scan state handling and fingerprint diff,
- one controlled vulnerability fix in the pilot app,
- open/new/resolved output,
- generated-flow rerun,
- evidence redaction, reproducibility checks,
- final container + README cleanup,
- recorded end-to-end demo covering all four requirements section 9 acceptance steps.

### Local vs. GitHub lifecycle (keep them separate)
- **Acceptance criterion (local):** fingerprint diff flips one detection to `resolved` while others
  stay `open` (FR-L1/L2).
- **Separate observation (GitHub):** what the Security tab shows after the **second** SARIF upload.
  SARIF-driven alert resolution has its own branch/category/re-upload semantics; do **not** make it
  a pass/fail condition unless the exact behavior has been verified.

### Fingerprint stability testing (beyond "scan twice")
Canonicalize before hashing: scheme/host normalization, trailing slashes, query ordering, endpoint
templates, parameter names, and **payload families** rather than literal payloads. Test at least:
1. identical scan twice,
2. same weakness with a changed payload,
3. an unrelated endpoint finding,
4. a fixed weakness,
5. changed ZAP message text.

Keep canonicalization **minimal for the single pinned pilot app** — enough to pass these five tests,
not a full production canonicalization matrix.

**Requirements covered:** full loop, FR-L1/L2, NFR-1/3/4

---

## Known gaps (documented, not built in the POC)

Per requirements section 3.2, these are recorded as gaps, not Week 1-3 work:
- Scope enforcement edge cases: IPv6 forms, host aliases, alternate ports, redirect chains, IP
  literals. POC uses the simple rule: **proxy every request; block/log/fail on any non-allow-listed
  host**, tested through the same path shown in the demo.
- Full fingerprint canonicalization across ZAP output variants beyond the single pinned version.
- Durable/governed evidence hosting beyond a GitHub Actions artifact.
- GitHub alert auto-resolution semantics (observed, not asserted).

---

## Contract-freeze checklist (resolve before coding)

Must-resolve:
- [ ] **FR-S4:** on an out-of-scope request — block-and-continue or block-and-abort?
      (Default: block, log, fail.)
- [ ] **LLM output:** generate Python directly, or a declarative JSON plan? (Recommend JSON plan.)
- [ ] **Evidence hosting:** where do files live so SARIF links resolve? (Recommend Actions artifact.)
- [ ] **`auth.json`:** the 3-week plan already assumes `generate` produces it (listed as a `generate`
      output); requirements FR-G2/G3 do not formally require it. Default: treat as required, and
      update FR-G3 to say so explicitly.
- [ ] **FR-G3 file count:** "all four files" lists three artifacts — fix the inconsistency
      (likely the missing fourth is `auth.json`, per the point above).
- [ ] **Lifecycle:** is GitHub alert resolution required, or only local lifecycle? (Recommend local.)
- [ ] **Deterministic pass:** which weakness + endpoint constitutes the Phase 1 detection assertion?

Sensible defaults (confirm, low risk):
- [ ] **Scope granularity:** host-only, or host + scheme + port + path? (Default: host + scheme + port.)
- [ ] **`avoid_action_list` enforcement:** how are avoided actions (e.g. logout, delete-account)
      prevented during replay/scan?

---

## Summary

```markdown
- [ ] Phase 1 (Week 1): Minimum-viable-scanner gate - safe authenticated scan, deterministic
      block/log/fail, >=1 high/medium alert on an authenticated endpoint
- [ ] Phase 2 (Week 2): Deterministic results pipeline + early GitHub/SARIF fixture proof, then
      LLM authoring behind a code-safety boundary
- [ ] Phase 3 (Week 3): Local fingerprint lifecycle (open/new/resolved) + hardening; GitHub alert
      resolution observed separately
```
