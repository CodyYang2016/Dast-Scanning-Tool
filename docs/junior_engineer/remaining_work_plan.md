# DAST POC — Remaining Work Plan (comprehensive, 3-week scope)

## Context

Day 1 is effectively complete: the shared contracts are frozen and committed
(`contracts/scope.json` + `scope.schema.json`, `detection.schema.json`, the fingerprint
formula with real worked examples), a real ZAP fixture is captured
(`contracts/sample_zap_output.json` — 38 alerts, 8 rule types, 1 High SQLi), and a
repeatable capture script exists (`runner/capture_zap_fixture.sh`). ZAP + Juice Shop run
locally on the `dast` docker network.

**But there is zero application code yet** — every green "build" component in the
requirements doc §5.1 is unbuilt. This plan lays out everything that remains to reach the
POC's definition of done: the four proof points demoed end-to-end on the pilot app. Scope
follows the requirements doc and the 3-week plan; both engineer streams are covered.

## The four proof points (definition of done — requirements §9)

1. `record` → `generate` → `validate` produce LLM-assisted artifacts; validation passes.
2. Scan runs; **scope enforcement blocks an out-of-allow-list request** (the guardrail).
3. Detections appear in the **GitHub Security tab** as SARIF, with severity + evidence link.
4. Fix one weakness, re-scan; that detection flips to **resolved** via the fingerprint diff
   while others stay open.

## Component inventory (all remaining unless noted)

| Component | Dir | FRs | Owner | Notes / reusable assets |
|-----------|-----|-----|-------|-------------------------|
| Normalizer + fingerprint | `detections/` | N1, N2 | Eng 1 | Reuse fingerprint ref impl in `contracts/README.md`; input = the fixture |
| SARIF exporter | `detections/` | X1 | Eng 1 | SARIF 2.1.0 + `partialFingerprints` |
| SARIF upload to GitHub | `detections/` or CI | X2 | Eng 1 | Personal public repo → code-scanning works via `gh` |
| Lifecycle diff + state | `detections/` | L1, L2 | Eng 1 | Set-compare fingerprints → open/new/resolved |
| Scan runner (orchestration) | `runner/` | S1, S2, S5 | Eng 2 | **Head start:** capture script already does spider+active-scan+scope-bound |
| Scope enforcement | `runner/` | S3, S4, NFR-2 | Eng 2 | env-class guard + allow/deny at proxy + interceptor |
| Evidence capture | `runner/` | E1 | Eng 2 | HAR + screenshot per scan; referenced from SARIF |
| `record` CLI | `authoring/` | R1, R2, R3 | Eng 1/2 | Playwright crawl → trace.json/index.json |
| `generate` CLI (LLM) | `authoring/` | G1–G4 | Eng 2 + Eng 1 | LLM → flow.py + scope.json + policy/manifest/lock |
| `validate` CLI | `authoring/` | V1, V2, V3 | Eng 1 | Replay flow + allow-list check + report/exit code |
| Packaging | repo root | NFR-5, NFR-1 | Eng 2 | Containerize; single command; lock file |
| Test suite | `tests/` | — | both | Fixture-driven unit tests + integration |

Cross-cutting throughout: NFR-2 safety, NFR-3 secrets/config, NFR-4 structured logging.

## Week-by-week

### Week 1 — de-risk in parallel (fixture pipeline + scan spike)
**Eng 1 (fixture-driven, unblocked now):**
- `detections/normalizer.py` (FR-N1): map ZAP alert → detection record. Field mapping:
  `pluginId`→`rule_id`, `alert`→`title`, `risk`→`severity` (High→high, Medium→medium,
  Low→low, Informational→info), `url`→`endpoint` (path-only, ID-collapsed), `param`→
  `parameter` (null when empty), `cweid`→`cwe_id` (`CWE-<n>` or null).
- `detections/fingerprint.py` (FR-N2): lift the frozen ref impl from `contracts/README.md`;
  add the `payload_family` mapping table (also pinned in the README) + `endpoint_pattern` rule.
- Unit tests against `contracts/sample_zap_output.json`; assert the README's two worked
  digests reproduce, and twice-normalizing is stable.
- `detections/sarif_export.py` (FR-X1) + validate output; upload a hand-made SARIF to prove
  the Security-tab path (FR-X2) independently of the runner.

**Eng 2 (the critical-path spike — no Speckit ceremony):**
- Stand up the runner shell: launch ZAP (daemon already proven), route Playwright through
  the ZAP proxy, replay a hand-authored flow, run a scope-bounded active scan (FR-S1/S2).
  Start from `runner/capture_zap_fixture.sh`'s proven API sequence.
- Auth replay against Juice Shop login (the hardest, time-boxed bit).
- Scope enforcement mechanism (FR-S4) + the env-class/prod guard (FR-S3).

**Checkpoint (end Wk1):** real runner output flows into Eng 1's normalizer (assembly, not
rewrite — both coded to the frozen contract).

### Week 2 — authoring CLIs + finish the results pipeline
**Eng 1:** `detections/lifecycle_diff.py` + state store (FR-L1/L2); thin `authoring/record`
(FR-R1/R3) and `authoring/validate` (FR-V2/V3); harden with tests.
**Eng 2 (pairing w/ Eng 1):** `authoring/generate` — LLM call, prompt design, robust parsing
of imperfect output → `flow.py` + `scope.json` + `zap-policy` + `manifest`/`lock` (FR-G1–4).
Keep a hand-authored flow as fallback (risk mitigation).
**Checkpoint (end Wk2):** first full chain `record → generate → validate → runner →
normalizer → SARIF → GitHub`.

### Week 3 — integrate, lifecycle, package, demo
- Run two consecutive scans to exercise the diff (fix one Juice Shop weakness → that
  detection flips `resolved`, others stay `open`).
- Evidence capture wired into SARIF (FR-E1); structured logging pass (NFR-4).
- Containerize the runner, single documented command (NFR-5); pin versions in lock (NFR-1).
- Harden seams, buffer, record the 4-step demo + a written gaps/next-steps summary.

## Technical approach notes (per component, concise)

- **Stack:** Python 3.12 (installed); `playwright` + Chromium; ZAP via its HTTP API (pattern
  already in the capture script); `jsonschema` for contract validation (venv, PEP-668).
- **Normalizer/fingerprint:** pure functions, no I/O in the core → trivially unit-testable
  against the fixture. The fixture's real fields are already known (see capture work).
- **SARIF:** hand-roll SARIF 2.1.0 (few deps) with `partialFingerprints.dastFingerprint/v1`
  carrying our fingerprint; map severity→SARIF level; validate against the SARIF schema.
- **Upload:** `gh api` code-scanning `sarifs` endpoint or the `upload-sarif` Action; the repo
  is public so no GHAS needed.
- **Runner:** the capture script already proves spider + bounded active scan + scope-to-host
  + the DOM-XSS/`-silent` gotchas; extend it with Playwright-through-proxy + auth replay.
- **Scope enforcement (NFR-2, the #1 guardrail):** refuse if `scope.json` missing / no
  `environment_class` / `environment_class == prod`; block any in-flight host not in
  `fqdn_allow_list` (or in deny-list); log every decision.
- **CLIs:** thin `argparse` wrappers; config/secrets from env or untracked file (NFR-3).

## Dependencies, sequencing, critical path
- **Eng 1's entire stream is unblocked today** — it runs against the committed fixture with
  zero dependency on the runner. This is why Day 1 front-loaded the contracts + fixture.
- **The runner/auth-replay spike is the critical path.** If it slips, Eng 1's fixture-tested
  modules still progress; only the *end-to-end demo* waits on the runner.
- Three handshakes gate integration: end of Day 1 (done), end of Wk1 (runner→normalizer),
  end of Wk2 (full chain).

## Risks & mitigations (from requirements §11 / plan)
- LLM flow generation flaky → seed from Playwright codegen; keep a hand-authored fallback flow.
- ZAP+Playwright session/auth finicky → start with the simplest login; time-box; it's Wk1.
- Scope creep toward Step 2 / dashboards / Harness → treat the out-of-scope list as hard.
- Solo capacity → cut optional metrics; protect the four proof points.

## Verification strategy
- **Per proof point:** (1) run the three CLIs, show artifacts; (2) inject an out-of-scope
  host, show the block in logs; (3) open the GitHub Security tab, show the SARIF alerts +
  evidence link; (4) two scans across a fix, show the `resolved` flip.
- **Unit:** `tests/` fixture-driven — normalizer field mapping, fingerprint stability +
  README digests, SARIF schema-valid, diff open/new/resolved on synthetic fingerprint sets.
- **Integration:** end-to-end runner on Juice Shop completes < 15 min (FR-S5).

## Out of scope (do NOT build — requirements §3.2)
Production/blackbox scanning, prod-safe policies, rate-limiting/circuit-breakers, Databricks
ingestion / BI dashboards, App Registry, scheduler, on-demand console, API triggers, Archer,
full 7-control enforcement stack, multi-app support, automated PR-review gates.

## Note on the deferred Day-1 admin items
Speckit constitution, Week-1 split doc, branch protection, and the 3 calendar checkpoints
were de-prioritized. They're not blockers for any build work above; pick them up later if the
POC goes toward a real team hand-off.
