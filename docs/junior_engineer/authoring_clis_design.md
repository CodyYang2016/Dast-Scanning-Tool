# Authoring CLIs — Design (record / generate / validate) — Phase 2

The three CLIs that turn a recording of the pilot app into the scan config — the LLM-assisted
"differentiator." Closes FR-R1–R3, FR-G1–G4, FR-V1–V3 and the Week-2 checkpoint
(`record → generate → validate → runner → normalizer → SARIF → GitHub`).

## The safety architecture (why this design)

```
record ──▶ trace.json ──▶ generate ──▶ journey.json (LLM DATA, schema-validated)
                                   │                      │  deterministic render
                                   │                      ▼
                                   └──▶ scope.json, auth.json, zap-policy.yaml,
                                        manifest.json, lock            flow.py (templated)
                                                                          │
validate (allow-list + live auth replay) ◀────────────────────────────────┘
```

**The LLM emits DATA, not code.** `generate` asks the LLM for a **constrained JSON journey
plan** (validated against `contracts/journey.schema.json`); deterministic code renders that
plan into `flow.py`. The model never authors executable Python. This is the demo plan's LLM
safety boundary, and it makes idempotency (FR-G4) nearly free — same plan → byte-identical
`flow.py`. The rendered code is also AST-compile-checked before use, and credentials come from
env (`auth.json` holds only env-var *names*), never baked in (NFR-3).

## LLM handling (primary, with fallback)
- **Primary:** Anthropic SDK (`ANTHROPIC_API_KEY`, latest Claude model, temperature 0),
  lazy-imported. The trace (no secrets) + the journey schema go in; a JSON plan comes back,
  parsed (`parse_plan_text` strips fences) and validated. One repair retry, then fallback.
- **Fallback (resilience):** `journey_from_trace` builds a valid plan deterministically from the
  trace's routes + GET API calls — used only if the key is absent or the model output can't be
  made schema-valid. Lets the pipeline run/demo without a key.

## New contracts
- `contracts/trace.schema.json` — record output (pages / interactions / forms / api / hosts).
- `contracts/journey.schema.json` — the constrained plan: `login` block (selectors + token
  check) + a `journey` of `goto` / `click` / `api_get` steps. No credentials.

## Components

### `authoring/record.py` (FR-R1/R2/R3)
- `build_trace(app_id, base_url, events)` — **pure**, unit-tested: raw events → schema-valid
  trace (hosts via `runner.scope_guard.host_of`).
- `crawl(...)` — **live**: Chromium (optionally through the ZAP proxy so recorded hosts match
  the runner topology, D7) drives register → login → an authenticated page, recording
  goto/fill/click/form interactions and `/rest//api/` XHR.

### `authoring/generate.py` (FR-G1–G4)
- `emit_scope` (FR-G2, allow-list from trace hosts; validates vs scope schema), `render_flow`
  (deterministic plan→`flow.py`), `validate_plan`, `parse_plan_text`, `emit_zap_policy` /
  `emit_manifest` / `emit_lock` / `emit_auth` (FR-G3) — all **pure, unit-tested**.
- `plan_from_llm` (live) + `make_plan` (LLM-or-fallback) + `generate` (writes all artifacts).
- `json.dumps` is valid YAML, so `zap-policy.yaml` needs no PyYAML dependency.

### `authoring/validate.py` (FR-V1/V2/V3)
- `check_allowlist` (FR-V2, reuses `runner.scope_guard`) + `build_report` — **pure, unit-tested**.
- Live auth replay via `runner.replay.replay()` (FR-V1); writes `validation-report.json` and
  returns **non-zero** on any failing check (FR-V3).

## Testing
Deterministic pieces are **test-first** (frozen red, then implemented): `tests/test_record.py`,
`tests/test_generate.py`, `tests/test_validate.py` (22 tests). Oracles: the committed schemas,
Python's own compiler (rendered flow must compile), determinism/identity, and hand-built
plans/scopes with known allow/deny outcomes. Live pieces (crawl, LLM call, auth replay) are
verified by running them.

## Verification (this environment, fallback path)
`record` → `generate --no-llm` → `validate` (live replay) → `runner.main`, all against Juice
Shop + ZAP. Record captured a real trace (hosts=`juice`, 22 API calls); generate emitted 6
artifacts (all parse, `flow.py` compiles, identical across runs); validate passed allow-list +
**live auth replay** (rc 0); the generated bundle then drove `runner.main`. The **LLM path is
verified separately once `ANTHROPIC_API_KEY` is provided** (FR-G1 with the real model).

## Out of scope
Deep prompt tuning; multi-app; `testdata.json` form-input framework; durable evidence hosting.
